"""Linux integration check: two isolated OpenSIPS nodes and two UDP phones.

Run with Python 3 on a host with OpenSIPS installed. Uses only loopback
addresses and temporary configuration; never touches the system service.
"""

import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]


def headers(message, name):
    return re.findall(r"^" + re.escape(name) + r":\s*(.*?)\r?$", message,
                      re.MULTILINE | re.IGNORECASE)


def header(message, name):
    return headers(message, name)[0]


def uri(value):
    return re.search(r"<([^>]+)>", value).group(1)


def address(value):
    match = re.search(r"sip:(?:[^@;>]+@)?([\d.]+)(?::(\d+))?", value)
    return match.group(1), int(match.group(2) or 5060)


def wire(start, fields):
    return (start + "\r\n" + "\r\n".join(fields) +
            "\r\nContent-Length: 0\r\n\r\n").encode()


class Phone:
    def __init__(self, user, ip, node):
        self.user, self.node = user, node
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, 0))
        self.sock.settimeout(5)
        self.ip, self.port = self.sock.getsockname()
        self.identity = f"<sip:{user}@{node}>"
        self.contact = f"<sip:{user}@10.99.99.99:6000>"

    def send(self, method, target, call_id, from_value, to_value, routes=(), seq=1):
        fields = [f"Via: SIP/2.0/UDP {self.ip}:{self.port};rport;branch=z9hG4bK{uuid.uuid4().hex}",
                  "Max-Forwards: 70", f"From: {from_value}", f"To: {to_value}",
                  f"Call-ID: {call_id}", f"CSeq: {seq} {method}"]
        fields.extend("Route: " + route for route in routes)
        if method in ("REGISTER", "INVITE"):
            fields.append("Contact: " + self.contact)
        if method == "REGISTER":
            fields.append("Expires: 120")
        destination = address(routes[0]) if routes else (self.node, 5060)
        self.sock.sendto(wire(f"{method} {target} SIP/2.0", fields), destination)

    def receive(self, call_id, prefix):
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            data, source = self.sock.recvfrom(65535)
            message = data.decode()
            if header(message, "Call-ID") != call_id:
                continue
            if message.startswith(prefix):
                return message, source
            if message.startswith("SIP/2.0 ") and int(message.split()[1]) >= 300:
                raise AssertionError(message)
        raise AssertionError(f"Timed out waiting for {prefix}")

    def reply(self, request, source, contact=False):
        fields = ["Via: " + value for value in headers(request, "Via")]
        fields.extend("Record-Route: " + value for value in headers(request, "Record-Route"))
        to_value = header(request, "To")
        if ";tag=" not in to_value:
            to_value += ";tag=answer"
        fields.extend(["From: " + header(request, "From"), "To: " + to_value,
                       "Call-ID: " + header(request, "Call-ID"),
                       "CSeq: " + header(request, "CSeq")])
        if contact:
            fields.append("Contact: " + self.contact)
        self.sock.sendto(wire("SIP/2.0 200 OK", fields), source)

    def register(self):
        call_id = uuid.uuid4().hex
        self.send("REGISTER", "sip:" + self.node, call_id,
                  self.identity + ";tag=register", self.identity)
        self.receive(call_id, "SIP/2.0 200")


def check_call(caller, callee, hangup):
    call_id = uuid.uuid4().hex
    caller.send("INVITE", f"sip:{callee.user}@{caller.node}", call_id,
                caller.identity + ";tag=caller", callee.identity)
    invite, source = callee.receive(call_id, "INVITE ")
    assert address(header(invite, "Contact")) == (caller.ip, caller.port), "Caller Contact corrupted"
    route_set = headers(invite, "Record-Route")
    expected_hops = 1 if caller.node == callee.node else 2
    assert len(route_set) == expected_hops, f"Every traversed node must Record-Route: {route_set}"
    assert {address(item)[0] for item in route_set} == {caller.node, callee.node}
    callee.reply(invite, source, contact=True)
    answer, _ = caller.receive(call_id, "SIP/2.0 200")
    assert address(header(answer, "Contact")) == (callee.ip, callee.port), "Callee Contact corrupted"
    caller_routes = list(reversed(headers(answer, "Record-Route")))
    caller.send("ACK", uri(header(answer, "Contact")), call_id,
                header(answer, "From"), header(answer, "To"), caller_routes)
    callee.receive(call_id, "ACK ")
    if hangup == "caller":
        sender, receiver = caller, callee
        target, routes = uri(header(answer, "Contact")), caller_routes
        from_value, to_value = header(answer, "From"), header(answer, "To")
    else:
        sender, receiver = callee, caller
        target, routes = uri(header(invite, "Contact")), route_set
        from_value, to_value = header(answer, "To"), header(answer, "From")
    sender.send("BYE", target, call_id, from_value, to_value, routes, seq=2)
    bye, source = receiver.receive(call_id, "BYE ")
    receiver.reply(bye, source)
    sender.receive(call_id, "SIP/2.0 200")
    print(f"PASS {caller.user} -> {callee.user}, {hangup} hangs up: ACK, BYE and 200 OK delivered", flush=True)


def check_unknown_user(caller):
    call_id = uuid.uuid4().hex
    caller.send("INVITE", f"sip:91999@{caller.node}", call_id,
                caller.identity + ";tag=caller", f"<sip:91999@{caller.node}>")
    caller.receive(call_id, "SIP/2.0 404")
    print("PASS unregistered destination returns 404", flush=True)


def main():
    stage = Path(tempfile.mkdtemp(prefix="sipmesh-dialog-test-"))
    print(f"Test configs and logs: {stage}", flush=True)
    processes, logs, phones = [], [], []
    try:
        for number, ip, peer in [(1, "127.0.0.2", "127.0.0.3"), (2, "127.0.0.3", "127.0.0.2")]:
            node = stage / str(number)
            (node / "conf.d").mkdir(parents=True)
            for relative in ["opensips.cfg", "conf.d/routing.cfg", "conf.d/modules.cfg", "conf.d/cluster-common.cfg"]:
                text = (ROOT / relative).read_text().replace("/etc/opensips/", str(node) + "/")
                text = text.replace("<CHANGE_ME>", ip).replace("<NODE_IP>", ip)
                text = text.replace('"my_node_id", 1', f'"my_node_id", {number}')
                text = text.replace("stderror_enabled=no", "stderror_enabled=yes").replace("syslog_enabled=yes", "syslog_enabled=no")
                text = text.replace("/run/opensips/opensips_fifo", str(node / "mi.fifo"))
                text = re.sub(r'^modparam\("mi_fifo", "fifo_group".*$', "", text, flags=re.MULTILINE)
                # Avoid unrelated 2-ms cluster flapping in the dialog test.
                text = text.replace('"ping_timeout", 2)', '"ping_timeout", 1000)')
                (node / relative).write_text(text)
            (node / "conf.d/neighbors.cfg").write_text(
                f'modparam("clusterer", "neighbor_node_info", "cluster_id=1,node_id={3-number},url=bin:{peer}:5566,sip_addr=sip:{peer}:5060")\n')
            log = (node / "opensips.log").open("w")
            logs.append(log)
            processes.append(subprocess.Popen(["opensips", "-F", "-f", str(node / "opensips.cfg"),
                                               "-P", str(node / "pid"), "-m", "32"],
                                              stdout=log, stderr=log, start_new_session=True))
        time.sleep(3)
        assert all(proc.poll() is None for proc in processes), "OpenSIPS failed to start; inspect test logs"
        phones = [Phone("91001", "127.0.0.10", "127.0.0.2"),
                  Phone("91002", "127.0.0.11", "127.0.0.3"),
                  Phone("91003", "127.0.0.12", "127.0.0.2")]
        for phone in phones:
            phone.register()
        time.sleep(1)
        for caller, callee in [(phones[0], phones[1]), (phones[1], phones[0]),
                               (phones[0], phones[2]), (phones[2], phones[0])]:
            for hangup in ["caller", "callee"]:
                check_call(caller, callee, hangup)
        check_unknown_user(phones[0])
    finally:
        for phone in phones:
            phone.sock.close()
        for proc in processes:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
        for log in logs:
            log.close()


if __name__ == "__main__":
    main()
