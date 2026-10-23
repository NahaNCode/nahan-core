#!/usr/bin/env python3
"""Bounded loopback acceptance; run only inside an isolated LAB namespace."""
import argparse
import json
import pathlib
import socket
import struct
import subprocess
import tempfile
import threading
import time
import uuid


def receive(conn, length):
    chunks = bytearray()
    while len(chunks) < length:
        chunk = conn.recv(length - len(chunks))
        if not chunk:
            raise RuntimeError("premature EOF")
        chunks.extend(chunk)
    return bytes(chunks)


def echo(listener):
    def handle(conn):
        with conn:
            try:
                while data := conn.recv(8192):
                    conn.sendall(data)
            except OSError:
                return
    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def resources(process):
    root = pathlib.Path("/proc") / str(process.pid)
    values = {}
    for line in (root / "status").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in ("VmRSS", "Threads"):
            values[key] = int(value.split()[0])
    values["fds"] = len(list((root / "fd").iterdir()))
    return values


def stop(process):
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def exercise(binary, seconds):
    identity = uuid.uuid4()
    with tempfile.TemporaryDirectory(prefix="nahan-soak-") as directory:
        root = pathlib.Path(directory)
        with socket.socket() as target, socket.socket() as reservation:
            target.bind(("127.0.0.1", 0))
            target.listen()
            threading.Thread(target=echo, args=(target,), daemon=True).start()
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
            reservation.close()
            inbound = [{"listen": "127.0.0.1", "port": port, "protocol": "vless",
                        "settings": {"decryption": "none", "clients": [{"id": str(identity)}]}}]
            outbound = [{"protocol": "freedom", "settings": {
                "finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"]}]}}]
            (root / "in.json").write_text(json.dumps(inbound))
            (root / "out.json").write_text(json.dumps(outbound))
            config = {"Log": {"Level": "none"}, "Nodes": [],
                      "InboundConfigPath": str(root / "in.json"),
                      "OutboundConfigPath": str(root / "out.json")}
            (root / "config.json").write_text(json.dumps(config))

            def connect():
                conn = socket.create_connection(("127.0.0.1", port), timeout=5)
                try:
                    request = (b"\0" + identity.bytes + b"\0\1"
                               + struct.pack("!H", target.getsockname()[1]) + b"\1\x7f\0\0\1")
                    conn.sendall(request + b"probe")
                    header = receive(conn, 2)
                    if header[0] != 0:
                        raise RuntimeError("invalid VLESS response")
                    receive(conn, header[1])
                    if receive(conn, 5) != b"probe":
                        raise RuntimeError("handshake payload mismatch")
                    return conn
                except BaseException:
                    conn.close()
                    raise

            with (root / "runtime.log").open("w+") as log:
                process = subprocess.Popen([str(binary), "--config", str(root / "config.json")],
                                           stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 20
                    while True:
                        if process.poll() is not None:
                            raise RuntimeError("core exited during startup")
                        try:
                            retained = connect()
                            break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise
                            time.sleep(.1)
                    samples = [resources(process)]
                    transfers = 0
                    payload = b"nahan-loopback-soak" * 128
                    start = time.monotonic()
                    next_sample = start + 10
                    with retained:
                        while time.monotonic() - start < seconds:
                            if process.poll() is not None:
                                raise RuntimeError("core exited during soak")
                            retained.sendall(payload)
                            if receive(retained, len(payload)) != payload:
                                raise RuntimeError("retained stream payload mismatch")
                            with connect() as short:
                                short.sendall(payload)
                                if receive(short, len(payload)) != payload:
                                    raise RuntimeError("short stream payload mismatch")
                            transfers += 1
                            if time.monotonic() >= next_sample:
                                samples.append(resources(process))
                                next_sample += 10
                            time.sleep(.25)
                    # Allow connection cleanup before measuring the final idle state.
                    time.sleep(5)
                    final = resources(process)
                    samples.append(final)
                    if final["fds"] > samples[0]["fds"] + 16:
                        raise RuntimeError("file descriptor cleanup exceeded acceptance bound")
                    result = {"binary": binary.name, "seconds": seconds,
                              "short_connections": transfers, "retained_transfers": transfers,
                              "samples": samples, "final": final,
                              "peak_rss_kib": max(s.get("VmRSS", 0) for s in samples)}
                    print(json.dumps(result), flush=True)
                finally:
                    stop(process)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binaries", nargs="+", type=pathlib.Path)
    parser.add_argument("--seconds", type=int, default=120)
    args = parser.parse_args()
    if not 30 <= args.seconds <= 1800:
        parser.error("seconds must be between 30 and 1800")
    for binary in args.binaries:
        exercise(binary.resolve(strict=True), args.seconds)
