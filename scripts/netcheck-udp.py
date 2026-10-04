#!/usr/bin/env python3
"""The same question as netcheck.py, over UDP.

  netcheck-udp.py serve PORT            answers a hello with as many datagrams as asked
  netcheck-udp.py pull HOST PORT BYTES  says hello, counts what arrives (10 s)
"""
import socket, sys, time

SIZE = 1200

def serve(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    print("udp listening on", port, flush=True)
    while True:
        data, peer = s.recvfrom(2048)
        words = data.decode(errors="replace").split()
        if len(words) != 2 or words[0] != "SEND":
            continue
        count = int(words[1]) // SIZE
        payload = b"\xa5" * SIZE
        for i in range(count):
            s.sendto(payload, peer)
            if i % 50 == 49:
                time.sleep(0.01)   # about 5 MB/s: fast, and no flood
        print("sent", count, "datagrams to", peer, flush=True)

def pull(host, port, total):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1)
    s.sendto(("SEND %d" % total).encode(), (host, port))
    got, started, last = 0, time.time(), time.time()
    while time.time() - started < 10 and time.time() - last < 3:
        try:
            data, _ = s.recvfrom(2048)
        except socket.timeout:
            continue
        got += len(data)
        last = time.time()
    want = (total // SIZE) * SIZE
    print("udp pull %d of %d bytes (%.0f%%)" % (got, want, 100.0 * got / want))

if sys.argv[1] == "serve":
    serve(int(sys.argv[2]))
else:
    pull(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
