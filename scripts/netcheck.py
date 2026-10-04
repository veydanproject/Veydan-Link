#!/usr/bin/env python3
"""Does a connection between two machines carry bytes, and in which direction?

One side listens, the other dials; then either side may be the one that
sends. What is measured is how many bytes arrive within a time limit: a
throttled path stalls after some tens of kilobytes without closing.

  netcheck.py serve PORT [--tls CERT KEY]
  netcheck.py pull HOST PORT BYTES [--tls] [--sni NAME] [--alpn PROTO] [--secs N]
        the listener sends BYTES, the dialler counts what arrives
  netcheck.py push HOST PORT BYTES [--tls] [--sni NAME] [--alpn PROTO] [--secs N]
        the dialler sends BYTES, the listener says how many arrived
"""
import socket, ssl, sys, threading, time

CHUNK = b"\xa5" * 65536


def read_line(conn):
    line = b""
    while not line.endswith(b"\n"):
        b = conn.recv(1)
        if not b:
            break
        line += b
    return line.decode().strip()


def handle(conn):
    try:
        conn.settimeout(60)
        words = read_line(conn).split()
        if len(words) != 2:
            return
        command, count = words[0], int(words[1])
        if command == "SEND":
            left = count
            while left > 0:
                n = min(left, len(CHUNK))
                conn.sendall(CHUNK[:n])
                left -= n
        elif command == "RECV":
            got = 0
            try:
                while got < count:
                    data = conn.recv(65536)
                    if not data:
                        break
                    got += len(data)
            except socket.timeout:
                pass
            conn.sendall(("GOT %d\n" % got).encode())
    except Exception as e:
        print("connection:", e, flush=True)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def serve(port, tls):
    context = None
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(tls[0], tls[1])
        context.set_alpn_protocols(["h2", "http/1.1", "vlink-hub/1"])
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(16)
    print("listening on", port, "tls" if tls else "plain", flush=True)
    while True:
        conn, _ = listener.accept()
        if context:
            try:
                conn = context.wrap_socket(conn, server_side=True)
            except Exception as e:
                print("handshake:", e, flush=True)
                continue
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def dial(host, port, tls, sni, alpn):
    conn = socket.create_connection((host, port), timeout=15)
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if alpn:
            context.set_alpn_protocols([alpn])
        conn = context.wrap_socket(conn, server_hostname=sni)
    return conn


def main():
    args = sys.argv[1:]
    def flag(name, takes=0):
        if name not in args:
            return None
        i = args.index(name)
        value = args[i + 1:i + 1 + takes] if takes else True
        del args[i:i + 1 + takes]
        return value
    tls_files = flag("--tls", 2) if args and args[0] == "serve" else None
    tls = flag("--tls") if tls_files is None else None
    sni = (flag("--sni", 1) or [None])[0]
    alpn = (flag("--alpn", 1) or [None])[0]
    secs = float((flag("--secs", 1) or ["20"])[0])
    if args[0] == "serve":
        return serve(int(args[1]), tls_files)
    mode, host, port, count = args[0], args[1], int(args[2]), int(args[3])
    conn = dial(host, port, tls, sni, alpn)
    started = time.time()
    if mode == "pull":
        conn.sendall(("SEND %d\n" % count).encode())
        conn.settimeout(2)
        got = 0
        while got < count and time.time() - started < secs:
            try:
                data = conn.recv(65536)
            except (socket.timeout, ssl.SSLError):
                continue
            if not data:
                break
            got += len(data)
        took = time.time() - started
        print("pull %d of %d bytes in %.1f s%s" % (got, count, took, "" if got == count else "  STALLED"))
    else:
        conn.sendall(("RECV %d\n" % count).encode())
        conn.settimeout(secs)
        sent = 0
        try:
            while sent < count:
                n = min(count - sent, len(CHUNK))
                conn.sendall(CHUNK[:n])
                sent += n
            answer = read_line(conn)
        except (socket.timeout, ssl.SSLError, OSError) as e:
            answer = "no answer (%s) after %d bytes handed to the system" % (type(e).__name__, sent)
        took = time.time() - started
        ok = answer == "GOT %d" % count
        print("push %d bytes in %.1f s: %s%s" % (count, took, answer, "" if ok else "  STALLED"))


if __name__ == "__main__":
    main()
