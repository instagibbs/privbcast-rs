"""A fake Tor SocksPort that is also every recipient, recording what a private broadcast job sends.

The proxy side records each stream's SOCKS5 greeting, authentication and request as sent, answers
RESOLVE from a script, and answers CONNECT with success or a refusal code. A CONNECT that succeeds
is then served on the same socket by a recipient with a scripted behaviour, a BIP324 responder
built on the functional test framework, so the initiator's writes arrive as it made them. Every
event is recorded with a monotonic timestamp.
"""
import random
import socket
import threading
import time

from test_framework.v2_p2p import EncryptedP2PState, MSGTYPE_TO_SHORTID, SHORTID

NODE_NETWORK = 1
NODE_WITNESS = 8
MSG_WTX = 5


def compact_size(n):
    if n < 253:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xffffffff:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def version_payload(version=70016, services=NODE_NETWORK | NODE_WITNESS, user_agent=b"/Satoshi:30.0.0/", relay=1):
    """A VERSION as a Bitcoin Core recipient sends it, with the fields that matter here."""
    return (version.to_bytes(4, "little", signed=True) + services.to_bytes(8, "little") + int(time.time()).to_bytes(8, "little")
            + bytes(26) + services.to_bytes(8, "little") + bytes(18) + random.randbytes(8)
            + compact_size(len(user_agent)) + user_agent + (200).to_bytes(4, "little") + bytes([relay]))


# What a recipient does. Keys: what it sends after the job's VERSION ("after_version", a list of
# (type, payload) where payload may be a callable of the job's VERSION), how it answers the INV
# ("getdata": None, "wtx", "other", "extra_byte", "twice"), the PING ("pong": None, "right", "wrong",
# "extra_byte"), plus "silent" (complete no handshake), "garbage" (its garbage length, default
# random), "decoys" (decoy packets around its messages), "noise" (unknown messages first),
# "flood" (bytes of unknown messages after its VERSION), "close_after_version".
COOP = {"after_version": [("version", None), ("wtxidrelay", b""), ("sendaddrv2", b""), ("verack", b"")],
        "after_verack": [("sendcmpct", bytes([0]) + (2).to_bytes(8, "little")), ("ping", None), ("feefilter", (1000).to_bytes(8, "little"))],
        "getdata": "wtx", "pong": "right"}


def behaviour(**changes):
    b = dict(COOP)
    b.update(changes)
    return b


BEHAVIOURS = {
    "coop": behaviour(),
    "silent": behaviour(silent=True),
    "noreq": behaviour(getdata=None),
    "low_version": behaviour(after_version=[("version", version_payload(version=70015)), ("wtxidrelay", b""), ("verack", b"")]),
    "no_witness": behaviour(after_version=[("version", version_payload(services=NODE_NETWORK)), ("wtxidrelay", b""), ("verack", b"")]),
    "no_relay": behaviour(after_version=[("version", version_payload(relay=0)), ("wtxidrelay", b""), ("verack", b"")]),
    "no_wtxidrelay": behaviour(after_version=[("version", None), ("verack", b"")]),
    "version_extra_byte": behaviour(after_version=[("version", version_payload() + b"\x00"), ("wtxidrelay", b""), ("verack", b"")]),
    "verack_payload": behaviour(after_version=[("version", None), ("wtxidrelay", b""), ("verack", b"\x00")]),
    "getdata_other": behaviour(getdata="other"),
    "getdata_extra_byte": behaviour(getdata="extra_byte"),
    "getdata_twice": behaviour(getdata="twice"),
    "pong_wrong": behaviour(pong="wrong"),
    "pong_extra_byte": behaviour(pong="extra_byte"),
    "peer_decoys": behaviour(decoys=True, garbage=4095),
    "noise": behaviour(noise=True),
    "flood": behaviour(flood=140 * 1024),
    "close_after_version": behaviour(close_after_version=True),
    "slow_version_packet": behaviour(delay_version_packet=0.4, getdata=None),
    # Requests the transaction, then stops reading: the job's write of a large TX blocks.
    "stall_reads": behaviour(stall_after_getdata=30),
}

# Behaviours that need a small receive buffer, so that the job's writes block.
SMALL_RCVBUF = {"stall_reads"}


class Recorder:
    def __init__(self):
        self.lock = threading.Lock()
        self.events = []

    def add(self, **event):
        event["t"] = time.monotonic()
        with self.lock:
            self.events.append(event)
        return event


class Recipient:
    """A BIP324 responder with a scripted behaviour on an accepted socket."""

    def __init__(self, sock, b, rec, stream_id, net, wtxid, timeout):
        self.sock, self.b, self.rec, self.id, self.net, self.wtxid = sock, b, rec, stream_id, net, wtxid
        self.timeout = timeout
        self.buf = b""
        self.state = None

    def recv_until(self, deadline):
        """Read what arrives until deadline, recording each chunk; the stream stays open."""
        while (left := deadline - time.monotonic()) > 0:
            self.sock.settimeout(left)
            try:
                data = self.sock.recv(65536)
            except socket.timeout:
                break
            finally:
                self.sock.settimeout(self.timeout)
            if not data:
                self.rec.add(kind="close", stream=self.id, how="fin")
                raise EOFError
            self.rec.add(kind="chunk", stream=self.id, n=len(data))
            self.buf += data

    def recv_more(self):
        try:
            data = self.sock.recv(65536)
        except (ConnectionResetError, ConnectionAbortedError):
            self.rec.add(kind="close", stream=self.id, how="rst")
            raise EOFError
        except socket.timeout:
            self.rec.add(kind="close", stream=self.id, how="timeout")
            raise EOFError
        if not data:
            self.rec.add(kind="close", stream=self.id, how="fin")
            raise EOFError
        self.rec.add(kind="chunk", stream=self.id, n=len(data))
        self.buf += data

    def send(self, data):
        try:
            self.sock.sendall(data)
        except OSError:
            pass

    def send_msg(self, msg_type, payload):
        if msg_type.encode() in MSGTYPE_TO_SHORTID:
            contents = bytes([MSGTYPE_TO_SHORTID[msg_type.encode()]]) + payload
        else:
            contents = b"\x00" + msg_type.encode().ljust(12, b"\x00") + payload
        if self.b.get("decoys"):
            self.send(self.state.v2_enc_packet(random.randbytes(random.randrange(100)), ignore=True))
        self.send(self.state.v2_enc_packet(contents))

    def run(self):
        try:
            while len(self.buf) < 64:
                self.recv_more()
            self.rec.add(kind="key", stream=self.id, ellswift=self.buf[:64].hex())
            if self.b.get("silent"):
                while True:
                    self.recv_more()
            st = self.state = EncryptedP2PState(initiating=False, net=self.net)
            ours = st.generate_keypair_and_garbage(self.b.get("garbage"))
            secret = st.v2_ecdh(st.privkey_ours, self.buf[:64], st.ellswift_ours, False)
            st.initialize_v2_transport(secret)
            out = b""
            if self.b.get("delay_version_packet"):
                # Key and garbage now; terminator and version packet later, reading meanwhile, so
                # that what the initiator sends before it has our version packet is seen.
                self.send(ours)
                self.rec.add(kind="key_sent", stream=self.id)
                self.recv_until(time.monotonic() + self.b["delay_version_packet"])
                ours = b""
            out = ours + st.peer["send_garbage_terminator"]
            if self.b.get("decoys"):
                out += st.v2_enc_packet(random.randbytes(50), aad=st.sent_garbage, ignore=True)
                out += st.v2_enc_packet(b"")
            else:
                out += st.v2_enc_packet(b"", aad=st.sent_garbage)
            self.send(out)
            self.rec.add(kind="version_packet_sent" if self.b.get("delay_version_packet") else "key_sent", stream=self.id)
            self.buf = self.buf[64:]
            term = st.peer["recv_garbage_terminator"]
            while term not in self.buf[:4095 + 16]:
                if len(self.buf) >= 4095 + 16:
                    self.rec.add(kind="error", stream=self.id, what="no garbage terminator")
                    return
                self.recv_more()
            garbage, self.buf = self.buf.split(term, 1)
            self.rec.add(kind="garbage", stream=self.id, n=len(garbage))
            aad, version_seen, decoys = garbage, False, 0
            while True:
                n, contents = st.v2_receive_packet(self.buf, aad)
                if n == 0:
                    self.recv_more()
                    continue
                if n < 0:
                    self.rec.add(kind="error", stream=self.id, what="decryption failure")
                    return
                packet_len, self.buf, aad = n, self.buf[n:], b""
                if contents is None:
                    decoys += 1
                    self.rec.add(kind="decoy", stream=self.id, n=packet_len)
                    continue
                if not version_seen:
                    version_seen = True
                    self.rec.add(kind="version_packet", stream=self.id, contents=contents.hex(), decoys_before=decoys)
                    continue
                if contents[0] != 0:
                    msg_type, payload, enc = SHORTID.get(contents[0], f"short{contents[0]}".encode()).decode(), contents[1:], "short"
                else:
                    msg_type, payload, enc = contents[1:13].rstrip(b"\x00").decode(), contents[13:], "long"
                self.rec.add(kind="msg", stream=self.id, type=msg_type, payload=payload.hex(), enc=enc, packet=packet_len)
                self.react(msg_type, payload)
        except EOFError:
            return
        except OSError as e:
            self.rec.add(kind="close", stream=self.id, how=f"error {e}")

    def react(self, msg_type, payload):
        b = self.b
        if msg_type == "version":
            if b.get("noise"):
                self.send(self.state.v2_enc_packet(bytes([200]) + b"x"))
                self.send_msg("unknownmsg", b"y" * 10)
            for t, p in b["after_version"]:
                self.send_msg(t, version_payload() if p is None else p)
            if b.get("flood"):
                chunk = b"z" * 10_000
                for _ in range(b["flood"] // len(chunk) + 1):
                    self.send_msg("unknownmsg", chunk)
            if b.get("close_after_version"):
                self.sock.shutdown(socket.SHUT_RDWR)
        elif msg_type == "verack":
            for t, p in b.get("after_verack", []):
                self.send_msg(t, random.randbytes(8) if p is None else p)
        elif msg_type == "inv" and b.get("getdata"):
            right = compact_size(1) + MSG_WTX.to_bytes(4, "little") + self.wtxid
            mode = b["getdata"]
            if mode == "other":
                self.send_msg("getdata", compact_size(1) + MSG_WTX.to_bytes(4, "little") + bytes(32))
            elif mode == "extra_byte":
                self.send_msg("getdata", right + b"\x00")
            else:
                self.send_msg("getdata", right)
                if mode == "twice":
                    self.send_msg("getdata", right)
            if b.get("stall_after_getdata"):
                self.rec.add(kind="stall", stream=self.id)
                time.sleep(b["stall_after_getdata"])
        elif msg_type == "ping" and b.get("pong"):
            mode = b["pong"]
            nonce = payload[:8] if mode != "wrong" else bytes(8)
            self.send_msg("pong", nonce + (b"\x00" if mode == "extra_byte" else b""))


class FakeTor:
    """resolve(name, n): the answer to the n-th RESOLVE of name: an address string, or None to
    answer host unreachable. connect(addr, port): a behaviour name, or an int, a refusal code."""

    def __init__(self, resolve, connect, net, wtxid, timeout=60, small_rcvbuf=False):
        self.resolve, self.connect, self.net, self.wtxid, self.timeout = resolve, connect, net, wtxid, timeout
        self.rec = Recorder()
        self.resolves = {}
        self.next_id = 0
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if small_rcvbuf:
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(128)
        self.port = self.listener.getsockname()[1]
        self.threads = []
        self.running = True
        threading.Thread(target=self.accept_loop, daemon=True).start()

    def accept_loop(self):
        while self.running:
            try:
                sock, _ = self.listener.accept()
            except OSError:
                return
            with self.rec.lock:
                stream_id = self.next_id
                self.next_id += 1
            t = threading.Thread(target=self.serve, args=(sock, stream_id), daemon=True)
            self.threads.append(t)
            t.start()

    def stop(self):
        self.running = False
        self.listener.close()

    @staticmethod
    def recvall(sock, n):
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return data

    def serve(self, sock, stream_id):
        sock.settimeout(self.timeout)
        rec = self.rec
        try:
            ver, nmethods = self.recvall(sock, 2)
            methods = self.recvall(sock, nmethods)
            rec.add(kind="greeting", stream=stream_id, raw=(bytes([ver, nmethods]) + methods).hex())
            if 0x02 not in methods:
                sock.sendall(b"\x05\xff")
                return
            sock.sendall(b"\x05\x02")
            auth_ver, ulen = self.recvall(sock, 2)
            user = self.recvall(sock, ulen)
            plen = self.recvall(sock, 1)[0]
            password = self.recvall(sock, plen)
            sock.sendall(b"\x01\x00")
            head = self.recvall(sock, 4)
            atyp = head[3]
            if atyp == 3:
                n = self.recvall(sock, 1)[0]
                addr = self.recvall(sock, n).decode()
            elif atyp == 1:
                addr = socket.inet_ntop(socket.AF_INET, self.recvall(sock, 4))
            else:
                addr = socket.inet_ntop(socket.AF_INET6, self.recvall(sock, 16))
            port = int.from_bytes(self.recvall(sock, 2), "big")
            cmd = head[1]
            stream = rec.add(kind="request", stream=stream_id, cmd=cmd, atyp=atyp, addr=addr, port=port, auth_ver=auth_ver,
                             user=user.decode(errors="replace"), password=password.decode(errors="replace"), head=head.hex())
            if cmd == 0xF0:
                with rec.lock:
                    n = self.resolves.get(addr, 0)
                    self.resolves[addr] = n + 1
                answer = self.resolve(addr, n)
                stream["answer"] = answer
                if answer is None:
                    sock.sendall(bytes([5, 4, 0, 1, 0, 0, 0, 0, 0, 0]))
                elif ":" in answer:
                    sock.sendall(bytes([5, 0, 0, 4]) + socket.inet_pton(socket.AF_INET6, answer) + b"\x00\x00")
                else:
                    sock.sendall(bytes([5, 0, 0, 1]) + socket.inet_pton(socket.AF_INET, answer) + b"\x00\x00")
                return
            what = self.connect(addr, port)
            stream["behaviour"] = what
            if isinstance(what, int):
                sock.sendall(bytes([5, what, 0, 1, 0, 0, 0, 0, 0, 0]))
                return
            sock.sendall(bytes([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
            Recipient(sock, BEHAVIOURS[what], rec, stream_id, self.net, self.wtxid, self.timeout).run()
        except (EOFError, OSError) as e:
            rec.add(kind="proxy_close", stream=stream_id, what=str(e) or type(e).__name__)
        finally:
            try:
                sock.close()
            except OSError:
                pass
