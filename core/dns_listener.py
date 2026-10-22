"""
Minimal UDP DNS listener with hand-rolled packet parsing.

This is the OOB (out-of-band) receiver for the toolkit. It binds to a
UDP port, parses incoming DNS query packets, records the queried name
in a hit list, and answers with either NXDOMAIN (default) or a fixed
A record, depending on configuration.

The parser handles only the subset of DNS that matters for OOB:
  - The header (ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
  - One question (QNAME, QTYPE, QCLASS)

It does not handle compressed names in the question section (they don't
occur in queries), EDNS0 OPT pseudo-records (they can occur; we parse
past them), or any answer/authority/additional records (we don't send
any unless configured).

Wire format reference (RFC 1035 §4.1):

  Header (12 bytes):
    ID       uint16   (query id; echoed in the response)
    FLAGS    uint16   (bit flags; for a query, typically 0x0100)
    QDCOUNT  uint16   (number of questions; usually 1)
    ANCOUNT  uint16   (number of answers; 0 in a query)
    NSCOUNT  uint16   (authority records; 0 in a query)
    ARCOUNT  uint16   (additional records; 0 or 1 for EDNS0)

  Question:
    QNAME    sequence of labels. Each label is (length-byte, bytes).
             Terminated by a single zero-length label (0x00).
    QTYPE    uint16   (1 = A, 28 = AAAA, 5 = CNAME, 15 = MX, ...)
    QCLASS   uint16   (1 = IN, ...)

  Answer (for our NXDOMAIN or A responses):
    NAME     pointer to QNAME (0xC0, 0x0C)
    TYPE     1 for A
    CLASS    1 for IN
    TTL      uint32
    RDLENGTH uint16
    RDATA    IPv4 address (4 bytes)
"""

import asyncio
import socket
import struct
import time

from core.output import info, warn


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

DEFAULT_DNS_PORT = 53533
DEFAULT_BIND_ADDR = "127.0.0.1"

# Response codes we can put in the DNS header's RCODE field (low 4 bits
# of the FLAGS word).
RCODE_NOERROR = 0
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3

# QTYPE values we care about. Anything else we accept and log, but the
# answer we return is always the same (NXDOMAIN or an A record).
QTYPE_A = 1
QTYPE_AAAA = 28
QTYPE_CNAME = 5
QTYPE_MX = 15

QTYPE_NAMES = {
    QTYPE_A: "A",
    QTYPE_AAAA: "AAAA",
    QTYPE_CNAME: "CNAME",
    QTYPE_MX: "MX",
}


# ---------------------------------------------------------------------
# Packet parsing
# ---------------------------------------------------------------------

def _parse_qname(data, offset):
    """Parse a DNS name starting at `offset` in `data`.

    Returns (name, new_offset) where `name` is the dotted-string
    representation and `new_offset` points just past the QNAME.

    Raises ValueError on malformed input.

    Note: queries don't use compression, so we don't handle it here.
    If a pointer byte (0b11xxxxxx) is found, we raise.
    """
    labels = []
    start = offset
    while True:
        if offset >= len(data):
            raise ValueError(f"qname truncated at offset {offset}")
        length = data[offset]
        offset += 1

        if length == 0:
            # End of name.
            break
        if length & 0xC0:
            # Compression pointer — not valid in a query.
            raise ValueError(
                f"compression pointer at offset {offset - 1} "
                f"(0x{length:02x}); not expected in queries")
        if offset + length > len(data):
            raise ValueError(
                f"label extends past packet end "
                f"(offset={offset} length={length} packet_len={len(data)})")

        try:
            label = data[offset:offset + length].decode("ascii")
        except UnicodeDecodeError:
            # Non-ASCII in a label; log the raw bytes as escaped form
            # rather than failing — we still want to record the hit.
            label = data[offset:offset + length].hex()
        labels.append(label)
        offset += length

    if not labels:
        raise ValueError("empty qname")

    return ".".join(labels), offset


def parse_query(data):
    """Parse a full DNS query packet.

    Returns a dict with keys: id, flags, qname, qtype, qclass, raw_qtype.
    Raises ValueError on malformed input.
    """
    if len(data) < 12:
        raise ValueError(f"packet shorter than header ({len(data)} bytes)")

    (msg_id, flags, qdcount, ancount, nscount, arcount) = struct.unpack(
        ">HHHHHH", data[:12]
    )

    if qdcount < 1:
        raise ValueError(f"QDCOUNT is {qdcount}; expected at least 1")

    qname, offset = _parse_qname(data, 12)

    if offset + 4 > len(data):
        raise ValueError("question truncated before QTYPE/QCLASS")

    qtype, qclass = struct.unpack(">HH", data[offset:offset + 4])

    return {
        "id": msg_id,
        "flags": flags,
        "qname": qname,
        "qtype": qtype,
        "qclass": qclass,
    }


# ---------------------------------------------------------------------
# Response building
# ---------------------------------------------------------------------

def build_response(query_id, qname, qtype, rcode=RCODE_NXDOMAIN,
                   answer_ip=None):
    """Build a DNS response packet.

    If answer_ip is provided (e.g. "127.0.0.1"), the response includes a
    single A record in the answer section. If None, the response has no
    answer records and RCODE is used (default NXDOMAIN).

    `qname` and `qtype` come from the parsed query and are echoed into
    the response's question section. We re-encode the qname from the
    dotted form; we don't echo the raw bytes. This handles the case
    where the query used unusual label encodings.
    """
    # FLAGS: QR=1 (response), AA=1 (authoritative — we're pretending to
    # be authoritative for our zone), RD/RA copied from... actually we
    # just set a sane default: QR=1, AA=1, RD=0, RA=0, RCODE as given.
    flags = 0x8400 | (rcode & 0x000F)
    ancount = 1 if answer_ip else 0

    header = struct.pack(">HHHHHH", query_id, flags, 1, ancount, 0, 0)

    # Encode QNAME: split on ".", emit length + bytes for each label,
    # then a terminating zero byte.
    qname_bytes = b""
    for label in qname.split("."):
        b = label.encode("ascii", errors="replace")
        if len(b) > 63:
            b = b[:63]
        qname_bytes += bytes([len(b)]) + b
    qname_bytes += b"\x00"

    question = qname_bytes + struct.pack(">HH", qtype, 1)  # QCLASS=IN

    if not answer_ip:
        return header + question

    # Answer: NAME is a compression pointer to offset 12 (start of the
    # question's QNAME). TYPE=A, CLASS=IN, TTL=60, RDLENGTH=4, RDATA.
    answer_name = b"\xC0\x0C"
    answer_head = struct.pack(">HHIH", QTYPE_A, 1, 60, 4)
    try:
        answer_data = socket.inet_aton(answer_ip)
    except OSError:
        answer_data = socket.inet_aton("127.0.0.1")

    return header + question + answer_name + answer_head + answer_data


# ---------------------------------------------------------------------
# Listener
# ---------------------------------------------------------------------

class DNSListener(asyncio.DatagramProtocol):
    """UDP listener that captures DNS queries and optionally answers them.

    Usage:
        listener = DNSListener(port=5353, respond_with="nxdomain")
        await listener.start()
        ...        # send some queries
        hit = await listener.wait_for_hit("marker", timeout=5.0)
        await listener.stop()
    """

    def __init__(self, port=DEFAULT_DNS_PORT, bind_addr=DEFAULT_BIND_ADDR,
                 respond_with="nxdomain", verbose=False):
        """
        respond_with:
          "nxdomain" — reply with RCODE=3, no answer (default)
          "a"        — reply with an A record pointing at 127.0.0.1
          "drop"     — do not reply at all (causes client to time out)
        """
        self.port = port
        self.bind_addr = bind_addr
        self.respond_with = respond_with
        self.verbose = verbose
        self.hits = []          # list of dicts
        self._transport = None

    # -- asyncio protocol API ----------------------------------------------

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data, addr):
        try:
            parsed = parse_query(data)
        except ValueError as e:
            if self.verbose:
                warn(f"DNS parse error from {addr[0]}:{addr[1]}: {e}")
            return

        qname = parsed["qname"]
        qtype_name = QTYPE_NAMES.get(parsed["qtype"],
                                     f"type{parsed['qtype']}")
        hit = {
            "qname": qname,
            "qtype": parsed["qtype"],
            "qtype_name": qtype_name,
            "remote": f"{addr[0]}:{addr[1]}",
            "ts": time.time(),
        }
        self.hits.append(hit)

        if self.verbose:
            info(f"DNS hit: {qname} {qtype_name} from {addr[0]}:{addr[1]}")

        if self.respond_with == "drop":
            return

        rcode = RCODE_NXDOMAIN
        answer_ip = None
        if self.respond_with == "a":
            rcode = RCODE_NOERROR
            answer_ip = "127.0.0.1"

        try:
            resp = build_response(parsed["id"], qname, parsed["qtype"],
                                  rcode=rcode, answer_ip=answer_ip)
            self._transport.sendto(resp, addr)
        except Exception as e:
            warn(f"DNS response build failed for {qname}: "
                 f"{type(e).__name__}: {e}")

    def error_received(self, exc):
        warn(f"DNS listener error: {type(exc).__name__}: {exc}")

    # -- lifecycle ---------------------------------------------------------

    async def start(self):
        loop = asyncio.get_running_loop()
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: self,
                local_addr=(self.bind_addr, self.port),
            )
        except OSError as e:
            raise RuntimeError(
                f"DNS listener could not bind to "
                f"{self.bind_addr}:{self.port} "
                f"({type(e).__name__}: {e}). "
                f"If the port is in use or privileged, pick another with "
                f"--oob-dns-port."
            )
        self._transport = transport
        info(f"OOB DNS listener on udp://{self.bind_addr}:{self.port} "
             f"(respond_with={self.respond_with})")
        return self.port

    async def stop(self):
        if self._transport:
            self._transport.close()
            self._transport = None

    # -- hit retrieval -----------------------------------------------------

    async def wait_for_hit(self, substring, timeout=5.0):
        """Return the first hit whose qname contains `substring`, or None.

        Polls every 100ms. Not the most efficient, but simple and
        sufficient for the scale of an OOB extraction.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            for hit in self.hits:
                if substring in hit["qname"]:
                    return hit
            await asyncio.sleep(0.1)
        return None

    def has_hit(self, substring):
        return any(substring in h["qname"] for h in self.hits)