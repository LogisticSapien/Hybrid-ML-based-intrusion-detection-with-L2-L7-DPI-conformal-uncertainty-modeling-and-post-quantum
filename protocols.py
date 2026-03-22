"""
Protocol Dissection Engine
===========================
Comprehensive packet parsers for layers 2–7:
  L2: Ethernet, ARP
  L3: IPv4, IPv6, ICMP, ICMPv6
  L4: TCP (flags, options, window), UDP
  L7: DNS (10+ record types), HTTP, TLS 1.2/1.3 (SNI, JA3, cipher suites),
      QUIC, SSH, DHCP
"""

from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from typing import Any, Dict, List, Optional, Tuple


# ──────────────────────────────────────────────────────────────────────
# Layer 2 — Ethernet
# ──────────────────────────────────────────────────────────────────────

class EtherType(IntEnum):
    IPv4 = 0x0800
    IPv6 = 0x86DD
    ARP  = 0x0806
    VLAN = 0x8100
    LLDP = 0x88CC


@dataclass
class EthernetFrame:
    dst_mac: str
    src_mac: str
    ether_type: int
    vlan_id: Optional[int] = None
    payload: bytes = b""

    @property
    def ether_type_name(self) -> str:
        try:
            return EtherType(self.ether_type).name
        except ValueError:
            return f"0x{self.ether_type:04X}"


def parse_ethernet(raw: bytes) -> Optional[EthernetFrame]:
    if len(raw) < 14:
        return None
    dst, src, etype = struct.unpack('!6s6sH', raw[:14])
    payload_start = 14
    vlan_id = None

    if etype == EtherType.VLAN:
        if len(raw) < 18:
            return None
        vlan_tci, etype = struct.unpack('!HH', raw[14:18])
        vlan_id = vlan_tci & 0x0FFF
        payload_start = 18

    return EthernetFrame(
        dst_mac=_format_mac(dst),
        src_mac=_format_mac(src),
        ether_type=etype,
        vlan_id=vlan_id,
        payload=raw[payload_start:],
    )


def _format_mac(b: bytes) -> str:
    return ':'.join(f'{x:02x}' for x in b)


# ──────────────────────────────────────────────────────────────────────
# Layer 2 — ARP
# ──────────────────────────────────────────────────────────────────────

class ARPOpcode(IntEnum):
    REQUEST = 1
    REPLY   = 2


@dataclass
class ARPPacket:
    hw_type: int
    proto_type: int
    opcode: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str

    @property
    def opcode_name(self) -> str:
        try:
            return ARPOpcode(self.opcode).name
        except ValueError:
            return str(self.opcode)


def parse_arp(data: bytes) -> Optional[ARPPacket]:
    if len(data) < 28:
        return None
    hw_type, proto, hw_len, proto_len, opcode = struct.unpack('!HHBBH', data[:8])
    if hw_len != 6 or proto_len != 4:
        return None
    sender_mac = _format_mac(data[8:14])
    sender_ip = _format_ip4(data[14:18])
    target_mac = _format_mac(data[18:24])
    target_ip = _format_ip4(data[24:28])
    return ARPPacket(hw_type, proto, opcode, sender_mac, sender_ip, target_mac, target_ip)


def _format_ip4(b: bytes) -> str:
    return '.'.join(str(x) for x in b)


# ──────────────────────────────────────────────────────────────────────
# Layer 3 — IPv4
# ──────────────────────────────────────────────────────────────────────

class IPProto(IntEnum):
    ICMP = 1
    TCP  = 6
    UDP  = 17
    ICMPv6 = 58


@dataclass
class IPv4Packet:
    version: int
    ihl: int
    dscp: int
    ecn: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    checksum: int
    src_ip: str
    dst_ip: str
    options: bytes
    payload: bytes

    @property
    def protocol_name(self) -> str:
        try:
            return IPProto(self.protocol).name
        except ValueError:
            return str(self.protocol)

    @property
    def dont_fragment(self) -> bool:
        return bool(self.flags & 0x02)

    @property
    def more_fragments(self) -> bool:
        return bool(self.flags & 0x01)


def parse_ipv4(data: bytes) -> Optional[IPv4Packet]:
    if len(data) < 20:
        return None
    ver_ihl = data[0]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    if version != 4 or len(data) < ihl:
        return None

    dscp_ecn = data[1]
    total_len, ident, flags_frag, ttl, proto, cksum = struct.unpack(
        '!HHHBBH', data[2:12]
    )
    src = _format_ip4(data[12:16])
    dst = _format_ip4(data[16:20])
    options = data[20:ihl] if ihl > 20 else b""

    return IPv4Packet(
        version=version, ihl=ihl,
        dscp=dscp_ecn >> 2, ecn=dscp_ecn & 0x03,
        total_length=total_len, identification=ident,
        flags=(flags_frag >> 13), fragment_offset=(flags_frag & 0x1FFF) * 8,
        ttl=ttl, protocol=proto, checksum=cksum,
        src_ip=src, dst_ip=dst,
        options=options, payload=data[ihl:],
    )


# ──────────────────────────────────────────────────────────────────────
# Layer 3 — IPv6
# ──────────────────────────────────────────────────────────────────────

@dataclass
class IPv6Packet:
    version: int
    traffic_class: int
    flow_label: int
    payload_length: int
    next_header: int
    hop_limit: int
    src_ip: str
    dst_ip: str
    payload: bytes

    @property
    def next_header_name(self) -> str:
        try:
            return IPProto(self.next_header).name
        except ValueError:
            return str(self.next_header)


def parse_ipv6(data: bytes) -> Optional[IPv6Packet]:
    if len(data) < 40:
        return None
    first_word = struct.unpack('!I', data[:4])[0]
    version = first_word >> 28
    if version != 6:
        return None
    tc = (first_word >> 20) & 0xFF
    fl = first_word & 0xFFFFF
    plen, nxt, hop = struct.unpack('!HBB', data[4:8])
    src = _format_ip6(data[8:24])
    dst = _format_ip6(data[24:40])
    return IPv6Packet(
        version=version, traffic_class=tc, flow_label=fl,
        payload_length=plen, next_header=nxt, hop_limit=hop,
        src_ip=src, dst_ip=dst, payload=data[40:],
    )


def _format_ip6(b: bytes) -> str:
    groups = [f'{struct.unpack("!H", b[i:i+2])[0]:x}' for i in range(0, 16, 2)]
    return ':'.join(groups)


# ──────────────────────────────────────────────────────────────────────
# Layer 3 — ICMP
# ──────────────────────────────────────────────────────────────────────

ICMP_TYPES = {
    0: "Echo Reply", 3: "Dest Unreachable", 4: "Source Quench",
    5: "Redirect", 8: "Echo Request", 11: "Time Exceeded",
    13: "Timestamp", 14: "Timestamp Reply", 30: "Traceroute",
}


@dataclass
class ICMPPacket:
    type: int
    code: int
    checksum: int
    identifier: int
    sequence: int
    payload: bytes

    @property
    def type_name(self) -> str:
        return ICMP_TYPES.get(self.type, f"Type_{self.type}")


def parse_icmp(data: bytes) -> Optional[ICMPPacket]:
    if len(data) < 8:
        return None
    icmp_type, code, cksum, ident, seq = struct.unpack('!BBHHH', data[:8])
    return ICMPPacket(icmp_type, code, cksum, ident, seq, data[8:])


# ──────────────────────────────────────────────────────────────────────
# Layer 4 — TCP
# ──────────────────────────────────────────────────────────────────────

class TCPFlags(IntFlag):
    FIN = 0x001
    SYN = 0x002
    RST = 0x004
    PSH = 0x008
    ACK = 0x010
    URG = 0x020
    ECE = 0x040
    CWR = 0x080
    NS  = 0x100


@dataclass
class TCPSegment:
    src_port: int
    dst_port: int
    seq_num: int
    ack_num: int
    data_offset: int
    flags: int
    window: int
    checksum: int
    urgent_ptr: int
    options: bytes
    payload: bytes

    @property
    def flag_names(self) -> List[str]:
        return [f.name for f in TCPFlags if self.flags & f]

    @property
    def flag_str(self) -> str:
        return '|'.join(self.flag_names) if self.flag_names else 'NONE'

    @property
    def is_syn(self) -> bool:
        return bool(self.flags & TCPFlags.SYN) and not (self.flags & TCPFlags.ACK)

    @property
    def is_syn_ack(self) -> bool:
        return bool(self.flags & TCPFlags.SYN) and bool(self.flags & TCPFlags.ACK)

    @property
    def is_fin(self) -> bool:
        return bool(self.flags & TCPFlags.FIN)

    @property
    def is_rst(self) -> bool:
        return bool(self.flags & TCPFlags.RST)

    @property
    def is_xmas(self) -> bool:
        return bool(self.flags & (TCPFlags.FIN | TCPFlags.PSH | TCPFlags.URG))

    @property
    def is_null(self) -> bool:
        return self.flags == 0


def parse_tcp(data: bytes) -> Optional[TCPSegment]:
    if len(data) < 20:
        return None
    src, dst, seq, ack, offset_flags, window, cksum, urg = struct.unpack(
        '!HHLLHHHH', data[:20]
    )
    data_offset = ((offset_flags >> 12) & 0xF) * 4
    flags = offset_flags & 0x1FF
    options = data[20:data_offset] if data_offset > 20 else b""
    return TCPSegment(
        src_port=src, dst_port=dst, seq_num=seq, ack_num=ack,
        data_offset=data_offset, flags=flags, window=window,
        checksum=cksum, urgent_ptr=urg,
        options=options, payload=data[data_offset:],
    )


# ──────────────────────────────────────────────────────────────────────
# Layer 4 — UDP
# ──────────────────────────────────────────────────────────────────────

@dataclass
class UDPDatagram:
    src_port: int
    dst_port: int
    length: int
    checksum: int
    payload: bytes


def parse_udp(data: bytes) -> Optional[UDPDatagram]:
    if len(data) < 8:
        return None
    src, dst, length, cksum = struct.unpack('!HHHH', data[:8])
    return UDPDatagram(src, dst, length, cksum, data[8:])


# ──────────────────────────────────────────────────────────────────────
# Layer 7 — DNS
# ──────────────────────────────────────────────────────────────────────

class DNSType(IntEnum):
    A     = 1
    NS    = 2
    CNAME = 5
    SOA   = 6
    PTR   = 12
    MX    = 15
    TXT   = 16
    AAAA  = 28
    SRV   = 33
    ANY   = 255


class DNSRcode(IntEnum):
    NOERROR  = 0
    FORMERR  = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP   = 4
    REFUSED  = 5


@dataclass
class DNSQuestion:
    name: str
    qtype: int
    qclass: int

    @property
    def type_name(self) -> str:
        try:
            return DNSType(self.qtype).name
        except ValueError:
            return str(self.qtype)


@dataclass
class DNSRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: str

    @property
    def type_name(self) -> str:
        try:
            return DNSType(self.rtype).name
        except ValueError:
            return str(self.rtype)


@dataclass
class DNSMessage:
    transaction_id: int
    is_response: bool
    opcode: int
    rcode: int
    questions: List[DNSQuestion]
    answers: List[DNSRecord]
    authorities: List[DNSRecord]
    additionals: List[DNSRecord]
    truncated: bool = False
    recursive_desired: bool = False
    recursive_available: bool = False

    @property
    def rcode_name(self) -> str:
        try:
            return DNSRcode(self.rcode).name
        except ValueError:
            return str(self.rcode)

    @property
    def query_names(self) -> List[str]:
        return [q.name for q in self.questions]


def _dns_read_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Read a DNS name with pointer compression support."""
    parts = []
    original_offset = offset
    jumped = False
    max_jumps = 10

    for _ in range(max_jumps + 1):
        if offset >= len(data):
            break
        length = data[offset]

        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
        else:
            offset += 1
            if offset + length > len(data):
                break
            parts.append(data[offset:offset+length].decode('utf-8', errors='replace'))
            offset += length

    return '.'.join(parts), original_offset if jumped else offset


def _dns_parse_rdata(rtype: int, rdata_bytes: bytes, full_data: bytes, rdata_offset: int) -> str:
    """Parse DNS record data based on type."""
    try:
        if rtype == DNSType.A and len(rdata_bytes) == 4:
            return _format_ip4(rdata_bytes)
        elif rtype == DNSType.AAAA and len(rdata_bytes) == 16:
            return _format_ip6(rdata_bytes)
        elif rtype in (DNSType.CNAME, DNSType.NS, DNSType.PTR):
            name, _ = _dns_read_name(full_data, rdata_offset)
            return name
        elif rtype == DNSType.MX:
            pref = struct.unpack('!H', rdata_bytes[:2])[0]
            name, _ = _dns_read_name(full_data, rdata_offset + 2)
            return f"{pref} {name}"
        elif rtype == DNSType.TXT:
            txt_len = rdata_bytes[0]
            return rdata_bytes[1:1+txt_len].decode('utf-8', errors='replace')
        elif rtype == DNSType.SOA:
            mname, off = _dns_read_name(full_data, rdata_offset)
            rname, off = _dns_read_name(full_data, off)
            if off + 20 <= len(full_data):
                serial, refresh, retry, expire, minimum = struct.unpack(
                    '!IIIII', full_data[off:off+20]
                )
                return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
            return f"{mname} {rname}"
        elif rtype == DNSType.SRV:
            if len(rdata_bytes) >= 6:
                priority, weight, port = struct.unpack('!HHH', rdata_bytes[:6])
                target, _ = _dns_read_name(full_data, rdata_offset + 6)
                return f"{priority} {weight} {port} {target}"
        return rdata_bytes.hex()
    except Exception:
        return rdata_bytes.hex()


def parse_dns(data: bytes) -> Optional[DNSMessage]:
    if len(data) < 12:
        return None

    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        '!HHHHHH', data[:12]
    )

    is_response = bool(flags & 0x8000)
    opcode = (flags >> 11) & 0xF
    rcode = flags & 0xF
    truncated = bool(flags & 0x0200)
    rd = bool(flags & 0x0100)
    ra = bool(flags & 0x0080)

    offset = 12
    questions = []
    for _ in range(qdcount):
        name, offset = _dns_read_name(data, offset)
        if offset + 4 > len(data):
            break
        qtype, qclass = struct.unpack('!HH', data[offset:offset+4])
        offset += 4
        questions.append(DNSQuestion(name, qtype, qclass))

    def _parse_rrs(count: int) -> List[DNSRecord]:
        nonlocal offset
        records = []
        for _ in range(count):
            name, offset = _dns_read_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset+10])
            offset += 10
            rdata_offset = offset
            rdata_bytes = data[offset:offset+rdlength]
            offset += rdlength
            rdata_str = _dns_parse_rdata(rtype, rdata_bytes, data, rdata_offset)
            records.append(DNSRecord(name, rtype, rclass, ttl, rdata_str))
        return records

    answers = _parse_rrs(ancount)
    authorities = _parse_rrs(nscount)
    additionals = _parse_rrs(arcount)

    return DNSMessage(
        txid, is_response, opcode, rcode,
        questions, answers, authorities, additionals,
        truncated, rd, ra,
    )


# ──────────────────────────────────────────────────────────────────────
# Layer 7 — HTTP
# ──────────────────────────────────────────────────────────────────────

HTTP_METHODS = {b'GET', b'POST', b'PUT', b'DELETE', b'PATCH', b'HEAD', b'OPTIONS', b'CONNECT', b'TRACE'}


@dataclass
class HTTPMessage:
    is_request: bool
    method: Optional[str] = None
    uri: Optional[str] = None
    version: Optional[str] = None
    status_code: Optional[int] = None
    status_text: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    host: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    user_agent: Optional[str] = None


def parse_http(data: bytes) -> Optional[HTTPMessage]:
    if len(data) < 4:
        return None

    try:
        header_end = data.find(b'\r\n\r\n')
        if header_end == -1:
            header_end = min(len(data), 8192)
        header_section = data[:header_end].decode('utf-8', errors='replace')
        lines = header_section.split('\r\n')
        if not lines:
            return None

        first_line = lines[0]

        # Check if it's a request
        parts = first_line.split(' ', 2)
        if len(parts) >= 2 and parts[0].encode() in HTTP_METHODS:
            msg = HTTPMessage(
                is_request=True,
                method=parts[0],
                uri=parts[1] if len(parts) > 1 else None,
                version=parts[2] if len(parts) > 2 else None,
            )
        elif first_line.startswith('HTTP/'):
            code = int(parts[1]) if len(parts) > 1 else 0
            msg = HTTPMessage(
                is_request=False,
                version=parts[0],
                status_code=code,
                status_text=parts[2] if len(parts) > 2 else None,
            )
        else:
            return None

        # Parse headers
        for line in lines[1:]:
            if ':' in line:
                key, _, val = line.partition(':')
                key = key.strip()
                val = val.strip()
                msg.headers[key.lower()] = val
                if key.lower() == 'host':
                    msg.host = val
                elif key.lower() == 'content-type':
                    msg.content_type = val
                elif key.lower() == 'content-length':
                    try:
                        msg.content_length = int(val)
                    except ValueError:
                        pass
                elif key.lower() == 'user-agent':
                    msg.user_agent = val

        return msg
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────────────
# Layer 7 — TLS (ClientHello dissection + JA3 fingerprinting)
# ──────────────────────────────────────────────────────────────────────

# Comprehensive TLS cipher suite database
TLS_CIPHER_SUITE_NAMES = {
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCAC: "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
}

# TLS extension types
TLS_EXTENSIONS = {
    0: "server_name", 1: "max_fragment_length", 5: "status_request",
    10: "supported_groups", 11: "ec_point_formats", 13: "signature_algorithms",
    16: "application_layer_protocol_negotiation", 18: "signed_certificate_timestamp",
    21: "padding", 23: "extended_master_secret", 27: "compress_certificate",
    35: "session_ticket", 41: "pre_shared_key", 42: "early_data",
    43: "supported_versions", 44: "cookie", 45: "psk_key_exchange_modes",
    47: "certificate_authorities", 48: "oid_filters",
    49: "post_handshake_auth", 50: "signature_algorithms_cert",
    51: "key_share", 65281: "renegotiation_info",
}

# Named groups (elliptic curves)
TLS_NAMED_GROUPS = {
    23: "secp256r1", 24: "secp384r1", 25: "secp521r1",
    29: "x25519", 30: "x448",
    256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096",
    # Post-quantum hybrid groups (draft standards)
    0x6399: "X25519Kyber768Draft00",
    0x639A: "SecP256r1Kyber768Draft00",
}

# GREASE values (should be ignored in JA3)
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
    0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


@dataclass
class TLSClientHello:
    tls_version: int
    random: bytes
    session_id: bytes
    cipher_suites: List[int]
    compression_methods: List[int]
    extensions: Dict[int, bytes]
    sni: Optional[str] = None
    supported_versions: List[int] = field(default_factory=list)
    supported_groups: List[int] = field(default_factory=list)
    signature_algorithms: List[int] = field(default_factory=list)
    alpn_protocols: List[str] = field(default_factory=list)
    ja3_hash: Optional[str] = None
    ja3_string: Optional[str] = None

    @property
    def tls_version_name(self) -> str:
        versions = {
            0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
            0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
        }
        # Use highest supported_versions if available
        if self.supported_versions:
            v = max(self.supported_versions)
            return versions.get(v, f"0x{v:04X}")
        return versions.get(self.tls_version, f"0x{self.tls_version:04X}")

    @property
    def cipher_suite_names(self) -> List[str]:
        return [
            TLS_CIPHER_SUITE_NAMES.get(cs, f"0x{cs:04X}")
            for cs in self.cipher_suites if cs not in GREASE_VALUES
        ]

    @property
    def has_post_quantum(self) -> bool:
        """Check if the ClientHello includes any post-quantum key shares."""
        pq_groups = {0x6399, 0x639A}
        return bool(pq_groups & set(self.supported_groups))


@dataclass
class TLSServerHello:
    tls_version: int
    random: bytes
    session_id: bytes
    cipher_suite: int
    compression_method: int
    extensions: Dict[int, bytes]

    @property
    def cipher_suite_name(self) -> str:
        return TLS_CIPHER_SUITE_NAMES.get(self.cipher_suite, f"0x{self.cipher_suite:04X}")


def _compute_ja3(hello: TLSClientHello) -> Tuple[str, str]:
    """Compute JA3 fingerprint from a TLS ClientHello."""
    # TLS version
    tls_ver = str(hello.tls_version)

    # Cipher suites (excluding GREASE)
    ciphers = '-'.join(str(cs) for cs in hello.cipher_suites if cs not in GREASE_VALUES)

    # Extensions (excluding GREASE)
    ext_ids = sorted(hello.extensions.keys())
    extensions = '-'.join(str(e) for e in ext_ids if e not in GREASE_VALUES)

    # Supported groups (excluding GREASE)
    groups = '-'.join(str(g) for g in hello.supported_groups if g not in GREASE_VALUES)

    # EC point formats
    ec_pf = ""
    if 11 in hello.extensions:
        ec_data = hello.extensions[11]
        if ec_data and len(ec_data) > 1:
            ec_pf = '-'.join(str(b) for b in ec_data[1:1+ec_data[0]])

    ja3_string = f"{tls_ver},{ciphers},{extensions},{groups},{ec_pf}"
    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
    return ja3_string, ja3_hash


def parse_tls(data: bytes) -> Optional[Any]:
    """Parse TLS record, returns TLSClientHello or TLSServerHello or None."""
    if len(data) < 6:
        return None

    content_type = data[0]
    if content_type != 22:  # Handshake
        return None

    tls_version = struct.unpack('!H', data[1:3])[0]
    record_length = struct.unpack('!H', data[3:5])[0]

    ptr = 5
    if ptr >= len(data):
        return None

    hs_type = data[ptr]
    hs_length = struct.unpack('!I', b'\x00' + data[ptr+1:ptr+4])[0]
    ptr += 4

    if hs_type == 1:  # ClientHello
        return _parse_client_hello(data, ptr)
    elif hs_type == 2:  # ServerHello
        return _parse_server_hello(data, ptr)
    return None


def _parse_client_hello(data: bytes, ptr: int) -> Optional[TLSClientHello]:
    try:
        client_version = struct.unpack('!H', data[ptr:ptr+2])[0]
        ptr += 2

        random = data[ptr:ptr+32]
        ptr += 32

        # Session ID
        sid_len = data[ptr]
        ptr += 1
        session_id = data[ptr:ptr+sid_len]
        ptr += sid_len

        # Cipher suites
        cs_len = struct.unpack('!H', data[ptr:ptr+2])[0]
        ptr += 2
        cipher_suites = []
        for i in range(0, cs_len, 2):
            cs = struct.unpack('!H', data[ptr+i:ptr+i+2])[0]
            cipher_suites.append(cs)
        ptr += cs_len

        # Compression methods
        comp_len = data[ptr]
        ptr += 1
        comp_methods = list(data[ptr:ptr+comp_len])
        ptr += comp_len

        # Extensions
        extensions = {}
        sni = None
        supported_versions = []
        supported_groups = []
        sig_algos = []
        alpn = []

        if ptr + 2 <= len(data):
            ext_len = struct.unpack('!H', data[ptr:ptr+2])[0]
            ptr += 2
            ext_end = ptr + ext_len

            while ptr + 4 <= ext_end:
                ext_type = struct.unpack('!H', data[ptr:ptr+2])[0]
                ext_size = struct.unpack('!H', data[ptr+2:ptr+4])[0]
                ptr += 4
                ext_data = data[ptr:ptr+ext_size]
                extensions[ext_type] = ext_data

                # SNI (extension 0)
                if ext_type == 0 and ext_size >= 5:
                    sni_len = struct.unpack('!H', ext_data[3:5])[0]
                    sni = ext_data[5:5+sni_len].decode('utf-8', errors='ignore')

                # Supported versions (extension 43)
                elif ext_type == 43 and ext_size >= 1:
                    sv_len = ext_data[0]
                    for i in range(0, sv_len, 2):
                        if 1 + i + 2 <= len(ext_data):
                            v = struct.unpack('!H', ext_data[1+i:3+i])[0]
                            supported_versions.append(v)

                # Supported groups (extension 10)
                elif ext_type == 10 and ext_size >= 2:
                    gl = struct.unpack('!H', ext_data[:2])[0]
                    for i in range(0, gl, 2):
                        if 2 + i + 2 <= len(ext_data):
                            g = struct.unpack('!H', ext_data[2+i:4+i])[0]
                            supported_groups.append(g)

                # Signature algorithms (extension 13)
                elif ext_type == 13 and ext_size >= 2:
                    sl = struct.unpack('!H', ext_data[:2])[0]
                    for i in range(0, sl, 2):
                        if 2 + i + 2 <= len(ext_data):
                            sa = struct.unpack('!H', ext_data[2+i:4+i])[0]
                            sig_algos.append(sa)

                # ALPN (extension 16)
                elif ext_type == 16 and ext_size >= 2:
                    alpn_total = struct.unpack('!H', ext_data[:2])[0]
                    ai = 2
                    while ai < 2 + alpn_total and ai < len(ext_data):
                        plen = ext_data[ai]
                        ai += 1
                        alpn.append(ext_data[ai:ai+plen].decode('utf-8', errors='ignore'))
                        ai += plen

                ptr += ext_size

        hello = TLSClientHello(
            tls_version=client_version,
            random=random,
            session_id=session_id,
            cipher_suites=cipher_suites,
            compression_methods=comp_methods,
            extensions=extensions,
            sni=sni,
            supported_versions=supported_versions,
            supported_groups=supported_groups,
            signature_algorithms=sig_algos,
            alpn_protocols=alpn,
        )

        ja3_string, ja3_hash = _compute_ja3(hello)
        hello.ja3_string = ja3_string
        hello.ja3_hash = ja3_hash

        return hello
    except Exception:
        return None


def _parse_server_hello(data: bytes, ptr: int) -> Optional[TLSServerHello]:
    try:
        server_version = struct.unpack('!H', data[ptr:ptr+2])[0]
        ptr += 2
        random = data[ptr:ptr+32]
        ptr += 32
        sid_len = data[ptr]
        ptr += 1
        session_id = data[ptr:ptr+sid_len]
        ptr += sid_len
        cipher_suite = struct.unpack('!H', data[ptr:ptr+2])[0]
        ptr += 2
        comp = data[ptr]
        ptr += 1

        extensions = {}
        if ptr + 2 <= len(data):
            ext_len = struct.unpack('!H', data[ptr:ptr+2])[0]
            ptr += 2
            ext_end = ptr + ext_len
            while ptr + 4 <= ext_end:
                et = struct.unpack('!H', data[ptr:ptr+2])[0]
                es = struct.unpack('!H', data[ptr+2:ptr+4])[0]
                ptr += 4
                extensions[et] = data[ptr:ptr+es]
                ptr += es

        return TLSServerHello(
            tls_version=server_version, random=random,
            session_id=session_id, cipher_suite=cipher_suite,
            compression_method=comp, extensions=extensions,
        )
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────────────
# Layer 7 — QUIC
# ──────────────────────────────────────────────────────────────────────

QUIC_VERSIONS = {
    0x00000001: "QUIC v1 (RFC 9000)",
    0x6B3343CF: "QUIC v2 (RFC 9369)",
    0xFF000020: "QUIC draft-32",
    0xFF00001D: "QUIC draft-29",
}


@dataclass
class QUICInitial:
    version: int
    dcid: bytes
    scid: bytes

    @property
    def version_name(self) -> str:
        return QUIC_VERSIONS.get(self.version, f"0x{self.version:08X}")


def parse_quic(data: bytes) -> Optional[QUICInitial]:
    """Detect QUIC Initial packets."""
    if len(data) < 6:
        return None
    # Long header: first bit set
    if not (data[0] & 0x80):
        return None
    # Form bit + fixed bit check
    if not (data[0] & 0x40):
        return None

    version = struct.unpack('!I', data[1:5])[0]
    if version == 0:
        return None  # Version negotiation
    dcid_len = data[5]
    if 6 + dcid_len >= len(data):
        return None
    dcid = data[6:6+dcid_len]
    scid_off = 6 + dcid_len
    if scid_off >= len(data):
        return None
    scid_len = data[scid_off]
    scid = data[scid_off+1:scid_off+1+scid_len]

    return QUICInitial(version=version, dcid=dcid, scid=scid)


# ──────────────────────────────────────────────────────────────────────
# Layer 7 — SSH
# ──────────────────────────────────────────────────────────────────────

@dataclass
class SSHBanner:
    protocol_version: str
    software_version: str
    raw: str


def parse_ssh_banner(data: bytes) -> Optional[SSHBanner]:
    """Parse SSH protocol version exchange."""
    if not data.startswith(b'SSH-'):
        return None
    try:
        line = data.split(b'\r\n')[0].split(b'\n')[0].decode('utf-8', errors='replace')
        parts = line.split('-', 2)
        if len(parts) >= 3:
            return SSHBanner(
                protocol_version=parts[1],
                software_version=parts[2],
                raw=line,
            )
    except Exception:
        pass
    return None


# ──────────────────────────────────────────────────────────────────────
# Layer 7 — DHCP
# ──────────────────────────────────────────────────────────────────────

DHCP_MSG_TYPES = {
    1: "DISCOVER", 2: "OFFER", 3: "REQUEST",
    4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM",
}


@dataclass
class DHCPMessage:
    op: int
    htype: int
    xid: int
    client_ip: str
    your_ip: str
    server_ip: str
    client_mac: str
    msg_type: Optional[int] = None
    hostname: Optional[str] = None
    requested_ip: Optional[str] = None

    @property
    def msg_type_name(self) -> str:
        if self.msg_type:
            return DHCP_MSG_TYPES.get(self.msg_type, str(self.msg_type))
        return "UNKNOWN"


def parse_dhcp(data: bytes) -> Optional[DHCPMessage]:
    """Parse DHCP message from UDP payload (ports 67/68)."""
    if len(data) < 240:
        return None
    try:
        op, htype, hlen, hops = struct.unpack('!BBBB', data[:4])
        xid = struct.unpack('!I', data[4:8])[0]
        ciaddr = _format_ip4(data[12:16])
        yiaddr = _format_ip4(data[16:20])
        siaddr = _format_ip4(data[20:24])
        chaddr = _format_mac(data[28:34])

        msg = DHCPMessage(op, htype, xid, ciaddr, yiaddr, siaddr, chaddr)

        # Parse options (starts at byte 240, after magic cookie)
        if data[236:240] == b'\x63\x82\x53\x63':
            ptr = 240
            while ptr < len(data) - 1:
                opt = data[ptr]
                if opt == 255:
                    break
                if opt == 0:
                    ptr += 1
                    continue
                opt_len = data[ptr + 1]
                opt_data = data[ptr+2:ptr+2+opt_len]
                ptr += 2 + opt_len

                if opt == 53 and opt_len == 1:
                    msg.msg_type = opt_data[0]
                elif opt == 12:
                    msg.hostname = opt_data.decode('utf-8', errors='replace')
                elif opt == 50 and opt_len == 4:
                    msg.requested_ip = _format_ip4(opt_data)

        return msg
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────────────
# Deep TLS Handshake Analysis
# ──────────────────────────────────────────────────────────────────────

# Order matters: more specific patterns first to avoid false matches
_KEX_PATTERNS = [
    ("ECDHE_RSA", ("ECDHE-RSA", "Ephemeral ECDH with RSA auth", True, 256)),
    ("ECDHE_ECDSA", ("ECDHE-ECDSA", "Ephemeral ECDH with ECDSA auth", True, 256)),
    ("DHE_RSA", ("DHE-RSA", "Ephemeral DH with RSA auth", True, 2048)),
    ("RSA", ("RSA", "Static RSA", False, 2048)),
]

_CIPHER_STRENGTH = {
    "AES_256_GCM": ("AES-256-GCM", "STRONG", 256, "AEAD"),
    "AES_128_GCM": ("AES-128-GCM", "STRONG", 128, "AEAD"),
    "CHACHA20_POLY1305": ("ChaCha20-Poly1305", "STRONG", 256, "AEAD"),
    "AES_256_CBC": ("AES-256-CBC", "MODERATE", 256, "CBC"),
    "AES_128_CBC": ("AES-128-CBC", "MODERATE", 128, "CBC"),
    "AES_128_CCM": ("AES-128-CCM", "STRONG", 128, "AEAD"),
    "NULL": ("NULL", "BROKEN", 0, "None"),
}


@dataclass
class TLSHandshakeAnalysis:
    """Deep analysis of a TLS handshake."""
    cipher_suite_id: int
    cipher_suite_name: str
    kex_type: str
    kex_description: str
    kex_strength_bits: int
    forward_secrecy: bool
    cipher_name: str
    cipher_strength: str
    cipher_bits: int
    cipher_mode: str
    tls_version: str
    tls_version_risk: str
    pqc_safe: bool
    pqc_verdict: str
    pqc_explanation: str
    overall_grade: str
    recommendations: List[str]


def _extract_kex(suite_name: str, tls_version: int = 0x0303) -> Tuple[str, str, bool, int]:
    # TLS 1.3 suites (TLS_AES_*) use ECDHE by default
    if tls_version == 0x0304 or suite_name.startswith("TLS_AES_") or suite_name.startswith("TLS_CHACHA20_"):
        return "TLS1.3-ECDHE", "TLS 1.3 (ECDHE by default)", True, 256
    for prefix, info in _KEX_PATTERNS:
        if prefix in suite_name:
            return info
    return "UNKNOWN", "Unknown key exchange", False, 0


def _extract_cipher(suite_name: str) -> Tuple[str, str, int, str]:
    for pattern, info in _CIPHER_STRENGTH.items():
        if pattern in suite_name:
            return info
    return "UNKNOWN", "UNKNOWN", 0, "UNKNOWN"


def analyze_tls_handshake(
    cipher_suite_id: int,
    tls_version: int = 0x0303,
    supported_groups: Optional[List[int]] = None,
) -> TLSHandshakeAnalysis:
    """Perform deep analysis of a TLS cipher suite with PQC safety assessment."""
    suite_name = TLS_CIPHER_SUITE_NAMES.get(cipher_suite_id, f"UNKNOWN_0x{cipher_suite_id:04X}")
    kex_type, kex_desc, forward_secrecy, kex_bits = _extract_kex(suite_name, tls_version)
    cipher_name, cipher_strength, cipher_bits, cipher_mode = _extract_cipher(suite_name)

    versions = {0x0300: ("SSL 3.0", "BROKEN"), 0x0301: ("TLS 1.0", "DEPRECATED"),
                0x0302: ("TLS 1.1", "DEPRECATED"), 0x0303: ("TLS 1.2", "LEGACY"),
                0x0304: ("TLS 1.3", "CURRENT")}
    tls_ver_name, tls_ver_risk = versions.get(tls_version, (f"0x{tls_version:04X}", "UNKNOWN"))

    pqc_safe = False
    has_pq_groups = bool({0x6399, 0x639A} & set(supported_groups or []))

    if has_pq_groups:
        pqc_safe = True
        pqc_verdict = "SAFE"
        pqc_explanation = (
            f"Post-quantum hybrid key exchange (X25519Kyber768) protects against "
            f"Shor's algorithm — even a quantum computer cannot break this key exchange."
        )
    elif "RSA" in kex_type and not forward_secrecy:
        pqc_verdict = "CRITICAL"
        pqc_explanation = (
            f"CRITICAL: Static {kex_type} is vulnerable to Shor's algorithm WITHOUT forward secrecy. "
            f"A quantum adversary who recorded this traffic can decrypt it in the future. "
            f"Past traffic cannot be protected retroactively."
        )
    elif "ECDHE" in kex_type or "DHE" in kex_type or kex_type.startswith("TLS1.3"):
        pqc_verdict = "AT_RISK"
        pqc_explanation = (
            f"{kex_type} provides forward secrecy but relies on elliptic curve / discrete log "
            f"problems solvable by Shor's algorithm. Migrate to hybrid PQ key exchange (X25519Kyber768)."
        )
    else:
        pqc_verdict = "AT_RISK"
        pqc_explanation = f"{kex_type} relies on classical cryptography vulnerable to quantum attacks."

    recommendations = []
    grade_score = 0
    if tls_ver_risk == "CURRENT": grade_score += 3
    elif tls_ver_risk == "LEGACY":
        grade_score += 2
        recommendations.append("Upgrade to TLS 1.3")
    else: recommendations.append("Migrate from deprecated TLS version")

    if cipher_strength == "STRONG": grade_score += 3
    elif cipher_strength == "MODERATE":
        grade_score += 2
        recommendations.append(f"Upgrade {cipher_name} to AEAD cipher")
    else: recommendations.append(f"Replace {cipher_name}")

    if forward_secrecy: grade_score += 2
    else: recommendations.append("Enable forward secrecy (ECDHE/DHE)")

    if pqc_safe: grade_score += 2
    else: recommendations.append("Enable PQ hybrid key exchange")

    grades = [(10, "A+"), (8, "A"), (6, "B"), (4, "C"), (2, "D")]
    overall_grade = next((g for s, g in grades if grade_score >= s), "F")

    return TLSHandshakeAnalysis(
        cipher_suite_id=cipher_suite_id, cipher_suite_name=suite_name,
        kex_type=kex_type, kex_description=kex_desc,
        kex_strength_bits=kex_bits, forward_secrecy=forward_secrecy,
        cipher_name=cipher_name, cipher_strength=cipher_strength,
        cipher_bits=cipher_bits, cipher_mode=cipher_mode,
        tls_version=tls_ver_name, tls_version_risk=tls_ver_risk,
        pqc_safe=pqc_safe, pqc_verdict=pqc_verdict, pqc_explanation=pqc_explanation,
        overall_grade=overall_grade, recommendations=recommendations,
    )


# ──────────────────────────────────────────────────────────────────────
# Self-test
# ──────────────────────────────────────────────────────────────────────

def test_protocols():
    """Run protocol parser self-tests with crafted packets."""
    print("=" * 60)
    print("  Protocol Dissector Self-Test")
    print("=" * 60)

    print("\n[1] Ethernet Frame...")
    eth_raw = bytes.fromhex('ffffffffffff' 'aabbccddeeff' '0800') + b'\x00' * 46
    eth = parse_ethernet(eth_raw)
    assert eth is not None
    assert eth.src_mac == 'aa:bb:cc:dd:ee:ff'
    print(f"    {eth.src_mac} -> {eth.dst_mac} [{eth.ether_type_name}]")
    print("    OK Ethernet PASSED")

    print("\n[2] IPv4 Packet...")
    ip_raw = bytes.fromhex('45' '00' '003c' '1c46' '4000' '40' '06' 'b1e6' 'ac100a63' 'ac100a0c')
    ipv4 = parse_ipv4(ip_raw)
    assert ipv4 is not None and ipv4.protocol == 6 and ipv4.ttl == 64
    print(f"    {ipv4.src_ip} -> {ipv4.dst_ip} proto={ipv4.protocol_name} TTL={ipv4.ttl}")
    print("    OK IPv4 PASSED")

    print("\n[3] TCP Segment...")
    tcp_raw = bytes.fromhex('c0d8' '0050' '00000001' '00000000' '5002' 'ffff' '0000' '0000')
    tcp = parse_tcp(tcp_raw)
    assert tcp is not None and tcp.src_port == 49368 and tcp.is_syn
    print(f"    :{tcp.src_port} -> :{tcp.dst_port} [{tcp.flag_str}] win={tcp.window}")
    print("    OK TCP PASSED")

    print("\n[4] DNS Message...")
    dns_raw = bytes.fromhex('abcd' '0100' '0001' '0000' '0000' '0000' '06') + b'google' + bytes.fromhex('03') + b'com' + bytes.fromhex('00' '0001' '0001')
    dns = parse_dns(dns_raw)
    assert dns is not None and dns.questions[0].name == 'google.com'
    print(f"    Query: {dns.questions[0].name} ({dns.questions[0].type_name})")
    print("    OK DNS PASSED")

    print("\n[5] HTTP Message...")
    http = parse_http(b'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n')
    assert http is not None and http.method == 'GET' and http.host == 'example.com'
    print(f"    {http.method} {http.uri} Host={http.host}")
    print("    OK HTTP PASSED")

    print("\n[6] ICMP Packet...")
    icmp = parse_icmp(bytes.fromhex('08' '00' 'f7ff' '0001' '0001') + b'abcdefgh')
    assert icmp is not None and icmp.type_name == "Echo Request"
    print(f"    Type={icmp.type_name} id={icmp.identifier} seq={icmp.sequence}")
    print("    OK ICMP PASSED")

    print("\n[7] SSH Banner...")
    ssh = parse_ssh_banner(b'SSH-2.0-OpenSSH_9.6\r\n')
    assert ssh is not None and ssh.protocol_version == '2.0'
    print(f"    Version={ssh.protocol_version} Software={ssh.software_version}")
    print("    OK SSH PASSED")

    print("\n[8] Deep TLS Analysis...")
    a1 = analyze_tls_handshake(0x002F, tls_version=0x0302)
    assert a1.pqc_verdict == "CRITICAL" and not a1.forward_secrecy
    print(f"    RSA: grade={a1.overall_grade} PQC={a1.pqc_verdict}")
    a2 = analyze_tls_handshake(0xC02F, tls_version=0x0303)
    assert a2.forward_secrecy and a2.cipher_strength == "STRONG"
    print(f"    ECDHE: grade={a2.overall_grade} PQC={a2.pqc_verdict} FS={a2.forward_secrecy}")
    a3 = analyze_tls_handshake(0x1301, tls_version=0x0304, supported_groups=[29, 0x6399])
    assert a3.pqc_safe
    print(f"    TLS1.3+PQ: grade={a3.overall_grade} PQC={a3.pqc_verdict}")
    print("    OK Deep TLS PASSED")

    print("\n" + "=" * 60)
    print("  All protocol tests PASSED")
    print("=" * 60)


if __name__ == "__main__":
    test_protocols()
