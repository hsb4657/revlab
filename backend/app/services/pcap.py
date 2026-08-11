"""网络抓包:pktmon 采集 + 自研 pcap 解析(DNS/HTTP/TLS-SNI/连接聚合)"""
import ipaddress
import socket
import struct
import subprocess
import time
from collections import defaultdict
from pathlib import Path

LINKTYPE_ETHERNET = 1


# ================================================================ pktmon
def pktmon_start(etl_path: str) -> bool:
    """启动 pktmon 抓包(需管理员权限)。"""
    p = subprocess.run(["pktmon", "start", "--capture", "--pkt-size", "0",
                        "--file-name", etl_path, "--comp", "nics"],
                       capture_output=True)
    return p.returncode == 0


def pktmon_stop() -> bool:
    p = subprocess.run(["pktmon", "stop"], capture_output=True)
    return p.returncode == 0


def pktmon_etl2pcap(etl_path: str, pcap_path: str) -> bool:
    p = subprocess.run(["pktmon", "etl2pcap", etl_path, "-o", pcap_path],
                       capture_output=True)
    return p.returncode == 0 and Path(pcap_path).exists()


def capture_network(duration: int, out_pcap: str, etl_path: str = "") -> dict:
    """抓包指定时长并转换为 pcap。返回 {ok, pcap, packet_count, error}。"""
    etl_path = etl_path or str(Path(out_pcap).with_suffix(".etl"))
    Path(out_pcap).parent.mkdir(parents=True, exist_ok=True)
    if not pktmon_start(etl_path):
        return {"ok": False, "error": "pktmon start failed (needs admin). Run capture manually."}
    time.sleep(duration)
    pktmon_stop()
    ok = pktmon_etl2pcap(etl_path, out_pcap)
    if ok:
        parsed = parse_pcap(open(out_pcap, "rb").read())
        return {"ok": True, "pcap": out_pcap, **parsed}
    return {"ok": False, "error": "etl2pcap failed"}


# ================================================================ pcap parse
def parse_pcap(data: bytes) -> dict:
    """解析 pcap(经典格式,含以太网/IPv4/IPv6/TCP/UDP,DNS/HTTP/SNI)。"""
    result = {"file_size": len(data), "packet_count": 0, "link_type": "",
              "connections": [], "dns_queries": [], "http_requests": [],
              "sni": [], "ip_stats": {}}
    if len(data) < 24:
        result["error"] = "not a pcap (too small)"
        return result

    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
        result["link_type"] = "Ethernet"
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian = "<"
        result["link_type"] = "Ethernet"
    else:
        result["error"] = "unsupported pcap format"
        return result

    linktype = struct.unpack(endian + "I", data[20:24])[0]
    result["link_type"] = "Ethernet" if linktype == LINKTYPE_ETHERNET else f"linktype={linktype}"
    if linktype != LINKTYPE_ETHERNET:
        return result

    off = 24
    conns = defaultdict(lambda: {"packets": 0, "bytes": 0, "first": 0, "last": 0, "server_name": ""})
    dns_q = []
    http_r = []
    sni = []
    ip_stats = defaultdict(lambda: {"packets": 0, "bytes": 0, "ports": set()})

    while off + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if off + incl_len > len(data):
            break
        pkt = data[off:off + incl_len]
        off += incl_len
        result["packet_count"] += 1
        ts = ts_sec + ts_usec / 1e6

        eth = _parse_eth(pkt)
        if not eth:
            continue
        l3, proto = eth
        if l3 is None:
            continue
        if proto == 0x0800:  # IPv4
            ip = _parse_ipv4(l3)
        elif proto == 0x86DD:  # IPv6
            ip = _parse_ipv6(l3)
        else:
            continue
        if not ip:
            continue
        src, dst, l4, l4proto = ip
        if l4 is None:
            continue
        ip_stats[src]["packets"] += 1
        ip_stats[src]["bytes"] += len(pkt)
        ip_stats[dst]["packets"] += 1
        ip_stats[dst]["bytes"] += len(pkt)

        if l4proto == 6:   # TCP
            sport, dport, payload = _parse_tcp(l4)
        elif l4proto == 17:  # UDP
            sport, dport, payload = _parse_udp(l4)
        else:
            continue
        ip_stats[src]["ports"].add(sport)
        ip_stats[dst]["ports"].add(dport)

        key = tuple(sorted([(src, sport), (dst, dport)]))
        c = conns[key]
        c["packets"] += 1
        c["bytes"] += len(payload)
        c["first"] = c["first"] or ts
        c["last"] = ts

        # DNS
        if dport == 53 or sport == 53:
            for q in _parse_dns(payload):
                dns_q.append({"src": src, "dst": dst, **q})
        # HTTP(简单:请求行)
        if dport == 80 and payload[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTIONS", b"CONNECT"):
            line = payload.split(b"\r\n", 1)[0].decode("latin-1", "ignore")
            http_r.append({"src": src, "dst": dst, "request": line})
        if sport == 80 and payload[:4] == b"HTTP":
            line = payload.split(b"\r\n", 1)[0].decode("latin-1", "ignore")
            http_r.append({"src": src, "dst": dst, "response": line})
        # TLS SNI
        if dport == 443 and payload[:1] == b"\x16":
            name = _tls_sni(payload)
            if name:
                c["server_name"] = name
                sni.append({"src": src, "dst": dst, "sni": name})

    result["connections"] = _serialize_conns(conns)
    result["dns_queries"] = dns_q
    result["http_requests"] = http_r
    result["sni"] = sni
    result["ip_stats"] = [
        {"ip": ip, "packets": st["packets"], "bytes": st["bytes"],
         "ports": sorted(st["ports"])}
        for ip, st in sorted(ip_stats.items())
    ]
    return result


def _parse_eth(pkt: bytes):
    if len(pkt) < 14:
        return None, 0
    etype = struct.unpack(">H", pkt[12:14])[0]
    return pkt[14:], etype


def _parse_ipv4(l3: bytes):
    if len(l3) < 20 or (l3[0] >> 4) != 4:
        return None
    ihl = (l3[0] & 0xF) * 4
    proto = l3[9]
    src = socket.inet_ntop(socket.AF_INET, l3[12:16])
    dst = socket.inet_ntop(socket.AF_INET, l3[16:20])
    return src, dst, l3[ihl:], proto


def _parse_ipv6(l3: bytes):
    if len(l3) < 40 or (l3[0] >> 4) != 6:
        return None
    # 简化:只处理无扩展头情况
    proto = l3[6]
    src = socket.inet_ntop(socket.AF_INET6, l3[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, l3[24:40])
    return src, dst, l3[40:], proto


def _parse_tcp(l4: bytes):
    if len(l4) < 20:
        return 0, 0, b""
    sport, dport = struct.unpack(">HH", l4[0:4])
    doff = (l4[12] >> 4) * 4
    return sport, dport, l4[doff:]


def _parse_udp(l4: bytes):
    if len(l4) < 8:
        return 0, 0, b""
    sport, dport, ln = struct.unpack(">HHH", l4[0:6])
    return sport, dport, l4[8:8 + max(0, ln - 8)]


def _parse_dns(payload: bytes):
    out = []
    try:
        if len(payload) < 12:
            return out
        qd = struct.unpack(">H", payload[4:6])[0]
        off = 12
        for _ in range(qd):
            name, off2 = _read_dns_name(payload, off)
            if off2 is None:
                break
            off = off2
            qtype, qclass = struct.unpack(">HH", payload[off:off + 4])
            off += 4
            out.append({"query": name, "type": qtype, "answers": []})
    except Exception:
        pass
    return out


def _read_dns_name(payload: bytes, off: int):
    labels = []
    while off < len(payload):
        ln = payload[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", payload[off:off + 2])[0] & 0x3FFF
            # 跟随指针
            if ptr < len(payload):
                tail, _ = _read_dns_name(payload, ptr)
                labels.append(tail)
            off += 2
            break
        if off + 1 + ln > len(payload):
            return "", None
        labels.append(payload[off + 1:off + 1 + ln].decode("latin-1", "ignore"))
        off += 1 + ln
    return ".".join(labels), off


def _tls_sni(payload: bytes) -> str:
    """从 TLS ClientHello 提取 SNI。"""
    try:
        if payload[5] != 0x01:
            return ""
        # handshake: type(1) len(3) version(2) random(32) sid...
        p = 5 + 1 + 3
        # client_version
        p += 2
        p += 32  # random
        sid_len = payload[p]
        p += 1 + sid_len
        cs_len = struct.unpack(">H", payload[p:p + 2])[0]
        p += 2 + cs_len
        comp_len = payload[p]
        p += 1 + comp_len
        ext_len = struct.unpack(">H", payload[p:p + 2])[0]
        p += 2
        end = p + ext_len
        while p + 4 <= end:
            etype, elen = struct.unpack(">HH", payload[p:p + 4])
            p += 4
            if etype == 0x0000:  # server_name
                if p + 3 <= end and payload[p + 1] == 0x00:
                    slen = struct.unpack(">H", payload[p + 2:p + 4])[0]
                    return payload[p + 4:p + 4 + slen].decode("latin-1", "ignore")
                return ""
            p += elen
    except Exception:
        pass
    return ""


def _serialize_conns(conns: dict) -> list:
    out = []
    for key, c in conns.items():
        a, b = key
        if c["packets"] == 0:
            continue
        # 判断方向:端口大的一侧为服务端
        (sa, spa), (sb, spb) = a, b
        if spa < spb:
            client, server = a, b
        else:
            client, server = b, a
        out.append({
            "client": {"ip": client[0], "port": client[1]},
            "server": {"ip": server[0], "port": server[1]},
            "packets": c["packets"], "bytes": c["bytes"],
            "first": round(c["first"], 3), "last": round(c["last"], 3),
            "server_name": c["server_name"],
        })
    out.sort(key=lambda x: -x["bytes"])
    return out
