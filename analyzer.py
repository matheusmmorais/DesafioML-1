#!/usr/bin/env python3
"""
Analisador de tráfego de rede.

Captura pacotes de uma interface (ou de um arquivo .pcap), grava em um banco
SQLite e exibe estatísticas básicas calculadas via SQL.

Campos capturados por pacote: IP de origem, IP de destino, protocolo, tamanho.
"""
import argparse
import html as htmllib
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone

from scapy.all import ARP, IP, IPv6, get_if_list, sniff

DEFAULT_DB = os.getenv("DB_PATH", "/data/traffic.db")
DEFAULT_IFACE = os.getenv("CAPTURE_INTERFACE", "eth0")

BATCH_SIZE = 200        # grava no banco a cada N pacotes...
FLUSH_INTERVAL = 2.0    # ...ou a cada N segundos, o que ocorrer primeiro
STATUS_INTERVAL = 5.0   # mensagem de progresso durante a captura

# Número do protocolo (campo "protocol" do IPv4 / "next header" do IPv6) -> nome
IP_PROTOCOLS = {
    0: "IPv6-HopByHop", 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE",
    50: "ESP", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    interface   TEXT NOT NULL,
    bpf_filter  TEXT,
    started_at  TEXT NOT NULL,
    ended_at    TEXT
);

CREATE TABLE IF NOT EXISTS packets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id),
    captured_at TEXT NOT NULL,      -- ISO 8601, UTC
    src_ip      TEXT NOT NULL,
    dst_ip      TEXT NOT NULL,
    protocol    TEXT NOT NULL,
    size        INTEGER NOT NULL    -- bytes (frame completo)
);

CREATE INDEX IF NOT EXISTS idx_packets_session  ON packets(session_id);
CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(session_id, protocol);
CREATE INDEX IF NOT EXISTS idx_packets_src      ON packets(session_id, src_ip);
CREATE INDEX IF NOT EXISTS idx_packets_dst      ON packets(session_id, dst_ip);
"""


# --------------------------------------------------------------------------
# Extração dos campos
# --------------------------------------------------------------------------
def extract_fields(pkt):
    """Retorna (src_ip, dst_ip, protocolo, tamanho) ou None se não houver IP."""
    if pkt.haslayer(IP):
        layer = pkt[IP]
        number = layer.proto
    elif pkt.haslayer(IPv6):
        layer = pkt[IPv6]
        number = layer.nh
    elif pkt.haslayer(ARP):
        # ARP não tem camada IP, mas carrega IPs de origem/destino
        return pkt[ARP].psrc, pkt[ARP].pdst, "ARP", len(pkt)
    else:
        return None  # STP, LLDP, CDP etc.: sem endereço IP

    protocol = IP_PROTOCOLS.get(number, f"OTHER({number})")
    return layer.src, layer.dst, protocol, len(pkt)


# --------------------------------------------------------------------------
# Banco de dados
# --------------------------------------------------------------------------
def open_db(path):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    return conn


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def start_session(conn, interface, bpf_filter):
    cur = conn.execute(
        "INSERT INTO sessions (interface, bpf_filter, started_at) VALUES (?, ?, ?)",
        (interface, bpf_filter, utc_now()),
    )
    conn.commit()
    return cur.lastrowid


def end_session(conn, session_id):
    conn.execute("UPDATE sessions SET ended_at = ? WHERE id = ?", (utc_now(), session_id))
    conn.commit()


def flush(conn, buffer):
    if not buffer:
        return
    conn.executemany(
        "INSERT INTO packets (session_id, captured_at, src_ip, dst_ip, protocol, size) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        buffer,
    )
    conn.commit()
    buffer.clear()


# --------------------------------------------------------------------------
# Modo demonstração: gera tráfego de teste dentro do próprio container
# --------------------------------------------------------------------------
def generate_demo_traffic():
    """Gera ICMP (ping), DNS (UDP) e HTTP (TCP) para ter o que capturar.
    Falhas de rede são ignoradas: o objetivo é apenas produzir pacotes."""
    time.sleep(2)  # dá tempo da captura começar
    try:
        subprocess.run(["ping", "-c", "8", "8.8.8.8"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=20)
    except Exception:
        pass
    for host in ("example.com", "google.com", "wikipedia.org"):
        try:
            socket.getaddrinfo(host, 80)                                  # DNS
            urllib.request.urlopen(f"http://{host}", timeout=5).read(2048)  # TCP/HTTP
        except Exception:
            pass


# --------------------------------------------------------------------------
# Captura
# --------------------------------------------------------------------------
def capture(conn, args):
    session_id = start_session(conn, args.pcap or args.interface, args.filter)
    buffer = []
    state = {"stored": 0, "ignored": 0}
    last_flush = last_status = time.monotonic()

    def handle(pkt):
        nonlocal last_flush, last_status
        fields = extract_fields(pkt)
        if fields is None:
            state["ignored"] += 1
            return
        src, dst, proto, size = fields
        ts = datetime.fromtimestamp(float(pkt.time), timezone.utc).isoformat(timespec="milliseconds")
        buffer.append((session_id, ts, src, dst, proto, size))
        state["stored"] += 1

        now = time.monotonic()
        if len(buffer) >= BATCH_SIZE or now - last_flush >= FLUSH_INTERVAL:
            flush(conn, buffer)
            last_flush = now
        if now - last_status >= STATUS_INTERVAL:
            print(f"  ... {state['stored']} pacotes capturados", flush=True)
            last_status = now

    kwargs = {"prn": handle, "store": False}
    if args.pcap:
        kwargs["offline"] = args.pcap
    else:
        kwargs["iface"] = args.interface
        if args.timeout:
            kwargs["timeout"] = args.timeout
    if args.filter:
        kwargs["filter"] = args.filter
    if args.count:
        kwargs["stop_filter"] = lambda _p: state["stored"] >= args.count

    if args.demo:
        threading.Thread(target=generate_demo_traffic, daemon=True).start()

    origin = args.pcap or args.interface
    print(f"Capturando de '{origin}' (sessão {session_id}). Ctrl+C para parar.", flush=True)
    try:
        sniff(**kwargs)
    except KeyboardInterrupt:
        print("\nCaptura interrompida pelo usuário.")
    finally:
        flush(conn, buffer)
        end_session(conn, session_id)

    if state["ignored"]:
        print(f"({state['ignored']} frames sem camada IP/ARP foram ignorados, ex.: STP, LLDP)")
    return session_id


# --------------------------------------------------------------------------
# Estatísticas
# --------------------------------------------------------------------------
def human_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def print_table(title, headers, rows):
    print(f"\n{title}")
    if not rows:
        print("  (sem dados)")
        return
    table = [headers] + [[str(c) for c in r] for r in rows]
    widths = [max(len(r[i]) for r in table) for i in range(len(headers))]
    line = "  " + "-+-".join("-" * w for w in widths)
    print("  " + " | ".join(h.ljust(w) for h, w in zip(table[0], widths)))
    print(line)
    for r in table[1:]:
        print("  " + " | ".join(c.ljust(w) for c, w in zip(r, widths)))


def report(conn, session_id, top):
    """Exibe as estatísticas de uma sessão (ou de todas, se session_id for None)."""
    where, params = ("WHERE session_id = ?", (session_id,)) if session_id else ("", ())

    total, total_bytes = conn.execute(
        f"SELECT COUNT(*), COALESCE(SUM(size), 0) FROM packets {where}", params
    ).fetchone()

    label = f"sessão {session_id}" if session_id else "todas as sessões"
    print("\n" + "=" * 60)
    print(f" ESTATÍSTICAS DE TRÁFEGO ({label})")
    print("=" * 60)
    print(f"\nTotal de pacotes capturados: {total}  ({human_bytes(total_bytes)})")
    if total == 0:
        return

    by_proto = conn.execute(
        f"SELECT protocol, COUNT(*), SUM(size) FROM packets {where} "
        "GROUP BY protocol ORDER BY COUNT(*) DESC",
        params,
    ).fetchall()
    print_table(
        "Pacotes por protocolo",
        ["Protocolo", "Pacotes", "%", "Bytes"],
        [(p, c, f"{c / total * 100:.1f}%", human_bytes(b)) for p, c, b in by_proto],
    )

    for column, title in (("src_ip", "origem"), ("dst_ip", "destino")):
        rows = conn.execute(
            f"SELECT {column}, SUM(size), COUNT(*) FROM packets {where} "
            f"GROUP BY {column} ORDER BY SUM(size) DESC, COUNT(*) DESC LIMIT ?",
            params + (top,),
        ).fetchall()
        print_table(
            f"Top {top} IPs de {title} (por volume de tráfego)",
            ["IP", "Bytes", "Pacotes"],
            [(ip, human_bytes(b), c) for ip, b, c in rows],
        )
    print()


def latest_session(conn):
    row = conn.execute("SELECT MAX(id) FROM sessions").fetchone()
    return row[0]


# --------------------------------------------------------------------------
# Relatório HTML (gráficos em SVG/CSS puro, sem dependências externas)
# --------------------------------------------------------------------------
PALETTE = ["#2d68c4", "#e8833a", "#3aa76d", "#c94f7c", "#8e6bbf", "#c9a400", "#3ba7b8", "#7a869a"]

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Relatório de Tráfego de Rede</title>
<style>
:root{--bg:#f4f6fa;--card:#fff;--text:#1d2433;--muted:#6b7488;--line:#e3e7ef}
@media (prefers-color-scheme:dark){:root{--bg:#12161f;--card:#1b2130;--text:#e8ecf4;--muted:#98a2b8;--line:#2a3246}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,Segoe UI,Arial,sans-serif;padding:24px}
.wrap{max-width:1000px;margin:auto}
h1{margin:0 0 4px;font-size:24px}.sub{color:var(--muted);margin-bottom:20px}
.grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px}
.card h2{margin:0 0 12px;font-size:15px;color:var(--muted);font-weight:600}
.kpi{font-size:32px;font-weight:700}.kpi small{font-size:14px;color:var(--muted);font-weight:400}
.donut{display:flex;gap:18px;align-items:center;flex-wrap:wrap}.donut svg{width:150px;height:150px}
.legend div{display:flex;align-items:center;gap:8px;font-size:14px}
.dot{width:10px;height:10px;border-radius:50%;flex:none}
.bar{margin:10px 0}.bar .top{display:flex;justify-content:space-between;font-size:13px;gap:8px}
.bar .ip{font-family:Consolas,monospace;overflow:hidden;text-overflow:ellipsis}
.bar .track{height:10px;background:var(--line);border-radius:5px;margin-top:4px;overflow:hidden}
.bar .fill{height:100%;border-radius:5px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:7px 6px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600}td.n,th.n{text-align:right}
.empty{color:var(--muted)}
</style></head><body><div class="wrap">
<h1>Relatório de Tráfego de Rede</h1>
<div class="sub">__SUB__</div>
<div class="grid">
<div class="card"><h2>Total de pacotes</h2><div class="kpi">__TOTAL__</div></div>
<div class="card"><h2>Volume total</h2><div class="kpi">__BYTES__</div></div>
<div class="card"><h2>Protocolos distintos</h2><div class="kpi">__NPROTO__</div></div>
</div>
<div class="grid">
<div class="card"><h2>Pacotes por protocolo</h2><div class="donut">__DONUT__</div></div>
<div class="card"><h2>Detalhe por protocolo</h2>__PROTO_TABLE__</div>
</div>
<div class="grid">
<div class="card"><h2>Top __TOP__ IPs de origem (por bytes)</h2>__SRC__</div>
<div class="card"><h2>Top __TOP__ IPs de destino (por bytes)</h2>__DST__</div>
</div>
</div></body></html>"""


def collect_stats(conn, session_id, top):
    """Reúne as estatísticas em um dicionário (mesmas consultas do relatório de texto)."""
    where, params = ("WHERE session_id = ?", (session_id,)) if session_id else ("", ())
    total, total_bytes = conn.execute(
        f"SELECT COUNT(*), COALESCE(SUM(size), 0) FROM packets {where}", params
    ).fetchone()
    protocols = conn.execute(
        f"SELECT protocol, COUNT(*), SUM(size) FROM packets {where} "
        "GROUP BY protocol ORDER BY COUNT(*) DESC", params).fetchall()
    ranking = {}
    for column in ("src_ip", "dst_ip"):
        ranking[column] = conn.execute(
            f"SELECT {column}, SUM(size), COUNT(*) FROM packets {where} "
            f"GROUP BY {column} ORDER BY SUM(size) DESC, COUNT(*) DESC LIMIT ?",
            params + (top,)).fetchall()
    session = None
    if session_id:
        session = conn.execute(
            "SELECT interface, bpf_filter, started_at, ended_at FROM sessions WHERE id = ?",
            (session_id,)).fetchone()
    return {"total": total, "bytes": total_bytes, "protocols": protocols,
            "src": ranking["src_ip"], "dst": ranking["dst_ip"], "session": session}


def _esc(value):
    return htmllib.escape(str(value))


def _bars_html(rows):
    if not rows:
        return '<div class="empty">(sem dados)</div>'
    biggest = max(r[1] for r in rows) or 1
    out = []
    for i, (ip, size, count) in enumerate(rows):
        width = max(size / biggest * 100, 2)
        color = PALETTE[i % len(PALETTE)]
        out.append(
            f'<div class="bar"><div class="top"><span class="ip">{_esc(ip)}</span>'
            f'<span>{human_bytes(size)} &middot; {count} pkts</span></div>'
            f'<div class="track"><div class="fill" style="width:{width:.1f}%;background:{color}">'
            f'</div></div></div>')
    return "".join(out)


def _donut_html(protocols, total):
    if not total:
        return '<div class="empty">(sem dados)</div>'
    circles, legend, offset = [], [], 25.0   # 25 = começa no topo do círculo
    for i, (proto, count, _size) in enumerate(protocols):
        pct = count / total * 100
        color = PALETTE[i % len(PALETTE)]
        circles.append(
            f'<circle cx="21" cy="21" r="15.915" fill="none" stroke="{color}" stroke-width="6" '
            f'stroke-dasharray="{pct:.3f} {100 - pct:.3f}" stroke-dashoffset="{offset:.3f}"/>')
        legend.append(f'<div><span class="dot" style="background:{color}"></span>'
                      f'{_esc(proto)} &mdash; {pct:.1f}%</div>')
        offset -= pct
    return (f'<svg viewBox="0 0 42 42" role="img" aria-label="Pacotes por protocolo">'
            f'{"".join(circles)}</svg><div class="legend">{"".join(legend)}</div>')


def render_html(stats, top, label):
    total = stats["total"]
    rows = "".join(
        f"<tr><td>{_esc(p)}</td><td class='n'>{c}</td><td class='n'>{c / total * 100:.1f}%</td>"
        f"<td class='n'>{human_bytes(b)}</td></tr>" for p, c, b in stats["protocols"])
    table = ("<table><tr><th>Protocolo</th><th class='n'>Pacotes</th><th class='n'>%</th>"
             f"<th class='n'>Bytes</th></tr>{rows}</table>") if total else '<div class="empty">(sem dados)</div>'
    sub = label
    if stats["session"]:
        iface, flt, started, ended = stats["session"]
        sub += f" &middot; origem: {_esc(iface)}"
        if flt:
            sub += f" &middot; filtro: {_esc(flt)}"
        sub += f" &middot; início: {_esc(started.replace('+00:00', '').replace('T', ' '))} UTC"
    page = HTML_TEMPLATE
    for key, value in {
        "__SUB__": sub, "__TOTAL__": f"{total:,}".replace(",", "."),
        "__BYTES__": human_bytes(stats["bytes"]), "__NPROTO__": str(len(stats["protocols"])),
        "__DONUT__": _donut_html(stats["protocols"], total), "__PROTO_TABLE__": table,
        "__TOP__": str(top), "__SRC__": _bars_html(stats["src"]), "__DST__": _bars_html(stats["dst"]),
    }.items():
        page = page.replace(key, value)
    return page


def write_html(conn, session_id, top, path):
    label = f"Sessão {session_id}" if session_id else "Todas as sessões"
    stats = collect_stats(conn, session_id, top)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_html(stats, top, label))
    print(f"Relatório HTML gerado: {path}")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Captura pacotes, grava em SQLite e mostra estatísticas de tráfego."
    )
    p.add_argument("-i", "--interface", default=DEFAULT_IFACE,
                   help=f"interface de rede (padrão: {DEFAULT_IFACE})")
    p.add_argument("-c", "--count", type=int, default=0,
                   help="para após N pacotes armazenados (padrão: sem limite)")
    p.add_argument("-t", "--timeout", type=int, default=0,
                   help="para após N segundos (padrão: sem limite)")
    p.add_argument("-f", "--filter", default=None,
                   help='filtro BPF opcional, ex.: "tcp port 443"')
    p.add_argument("--top", type=int, default=5, help="tamanho dos rankings (padrão: 5)")
    p.add_argument("--db", default=DEFAULT_DB, help=f"arquivo SQLite (padrão: {DEFAULT_DB})")
    p.add_argument("--pcap", help="lê de um arquivo .pcap em vez de uma interface (modo offline)")
    p.add_argument("--html", default=None,
                   help="caminho do relatório HTML (padrão: relatorio.html ao lado do banco)")
    p.add_argument("--demo", action="store_true",
                   help="gera tráfego de teste (ping, DNS, HTTP) durante a captura (padrão: 20 s)")
    p.add_argument("--list-interfaces", action="store_true", help="lista interfaces e sai")
    p.add_argument("--report", action="store_true",
                   help="não captura; apenas exibe estatísticas do banco")
    p.add_argument("--session", type=int, help="com --report: ID da sessão (padrão: a última)")
    p.add_argument("--all", action="store_true", help="com --report: agrega todas as sessões")
    return p.parse_args(argv)


def main():
    args = parse_args()
    # `docker stop` envia SIGTERM: tratamos como Ctrl+C para fechar o banco direito
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))

    if args.list_interfaces:
        print("\n".join(get_if_list()))
        return 0

    if args.demo and not args.timeout and not args.count:
        args.timeout = 20
    conn = open_db(args.db)
    html_path = args.html or os.path.join(os.path.dirname(os.path.abspath(args.db)), "relatorio.html")

    if args.report:
        session_id = None if args.all else (args.session or latest_session(conn))
        if not args.all and session_id is None:
            print("Banco vazio: nenhuma sessão de captura encontrada.")
            return 1
        report(conn, session_id, args.top)
        write_html(conn, session_id, args.top, html_path)
        return 0

    if not args.pcap and args.interface not in get_if_list():
        print(f"Erro: interface '{args.interface}' não encontrada.")
        print("Interfaces disponíveis: " + ", ".join(get_if_list()))
        return 1

    try:
        session_id = capture(conn, args)
    except PermissionError:
        print("Erro: sem permissão para capturar. Execute como root ou com a "
              "capability NET_RAW (no Docker: --cap-add=NET_RAW --cap-add=NET_ADMIN).")
        return 1
    except OSError as exc:
        print(f"Erro ao capturar: {exc}")
        return 1

    report(conn, session_id, args.top)
    write_html(conn, session_id, args.top, html_path)
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
