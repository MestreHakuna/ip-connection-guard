#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP Connection Guard + AbuseIPDB
Autor: M.Hakuna / ChatGPT
Descrição:
    App Windows em Tkinter para analisar conexões do netstat -ano, identificar
    processo/PID, tipo de IP, provável direção, dono do IP via RDAP e reputação
    via AbuseIPDB.

Requisitos:
    Python 3.10+
    Sem bibliotecas externas.
    Windows recomendado.

Como usar:
    python ip_connection_guard_abuseipdb.py

Observação:
    A chave da AbuseIPDB fica salva em ip_guard_config.json na mesma pasta.
    Trate sua chave como senha. Não envie para terceiros.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from tkinter import (
    Tk,
    StringVar,
    BooleanVar,
    IntVar,
    END,
    BOTH,
    LEFT,
    RIGHT,
    X,
    Y,
    TOP,
    BOTTOM,
    VERTICAL,
    HORIZONTAL,
    filedialog,
    messagebox,
)
from tkinter import ttk


APP_TITLE = "IP Connection Guard | AbuseIPDB | M.Hakuna"
BASE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
CONFIG_PATH = Path(__file__).resolve().parent / "ip_guard_config.json"
LOG_PATH = Path(__file__).resolve().parent / "ip_guard_errors.log"

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
RDAP_URL = "https://rdap.org/ip/{ip}"

COMMON_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    137: "NETBIOS",
    138: "NETBIOS",
    139: "NETBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-SUBMISSION",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    1723: "PPTP",
    2049: "NFS",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRES",
    5900: "VNC",
    5985: "WINRM-HTTP",
    5986: "WINRM-HTTPS",
    6379: "REDIS",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    27015: "STEAM/GAME",
    27016: "STEAM/GAME",
    27017: "STEAM/GAME",
    27018: "STEAM/GAME",
    27019: "STEAM/GAME",
    27020: "STEAM/GAME",
}

REMOTE_ACCESS_PORTS = {22, 23, 3389, 5900, 5985, 5986, 445, 139, 135}


def log_error(msg: str) -> None:
    try:
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
            f.write(traceback.format_exc())
            f.write("\n")
    except Exception:
        pass


def subprocess_no_window_kwargs() -> dict:
    kwargs = {}
    if os.name == "nt" and hasattr(subprocess, "CREATE_NO_WINDOW"):
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    return kwargs


def run_cmd(args: list[str], timeout: int = 10) -> str:
    try:
        out = subprocess.check_output(
            args,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            **subprocess_no_window_kwargs(),
        )
        return out
    except subprocess.CalledProcessError as e:
        return e.output or ""
    except Exception:
        log_error(f"Erro executando comando: {args}")
        return ""


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {"api_key": "", "max_age_days": 90, "only_established": True}
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"api_key": "", "max_age_days": 90, "only_established": True}


def save_config(config: dict) -> None:
    CONFIG_PATH.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")


def split_endpoint(endpoint: str) -> tuple[str, str]:
    """
    Retorna (ip, porta) para formatos:
      192.168.1.10:49722
      [2804:...:abcd]:443
      *:*
      0.0.0.0:0
    """
    endpoint = endpoint.strip()

    if endpoint in ("*", "*:*"):
        return "*", "*"

    ipv6_match = re.match(r"^\[(.+?)\]:(\d+|\*)$", endpoint)
    if ipv6_match:
        return ipv6_match.group(1), ipv6_match.group(2)

    if ":" in endpoint:
        ip, port = endpoint.rsplit(":", 1)
        return ip.strip("[]"), port

    return endpoint.strip("[]"), ""


def safe_int(value: str, default: int = -1) -> int:
    try:
        return int(value)
    except Exception:
        return default


def classify_ip(ip_text: str) -> str:
    ip_text = (ip_text or "").strip().strip("[]")
    if ip_text in ("", "*", "0.0.0.0", "::", "::0"):
        return "N/A"
    try:
        ip = ipaddress.ip_address(ip_text)
        if ip.is_loopback:
            return "LOCALHOST"
        if ip.is_private:
            return "LAN/PRIVADO"
        if ip.is_link_local:
            return "LINK-LOCAL"
        if ip.is_multicast:
            return "MULTICAST"
        if ip.is_reserved:
            return "RESERVADO"
        if ip.is_global:
            return "PÚBLICO"
        return "OUTRO"
    except ValueError:
        return "INVÁLIDO"


def is_public_ip(ip_text: str) -> bool:
    try:
        ip = ipaddress.ip_address((ip_text or "").strip().strip("[]"))
        return bool(ip.is_global)
    except ValueError:
        return False


def is_private_or_local(ip_text: str) -> bool:
    try:
        ip = ipaddress.ip_address((ip_text or "").strip().strip("[]"))
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


@dataclass
class ConnectionRow:
    proto: str
    local_addr: str
    local_ip: str
    local_port: str
    remote_addr: str
    remote_ip: str
    remote_port: str
    state: str
    pid: str
    process: str = ""
    ip_type: str = ""
    direction: str = ""
    hostname: str = ""
    rdap_owner: str = ""
    abuse_score: str = ""
    abuse_reports: str = ""
    abuse_country: str = ""
    abuse_isp_domain: str = ""
    risk: str = ""
    notes: str = ""


def parse_netstat(output: str, only_established: bool = True) -> list[ConnectionRow]:
    rows: list[ConnectionRow] = []

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        parts = line.split()
        proto = parts[0].upper() if parts else ""

        if proto == "TCP":
            # TCP local remote state pid
            if len(parts) < 5:
                continue
            local_addr, remote_addr, state, pid = parts[1], parts[2], parts[3], parts[4]
            if only_established and state.upper() != "ESTABLISHED":
                continue
        elif proto == "UDP":
            # UDP local remote pid
            if len(parts) < 4:
                continue
            local_addr, remote_addr, state, pid = parts[1], parts[2], "UDP", parts[-1]
            if only_established:
                continue
        else:
            continue

        local_ip, local_port = split_endpoint(local_addr)
        remote_ip, remote_port = split_endpoint(remote_addr)

        row = ConnectionRow(
            proto=proto,
            local_addr=local_addr,
            local_ip=local_ip,
            local_port=local_port,
            remote_addr=remote_addr,
            remote_ip=remote_ip,
            remote_port=remote_port,
            state=state,
            pid=pid,
            ip_type=classify_ip(remote_ip),
        )
        rows.append(row)

    return rows


def get_process_map() -> dict[str, str]:
    """
    Mapeia PID -> nome do processo usando tasklist.
    """
    result: dict[str, str] = {}
    if os.name != "nt":
        return result

    out = run_cmd(["tasklist", "/FO", "CSV", "/NH"], timeout=15)
    if not out:
        return result

    try:
        for row in csv.reader(out.splitlines()):
            # "Image Name","PID","Session Name","Session#","Mem Usage"
            if len(row) >= 2:
                image, pid = row[0].strip(), row[1].strip()
                result[pid] = image
    except Exception:
        log_error("Erro processando tasklist")

    return result


def guess_lan_name(ip: str) -> str:
    """
    Tenta resolver nome de dispositivo local.
    """
    if not ip or not is_private_or_local(ip) or classify_ip(ip) == "LOCALHOST":
        return ""

    # ping -a pode resolver o nome local
    out = run_cmd(["ping", "-a", "-n", "1", ip], timeout=4)
    # Exemplo: Pinging DESKTOP-ABC [192.168.1.20] with 32 bytes of data:
    m = re.search(r"(?i)(?:disparando|pinging)\s+([^\s\[]+)\s+\[" + re.escape(ip) + r"\]", out)
    if m:
        name = m.group(1).strip()
        if name and name != ip:
            return name

    # nbtstat funciona para alguns dispositivos Windows/NetBIOS
    out = run_cmd(["nbtstat", "-A", ip], timeout=5)
    for line in out.splitlines():
        if "<00>" in line and "UNIQUE" in line.upper():
            name = line.split("<00>")[0].strip()
            if name and len(name) <= 32:
                return name

    return ""


def reverse_dns(ip: str) -> str:
    if not ip or not is_public_ip(ip):
        return ""
    try:
        socket.setdefaulttimeout(2)
        host, _, _ = socket.gethostbyaddr(ip)
        return host or ""
    except Exception:
        return ""


def rdap_lookup(ip: str) -> dict:
    """
    Consulta RDAP público. Retorna nome/organização aproximada do bloco do IP.
    """
    if not is_public_ip(ip):
        return {}

    url = RDAP_URL.format(ip=urllib.parse.quote(ip, safe=""))
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "IP-Connection-Guard/1.0",
            "Accept": "application/rdap+json, application/json",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(body)
            return data if isinstance(data, dict) else {}
    except Exception:
        log_error(f"RDAP falhou para {ip}")
        return {}


def extract_vcard_value(entity: dict, keys: tuple[str, ...] = ("fn", "org")) -> str:
    try:
        vcard = entity.get("vcardArray")
        if not isinstance(vcard, list) or len(vcard) < 2:
            return ""
        items = vcard[1]
        found = []
        for item in items:
            if isinstance(item, list) and len(item) >= 4:
                key = str(item[0]).lower()
                if key in keys:
                    value = item[3]
                    if isinstance(value, str) and value.strip():
                        found.append(value.strip())
        return " / ".join(dict.fromkeys(found))
    except Exception:
        return ""
    return ""


def rdap_owner_text(data: dict) -> str:
    if not data:
        return ""

    names = []
    for key in ("name", "handle"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            names.append(value.strip())

    # entidades
    for ent in data.get("entities", []) or []:
        if isinstance(ent, dict):
            val = extract_vcard_value(ent)
            if val:
                names.append(val)

    # remarks/description às vezes têm algo útil
    for remark in data.get("remarks", []) or []:
        if isinstance(remark, dict):
            desc = remark.get("description")
            if isinstance(desc, list):
                for line in desc[:2]:
                    if isinstance(line, str) and line.strip():
                        names.append(line.strip())

    # bloco IP
    start = data.get("startAddress")
    end = data.get("endAddress")
    block = ""
    if isinstance(start, str) and isinstance(end, str):
        block = f"{start} - {end}"

    uniq = []
    for n in names:
        n = re.sub(r"\s+", " ", n).strip()
        if n and n not in uniq:
            uniq.append(n)

    text = " | ".join(uniq[:4])
    if block:
        text = f"{text} | bloco {block}" if text else f"bloco {block}"
    return text[:350]


def abuseipdb_check(ip: str, api_key: str, max_age_days: int = 90) -> dict:
    if not is_public_ip(ip):
        return {}

    params = {
        "ipAddress": ip,
        "maxAgeInDays": str(max(1, min(int(max_age_days), 365))),
    }
    url = ABUSEIPDB_CHECK_URL + "?" + urllib.parse.urlencode(params)

    req = urllib.request.Request(
        url,
        headers={
            "Key": api_key.strip(),
            "Accept": "application/json",
            "User-Agent": "IP-Connection-Guard/1.0",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(body)
            return data.get("data", {}) if isinstance(data, dict) else {}
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        raise RuntimeError(f"AbuseIPDB HTTP {e.code}: {detail[:300]}")
    except Exception as e:
        raise RuntimeError(f"Erro consultando AbuseIPDB para {ip}: {e}")


def infer_direction(row: ConnectionRow) -> str:
    lp = safe_int(row.local_port)
    rp = safe_int(row.remote_port)

    if row.ip_type == "LOCALHOST":
        return "Interna do próprio PC"

    if row.ip_type in ("LAN/PRIVADO", "LINK-LOCAL"):
        return "Rede local/LAN"

    if row.ip_type != "PÚBLICO":
        return "Indefinido"

    if lp in REMOTE_ACCESS_PORTS:
        return "ATENÇÃO: serviço local acessado"

    if lp < 1024 and lp > 0:
        return "Possível entrada/serviço local"

    if rp in COMMON_PORTS and lp >= 49152:
        return "Provável saída do seu PC"

    if rp in COMMON_PORTS:
        return "Provável saída/app conectado"

    if lp >= 49152 and rp >= 1024:
        return "Provável saída ou app P2P/jogo"

    return "Indefinido"


def build_notes(row: ConnectionRow) -> str:
    notes = []

    lp = safe_int(row.local_port)
    rp = safe_int(row.remote_port)

    if row.ip_type == "LOCALHOST":
        notes.append("Conexão interna 127.0.0.1/::1; normalmente não é acesso externo.")

    if row.ip_type in ("LAN/PRIVADO", "LINK-LOCAL"):
        notes.append("IP remoto privado/local; verifique se é um dispositivo conhecido na sua rede.")

    if rp in COMMON_PORTS:
        notes.append(f"Porta remota {rp}: {COMMON_PORTS[rp]}.")

    if lp in COMMON_PORTS:
        notes.append(f"Porta local {lp}: {COMMON_PORTS[lp]}.")

    if lp in REMOTE_ACCESS_PORTS and row.state.upper() == "ESTABLISHED":
        notes.append("A porta local é típica de acesso remoto/serviço Windows; investigue com prioridade.")

    if row.process:
        lower = row.process.lower()
        if lower in ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"):
            notes.append("Processo de navegador; conexões HTTPS são comuns.")
        elif lower in ("discord.exe", "steam.exe", "epicgameslauncher.exe"):
            notes.append("Processo comum de app/jogo; verifique se você estava usando.")
        elif lower in ("svchost.exe", "system"):
            notes.append("Processo do Windows; pode ser normal, mas confirme porta/destino.")

    return " ".join(notes)


def calculate_risk(row: ConnectionRow) -> str:
    score = safe_int(str(row.abuse_score), default=0)
    lp = safe_int(row.local_port)

    if score >= 75:
        return "CRÍTICO"
    if score >= 50:
        return "ALTO"
    if score >= 10:
        return "MÉDIO"
    if row.ip_type == "PÚBLICO" and lp in REMOTE_ACCESS_PORTS:
        return "MÉDIO"
    if row.ip_type in ("LAN/PRIVADO", "LINK-LOCAL"):
        return "LAN"
    if row.ip_type == "LOCALHOST":
        return "LOCAL"
    return "BAIXO"


class App:
    def __init__(self, root: Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1450x780")
        self.root.minsize(1150, 650)

        self.config = load_config()
        self.rows: list[ConnectionRow] = []
        self.abuse_cache: dict[str, dict] = {}
        self.rdap_cache: dict[str, str] = {}
        self.hostname_cache: dict[str, str] = {}

        self.api_key_var = StringVar(value=self.config.get("api_key", ""))
        self.max_age_var = IntVar(value=int(self.config.get("max_age_days", 90) or 90))
        self.only_established_var = BooleanVar(value=bool(self.config.get("only_established", True)))
        self.status_var = StringVar(value="Pronto.")

        self._build_ui()

    def _build_ui(self) -> None:
        top = ttk.Frame(self.root, padding=8)
        top.pack(side=TOP, fill=X)

        ttk.Label(top, text="API Key AbuseIPDB:").pack(side=LEFT)
        api_entry = ttk.Entry(top, textvariable=self.api_key_var, show="*", width=45)
        api_entry.pack(side=LEFT, padx=(5, 10))

        ttk.Label(top, text="Dias:").pack(side=LEFT)
        days_spin = ttk.Spinbox(top, from_=1, to=365, textvariable=self.max_age_var, width=5)
        days_spin.pack(side=LEFT, padx=(5, 10))

        ttk.Checkbutton(
            top,
            text="Somente ESTABLISHED",
            variable=self.only_established_var,
        ).pack(side=LEFT, padx=(0, 10))

        ttk.Button(top, text="Salvar chave", command=self.save_settings).pack(side=LEFT, padx=3)
        ttk.Button(top, text="1) Escanear netstat", command=self.scan_thread).pack(side=LEFT, padx=3)
        ttk.Button(top, text="2) Analisar AbuseIPDB + dono IP", command=self.analyze_thread).pack(side=LEFT, padx=3)
        ttk.Button(top, text="Exportar CSV", command=self.export_csv).pack(side=LEFT, padx=3)
        ttk.Button(top, text="Limpar", command=self.clear).pack(side=LEFT, padx=3)

        info = ttk.Frame(self.root, padding=(8, 0, 8, 4))
        info.pack(side=TOP, fill=X)

        ttk.Label(
            info,
            text=(
                "Leitura: LOCALHOST = interno do PC | LAN = outro dispositivo da sua rede | "
                "PÚBLICO = internet. Score AbuseIPDB >=50 merece atenção; >=75 é crítico."
            ),
        ).pack(side=LEFT)

        table_frame = ttk.Frame(self.root, padding=8)
        table_frame.pack(side=TOP, fill=BOTH, expand=True)

        self.columns = (
            "risk",
            "proto",
            "local",
            "remote",
            "state",
            "pid",
            "process",
            "ip_type",
            "direction",
            "abuse",
            "reports",
            "country",
            "owner",
            "isp_domain",
            "hostname",
            "notes",
        )

        self.tree = ttk.Treeview(
            table_frame,
            columns=self.columns,
            show="headings",
            height=20,
        )

        headings = {
            "risk": "Risco",
            "proto": "Proto",
            "local": "Local",
            "remote": "Remoto",
            "state": "Estado",
            "pid": "PID",
            "process": "Processo",
            "ip_type": "Tipo IP",
            "direction": "Direção provável",
            "abuse": "Abuse %",
            "reports": "Reports",
            "country": "País",
            "owner": "Quem é / Dono do IP",
            "isp_domain": "ISP/Domínio",
            "hostname": "Hostname",
            "notes": "Notas",
        }

        widths = {
            "risk": 80,
            "proto": 55,
            "local": 170,
            "remote": 210,
            "state": 105,
            "pid": 70,
            "process": 150,
            "ip_type": 95,
            "direction": 190,
            "abuse": 75,
            "reports": 70,
            "country": 60,
            "owner": 300,
            "isp_domain": 260,
            "hostname": 230,
            "notes": 420,
        }

        for col in self.columns:
            self.tree.heading(col, text=headings[col], command=lambda c=col: self.sort_by(c, False))
            self.tree.column(col, width=widths[col], anchor="w", stretch=False)

        vsb = ttk.Scrollbar(table_frame, orient=VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient=HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self.tree.tag_configure("CRÍTICO", background="#ffb3b3")
        self.tree.tag_configure("ALTO", background="#ffd0b3")
        self.tree.tag_configure("MÉDIO", background="#fff0b3")
        self.tree.tag_configure("LAN", background="#d9ecff")
        self.tree.tag_configure("LOCAL", background="#eeeeee")
        self.tree.tag_configure("BAIXO", background="#ddffdd")

        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        bottom = ttk.Frame(self.root, padding=8)
        bottom.pack(side=BOTTOM, fill=X)

        self.detail = ttk.Label(bottom, textvariable=self.status_var, anchor="w", justify="left")
        self.detail.pack(side=LEFT, fill=X, expand=True)

    def save_settings(self) -> None:
        self.config["api_key"] = self.api_key_var.get().strip()
        self.config["max_age_days"] = int(self.max_age_var.get() or 90)
        self.config["only_established"] = bool(self.only_established_var.get())
        try:
            save_config(self.config)
            self.status_var.set(f"Configurações salvas em {CONFIG_PATH}")
        except Exception as e:
            messagebox.showerror("Erro", f"Não consegui salvar config: {e}")

    def set_status(self, text: str) -> None:
        self.root.after(0, lambda: self.status_var.set(text))

    def clear(self) -> None:
        self.rows.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.status_var.set("Lista limpa.")

    def scan_thread(self) -> None:
        threading.Thread(target=self.scan, daemon=True).start()

    def analyze_thread(self) -> None:
        threading.Thread(target=self.analyze, daemon=True).start()

    def scan(self) -> None:
        self.set_status("Executando netstat -ano...")
        try:
            out = run_cmd(["netstat", "-ano"], timeout=20)
            rows = parse_netstat(out, only_established=bool(self.only_established_var.get()))

            proc_map = get_process_map()
            for row in rows:
                row.process = proc_map.get(row.pid, "")
                row.direction = infer_direction(row)
                row.notes = build_notes(row)
                row.risk = calculate_risk(row)

            self.rows = rows
            self.root.after(0, self.refresh_table)
            self.set_status(f"Scan concluído. {len(rows)} conexão(ões) listada(s).")
        except Exception as e:
            log_error("Erro no scan")
            self.set_status(f"Erro no scan: {e}")

    def analyze(self) -> None:
        api_key = self.api_key_var.get().strip()
        max_age = int(self.max_age_var.get() or 90)

        if not self.rows:
            self.scan()

        public_ips = sorted({r.remote_ip for r in self.rows if is_public_ip(r.remote_ip)})
        lan_ips = sorted({r.remote_ip for r in self.rows if classify_ip(r.remote_ip) in ("LAN/PRIVADO", "LINK-LOCAL")})

        if public_ips and not api_key:
            self.set_status(
                "Sem API Key. Vou fazer RDAP/hostname, mas AbuseIPDB ficará vazio. "
                "Cadastre sua chave no campo acima."
            )
        else:
            self.set_status(f"Analisando {len(public_ips)} IP(s) público(s) e {len(lan_ips)} IP(s) LAN...")

        # LAN names
        for idx, ip in enumerate(lan_ips, start=1):
            self.set_status(f"Identificando dispositivo LAN {idx}/{len(lan_ips)}: {ip}")
            if ip not in self.hostname_cache:
                self.hostname_cache[ip] = guess_lan_name(ip)

        # Public IP analysis
        for idx, ip in enumerate(public_ips, start=1):
            self.set_status(f"Analisando IP público {idx}/{len(public_ips)}: {ip}")

            if ip not in self.hostname_cache:
                self.hostname_cache[ip] = reverse_dns(ip)

            if ip not in self.rdap_cache:
                rdap = rdap_lookup(ip)
                self.rdap_cache[ip] = rdap_owner_text(rdap)

            if api_key and ip not in self.abuse_cache:
                try:
                    self.abuse_cache[ip] = abuseipdb_check(ip, api_key, max_age)
                except Exception as e:
                    self.abuse_cache[ip] = {"_error": str(e)}
                    log_error(str(e))

        # Apply analysis to rows
        for row in self.rows:
            ip = row.remote_ip
            row.hostname = self.hostname_cache.get(ip, "")
            row.rdap_owner = self.rdap_cache.get(ip, "")

            data = self.abuse_cache.get(ip, {})
            if data:
                if "_error" in data:
                    row.abuse_score = "ERRO"
                    row.notes = (row.notes + " " + str(data["_error"]))[:600]
                else:
                    row.abuse_score = str(data.get("abuseConfidenceScore", ""))
                    row.abuse_reports = str(data.get("totalReports", ""))
                    row.abuse_country = str(data.get("countryCode", ""))
                    isp = str(data.get("isp", "") or "")
                    domain = str(data.get("domain", "") or "")
                    usage = str(data.get("usageType", "") or "")
                    parts = [p for p in (isp, domain, usage) if p]
                    row.abuse_isp_domain = " | ".join(parts)
            elif classify_ip(ip) in ("LAN/PRIVADO", "LINK-LOCAL"):
                row.hostname = self.hostname_cache.get(ip, "")

            row.direction = infer_direction(row)
            row.notes = build_notes(row)
            row.risk = calculate_risk(row)

        self.root.after(0, self.refresh_table)
        self.set_status("Análise concluída.")

    def row_values(self, row: ConnectionRow) -> tuple:
        return (
            row.risk,
            row.proto,
            row.local_addr,
            row.remote_addr,
            row.state,
            row.pid,
            row.process,
            row.ip_type,
            row.direction,
            row.abuse_score,
            row.abuse_reports,
            row.abuse_country,
            row.rdap_owner,
            row.abuse_isp_domain,
            row.hostname,
            row.notes,
        )

    def refresh_table(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Ordena por risco mais importante primeiro
        rank = {"CRÍTICO": 0, "ALTO": 1, "MÉDIO": 2, "LAN": 3, "BAIXO": 4, "LOCAL": 5}
        rows = sorted(self.rows, key=lambda r: (rank.get(r.risk, 9), r.remote_ip, r.pid))

        for idx, row in enumerate(rows):
            tag = row.risk if row.risk in ("CRÍTICO", "ALTO", "MÉDIO", "LAN", "LOCAL", "BAIXO") else ""
            self.tree.insert("", END, iid=str(idx), values=self.row_values(row), tags=(tag,))

        # Mantém a ordem renderizada
        self.rows = rows

    def sort_by(self, col: str, descending: bool) -> None:
        children = list(self.tree.get_children(""))
        col_index = self.columns.index(col)

        def key_func(item: str):
            value = self.tree.set(item, col)
            try:
                return int(value)
            except Exception:
                return value.lower()

        children.sort(key=key_func, reverse=descending)
        for index, iid in enumerate(children):
            self.tree.move(iid, "", index)

        self.tree.heading(col, command=lambda c=col: self.sort_by(c, not descending))

    def on_select(self, _event=None) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        try:
            idx = int(selected[0])
            row = self.rows[idx]
        except Exception:
            return

        self.status_var.set(
            f"PID {row.pid} / {row.process or 'processo não identificado'} | "
            f"{row.local_addr} -> {row.remote_addr} | "
            f"Tipo: {row.ip_type} | Risco: {row.risk} | "
            f"Quem é: {row.rdap_owner or row.hostname or 'sem identificação'} | "
            f"Notas: {row.notes}"
        )

    def export_csv(self) -> None:
        if not self.rows:
            messagebox.showinfo("Exportar", "Não há dados para exportar.")
            return

        filename = filedialog.asksaveasfilename(
            title="Salvar relatório CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile=f"ip_guard_report_{time.strftime('%Y%m%d_%H%M%S')}.csv",
        )
        if not filename:
            return

        try:
            with open(filename, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=list(asdict(self.rows[0]).keys()))
                writer.writeheader()
                for row in self.rows:
                    writer.writerow(asdict(row))
            self.status_var.set(f"CSV salvo em: {filename}")
        except Exception as e:
            messagebox.showerror("Erro", f"Não consegui exportar: {e}")


def main() -> None:
    root = Tk()

    try:
        style = ttk.Style(root)
        # Usa tema nativo quando disponível.
        if "vista" in style.theme_names():
            style.theme_use("vista")
        elif "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass

    app = App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
