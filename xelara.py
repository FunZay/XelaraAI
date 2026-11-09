#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Combined Source Loader + Xray Checker (полная версия, точная).

Возможности:
  - загрузка подписок: plain / base64 / Clash YAML / Xray JSON / Happ-метод
  - blacklist источников (после 3 неудач подряд)
  - парсинг vless / vmess / trojan / hysteria2 (hy2)
  - проверка через xray: 3 независимых probe-URL (нужно --min-probes),
    IP выхода подтверждён 2 эхо-сервисами, иначе сервер не считается рабочим
  - скорость down / up (опционально), двойная проверка, выбрасывание мёртвых
  - страна входа (DNS-IP сервера) и выхода (IP выхода) по консенсусу геосервисов
  - каскад = страна входа != страна выхода (оба подтверждены)
  - стабильные ⚡ и новые 🟢, батчинг, кэш, blacklist серверов
  - режимы --only-new / --only-old, перепроверка файлов
  - готовые Xray-конфиги по странам (балансировщик, маршрутизация RU-доменов)
  - --interface: отправка через конкретный сетевой интерфейс (wifi / mobile)
  - --eu-fallback: вернуть старое поведение (неизвестную страну считать EU)

Ограничения:
  - страна входа берётся из DNS. Если хост за CDN, страна входа = страна CDN
  - точность геолокации = консенсус внешних геосервисов
  - hysteria2 obfs (salamander) не передаётся в xray-outbound
"""

import subprocess
import sys


def _bootstrap():
    req = {"requests": "requests>=2.28.0", "socks": "PySocks>=1.7.1",
           "psutil": "psutil>=5.9.0", "yaml": "PyYAML>=6.0"}
    miss = []
    for mod, pkg in req.items():
        try:
            __import__(mod)
        except ImportError:
            miss.append(pkg)
    if miss:
        print(f"[deps] устанавливаю: {', '.join(miss)}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install",
                                   "--disable-pip-version-check", *miss])
        except subprocess.CalledProcessError:
            sys.exit(1)


_bootstrap()

import argparse
import base64
import csv
import hashlib
import json
import os
import platform
import random
import re
import shutil
import socket
import stat
import statistics
import tempfile
import threading
import time
import zipfile
import subprocess as _sp
import urllib.parse as up
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Set, Tuple
from urllib.parse import parse_qs, quote, unquote, urlparse

import requests
import yaml
from requests.adapters import HTTPAdapter

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

# ============================================================================
# Константы
# ============================================================================
SOURCES_FILE = "sources.txt"
CONFIGS_FILE = "configs.txt"
MY_CONFIGS_FILE = "my_configs.txt"
BLACKLIST_FILE = "blacklist_sources.txt"
SOURCES_STATE_FILE = "sources_state.json"
DISCARD_FILE = "discarded.txt"
GEO_CACHE_FILE = "geo_cache.json"

THREADS = 50
TIMEOUT_NORMAL = 8
TIMEOUT_HAPP = 8
MAX_BATCH_SIZE = 10_000
MAX_CONCURRENCY = 256
BLACKLIST_FAIL_THRESHOLD = 3
SOURCE_FAIL_THRESHOLD = 3
TOP_FASTEST_COUNT = 150
CACHE_VERSION = 6
SERVER_TIMEOUT_DEFAULT = 8.0
SPEED_UP_BYTES = 500_000

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 combined/1.0")
HWID_STATIC = "d060e73eb61d1ba7"
HAPP_USER_AGENTS = ["Happ/3.18.3/Android/17771400994551771562"]

PROBE_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204",
]
ECHO_URLS = [
    ("https://api.ipify.org?format=json", "json"),
    ("https://ifconfig.me/ip", "text"),
    ("https://icanhazip.com", "text"),
    ("https://ipinfo.io/ip", "text"),
]
SPEED_DOWN_URLS = [
    "https://speed.cloudflare.com/__down?bytes=2000000",
    "https://speed.cloudflare.com/__down?bytes=1000000",
    "https://proof.ovh.net/files/1Mb.dat",
]
SPEED_UP_URLS = ["https://speed.cloudflare.com/__up", "https://httpbin.org/post"]

# (имя, шаблон, минимальный интервал между запросами, сек)
GEO_PROVIDERS = [
    ("ipwho.is", "https://ipwho.is/{ip}", 1.0),
    ("ipapi.co", "https://ipapi.co/{ip}/json/", 1.5),
    ("ip-api.com", "http://ip-api.com/json/{ip}?fields=status,countryCode", 1.5),
    ("ipinfo.io", "https://ipinfo.io/{ip}/country", 1.0),
]
GEO_TTL_OK = timedelta(days=30)
GEO_TTL_UNKNOWN = timedelta(hours=24)

STATUS_MARKERS = {"stable": "⚡", "new": "🟢", "regular": ""}
EU_FALLBACK = False  # задаётся из --eu-fallback

VLESS_REGEX = re.compile(r"vless://[^\s#]+", re.IGNORECASE)
TROJAN_REGEX = re.compile(r"trojan://[^\s#]+", re.IGNORECASE)
HY2_REGEX = re.compile(r"(?:hysteria2|hy2)://[^\s#]+", re.IGNORECASE)
VMESS_REGEX = re.compile(r"vmess://[^\s#]+", re.IGNORECASE)
URI_REGEX = re.compile(r"(?:vless|vmess|trojan|hysteria2|hy2)://[^\s\"'<>]+", re.IGNORECASE)
BASE64_REGEX = re.compile(r"^[A-Za-z0-9+/=_-]+$")
UUID_REGEX = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
IP_REGEX = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")

COUNTRY_RU = {
    "RU": "Россия", "DE": "Германия", "NL": "Нидерланды", "SE": "Швеция",
    "FR": "Франция", "GB": "Великобритания", "UK": "Великобритания",
    "IT": "Италия", "PL": "Польша", "LT": "Литва", "LV": "Латвия",
    "EE": "Эстония", "FI": "Финляндия", "NO": "Норвегия", "DK": "Дания",
    "CH": "Швейцария", "AT": "Австрия", "BE": "Бельгия", "CZ": "Чехия",
    "SK": "Словакия", "HU": "Венгрия", "RO": "Румыния", "BG": "Болгария",
    "GR": "Греция", "PT": "Португалия", "ES": "Испания", "IE": "Ирландия",
    "IS": "Исландия", "HR": "Хорватия", "SI": "Словения", "RS": "Сербия",
    "UA": "Украина", "BY": "Беларусь", "MD": "Молдова", "TR": "Турция",
    "US": "США", "CA": "Канада", "MX": "Мексика", "BR": "Бразилия",
    "AR": "Аргентина", "CL": "Чили", "CO": "Колумбия", "PE": "Перу",
    "JP": "Япония", "KR": "Южная Корея", "CN": "Китай", "HK": "Гонконг",
    "TW": "Тайвань", "SG": "Сингапур", "MY": "Малайзия", "TH": "Таиланд",
    "VN": "Вьетнам", "ID": "Индонезия", "PH": "Филиппины", "IN": "Индия",
    "PK": "Пакистан", "BD": "Бангладеш", "IR": "Иран", "IL": "Израиль",
    "AE": "ОАЭ", "SA": "Саудовская Аравия", "QA": "Катар", "KW": "Кувейт",
    "EG": "Египет", "ZA": "ЮАР", "NG": "Нигерия", "KE": "Кения",
    "MA": "Марокко", "TN": "Тунис", "DZ": "Алжир",
    "AU": "Австралия", "NZ": "Новая Зеландия",
    "KZ": "Казахстан", "UZ": "Узбекистан", "KG": "Киргизия",
    "AM": "Армения", "GE": "Грузия", "AZ": "Азербайджан",
    "MN": "Монголия", "NP": "Непал", "LK": "Шри-Ланка",
    "CY": "Кипр", "MT": "Мальта", "LU": "Люксембург",
    "AL": "Албания", "MK": "Северная Македония", "BA": "Босния и Герцеговина",
    "ME": "Черногория", "XK": "Косово",
}

DOMAINS_DIRECT = [
    "vk.com", "yandex.ru", "mail.ru", "ok.ru", "gosuslugi.ru", "kremlin.ru",
    "ozon.ru", "wildberries.ru", "vseinstrumenti.ru", "max.ru", "dzen.ru",
    "rutube.ru", "avito.ru", "2gis.ru", "kinopoisk.ru", "sberbank.ru",
    "tbank.ru", "rzd.ru", "nalog.ru", "mchs.gov.ru", "minzdrav.gov.ru",
    "edu.gov.ru", "mos.ru", "spb.ru",
]


# ============================================================================
# Утилиты
# ============================================================================
def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_json(path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json(path, data):
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")


def _write_lines(path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _b64decode(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _safe_int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def safe_quote(s):
    return up.quote(str(s), safe="")


def build_query(params):
    parts = []
    for k, v in params.items():
        if v is None or v == "":
            continue
        if isinstance(v, bool):
            v = "true" if v else "false"
        parts.append(f"{k}={safe_quote(v)}")
    return "&".join(parts)


def flag_of(cc):
    if cc == "EU":
        return "🇪🇺"
    if cc and len(cc) == 2 and cc.isalpha():
        return "".join(chr(0x1F1E6 + ord(c.upper()) - 65) for c in cc)
    return "❓"


def group_name(cc):
    if cc == "EU":
        return "EU"
    if not cc or cc == "UNKNOWN":
        return "Неизвестно"
    return COUNTRY_RU.get(cc, cc)


def item_cc(item):
    cc = (item or {}).get("country_code") or ""
    if cc:
        return cc
    return "EU" if EU_FALLBACK else "UNKNOWN"


def marker_for(cluster, stable_cfg=None, new_cfg=None):
    if cluster == "stable":
        return (stable_cfg or {}).get("marker", STATUS_MARKERS["stable"])
    if cluster == "new":
        return (new_cfg or {}).get("marker", STATUS_MARKERS["new"])
    return ""


def _extra_hash(ex):
    if not ex:
        return ""
    try:
        return hashlib.md5(json.dumps(ex, ensure_ascii=False, sort_keys=True).encode()).hexdigest()[:10]
    except Exception:
        return ""


class RateLimiter:
    def __init__(self, interval):
        self.interval = interval
        self.lock = threading.Lock()
        self.last = 0.0

    def wait(self):
        with self.lock:
            delay = self.last + self.interval - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self.last = time.monotonic()


# ============================================================================
# Конвертеры JSON / YAML -> URI
# ============================================================================
def outbound_to_vless_url(out):
    settings = out.get("settings", {})
    vnext = settings.get("vnext", [])
    if not vnext:
        return None
    first = vnext[0]
    address, port = first.get("address"), first.get("port")
    users = first.get("users", [])
    if not users:
        return None
    user = users[0]
    uuid = user.get("id")
    if not uuid:
        return None
    stream = out.get("streamSettings", {})
    network = stream.get("network", "tcp")
    security = stream.get("security", "")
    reality = stream.get("realitySettings", {})
    tls = stream.get("tlsSettings", {})
    ws = stream.get("wsSettings", {})
    grpc = stream.get("grpcSettings", {})
    params = {"encryption": user.get("encryption", "none"), "type": network}
    if user.get("flow"):
        params["flow"] = user["flow"]
    if security == "reality":
        params["security"] = "reality"
        if "serverName" in reality: params["sni"] = reality["serverName"]
        if "publicKey" in reality: params["pbk"] = reality["publicKey"]
        if "shortId" in reality: params["sid"] = reality["shortId"]
        if "fingerprint" in reality: params["fp"] = reality["fingerprint"]
    elif security == "tls":
        params["security"] = "tls"
        if "serverName" in tls: params["sni"] = tls["serverName"]
        if "fingerprint" in tls: params["fp"] = tls["fingerprint"]
        if "alpn" in tls: params["alpn"] = ",".join(tls["alpn"])
    if network == "ws" and ws:
        if "path" in ws: params["path"] = ws["path"]
        if "headers" in ws and "Host" in ws["headers"]: params["host"] = ws["headers"]["Host"]
    elif network == "grpc" and grpc:
        if "serviceName" in grpc: params["serviceName"] = grpc["serviceName"]
    remark = f"#{safe_quote(out.get('tag', ''))}" if out.get("tag") else ""
    return f"vless://{uuid}@{address}:{port}?{build_query(params)}{remark}"


def outbound_to_trojan_url(out):
    servers = out.get("settings", {}).get("servers", [])
    if not servers:
        return None
    s = servers[0]
    address, port, password = s.get("address"), s.get("port"), s.get("password")
    if not all([address, port, password]):
        return None
    stream = out.get("streamSettings", {})
    tls = stream.get("tlsSettings", {})
    params = {}
    if stream.get("security", "tls") == "tls":
        params["security"] = "tls"
        if "serverName" in tls: params["sni"] = tls["serverName"]
        if "fingerprint" in tls: params["fp"] = tls["fingerprint"]
    remark = f"#{safe_quote(out.get('tag', ''))}" if out.get("tag") else ""
    q = build_query(params)
    return f"trojan://{password}@{address}:{port}" + (f"?{q}" if q else "") + remark


def outbound_to_hysteria2_url(out):
    servers = out.get("settings", {}).get("servers", [])
    if not servers and out.get("settings", {}).get("address"):
        s = out["settings"]
    elif servers:
        s = servers[0]
    else:
        return None
    address, port = s.get("address"), s.get("port")
    auth = s.get("auth", "") or s.get("password", "")
    if not address or not port:
        return None
    tls = out.get("streamSettings", {}).get("tlsSettings", {})
    params = {}
    if "serverName" in tls: params["sni"] = tls["serverName"]
    if tls.get("allowInsecure"): params["insecure"] = "1"
    remark = f"#{safe_quote(out.get('tag', ''))}" if out.get("tag") else ""
    auth_part = f"{auth}@" if auth else ""
    return f"hy2://{auth_part}{address}:{port}?{build_query(params)}{remark}"


def convert_json_to_urls(content):
    urls = []
    try:
        decoder = json.JSONDecoder()
        idx, content = 0, content.strip()
        while idx < len(content):
            try:
                obj, end = decoder.raw_decode(content, idx)
            except json.JSONDecodeError:
                break
            idx = end
            while idx < len(content) and content[idx] in " \t\r\n":
                idx += 1
            outbounds = None
            if isinstance(obj, dict):
                outbounds = obj.get("outbounds")
                if outbounds is None and isinstance(obj.get("config"), dict):
                    outbounds = obj["config"].get("outbounds")
            elif isinstance(obj, list):
                outbounds = obj
            if not isinstance(outbounds, list):
                continue
            for out in outbounds:
                if not isinstance(out, dict):
                    continue
                proto = out.get("protocol", "")
                url = None
                if proto == "vless": url = outbound_to_vless_url(out)
                elif proto == "trojan": url = outbound_to_trojan_url(out)
                elif proto in ("hysteria2", "hy2", "hysteria"): url = outbound_to_hysteria2_url(out)
                if url and is_valid_config(url):
                    urls.append(url)
    except Exception:
        pass
    return urls


def yaml_proxy_to_url(px):
    t = px.get("type")
    name = px.get("name", "")
    server, port = px.get("server"), px.get("port")
    if not server or not port:
        return None
    remark = f"#{safe_quote(name)}" if name else ""
    sni = px.get("servername") or px.get("sni") or ""
    if t == "vless" and px.get("uuid"):
        params = {"encryption": "none", "type": px.get("network", "tcp")}
        if px.get("flow"): params["flow"] = px["flow"]
        ro = px.get("reality-opts") or {}
        if ro:
            params["security"] = "reality"
            if ro.get("public-key"): params["pbk"] = ro["public-key"]
            if ro.get("short-id"): params["sid"] = ro["short-id"]
        elif px.get("tls"):
            params["security"] = "tls"
        if sni: params["sni"] = sni
        if px.get("client-fingerprint"): params["fp"] = px["client-fingerprint"]
        if params.get("security") == "reality" and "alpn" not in params:
            params["alpn"] = "http/1.1"
        return f"vless://{px['uuid']}@{server}:{port}?{build_query(params)}{remark}"
    if t == "trojan" and px.get("password"):
        params = {"security": "tls"}
        if sni: params["sni"] = sni
        return f"trojan://{px['password']}@{server}:{port}?{build_query(params)}{remark}"
    if t in ("hysteria2", "hy2") and px.get("password"):
        params = {}
        if sni: params["sni"] = sni
        if px.get("skip-cert-verify"): params["insecure"] = "1"
        return f"hy2://{px['password']}@{server}:{port}?{build_query(params)}{remark}"
    return None


def convert_yaml_to_urls(content):
    urls = []
    try:
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            return []
        proxies = data.get("proxies", [])
        if not isinstance(proxies, list):
            return []
        for px in proxies:
            if not isinstance(px, dict):
                continue
            url = yaml_proxy_to_url(px)
            if url and is_valid_config(url):
                urls.append(url)
    except Exception:
        pass
    return urls


def is_valid_config(url):
    url = url.strip()
    if url.startswith("vless://"):
        return "@" in url and bool(UUID_REGEX.search(url))
    if url.startswith("trojan://") or url.startswith(("hysteria2://", "hy2://")):
        return "@" in url
    if url.startswith("vmess://"):
        return True
    return False


def extract_uris(text):
    """Все URI из текста: plain, base64, JSON (Xray), YAML (Clash)."""
    if not text:
        return []
    found = URI_REGEX.findall(text)
    stripped = "".join(text.split())
    if not found and len(stripped) >= 16 and BASE64_REGEX.match(stripped):
        dec = _b64decode(stripped)
        if dec:
            found = URI_REGEX.findall(dec)
    t = text.strip()
    if t.startswith(("{", "[")):
        found.extend(convert_json_to_urls(t))
    if "proxies:" in text:
        found.extend(convert_yaml_to_urls(text))
    return [u for u in found if is_valid_config(u) or u.lower().startswith("vmess://")]


# ============================================================================
# Загрузка источников (plain + Happ)
# ============================================================================
def fetch_with_happ_method(url):
    if up.urlparse(url).scheme not in ("http", "https"):
        return None
    sep = "&" if "?" in url else "?"
    url_h = url if "hwid=" in url else f"{url}{sep}hwid={HWID_STATIC}"
    for try_url in (url_h, url):
        for ua in HAPP_USER_AGENTS:
            try:
                headers = {"User-Agent": ua, "X-HWID": HWID_STATIC, "Accept": "*/*",
                           "Accept-Encoding": "gzip, deflate", "Connection": "keep-alive"}
                resp = requests.get(try_url, headers=headers, timeout=TIMEOUT_HAPP)
                resp.raise_for_status()
                content = resp.text.strip()
                if "<html" in content.lower():
                    continue
                if BASE64_REGEX.match(content.replace("\n", "").replace("\r", "")):
                    dec = _b64decode(content)
                    if dec:
                        content = dec
                return content
            except Exception:
                continue
    return None


def fetch_source(url):
    try:
        r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT_NORMAL)
        if r.status_code == 200 and len(r.text) >= 50 and "<html" not in r.text[:500].lower():
            return r.text
    except requests.RequestException:
        pass
    return fetch_with_happ_method(url)


def load_sources():
    """Возвращает (uris_из_источников, uris_из_my_configs, stats)."""
    print("\n" + "=" * 60)
    print("Скачивание конфигураций из источников")
    print("=" * 60)
    src = Path(SOURCES_FILE)
    if not src.exists():
        print(f"Файл {SOURCES_FILE} не найден.")
        return [], [], {}
    urls = [l.strip() for l in src.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.strip().startswith("#")]
    if not urls:
        print("Нет источников в sources.txt")
        return [], [], {}
    print(f"Источников: {len(urls)}")

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        texts = dict(zip(urls, ex.map(fetch_source, urls)))

    state = load_json(SOURCES_STATE_FILE, {})
    all_uris, alive, stats = [], [], {"ok": 0, "fail": 0, "blacklisted": 0, "uris": 0}
    for i, u in enumerate(urls, 1):
        uris = extract_uris(texts.get(u) or "")
        if uris:
            all_uris.extend(uris)
            state.pop(u, None)
            alive.append(u)
            stats["ok"] += 1
            print(f"  [{i}/{len(urls)}] ok    {len(uris):6}  {u[:80]}")
        else:
            n = state.get(u, 0) + 1
            state[u] = n
            stats["fail"] += 1
            if n < SOURCE_FAIL_THRESHOLD:
                alive.append(u)
                print(f"  [{i}/{len(urls)}] fail {n}/{SOURCE_FAIL_THRESHOLD}  {u[:80]}")
            else:
                stats["blacklisted"] += 1
                state.pop(u, None)
                with open(BLACKLIST_FILE, "a", encoding="utf-8") as f:
                    f.write(u + "\n")
                print(f"  [{i}/{len(urls)}] BLACKLIST      {u[:80]}")
    stats["uris"] = len(all_uris)

    src.write_text("\n".join(alive) + ("\n" if alive else ""), encoding="utf-8")
    save_json(SOURCES_STATE_FILE, state)

    my_uris = []
    if Path(MY_CONFIGS_FILE).exists():
        my_uris = extract_uris(Path(MY_CONFIGS_FILE).read_text(encoding="utf-8", errors="replace"))
        print(f"  Мои конфиги: {len(my_uris)}")

    print(f"\nИтог: ok={stats['ok']} fail={stats['fail']} blacklist={stats['blacklisted']} "
          f"ссылок={stats['uris']}")
    return all_uris, my_uris, stats


# ============================================================================
# Proxy и парсер URI
# ============================================================================
@dataclass
class Proxy:
    raw: str = ""
    kind: str = ""
    params: dict = field(default_factory=dict)
    name: str = ""

    def dedup_key(self):
        p = self.params
        parts = [self.kind, str(p.get("server", "")).strip().lower(), str(p.get("port", "")),
                 str(p.get("uuid", "") or p.get("password", "")),
                 str(p.get("sni", "")).strip().lower(), str(p.get("host", "")).strip().lower(),
                 str(p.get("path", "")), str(p.get("network", "")), str(p.get("security", ""))]
        if self.kind == "vmess":
            parts.append(str(p.get("alterId", "")))
        eh = _extra_hash(p.get("extra"))
        if eh:
            parts.append(eh)
        return "|".join(parts)


def _p_vmess(uri):
    d = _b64decode(uri[len("vmess://"):].strip())
    if not d:
        return None
    try:
        cfg = json.loads(d)
    except Exception:
        return None
    tls_on = (cfg.get("tls", "") or "").lower() in ("tls", "reality")
    return Proxy(raw=uri, kind="vmess", name=cfg.get("ps", ""), params={
        "server": cfg.get("add", ""), "port": _safe_int(cfg.get("port"), 443),
        "uuid": cfg.get("id", ""), "alterId": _safe_int(cfg.get("aid"), 0),
        "cipher": cfg.get("scy", "auto") or "auto",
        "network": cfg.get("net", "tcp") or "tcp",
        "host": cfg.get("host", ""), "path": cfg.get("path", ""),
        "tls": tls_on, "sni": cfg.get("sni", "") or cfg.get("host", ""),
        "fp": cfg.get("fp", ""), "alpn": cfg.get("alpn", ""),
        "security": "tls" if tls_on else "none", "extra": {},
    })


def _p_vless(uri):
    u = urlparse(uri)
    if not u.hostname:
        return None
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    extra = {}
    if q.get("extra"):
        try:
            extra = json.loads(unquote(q["extra"]))
        except Exception:
            extra = {}
    return Proxy(raw=uri, kind="vless", name=unquote(u.fragment) if u.fragment else "", params={
        "server": u.hostname, "port": _safe_int(u.port, 443),
        "uuid": unquote(u.username or ""), "flow": q.get("flow", ""),
        "network": q.get("type", "tcp") or "tcp",
        "security": q.get("security", "none") or "none",
        "sni": q.get("sni", ""), "fp": q.get("fp", ""),
        "pbk": q.get("pbk", ""), "sid": q.get("sid", ""), "spx": q.get("spx", ""),
        "path": q.get("path", ""), "host": q.get("host", ""),
        "serviceName": q.get("serviceName", ""), "alpn": q.get("alpn", ""),
        "extra": extra,
    })


def _p_trojan(uri):
    u = urlparse(uri)
    if not u.hostname:
        return None
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    return Proxy(raw=uri, kind="trojan", name=unquote(u.fragment) if u.fragment else "", params={
        "server": u.hostname, "port": _safe_int(u.port, 443),
        "password": unquote(u.username or ""),
        "network": q.get("type", "tcp") or "tcp",
        "security": q.get("security", "tls") or "tls",
        "sni": q.get("sni", ""), "fp": q.get("fp", ""),
        "path": q.get("path", ""), "host": q.get("host", ""),
        "serviceName": q.get("serviceName", ""), "alpn": q.get("alpn", ""),
    })


def _p_hy2(uri):
    u = urlparse(uri)
    if not u.hostname:
        return None
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    return Proxy(raw=uri, kind="hysteria2", name=unquote(u.fragment) if u.fragment else "", params={
        "server": u.hostname, "port": _safe_int(u.port, 443),
        "password": unquote(u.username or ""),
        "sni": q.get("sni", ""), "insecure": q.get("insecure", "0") in ("1", "true"),
        "obfs": q.get("obfs", ""), "obfs-password": q.get("obfs-password", ""),
    })


def parse_uri(uri):
    uri = uri.strip()
    try:
        if uri.startswith("vmess://"): return _p_vmess(uri)
        if uri.startswith("vless://"): return _p_vless(uri)
        if uri.startswith("trojan://"): return _p_trojan(uri)
        if uri.startswith(("hysteria2://", "hy2://")): return _p_hy2(uri)
    except Exception:
        return None
    return None


def parse_all(uris):
    unique, bad = {}, 0
    for u in uris:
        pr = parse_uri(u)
        if not pr or not pr.params.get("server") or not pr.params.get("port"):
            bad += 1
            continue
        if not (pr.params.get("uuid") or pr.params.get("password")):
            bad += 1
            continue
        unique.setdefault(pr.dedup_key(), pr)
    return unique, bad


def _collect_proxies_from_uris(uris):
    out = []
    for u in uris:
        pr = parse_uri(u)
        if pr and pr.params.get("server"):
            out.append(pr)
    return out


def _dedup(proxies):
    seen, out = set(), []
    for p in proxies:
        if not p or not p.params.get("server"):
            continue
        k = p.dedup_key()
        if k in seen:
            continue
        seen.add(k)
        out.append(p)
    return out


def _load_recheck_files(paths):
    result = []
    for path_str in paths:
        path_str = path_str.strip()
        if not path_str:
            continue
        p = Path(path_str)
        if not p.exists():
            print(f"[i] recheck: {path_str} — не найден")
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"[!] recheck: {path_str}: {e}")
            continue
        parsed = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pr = parse_uri(line)
            if pr and pr.params.get("server"):
                parsed.append(pr)
            else:
                for u in URI_REGEX.findall(line):
                    pr2 = parse_uri(u)
                    if pr2 and pr2.params.get("server"):
                        parsed.append(pr2)
        print(f"[i] recheck: {path_str} → {len(parsed)} серверов")
        result.extend(parsed)
    return _dedup(result)


# ============================================================================
# Xray: outbound, порты, запуск
# ============================================================================
def _stream(pr):
    p = pr.params
    net = (p.get("network") or "tcp").lower()
    sec = (p.get("security") or "none").lower()
    st = {"network": net}
    if net == "ws":
        ws = {"path": p.get("path") or "/"}
        if p.get("host"):
            ws["headers"] = {"Host": p["host"]}
        st["wsSettings"] = ws
    elif net == "grpc":
        st["grpcSettings"] = {"serviceName": p.get("serviceName") or p.get("path") or "",
                              "multiMode": False}
    elif net == "xhttp":
        xh = {"path": p.get("path") or "/"}
        if p.get("host"):
            xh["host"] = p["host"]
        st["xhttpSettings"] = xh
    if sec == "tls":
        tls = {"serverName": p.get("sni") or p.get("host") or p["server"],
               "allowInsecure": bool(p.get("insecure", False))}
        if p.get("fp"):
            tls["fingerprint"] = p["fp"]
        if p.get("alpn"):
            tls["alpn"] = p["alpn"].split(",") if isinstance(p["alpn"], str) else p["alpn"]
        st["security"] = "tls"
        st["tlsSettings"] = tls
    elif sec == "reality":
        st["security"] = "reality"
        st["realitySettings"] = {
            "serverName": p.get("sni") or p["server"],
            "fingerprint": p.get("fp") or "chrome",
            "publicKey": p.get("pbk") or "",
            "shortId": p.get("sid") or "",
            "spiderX": p.get("spx") or "/",
        }
    else:
        st["security"] = "none"
    return st


def _outbound(pr):
    p = pr.params
    if pr.kind == "vless":
        user = {"id": p["uuid"], "encryption": "none"}
        if p.get("flow"):
            user["flow"] = p["flow"]
        return {"protocol": "vless",
                "settings": {"vnext": [{"address": p["server"], "port": p["port"], "users": [user]}]},
                "streamSettings": _stream(pr)}
    if pr.kind == "vmess":
        user = {"id": p["uuid"], "alterId": p.get("alterId", 0), "security": p.get("cipher") or "auto"}
        return {"protocol": "vmess",
                "settings": {"vnext": [{"address": p["server"], "port": p["port"], "users": [user]}]},
                "streamSettings": _stream(pr)}
    if pr.kind == "trojan":
        return {"protocol": "trojan",
                "settings": {"servers": [{"address": p["server"], "port": p["port"],
                                          "password": p["password"]}]},
                "streamSettings": _stream(pr)}
    if pr.kind == "hysteria2":
        return {"protocol": "hysteria",
                "settings": {"version": 2, "address": p["server"], "port": p["port"]},
                "streamSettings": {
                    "network": "hysteria", "security": "tls",
                    "tlsSettings": {"serverName": p.get("sni") or p["server"],
                                    "allowInsecure": bool(p.get("insecure")), "alpn": ["h3"]},
                    "hysteriaSettings": {"version": 2, "auth": p.get("password", "")}}}
    raise ValueError(f"unsupported kind {pr.kind}")


_PORT_POOL = set()
_PORT_LOCK = threading.Lock()


def _free_port():
    for _ in range(300):
        p = random.randint(20000, 59000)
        with _PORT_LOCK:
            if p in _PORT_POOL:
                continue
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", p))
        except OSError:
            continue
        finally:
            s.close()
        with _PORT_LOCK:
            _PORT_POOL.add(p)
        return p
    raise RuntimeError("не найден свободный порт")


def _release_port(port):
    with _PORT_LOCK:
        _PORT_POOL.discard(port)


def _wait_port(port, proc, timeout=6.0):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _get_iface_ip(iface_name):
    try:
        import psutil
        for addr in psutil.net_if_addrs().get(iface_name, []):
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                return addr.address
    except Exception:
        pass
    return None


class XrayManager:
    def __init__(self, xray_dir):
        self.dir = Path(xray_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.exe = self.dir / ("xray.exe" if platform.system() == "Windows" else "xray")

    def ensure(self):
        if self.exe.exists():
            return
        system = platform.system()
        m = platform.machine().lower()
        if system == "Windows":
            zip_name = "Xray-windows-64.zip"
        elif system == "Darwin":
            zip_name = "Xray-macos-arm64-v8a.zip" if "arm" in m else "Xray-macos-64.zip"
        elif "aarch64" in m or "arm64" in m:
            zip_name = "Xray-linux-arm64-v8a.zip"
        elif "arm" in m:
            zip_name = "Xray-linux-arm32-v7a.zip"
        else:
            zip_name = "Xray-linux-64.zip"
        url = f"https://github.com/XTLS/Xray-core/releases/latest/download/{zip_name}"
        print(f"[i] скачиваю Xray Core: {zip_name}")
        r = requests.get(url, timeout=120)
        r.raise_for_status()
        zp = self.dir / "xray.zip"
        zp.write_bytes(r.content)
        with zipfile.ZipFile(zp) as z:
            with z.open(self.exe.name) as src, open(self.exe, "wb") as dst:
                dst.write(src.read())
        zp.unlink()
        if system != "Windows":
            self.exe.chmod(self.exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        print("[i] Xray Core готов.")

    def run(self, cfg_path):
        return _sp.Popen([str(self.exe), "run", "-c", str(cfg_path)],
                         stdout=_sp.DEVNULL, stderr=_sp.PIPE, start_new_session=True)


# ============================================================================
# Скорость
# ============================================================================
def _measure_download_speed(session, timeout):
    for url in SPEED_DOWN_URLS:
        t0 = time.perf_counter()
        total = 0
        try:
            with session.get(url, timeout=timeout, stream=True,
                             headers={"Accept-Encoding": "identity"}) as r:
                if r.status_code != 200:
                    continue
                for chunk in r.iter_content(65536):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if time.perf_counter() - t0 > timeout:
                        break
        except Exception:
            continue
        dt = time.perf_counter() - t0
        if total >= 10_000 and dt > 0.05:
            return round(total * 8 / (dt * 1_000_000), 2)
    return None


def _measure_upload_speed(session, timeout):
    payload = os.urandom(SPEED_UP_BYTES)
    for url in SPEED_UP_URLS:
        t0 = time.perf_counter()
        try:
            r = session.post(url, data=payload, timeout=timeout)
            dt = time.perf_counter() - t0
            if r.status_code in (200, 201, 204) and dt > 0.05:
                return round(SPEED_UP_BYTES * 8 / (dt * 1_000_000), 2)
        except Exception:
            continue
    return None


# ============================================================================
# Проверка одного сервера
# ============================================================================
def _resolve_ipv4(host):
    try:
        socket.inet_pton(socket.AF_INET, host)
        return host
    except OSError:
        pass
    if ":" in host:
        return ""
    return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]


def _echo_exit_ip(session, timeout):
    votes = Counter()
    for url, kind in ECHO_URLS:
        try:
            r = session.get(url, timeout=timeout)
            if r.status_code != 200:
                continue
            ip = r.json().get("ip", "") if kind == "json" else r.text.strip()
            if ip and IP_REGEX.fullmatch(ip):
                votes[ip] += 1
                if votes[ip] >= 2:
                    return ip
        except Exception:
            continue
    return ""


def check_proxy(pr, xray, timeout=8.0, send_through=None, server_timeout=None,
                speed_test=False, speed_timeout=5.0, min_down=0.05, min_up=0.02,
                require_upload=False, min_probes=2):
    budget = server_timeout if server_timeout is not None else SERVER_TIMEOUT_DEFAULT
    t_start = time.time()

    def remaining():
        return max(0.0, budget - (time.time() - t_start))

    def fail(msg, **extra):
        out = {"ok": False, "latency": None, "download_mbps": None, "upload_mbps": None,
               "exit_ip": "", "inbound_ip": "", "probes_ok": 0, "test_url": None,
               "error": msg, "elapsed": round(time.time() - t_start, 2)}
        out.update(extra)
        return out

    inbound_ip = ""
    try:
        inbound_ip = _resolve_ipv4(pr.params.get("server", ""))
    except Exception:
        return fail("dns: не резолвится")

    port = _free_port()
    ob = _outbound(pr)
    if send_through:
        ob.setdefault("streamSettings", {}).setdefault("sockopt", {})["sendThrough"] = send_through
    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [ob],
    }
    fd, cfg_path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False)
    proc = None
    try:
        proc = xray.run(cfg_path)
        wait_budget = min(remaining(), 5.0)
        if wait_budget <= 0 or not _wait_port(port, proc, wait_budget):
            msg = "xray не поднял socks-порт"
            try:
                proc.terminate()
                _, e = proc.communicate(timeout=1)
                if e:
                    lines = e.decode("utf-8", "replace").strip().splitlines()
                    if lines:
                        msg = " | ".join(lines[-2:])[:180]
            except Exception:
                pass
            return fail(msg, inbound_ip=inbound_ip)

        session = requests.Session()
        session.proxies = {"http": f"socks5h://127.0.0.1:{port}",
                           "https": f"socks5h://127.0.0.1:{port}"}
        session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
        session.mount("http://", HTTPAdapter(max_retries=0))
        session.mount("https://", HTTPAdapter(max_retries=0))

        lats, working_url, last_err = [], None, "нет ответа"
        for url in PROBE_URLS:
            req_budget = min(remaining(), timeout)
            if req_budget <= 0.3:
                last_err = "бюджет исчерпан"
                break
            try:
                t0 = time.perf_counter()
                r = session.get(url, timeout=req_budget, allow_redirects=False)
                dt = int((time.perf_counter() - t0) * 1000)
                if r.status_code in (200, 204):
                    lats.append(dt)
                    working_url = working_url or url
                else:
                    last_err = f"HTTP {r.status_code}"
            except requests.exceptions.RequestException as e:
                last_err = str(e)[:60]

        if len(lats) < min_probes:
            return fail(f"probes {len(lats)}/{len(PROBE_URLS)}: {last_err}",
                        inbound_ip=inbound_ip, probes_ok=len(lats))

        latency = int(statistics.median(lats))
        exit_ip = _echo_exit_ip(session, min(remaining(), timeout)) if remaining() > 0.5 else ""
        if not exit_ip:
            return fail("IP выхода не подтверждён (2 эхо-сервиса)",
                        inbound_ip=inbound_ip, probes_ok=len(lats), latency=latency,
                        test_url=working_url)

        down = up_mbps = None
        if speed_test:
            down = _measure_download_speed(session, speed_timeout)
            if require_upload:
                up_mbps = _measure_upload_speed(session, speed_timeout)
            speed_ok = down is not None and down >= min_down
            if require_upload:
                speed_ok = speed_ok and up_mbps is not None and up_mbps >= min_up
            if not speed_ok:
                return fail(f"dead/too slow: ↓{down} ↑{up_mbps} Mbps (min ↓{min_down} ↑{min_up})",
                            inbound_ip=inbound_ip, exit_ip=exit_ip, latency=latency,
                            download_mbps=down, upload_mbps=up_mbps,
                            probes_ok=len(lats), test_url=working_url)

        return {"ok": True, "latency": latency, "download_mbps": down, "upload_mbps": up_mbps,
                "exit_ip": exit_ip, "inbound_ip": inbound_ip, "probes_ok": len(lats),
                "test_url": working_url, "error": None,
                "elapsed": round(time.time() - t_start, 2)}
    except Exception as e:
        return fail(f"{type(e).__name__}: {str(e)[:100]}", inbound_ip=inbound_ip)
    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        try:
            os.unlink(cfg_path)
        except OSError:
            pass
        _release_port(port)


# ============================================================================
# Кэш состояния
# ============================================================================
class Cache:
    def __init__(self, path):
        self.path = Path(path)
        self.items = {}
        data = load_json(self.path, {})
        if isinstance(data, dict) and data.get("version") == CACHE_VERSION:
            self.items = data.get("items", {})

    def save(self):
        save_json(self.path, {"version": CACHE_VERSION, "items": self.items})

    def upsert(self, pr, result, sub_index):
        key = pr.dedup_key()
        now = now_iso()
        if key not in self.items:
            self.items[key] = {"raw": pr.raw, "kind": pr.kind, "params": pr.params,
                               "name": pr.name, "status": "unknown", "first_seen": now,
                               "check_count": 0, "fail_count": 0, "consecutive_fails": 0,
                               "consecutive_successes": 0, "sub_index": sub_index,
                               "history": ""}
        it = self.items[key]
        it["raw"], it["name"] = pr.raw, pr.name
        it["last_checked"] = now
        it["check_count"] += 1
        it["sub_index"] = sub_index
        it["history"] = (it.get("history", "") + ("1" if result["ok"] else "0"))[-30:]
        if result["ok"]:
            it["status"] = "working"
            it["consecutive_fails"] = 0
            it["consecutive_successes"] += 1
            it["fail_count"] = 0
            it["error"] = ""
            for k in ("latency", "download_mbps", "upload_mbps", "exit_ip", "inbound_ip",
                      "test_url", "elapsed", "probes_ok", "country_code", "country",
                      "is_cascade", "cascade_msg"):
                if k in result and result[k] is not None:
                    it[k] = result[k]
        else:
            it["status"] = "unworking"
            it["consecutive_successes"] = 0
            it["consecutive_fails"] += 1
            it["fail_count"] += 1
            it["error"] = result.get("error", "")[:150]
            if result.get("inbound_ip"):
                it["inbound_ip"] = result["inbound_ip"]

    def to_proxy(self, it):
        return Proxy(raw=it.get("raw", ""), kind=it.get("kind", ""),
                     params=it.get("params", {}), name=it.get("name", ""))

    def classify(self, it, stable_cfg, new_cfg):
        if new_cfg and new_cfg.get("enabled", True):
            try:
                first = datetime.fromisoformat(it.get("first_seen", "").replace("Z", "+00:00"))
                if datetime.now(timezone.utc) - first < timedelta(hours=new_cfg["recent_hours"]):
                    return "new"
            except Exception:
                pass
        if stable_cfg and stable_cfg.get("enabled", True):
            if stability_ok(it, stable_cfg):
                return "stable"
        return "regular"

    def working_all(self):
        return [self.to_proxy(v) for v in self.items.values() if v.get("status") == "working"]

    def working_by_first_sub(self):
        res = defaultdict(list)
        for v in self.items.values():
            if v.get("status") == "working":
                res[v.get("sub_index", 0)].append(self.to_proxy(v))
        return res

    def stable_all(self, stable_cfg):
        return [self.to_proxy(v) for v in self.items.values()
                if v.get("status") == "working" and stability_ok(v, stable_cfg)]

    def new_all(self, recent_hours):
        out = []
        now = datetime.now(timezone.utc)
        for v in self.items.values():
            if v.get("status") != "working":
                continue
            try:
                first = datetime.fromisoformat(v.get("first_seen", "").replace("Z", "+00:00"))
                if now - first <= timedelta(hours=recent_hours):
                    out.append(self.to_proxy(v))
            except Exception:
                continue
        return out

    def unworking_all(self):
        return [self.to_proxy(v) for v in self.items.values() if v.get("status") == "unworking"]

    def blacklisted_keys(self):
        return {k for k, v in self.items.items() if v.get("fail_count", 0) >= BLACKLIST_FAIL_THRESHOLD}

    def blacklisted_items(self):
        return [v for v in self.items.values() if v.get("fail_count", 0) >= BLACKLIST_FAIL_THRESHOLD]

    def is_blacklisted(self, it):
        return it.get("fail_count", 0) >= BLACKLIST_FAIL_THRESHOLD


def stability_ok(it, stable_cfg):
    hist = it.get("history", "")
    recent = hist[-10:]
    if len(recent) < stable_cfg["min_checks"]:
        return False
    rate = recent.count("1") / len(recent)
    last_n = stable_cfg["min_consecutive"]
    return rate >= stable_cfg["min_rate"] and len(hist) >= last_n and hist[-last_n:] == "1" * last_n


def decide_cascade(inbound_ip, exit_ip, in_cc, out_cc):
    if inbound_ip and exit_ip and inbound_ip == exit_ip:
        return False
    if in_cc and out_cc:
        return in_cc != out_cc
    return None


# ============================================================================
# Геолокация: только консенсус геосервисов
# ============================================================================
def _parse_geo(name, r):
    try:
        if name == "ipinfo.io":
            cc = r.text.strip()
        elif name == "ip-api.com":
            d = r.json()
            cc = d.get("countryCode") if d.get("status") == "success" else None
        elif name == "ipwho.is":
            d = r.json()
            cc = d.get("country_code") if d.get("success") else None
        else:
            cc = r.json().get("country_code")
    except Exception:
        return None
    if isinstance(cc, str) and len(cc) == 2 and cc.isalpha():
        return cc.upper()
    return None


class GeoResolver:
    def __init__(self, path, min_agree):
        self.path = path
        self.min_agree = min_agree
        self.data = load_json(path, {})
        self.lock = threading.Lock()
        self.limiters = {name: RateLimiter(iv) for name, _, iv in GEO_PROVIDERS}

    def _fresh(self, e):
        try:
            ts = datetime.fromisoformat(e["ts"])
        except Exception:
            return False
        ttl = GEO_TTL_OK if e.get("cc") else GEO_TTL_UNKNOWN
        return datetime.now(timezone.utc) - ts < ttl

    def lookup(self, ip):
        if not ip:
            return None
        with self.lock:
            e = self.data.get(ip)
        if e and self._fresh(e):
            return e.get("cc")
        votes = Counter()
        for name, tmpl, _ in GEO_PROVIDERS:
            self.limiters[name].wait()
            try:
                r = requests.get(tmpl.format(ip=ip), timeout=8, headers={"User-Agent": USER_AGENT})
                if r.status_code != 200:
                    continue
                cc = _parse_geo(name, r)
                if cc:
                    votes[cc] += 1
            except requests.RequestException:
                continue
        cc = None
        if votes:
            top = votes.most_common(2)
            best, n = top[0]
            tie = len(top) == 2 and top[1][1] == n
            if n >= self.min_agree and not tie:
                cc = best
        with self.lock:
            self.data[ip] = {"cc": cc, "ts": now_iso()}
        return cc

    def save(self):
        with self.lock:
            save_json(self.path, self.data)


def geo_phase(cache, geo, workers):
    ips = set()
    targets = []
    for key, it in cache.items.items():
        if it.get("status") != "working":
            continue
        targets.append(it)
        if it.get("exit_ip"): ips.add(it["exit_ip"])
        if it.get("inbound_ip"): ips.add(it["inbound_ip"])
    ips = sorted(ips)
    print(f"\n[i] геолокация: {len(ips)} уникальных IP, согласие ≥ {geo.min_agree} сервисов")
    with ThreadPoolExecutor(max_workers=workers) as ex:
        mapping = dict(zip(ips, ex.map(geo.lookup, ips)))
    geo.save()
    for it in targets:
        in_cc = mapping.get(it.get("inbound_ip", "")) or ""
        out_cc = mapping.get(it.get("exit_ip", "")) or ""
        it["country_code"] = out_cc
        it["country"] = group_name(out_cc) if out_cc else ""
        it["entry_cc"] = in_cc
        casc = decide_cascade(it.get("inbound_ip", ""), it.get("exit_ip", ""), in_cc, out_cc)
        it["is_cascade"] = casc
        if casc is True:
            it["cascade_msg"] = f"Каскад {flag_of(in_cc)}{group_name(in_cc)} → {flag_of(out_cc)}{group_name(out_cc)}"
        elif casc is False:
            it["cascade_msg"] = "Прямой"
        else:
            it["cascade_msg"] = "Каскад не определён"


# ============================================================================
# Параллельная проверка с батчами, двойной проверкой, сбросом мёртвых
# ============================================================================
def _check_parallel(proxies, xray, timeout, ifaces, cache, sub_index, concurrency,
                    server_timeout=SERVER_TIMEOUT_DEFAULT, speed_test=True, speed_timeout=5.0,
                    min_down=0.05, min_up=0.02, require_upload=True, min_probes=2,
                    double_check=True, discard_failed=True, discard_log=DISCARD_FILE,
                    max_batch=MAX_BATCH_SIZE):
    results = {k: [] for k in ifaces}
    if double_check and discard_failed and discard_log:
        try:
            Path(discard_log).write_text("", encoding="utf-8")
        except Exception:
            pass
    total = len(proxies)
    if total == 0:
        return results
    n_batches = (total + max_batch - 1) // max_batch
    if n_batches > 1:
        print(f"\n[i] {total} серверов → {n_batches} батчей по ≤ {max_batch}")
    t_all = time.time()

    for bi in range(n_batches):
        start, end = bi * max_batch, min(bi * max_batch + max_batch, total)
        batch = proxies[start:end]
        t_batch = time.time()
        if n_batches > 1:
            print(f"\n{'═' * 70}\n[i] БАТЧ {bi + 1}/{n_batches} — серверы {start + 1}…{end} из {total}\n{'═' * 70}")

        for iface_key, iface_name in ifaces.items():
            send_through = None
            if iface_name:
                send_through = _get_iface_ip(iface_name)
                if not send_through:
                    print(f"[!] интерфейс '{iface_name}' не найден, пропускаю")
                    continue

            def run_batch(sub, label):
                if not sub:
                    return []
                pairs, lock, print_lock = [], threading.Lock(), threading.Lock()
                done = [0]

                def worker(pr):
                    r = check_proxy(pr, xray, timeout, send_through,
                                    server_timeout=server_timeout, speed_test=speed_test,
                                    speed_timeout=speed_timeout, min_down=min_down,
                                    min_up=min_up, require_upload=require_upload,
                                    min_probes=min_probes)
                    cache.upsert(pr, r, sub_index)
                    with lock:
                        pairs.append((pr, r))
                        done[0] += 1
                        n = done[0]
                    name = pr.name or f"{pr.kind}://{pr.params.get('server')}"
                    with print_lock:
                        dn, up_ = r.get("download_mbps"), r.get("upload_mbps")
                        sp = ""
                        if dn is not None or up_ is not None:
                            sp = (f" ↓{dn if dn is not None else '—'}Mbps "
                                  f"↑{up_ if up_ is not None else '—'}Mbps")
                        if r["ok"]:
                            print(f"  {label} [{n}/{len(sub)}] OK {r['latency']}ms{sp} "
                                  f"probes={r['probes_ok']} in={r['inbound_ip']} out={r['exit_ip']} "
                                  f"{r['elapsed']}s | {name}", flush=True)
                        else:
                            print(f"  {label} [{n}/{len(sub)}] FAIL{sp} {r['error']} | {name}", flush=True)

                with ThreadPoolExecutor(max_workers=concurrency) as ex:
                    list(ex.map(worker, sub))
                return pairs

            first = run_batch(batch, "1st")
            final = [(pr, r) for pr, r in first if r["ok"]]
            failed = [pr for pr, r in first if not r["ok"]]

            if double_check and failed:
                print(f"\n  ⟳ Двойная проверка: {len(failed)} серверов")
                retry = run_batch(failed, "2nd")
                final.extend([(pr, r) for pr, r in retry if r["ok"]])
                still = [(pr, r) for pr, r in retry if not r["ok"]]
                if still:
                    if discard_failed:
                        for pr, r in still:
                            cache.items.pop(pr.dedup_key(), None)
                            if discard_log:
                                try:
                                    with open(discard_log, "a", encoding="utf-8") as f:
                                        f.write(f"{pr.raw or pr.name}\t{r.get('error') or 'timeout'}\n")
                                except Exception:
                                    pass
                    else:
                        final.extend(still)
            elif failed and not double_check:
                final.extend([(pr, r) for pr, r in first if not r["ok"]])

            results[iface_key].extend(final)

        if n_batches > 1:
            try:
                cache.save()
                dt_b = time.time() - t_batch
                dt_all = time.time() - t_all
                eta = (dt_all / (bi + 1)) * (n_batches - bi - 1)
                print(f"\n[i] батч {bi + 1}/{n_batches} за {dt_b:.0f}s, кэш сохранён. ETA ~{eta / 60:.0f} мин")
            except Exception as e:
                print(f"[!] кэш не сохранён: {e}")
    return results


# ============================================================================
# Конфиги Xray по странам (балансировщик, маршрутизация)
# ============================================================================
def _build_country_config(cc, servers, cluster="regular", stable_cfg=None, new_cfg=None):
    flag = flag_of(cc)
    name = group_name(cc)
    mark = marker_for(cluster, stable_cfg, new_cfg)
    prefix = f"{mark} " if mark else ""
    remarks = f"{prefix}{flag} {name} | @XelaraVpn"
    prefix_id = cc.lower()

    outbounds, tags = [], []
    for i, (pr, _r) in enumerate(servers, 1):
        tag = f"{prefix_id}-{i}"
        ob = _outbound(pr)
        ob["tag"] = tag
        outbounds.append(ob)
        tags.append(tag)
    outbounds.append({"protocol": "freedom", "tag": "direct"})
    outbounds.append({"protocol": "blackhole", "tag": "block"})

    balancer_tag = f"{prefix_id}-balancer"
    balancer = {"tag": balancer_tag, "selector": tags,
                "strategy": {"type": "leastLoad", "settings": {
                    "maxRTT": "1s", "expected": min(2, max(1, len(tags))),
                    "baselines": ["1s"], "tolerance": 0.01}}}

    return {
        "remarks": remarks, "_cluster": cluster,
        "log": {"loglevel": "warning"},
        "dns": {"queryStrategy": "UseIP",
                "servers": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]},
        "inbounds": [
            {"listen": "127.0.0.1", "port": 10808, "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True},
             "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True}, "tag": "socks"},
            {"listen": "127.0.0.1", "port": 10809, "protocol": "http",
             "settings": {"allowTransparent": False},
             "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True}, "tag": "http"},
        ],
        "outbounds": outbounds,
        "routing": {
            "domainMatcher": "hybrid", "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "domain": DOMAINS_DIRECT, "outboundTag": "direct"},
                {"type": "field", "network": "tcp,udp", "balancerTag": balancer_tag},
            ],
            "balancers": [balancer],
        },
        "burstObservatory": {
            "pingConfig": {"timeout": "10s", "interval": "120s", "sampling": 5,
                           "destination": "http://www.gstatic.com/generate_204"},
            "subjectSelector": tags,
        },
    }


# ============================================================================
# Вывод файлов
# ============================================================================
def rename_uri(raw, label):
    if raw.lower().startswith("vmess://"):
        try:
            d = json.loads(_b64decode(raw[8:]))
            d["ps"] = label
            return "vmess://" + base64.b64encode(json.dumps(d, ensure_ascii=False).encode()).decode()
        except Exception:
            return raw
    return raw.split("#", 1)[0] + "#" + quote(label, safe="")


def _label(it, cluster, stable_cfg, new_cfg, brand):
    cc = it.get("country_code") or ("EU" if EU_FALLBACK else "UNKNOWN")
    mark = marker_for(cluster, stable_cfg, new_cfg)
    casc = " 🔗" if it.get("is_cascade") else ""
    ms = f" {it['latency']}ms" if it.get("latency") else ""
    parts = [p for p in (mark, flag_of(cc), group_name(cc) + casc + ms, brand) if p]
    return " ".join(parts)


class OutputWriter:
    def __init__(self, base):
        self.base = Path(base)
        self.working = self.base / "Working"
        self.unworking = self.base / "UnWorking"
        self.allworking = self.base / "AllWorking"
        self.logs = self.base / "logs"
        for d in (self.working, self.unworking, self.allworking, self.logs):
            d.mkdir(parents=True, exist_ok=True)

    def write_working_for_sub(self, sub_index, lines):
        _write_lines(self.working / f"{sub_index}.txt", lines)

    def write_working_all(self, lines):
        _write_lines(self.working / "all.txt", lines)

    def write_unworking_all(self, proxies):
        _write_lines(self.unworking / "all.txt", [p.raw for p in proxies])

    def write_blacklisted(self, items):
        lines = []
        for it in items:
            lines.append(f"# fails={it.get('fail_count', 0)}  last={it.get('last_checked', '')}")
            lines.append(it.get("raw", ""))
        _write_lines(self.unworking / "blacklisted.txt", lines)

    def write_speeds(self, lines):
        _write_lines(self.allworking / "speeds.txt", lines)

    def write_top_fastest(self, cache, stable_cfg, new_cfg, count):
        rows = []
        for v in cache.items.values():
            if v.get("status") != "working" or not (v.get("params") or {}).get("server"):
                continue
            if v.get("download_mbps") is None and v.get("latency") is None:
                continue
            rows.append(v)
        if not rows:
            return None

        def sort_key(v):
            dn = v.get("download_mbps")
            lat = v.get("latency") if v.get("latency") is not None else 999999
            return (0, -dn, lat) if dn is not None else (1, 0, lat)

        rows.sort(key=sort_key)
        top = rows[:count]
        lines = []
        for i, v in enumerate(top, 1):
            p = cache.to_proxy(v)
            dn, up_, lat = v.get("download_mbps"), v.get("upload_mbps"), v.get("latency")
            parts = []
            if dn is not None: parts.append(f"↓{dn}Mbps")
            if up_ is not None: parts.append(f"↑{up_}Mbps")
            if lat is not None: parts.append(f"{lat}ms")
            stats = " ".join(parts) or "no-stats"
            label = f"{flag_of(v.get('country_code') or ('EU' if EU_FALLBACK else 'UNKNOWN'))}{i} | {stats}"
            lines.append(rename_uri(p.raw, label))
        path = self.allworking / "top150.txt"
        _write_lines(path, lines)
        return path, top

    def write_versioned_all_working(self, lines):
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        snap = self.allworking / f"all_{ts}.txt"
        _write_lines(snap, lines)
        latest = self.allworking / "latest.txt"
        try:
            shutil.copyfile(snap, latest)
        except Exception:
            _write_lines(latest, lines)
        return snap, latest

    def write_latest_json(self, cache, stable_cfg, new_cfg):
        order = {"stable": 0, "new": 1, "regular": 2}
        groups = defaultdict(list)
        for v in cache.items.values():
            if v.get("status") != "working" or not (v.get("params") or {}).get("server"):
                continue
            cc = v.get("country_code") or ("EU" if EU_FALLBACK else "UNKNOWN")
            cluster = cache.classify(v, stable_cfg, new_cfg)
            groups[(cc, cluster)].append((cache.to_proxy(v), {"latency": v.get("latency")}))
        configs = []
        for cc, cluster in sorted(groups.keys(), key=lambda k: (k[0], order.get(k[1], 3))):
            cfg = _build_country_config(cc, groups[(cc, cluster)], cluster, stable_cfg, new_cfg)
            cfg["_counts"] = {"cluster": cluster, "total": len(groups[(cc, cluster)])}
            configs.append(cfg)
        latest = self.allworking / "latest.json"
        latest.write_text(json.dumps(configs, ensure_ascii=False, indent=1), encoding="utf-8")
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        snap = self.allworking / f"all_{ts}.json"
        try:
            shutil.copyfile(latest, snap)
        except Exception:
            snap.write_text(json.dumps(configs, ensure_ascii=False), encoding="utf-8")
        return latest, snap

    def write_cluster_bundle(self, name, cache, proxies, cluster, stable_cfg, new_cfg, brand):
        lines = []
        by_cc = defaultdict(list)
        for p in proxies:
            it = cache.items.get(p.dedup_key(), {})
            lines.append(rename_uri(p.raw, _label(it, cluster, stable_cfg, new_cfg, brand)))
            cc = it.get("country_code") or ("EU" if EU_FALLBACK else "UNKNOWN")
            by_cc[cc].append((p, {"latency": it.get("latency")}))
        txt = self.allworking / f"{name}.txt"
        _write_lines(txt, lines)
        configs = [_build_country_config(cc, by_cc[cc], cluster, stable_cfg, new_cfg)
                   for cc in sorted(by_cc)]
        js = self.allworking / f"{name}_latest.json"
        js.write_text(json.dumps(configs, ensure_ascii=False, indent=1), encoding="utf-8")
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        snap = self.allworking / f"{name}_{ts}.json"
        try:
            shutil.copyfile(js, snap)
        except Exception:
            snap.write_text(json.dumps(configs, ensure_ascii=False), encoding="utf-8")
        return {"txt": txt, "json": js, "snap": snap}

    def write_sub_logs(self, sub_index, working_now, unworking_now):
        d = self.logs / str(sub_index)
        d.mkdir(parents=True, exist_ok=True)
        _write_lines(d / "working_last_check.txt", [p.raw for p in working_now])
        _write_lines(d / "unworking_last_check.txt", [p.raw for p in unworking_now])
        self._append_union(d / "working_all_time.txt", working_now)
        self._append_union(d / "unworking_all_time.txt", unworking_now)

    def _append_union(self, path, proxies):
        ex = set()
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip() and not line.startswith("#"):
                    ex.add(line.strip())
        for p in proxies:
            if p.raw:
                ex.add(p.raw)
        _write_lines(path, sorted(ex))


def write_report_csv(path, cache):
    fields = ["status", "country", "entry_cc", "exit_cc", "inbound_ip", "exit_ip", "cascade",
              "latency_ms", "download_mbps", "upload_mbps", "probes_ok", "kind", "name",
              "server", "port", "first_seen", "last_checked", "history", "error", "raw"]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for v in cache.items.values():
            p = v.get("params") or {}
            casc = v.get("is_cascade")
            w.writerow({
                "status": v.get("status", ""),
                "country": group_name(v.get("country_code")) if v.get("country_code") else "UNKNOWN",
                "entry_cc": v.get("entry_cc", ""), "exit_cc": v.get("country_code", ""),
                "inbound_ip": v.get("inbound_ip", ""), "exit_ip": v.get("exit_ip", ""),
                "cascade": "" if casc is None else ("yes" if casc else "no"),
                "latency_ms": v.get("latency", ""), "download_mbps": v.get("download_mbps", ""),
                "upload_mbps": v.get("upload_mbps", ""), "probes_ok": v.get("probes_ok", ""),
                "kind": v.get("kind", ""), "name": v.get("name", ""),
                "server": p.get("server", ""), "port": p.get("port", ""),
                "first_seen": v.get("first_seen", ""), "last_checked": v.get("last_checked", ""),
                "history": v.get("history", ""), "error": v.get("error", ""),
                "raw": v.get("raw", ""),
            })


def _write_final(cache, writer, sources_count, final_file, stable_cfg, new_cfg,
                 top_fastest_count, geo, brand, out_dir):
    print(f"\n[i] кэш: {len(cache.items)} записей")
    if geo is not None:
        geo_phase(cache, geo, workers=8)

    new_window = new_cfg.get("recent_hours", 24.0) if new_cfg and new_cfg.get("enabled", True) else None
    new_proxies = cache.new_all(new_window) if new_window is not None else []
    new_keys = {p.dedup_key() for p in new_proxies}
    stable_proxies = []
    if stable_cfg and stable_cfg.get("enabled", True):
        stable_proxies = [p for p in cache.stable_all(stable_cfg)
                          if new_window is None or p.dedup_key() not in new_keys]

    by_first = cache.working_by_first_sub()
    for sub_index in range(1, sources_count + 1):
        lines = [rename_uri(p.raw, _label(cache.items[p.dedup_key()],
                                          cache.classify(cache.items[p.dedup_key()], stable_cfg, new_cfg),
                                          stable_cfg, new_cfg, brand))
                 for p in by_first.get(sub_index, []) if p.dedup_key() in cache.items]
        writer.write_working_for_sub(sub_index, lines)

    all_working = cache.working_all()
    lines_all = []
    for p in all_working:
        it = cache.items[p.dedup_key()]
        cluster = cache.classify(it, stable_cfg, new_cfg)
        lines_all.append(rename_uri(p.raw, _label(it, cluster, stable_cfg, new_cfg, brand)))
    writer.write_working_all(lines_all)
    print(f"[i] Working/all.txt: {len(all_working)} рабочих (⚡ {len(stable_proxies)}, 🟢 {len(new_proxies)})")

    speed_lines = []
    for v in cache.items.values():
        if v.get("status") != "working":
            continue
        dn, up_ = v.get("download_mbps"), v.get("upload_mbps")
        if dn is None and up_ is None:
            continue
        cluster = cache.classify(v, stable_cfg, new_cfg)
        pref = f"{marker_for(cluster, stable_cfg, new_cfg)} " if marker_for(cluster, stable_cfg, new_cfg) else ""
        speed_lines.append(f"{pref}↓{dn}Mbps\t↑{up_}Mbps\t{v.get('latency')}ms\t{v.get('raw')}")
    if speed_lines:
        writer.write_speeds(speed_lines)
        print(f"[i] speeds.txt: {len(speed_lines)} строк")

    res = writer.write_top_fastest(cache, stable_cfg, new_cfg, top_fastest_count)
    if res:
        path, top = res
        print(f"[i] AllWorking/{path.name}: {len(top)} серверов")
        for i, v in enumerate(top[:5], 1):
            print(f"    #{i} {flag_of(v.get('country_code') or 'UNKNOWN')}: "
                  f"↓{v.get('download_mbps')}Mbps ↑{v.get('upload_mbps')}Mbps {v.get('latency')}ms")

    unworking = cache.unworking_all()
    writer.write_unworking_all(unworking)
    blacklisted = cache.blacklisted_items()
    if blacklisted:
        writer.write_blacklisted(blacklisted)
    print(f"[i] UnWorking/all.txt: {len(unworking)} нерабочих (в блэклисте: {len(blacklisted)})")

    casc_lines = [l for l, v in zip(lines_all, all_working) if cache.items[v.dedup_key()].get("is_cascade")]
    direct_lines = [l for l, v in zip(lines_all, all_working) if cache.items[v.dedup_key()].get("is_cascade") is False]
    unknown_lines = [l for l, v in zip(lines_all, all_working) if not cache.items[v.dedup_key()].get("country_code")]
    _write_lines(out_dir / "working" / "cascade.txt", casc_lines)
    _write_lines(out_dir / "working" / "direct.txt", direct_lines)
    _write_lines(out_dir / "working" / "unknown_country.txt", unknown_lines)
    print(f"[i] каскадов: {len(casc_lines)} | прямых: {len(direct_lines)} | страна неизвестна: {len(unknown_lines)}")

    by_cc = defaultdict(list)
    for v in all_working:
        it = cache.items[v.dedup_key()]
        cc = it.get("country_code") or ("EU" if EU_FALLBACK else "UNKNOWN")
        by_cc[cc].append(v)
    bc = out_dir / "working" / "by_country"
    if bc.exists():
        for f in bc.glob("*.txt"):
            f.unlink()
    for cc, plist in by_cc.items():
        ls = []
        for p in plist:
            it = cache.items[p.dedup_key()]
            ls.append(rename_uri(p.raw, _label(it, cache.classify(it, stable_cfg, new_cfg), stable_cfg, new_cfg, brand)))
        _write_lines(bc / f"{cc}.txt", ls)
    if stable_proxies:
        writer.write_cluster_bundle("stable", cache, stable_proxies, "stable", stable_cfg, new_cfg, brand)
        print(f"[i] stable: {len(stable_proxies)} ⚡")
    if new_proxies and new_cfg and new_cfg.get("output", True):
        writer.write_cluster_bundle("new", cache, new_proxies, "new", stable_cfg, new_cfg, brand)
        print(f"[i] new: {len(new_proxies)} 🟢")

    snap_txt, _ = writer.write_versioned_all_working(lines_all)
    latest_json, _ = writer.write_latest_json(cache, stable_cfg, new_cfg)
    print(f"[i] AllWorking/{latest_json.name}, {snap_txt.name}")

    Path(final_file).write_text("\n".join(lines_all) + ("\n" if lines_all else ""), encoding="utf-8")
    print(f"[i] {final_file}: {len(all_working)} рабочих")
    write_report_csv(out_dir / "report.csv", cache)
    print(f"[i] report.csv: все серверы из кэша")


# ============================================================================
# main
# ============================================================================
def main():
    global EU_FALLBACK
    ap = argparse.ArgumentParser(description="Xray checker: серверы, страны, каскады")
    ap.add_argument("--no-load", action="store_true", help="не качать источники")
    ap.add_argument("-i", "--input", default=CONFIGS_FILE)
    ap.add_argument("-o", "--output-dir", default="output")
    ap.add_argument("--cache", default="cache.json")
    ap.add_argument("--geo-cache", default=GEO_CACHE_FILE)
    ap.add_argument("-c", "--concurrency", type=int, default=16)
    ap.add_argument("--timeout", type=float, default=8.0, help="таймаут запроса через прокси")
    ap.add_argument("--server-timeout", type=float, default=12.0, help="общий бюджет на сервер")
    ap.add_argument("--min-probes", type=int, default=2, help="из 3 probe-URL, по умолчанию 2")
    ap.add_argument("--geo-min-agree", type=int, default=2)
    ap.add_argument("--eu-fallback", action="store_true", help="неизвестную страну считать EU")
    ap.add_argument("--wifi-iface", default=None)
    ap.add_argument("--mobile-iface", default=None)
    ap.add_argument("--xray-dir", default="xray_bin")
    ap.add_argument("--final-file", default="working.txt")
    ap.add_argument("--recheck-files",
                    default="working.txt,output/AllWorking/latest.txt,output/AllWorking/latest.json")
    ap.add_argument("--no-recheck-final", action="store_true")
    ap.add_argument("--no-double-check", action="store_true")
    ap.add_argument("--keep-failed", action="store_true")
    ap.add_argument("--discard-log", default=DISCARD_FILE)
    ap.add_argument("--include-blacklisted", action="store_true")
    ap.add_argument("--reset-blacklist", action="store_true")
    ap.add_argument("--no-speed", action="store_true")
    ap.add_argument("--speed-timeout", type=float, default=5.0)
    ap.add_argument("--min-down", type=float, default=0.05)
    ap.add_argument("--min-up", type=float, default=0.02)
    ap.add_argument("--no-upload-check", action="store_true")
    ap.add_argument("--no-stable", action="store_true")
    ap.add_argument("--stable-min-checks", type=int, default=3)
    ap.add_argument("--stable-min-rate", type=float, default=0.8)
    ap.add_argument("--stable-min-consecutive", type=int, default=2)
    ap.add_argument("--stable-recent-hours", type=float, default=72.0)
    ap.add_argument("--stable-marker", default="⚡")
    ap.add_argument("--no-new-marker", action="store_true")
    ap.add_argument("--new-marker", default="🟢")
    ap.add_argument("--new-recent-hours", type=float, default=24.0)
    ap.add_argument("--no-new-output", action="store_true")
    ap.add_argument("--max-batch", type=int, default=MAX_BATCH_SIZE)
    ap.add_argument("--top-fastest", type=int, default=TOP_FASTEST_COUNT)
    ap.add_argument("--brand", default="@XelaraVpn")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--only-new", action="store_true")
    mode.add_argument("--only-old", action="store_true")
    args = ap.parse_args()

    EU_FALLBACK = args.eu_fallback
    args.concurrency = max(1, min(args.concurrency, MAX_CONCURRENCY))
    args.min_probes = max(1, min(args.min_probes, len(PROBE_URLS)))
    args.max_batch = max(100, args.max_batch)

    check_kwargs = dict(
        server_timeout=args.server_timeout, speed_test=not args.no_speed,
        speed_timeout=args.speed_timeout, min_down=args.min_down, min_up=args.min_up,
        require_upload=not args.no_upload_check, min_probes=args.min_probes,
        double_check=not args.no_double_check, discard_failed=not args.keep_failed,
        discard_log=args.discard_log, max_batch=args.max_batch,
    )
    stable_cfg = {"enabled": not args.no_stable, "min_checks": args.stable_min_checks,
                  "min_rate": args.stable_min_rate, "min_consecutive": args.stable_min_consecutive,
                  "recent_hours": args.stable_recent_hours, "marker": args.stable_marker}
    new_cfg = {"enabled": not args.no_new_marker, "recent_hours": args.new_recent_hours,
               "marker": args.new_marker, "output": not args.no_new_output}

    out_dir = Path(args.output_dir)
    cache = Cache(args.cache)
    writer = OutputWriter(out_dir)
    geo = GeoResolver(args.geo_cache, args.geo_min_agree)

    extra_uris, sources = [], []
    if not args.only_old and not args.no_load:
        loaded, my_cfgs, _ = load_sources()
        extra_uris = list(loaded) + list(my_cfgs)
        src = Path(SOURCES_FILE)
        if src.exists():
            sources = [l.strip() for l in src.read_text(encoding="utf-8", errors="replace").splitlines()
                       if l.strip() and not l.strip().startswith("#")]
    elif not args.only_old:
        src = Path(SOURCES_FILE)
        if src.exists():
            sources = [l.strip() for l in src.read_text(encoding="utf-8", errors="replace").splitlines()
                       if l.strip() and not l.strip().startswith("#")]

    print(f"\n[i] режим: {'only-new' if args.only_new else 'only-old' if args.only_old else 'all'}")
    print(f"[i] источников: {len(sources)} | параллельно: {args.concurrency} | бюджет: {args.server_timeout}s")
    print(f"[i] probes: {args.min_probes}/{len(PROBE_URLS)} | гео-согласие: {args.geo_min_agree} | "
          f"неизвестная страна: {'EU' if EU_FALLBACK else 'UNKNOWN'}")
    print(f"[i] батч: ≤{args.max_batch} | двойная: {'ВКЛ' if check_kwargs['double_check'] else 'ВЫКЛ'} | "
          f"скорость: {'ВКЛ' if check_kwargs['speed_test'] else 'ВЫКЛ'}")
    print(f"[i] в кэше: {len(cache.items)}")

    xray = XrayManager(args.xray_dir)
    try:
        xray.ensure()
    except Exception as e:
        print(f"[!] Xray недоступен: {e}")
        sys.exit(1)

    ifaces = {"default": None}
    if args.wifi_iface:
        ifaces = {"wifi": args.wifi_iface}
    if args.mobile_iface:
        ifaces["mobile"] = args.mobile_iface
        ifaces.pop("default", None)

    file_uris = []
    if Path(args.input).exists():
        for line in Path(args.input).read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip() and not line.strip().startswith("#"):
                file_uris.append(line.strip())

    all_uris = extra_uris if extra_uris else file_uris
    unique_map, bad = parse_all(all_uris)
    proxies = list(unique_map.values())
    print(f"[i] ссылок: {len(all_uris)} → серверов: {len(proxies)} (нераспознано: {bad})")

    if args.reset_blacklist:
        n = 0
        for v in cache.items.values():
            if int(v.get("fail_count", 0)) > 0:
                v["fail_count"] = 0
                n += 1
        print(f"[i] blacklist сброшен у {n} серверов")

    proxies = _dedup(proxies)
    if not args.include_blacklisted:
        bl = cache.blacklisted_keys()
        before = len(proxies)
        proxies = [p for p in proxies if p.dedup_key() not in bl]
        if before - len(proxies):
            print(f"[i] пропущено блэклистнутых: {before - len(proxies)}")

    prev_final = []
    if not args.no_recheck_final and not args.only_new:
        paths = [s.strip() for s in args.recheck_files.split(",") if s.strip()]
        prev_final = _load_recheck_files(paths)
        if prev_final and not args.include_blacklisted:
            bl = cache.blacklisted_keys()
            prev_final = [p for p in prev_final if p.dedup_key() not in bl]

    if args.only_old:
        cached = []
        for it in cache.items.values():
            if not args.include_blacklisted and cache.is_blacklisted(it):
                continue
            p = cache.to_proxy(it)
            if p.params.get("server"):
                cached.append(p)
        uniq = _dedup(cached + prev_final)
        print(f"[i] перепроверяю старые: {len(uniq)}")
        if uniq:
            _check_parallel(uniq, xray, args.timeout, ifaces, cache, 0, args.concurrency, **check_kwargs)
        cache.save()
        _write_final(cache, writer, 0, args.final_file, stable_cfg, new_cfg,
                     args.top_fastest, geo, args.brand, out_dir)
        return

    if args.only_new:
        known = set(cache.items.keys())
        if args.include_blacklisted:
            known -= cache.blacklisted_keys()
        new_only = [p for p in proxies if p.dedup_key() not in known]
        print(f"[i] only-new: всего {len(proxies)}, новых {len(new_only)}")
        if new_only:
            _check_parallel(new_only, xray, args.timeout, ifaces, cache, 1, args.concurrency, **check_kwargs)
        cache.save()
        _write_final(cache, writer, len(sources) or 1, args.final_file, stable_cfg, new_cfg,
                     args.top_fastest, geo, args.brand, out_dir)
        return

    if proxies:
        print(f"\n{'=' * 70}\n=== Проверка {len(proxies)} серверов\n{'=' * 70}")
        _check_parallel(proxies, xray, args.timeout, ifaces, cache, 1, args.concurrency, **check_kwargs)

    if prev_final:
        print(f"\n{'=' * 70}\n=== Перепроверка файлов: {len(prev_final)}\n{'=' * 70}")
        results = _check_parallel(prev_final, xray, args.timeout, ifaces, cache, 999,
                                  args.concurrency, **check_kwargs)
        sub_w, sub_u = [], []
        for pairs in results.values():
            for pr, r in pairs:
                (sub_w if r["ok"] else sub_u).append(pr)
        writer.write_sub_logs(999, _dedup(sub_w), _dedup(sub_u))

    cache.save()
    _write_final(cache, writer, max(len(sources), 1), args.final_file, stable_cfg, new_cfg,
                 args.top_fastest, geo, args.brand, out_dir)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nОстановлено пользователем")
