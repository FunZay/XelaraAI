#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Combined Source Loader + Xray Parser & Checker
v-dbl + v-speed + v-stable + v-new + blacklist + batched + split-cache + top-fastest
[ИСПРАВЛЕНО]: Структура JSON конфига Xray и дефолтные параметры speed_test
"""

import importlib, subprocess, sys

REQUIRED = {
    "requests": "requests>=2.28.0",
    "socks":    "PySocks>=1.7.1",
    "psutil":   "psutil>=5.9.0",
    "aiohttp":  "aiohttp>=3.8.0",
    "aiofiles": "aiofiles>=22.0.0",
    "yaml":     "PyYAML>=6.0",
}

def _bootstrap():
    miss = []
    for m, p in REQUIRED.items():
        try:
            importlib.import_module(m)
        except ImportError:
            miss.append(p)
    if not miss:
        return
    print(f"[deps] устанавливаю: {', '.join(miss)}")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install",
                               "--disable-pip-version-check", *miss])
    except subprocess.CalledProcessError:
        sys.exit(1)
    importlib.invalidate_caches()

_bootstrap()

import argparse
import asyncio
import base64
import concurrent.futures as cf
import hashlib
import json
import os
import platform
import random
import re
import shutil
import socket
import stat
import subprocess as _sp
import tempfile
import threading
import time
import urllib.parse
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Set, Tuple
from urllib.parse import parse_qs, quote, unquote, urlparse

import aiofiles
import aiohttp
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
SOURCES_FILE     = "sources.txt"
CONFIGS_FILE     = "configs.txt"
MY_CONFIGS_FILE  = "my_configs.txt"
BLACKLIST_FILE   = "blacklist_sources.txt"
DISCARD_FILE     = "discarded.txt"

THREADS         = 50
TIMEOUT_NORMAL  = 5
TIMEOUT_HAPP    = 5

MAX_BATCH_SIZE  = 10_000
MAX_CONCURRENCY = 256

BLACKLIST_FAIL_THRESHOLD = 3
TOP_FASTEST_COUNT        = 150

CACHE_SPLIT_THRESHOLD_MB    = 50
CACHE_SPLIT_THRESHOLD_BYTES = CACHE_SPLIT_THRESHOLD_MB * 1024 * 1024

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 combined/1.0")

HWID_STATIC = "d060e73eb61d1ba7"
HAPP_USER_AGENTS = ["Happ/3.18.3/Android/17771400994551771562"]

CACHE_VERSION = 5
SERVER_TIMEOUT_DEFAULT = 8.0

TEST_URLS_FALLBACK = ["https://www.gstatic.com/generate_204"]
IP_URL = "https://api.ipify.org"

SPEED_DOWN_URLS = [
    "https://speed.cloudflare.com/__down?bytes=2000000",
    "https://speed.cloudflare.com/__down?bytes=1000000",
    "https://proof.ovh.net/files/1Mb.dat",
]
SPEED_UP_URLS = [
    "https://speed.cloudflare.com/__up",
    "https://httpbin.org/post",
]
SPEED_UP_BYTES = 1_000_000

COUNTRY_SOURCES = [
    ("http://ip-api.com/json/?fields=status,countryCode,country,query", "ip-api"),
    ("https://ipwho.is/", "ipwho"),
    ("https://ipapi.co/json/", "ipapi-co"),
    ("https://ipinfo.io/json", "ipinfo"),
]
_COUNTRY_SEM = threading.Semaphore(3)

STATUS_MARKERS = {"stable": "⚡", "new": "🟢", "regular": ""}

def marker_for(cluster, stable_cfg=None, new_cfg=None):
    if cluster == "stable":
        return (stable_cfg or {}).get("marker", STATUS_MARKERS["stable"])
    if cluster == "new":
        return (new_cfg or {}).get("marker", STATUS_MARKERS["new"])
    return ""

VLESS_REGEX   = re.compile(r"vless://[^\s#]+", re.IGNORECASE)
TROJAN_REGEX  = re.compile(r"trojan://[^\s#]+", re.IGNORECASE)
HY2_REGEX     = re.compile(r"(?:hysteria2|hy2)://[^\s#]+", re.IGNORECASE)
URL_REGEX     = re.compile(r'https?://[^\s<>"\'(){}|^`\[\]]+', re.IGNORECASE)
BASE64_REGEX  = re.compile(r'^[A-Za-z0-9+/]+=*$', re.MULTILINE)
UUID_REGEX    = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
URI_REGEX     = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s\"'<>]+")

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
    "AL": "Албания", "MK": "Северная Македония", "BA": "Босния",
    "ME": "Черногория", "XK": "Косово",
}

def country_ru(cc, fallback=""):
    if cc and cc in COUNTRY_RU:
        return COUNTRY_RU[cc]
    if cc:
        return fallback or cc
    return "Европа"

def clean_text(text: str) -> str:
    if not text:
        return ""
    return text.replace('\ufeff', '').replace('\u200b', '')

def _b64decode(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    pad = (-len(s)) % 4
    try:
        return base64.b64decode(s + "=" * pad).decode("utf-8", errors="replace")
    except Exception:
        return ""

def _safe_int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default

def _safe_urlparse(uri):
    try:
        return urlparse(uri)
    except ValueError:
        return None

def flag_from_cc(cc):
    if not cc or len(cc) != 2:
        return "🏳️"
    try:
        return "".join(chr(0x1F1E6 + ord(c.upper()) - ord('A')) for c in cc)
    except Exception:
        return "🏳️"

def resolve_flag(item):
    cc = (item or {}).get("country_code", "") or ""
    return flag_from_cc(cc) if cc else "🏳️"

def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _extra_hash(ex):
    if not ex:
        return ""
    try:
        return hashlib.md5(
            json.dumps(ex, ensure_ascii=False, sort_keys=True).encode()
        ).hexdigest()[:10]
    except Exception:
        return ""

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
            return round((total * 8) / (dt * 1_000_000), 2)
    return None

def _measure_upload_speed(session, timeout):
    payload = b"\0" * SPEED_UP_BYTES
    for url in SPEED_UP_URLS:
        t0 = time.perf_counter()
        try:
            r = session.post(url, data=payload, timeout=timeout, stream=True)
            dt = time.perf_counter() - t0
            ok_status = r.status_code in (200, 201, 204)
            r.close()
            if ok_status and dt > 0.05:
                return round((SPEED_UP_BYTES * 8) / (dt * 1_000_000), 2)
        except Exception:
            continue
    return None

# ============================================================================
# Конвертеры JSON/YAML → URI
# ============================================================================
def safe_quote(s: str) -> str:
    return urllib.parse.quote(s, safe='')

def build_query(params: dict) -> str:
    parts = []
    for k, v in params.items():
        if v is None or v == '':
            continue
        if isinstance(v, bool):
            v = 'true' if v else 'false'
        parts.append(f"{k}={safe_quote(str(v))}")
    return '&'.join(parts)

def is_valid_config(url: str) -> bool:
    url = url.strip()
    if url.startswith("vless://"):
        return "@" in url and UUID_REGEX.search(url)
    if url.startswith("trojan://"):
        return "@" in url
    if url.startswith(("hysteria2://", "hy2://")):
        return "@" in url
    return False

def outbound_to_vless_url(out: dict) -> Optional[str]:
    settings = out.get('settings', {})
    vnext = settings.get('vnext', [])
    if not vnext: return None
    first = vnext[0]
    address = first.get('address'); port = first.get('port')
    users = first.get('users', [])
    if not users: return None
    user = users[0]
    uuid = user.get('id')
    if not uuid: return None
    encryption = user.get('encryption', 'none')
    flow = user.get('flow', '')
    stream = out.get('streamSettings', {})
    network = stream.get('network', 'tcp')
    security = stream.get('security', '')
    reality = stream.get('realitySettings', {})
    tls = stream.get('tlsSettings', {})
    ws = stream.get('wsSettings', {})
    grpc = stream.get('grpcSettings', {})
    http = stream.get('httpSettings', {})
    params = {}
    if encryption: params['encryption'] = encryption
    if network: params['type'] = network
    if flow: params['flow'] = flow
    if security == 'reality':
        params['security'] = 'reality'
        if 'serverName' in reality: params['sni'] = reality['serverName']
        if 'publicKey' in reality:  params['pbk'] = reality['publicKey']
        if 'shortId' in reality:    params['sid'] = reality['shortId']
        if 'fingerprint' in reality: params['fp'] = reality['fingerprint']
    elif security == 'tls':
        params['security'] = 'tls'
        if 'serverName' in tls: params['sni'] = tls['serverName']
        if 'allowInsecure' in tls: params['allowInsecure'] = '1' if tls['allowInsecure'] else '0'
        if 'fingerprint' in tls: params['fp'] = tls['fingerprint']
        if 'alpn' in tls: params['alpn'] = ','.join(tls['alpn'])
    if network == 'ws' and ws:
        if 'path' in ws: params['path'] = safe_quote(ws['path'])
        if 'headers' in ws and 'Host' in ws['headers']: params['host'] = ws['headers']['Host']
    elif network == 'grpc' and grpc:
        if 'serviceName' in grpc: params['serviceName'] = safe_quote(grpc['serviceName'])
    elif network in ('xhttp', 'splithttp') and 'xhttpSettings' in stream:
        xhttp = stream.get('xhttpSettings', {})
        if 'path' in xhttp: params['path'] = safe_quote(xhttp['path'])
        if 'host' in xhttp: params['host'] = xhttp['host']
    elif network in ('h2', 'http2') and http:
        if 'path' in http: params['path'] = safe_quote(http['path'])
        if 'host' in http:
            params['host'] = ','.join(http['host']) if isinstance(http['host'], list) else http['host']
    if params.get('security') == 'reality' and 'alpn' not in params:
        params['alpn'] = urllib.parse.quote('http/1.1')
    params = {k: v for k, v in params.items() if v not in (None, '')}
    query = build_query(params)
    remark = out.get('tag', '')
    remark = f"#{safe_quote(remark)}" if remark else ''
    return f"vless://{uuid}@{address}:{port}?{query}{remark}"

def outbound_to_trojan_url(out: dict) -> Optional[str]:
    settings = out.get('settings', {})
    servers = settings.get('servers', [])
    if not servers: return None
    s = servers[0]
    address = s.get('address'); port = s.get('port'); password = s.get('password')
    if not all([address, port, password]): return None
    stream = out.get('streamSettings', {})
    security = stream.get('security', 'tls')
    tls = stream.get('tlsSettings', {})
    ws = stream.get('wsSettings', {})
    grpc = stream.get('grpcSettings', {})
    params = {}
    if security == 'tls':
        if 'serverName' in tls: params['sni'] = tls['serverName']
        if 'allowInsecure' in tls: params['allowInsecure'] = '1' if tls['allowInsecure'] else '0'
        if 'fingerprint' in tls: params['fp'] = tls['fingerprint']
        if 'alpn' in tls: params['alpn'] = ','.join(tls['alpn'])
    network = stream.get('network', 'tcp')
    if network != 'tcp':
        params['type'] = network
        if network == 'ws' and ws:
            if 'path' in ws: params['path'] = safe_quote(ws['path'])
            if 'headers' in ws and 'Host' in ws['headers']: params['host'] = ws['headers']['Host']
        elif network == 'grpc' and grpc:
            if 'serviceName' in grpc: params['serviceName'] = safe_quote(grpc['serviceName'])
    query = build_query(params)
    remark = out.get('tag', '')
    remark = f"#{safe_quote(remark)}" if remark else ''
    base = f"trojan://{password}@{address}:{port}"
    if query:
        base += f"?{query}"
    return base + remark

def outbound_to_hysteria2_url(out: dict) -> Optional[str]:
    settings = out.get('settings', {})
    servers = settings.get('servers', [])
    if not servers: return None
    s = servers[0]
    address = s.get('address'); port = s.get('port'); auth = s.get('auth', '')
    if not address or not port: return None
    stream = out.get('streamSettings', {})
    security = stream.get('security', 'tls')
    tls = stream.get('tlsSettings', {})
    params = {}
    if security == 'tls':
        if 'serverName' in tls: params['sni'] = tls['serverName']
        if 'allowInsecure' in tls: params['insecure'] = '1' if tls['allowInsecure'] else '0'
        if 'alpn' in tls: params['alpn'] = ','.join(tls['alpn'])
    transport = stream.get('transport', {})
    if 'hopConfig' in transport:
        hop = transport['hopConfig']
        if hop.get('obfs') == 'salamander' and hop.get('password'):
            params['obfs-password'] = hop['password']
            params['obfs'] = 'salamander'
    query = build_query(params)
    remark = out.get('tag', '')
    remark = f"#{safe_quote(remark)}" if remark else ''
    auth_part = f"{auth}@" if auth else ''
    return f"hy2://{auth_part}{address}:{port}?{query}{remark}"

def yaml_proxy_to_vless_url(proxy: dict) -> Optional[str]:
    name = proxy.get('name', ''); server = proxy.get('server')
    port = proxy.get('port'); uuid = proxy.get('uuid')
    if not all([server, port, uuid]): return None
    params = {'encryption': 'none', 'type': proxy.get('network', 'tcp')}
    if proxy.get('flow'): params['flow'] = proxy['flow']
    tls = proxy.get('tls', False)
    reality_opts = proxy.get('reality-opts', {})
    if reality_opts:
        params['security'] = 'reality'
        if 'public-key' in reality_opts: params['pbk'] = reality_opts['public-key']
        if 'short-id' in reality_opts and reality_opts['short-id']: params['sid'] = reality_opts['short-id']
    elif tls:
        params['security'] = 'tls'
    sni = proxy.get('servername')
    if sni: params['sni'] = sni
    fp = proxy.get('client-fingerprint')
    if fp: params['fp'] = fp
    network = proxy.get('network', 'tcp')
    if network == 'grpc':
        grpc_opts = proxy.get('grpc-opts', {})
        if 'grpc-service-name' in grpc_opts: params['serviceName'] = grpc_opts['grpc-service-name']
    elif network in ('ws', 'websocket'):
        ws_opts = proxy.get('ws-opts', {})
        if 'path' in ws_opts: params['path'] = safe_quote(ws_opts['path'])
        if 'headers' in ws_opts and 'Host' in ws_opts['headers']: params['host'] = ws_opts['headers']['Host']
    if params.get('security') == 'reality' and 'alpn' not in params:
        params['alpn'] = urllib.parse.quote('http/1.1')
    params = {k: v for k, v in params.items() if v not in (None, '')}
    query = build_query(params)
    remark = f"#{safe_quote(name)}" if name else ''
    return f"vless://{uuid}@{server}:{port}?{query}{remark}"

def yaml_proxy_to_trojan_url(proxy: dict) -> Optional[str]:
    name = proxy.get('name', ''); server = proxy.get('server')
    port = proxy.get('port'); password = proxy.get('password')
    if not all([server, port, password]): return None
    params = {}
    sni = proxy.get('servername')
    if sni: params['sni'] = sni
    tls = proxy.get('tls', False)
    if tls: params['security'] = 'tls'
    fp = proxy.get('client-fingerprint')
    if fp: params['fp'] = fp
    query = build_query(params)
    remark = f"#{safe_quote(name)}" if name else ''
    base = f"trojan://{password}@{server}:{port}"
    if query:
        base += f"?{query}"
    return base + remark

def yaml_proxy_to_hysteria2_url(proxy: dict) -> Optional[str]:
    name = proxy.get('name', ''); server = proxy.get('server')
    port = proxy.get('port'); auth = proxy.get('auth', '')
    if not all([server, port]): return None
    params = {}
    sni = proxy.get('servername')
    if sni: params['sni'] = sni
    tls = proxy.get('tls', False)
    if tls: params['insecure'] = '0'
    query = build_query(params)
    remark = f"#{safe_quote(name)}" if name else ''
    auth_part = f"{auth}@" if auth else ''
    return f"hy2://{auth_part}{server}:{port}?{query}{remark}"

def convert_json_to_urls(content: str) -> List[str]:
    urls = []
    try:
        decoder = json.JSONDecoder()
        idx = 0
        content = content.strip()
        while idx < len(content):
            try:
                obj, end = decoder.raw_decode(content, idx)
                idx = end
                while idx < len(content) and content[idx] in ' \t\n\r':
                    idx += 1
                outbounds = None
                if isinstance(obj, dict):
                    outbounds = obj.get('outbounds')
                    if outbounds is None and 'config' in obj:
                        outbounds = obj['config'].get('outbounds')
                elif isinstance(obj, list):
                    outbounds = obj
                if not outbounds or not isinstance(outbounds, list):
                    continue
                for out in outbounds:
                    if not isinstance(out, dict): continue
                    protocol = out.get('protocol', '')
                    if protocol == 'vless':
                        url = outbound_to_vless_url(out)
                        if url and is_valid_config(url): urls.append(url)
                    elif protocol == 'trojan':
                        url = outbound_to_trojan_url(out)
                        if url and is_valid_config(url): urls.append(url)
                    elif protocol in ('hysteria2', 'hy2'):
                        url = outbound_to_hysteria2_url(out)
                        if url and is_valid_config(url): urls.append(url)
            except json.JSONDecodeError:
                break
    except Exception:
        pass
    return urls

def convert_yaml_to_urls(content: str) -> List[str]:
    urls = []
    try:
        data = yaml.safe_load(content)
        if not data or not isinstance(data, dict): return []
        proxies = data.get('proxies', [])
        if not isinstance(proxies, list): return []
        for proxy in proxies:
            ptype = proxy.get('type')
            if ptype == 'vless': url = yaml_proxy_to_vless_url(proxy)
            elif ptype == 'trojan': url = yaml_proxy_to_trojan_url(proxy)
            elif ptype in ('hysteria2', 'hy2'): url = yaml_proxy_to_hysteria2_url(proxy)
            else: continue
            if url and is_valid_config(url): urls.append(url)
    except Exception:
        pass
    return urls

def decode_base64_content(content: str) -> Tuple[Optional[str], List[str]]:
    try:
        content = content.strip()
        if not BASE64_REGEX.match(content.replace('\n', '').replace('\r', '')):
            return None, []
        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
        matches = []
        matches.extend(VLESS_REGEX.findall(decoded))
        matches.extend(TROJAN_REGEX.findall(decoded))
        matches.extend(HY2_REGEX.findall(decoded))
        if len(decoded) > 100 and BASE64_REGEX.match(decoded.replace('\n', '').replace('\r', '')):
            deeper = decode_base64_content(decoded)
            if deeper[1]: matches.extend(deeper[1])
        return decoded, matches
    except Exception:
        return None, []

def extract_configs_from_text(text: str):
    vless_list, trojan_list, hy2_list = [], [], []
    base64_count = json_count = yaml_count = 0

    for v in VLESS_REGEX.findall(text):  vless_list.append(v)
    for t in TROJAN_REGEX.findall(text): trojan_list.append(t)
    for h in HY2_REGEX.findall(text):    hy2_list.append(h)

    _, b64_matches = decode_base64_content(text)
    if b64_matches:
        base64_count = 1
        for m in b64_matches:
            if m.startswith("vless://"):   vless_list.append(m)
            elif m.startswith("trojan://"): trojan_list.append(m)
            elif m.startswith(("hysteria2://", "hy2://")): hy2_list.append(m)

    if text.strip().startswith(('{', '[')):
        json_urls = convert_json_to_urls(text)
        if json_urls:
            json_count = 1
            for u in json_urls:
                if u.startswith("vless://"):   vless_list.append(u)
                elif u.startswith("trojan://"): trojan_list.append(u)
                elif u.startswith(("hysteria2://", "hy2://")): hy2_list.append(u)

    if 'proxies:' in text or 'type: vless' in text.lower():
        yaml_urls = convert_yaml_to_urls(text)
        if yaml_urls:
            yaml_count = 1
            for u in yaml_urls:
                if u.startswith("vless://"):   vless_list.append(u)
                elif u.startswith("trojan://"): trojan_list.append(u)
                elif u.startswith(("hysteria2://", "hy2://")): hy2_list.append(u)

    return vless_list, trojan_list, hy2_list, base64_count, json_count, yaml_count

# ============================================================================
# Happ
# ============================================================================
def fetch_with_happ_method(url: str) -> Optional[str]:
    parsed = _safe_urlparse(url)
    if parsed is None: return None
    if 'hwid=' not in url:
        separator = '&' if parsed.query else '?'
        url_with_hwid = f"{url}{separator}hwid={HWID_STATIC}"
    else:
        url_with_hwid = url
    for try_url in [url_with_hwid, url]:
        for ua in HAPP_USER_AGENTS:
            try:
                headers = {"User-Agent": ua, "X-HWID": HWID_STATIC,
                           "Accept": "*/*", "Accept-Encoding": "gzip, deflate",
                           "Connection": "keep-alive"}
                resp = requests.get(try_url, headers=headers, timeout=TIMEOUT_HAPP)
                resp.raise_for_status()
                content = resp.text.strip()
                if "<html" in content.lower(): continue
                if BASE64_REGEX.match(content.replace('\n', '').replace('\r', '')):
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                    if decoded: content = decoded
                return content
            except Exception:
                continue
    return None

# ============================================================================
# Загрузка источников
# ============================================================================
async def process_source(session, url, sem, stats, stats_lock):
    async with sem:
        content = None
        used_happ = False
        try:
            async with session.get(url, timeout=TIMEOUT_NORMAL, ssl=False) as resp:
                if resp.status == 200:
                    content = await resp.text()
        except Exception:
            pass
        if content is None or len(content) < 50:
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor(max_workers=1) as executor:
                content = await loop.run_in_executor(executor, fetch_with_happ_method, url)
            used_happ = True
        if not content or len(content) < 10:
            async with stats_lock:
                stats['failed'].append(url)
            return
        vless_list, trojan_list, hy2_list, b64_cnt, json_cnt, yaml_cnt = \
            extract_configs_from_text(content)
        total_found = len(vless_list) + len(trojan_list) + len(hy2_list)
        if total_found == 0:
            async with stats_lock:
                stats['failed'].append(url)
            return
        async with stats_lock:
            stats['processed'] += 1
            stats['vless_count'] += len(vless_list)
            stats['trojan_count'] += len(trojan_list)
            stats['hy2_count'] += len(hy2_list)
            stats['base64'] += b64_cnt
            stats['json'] += json_cnt
            stats['yaml'] += yaml_cnt
            stats['total_configs'] += total_found
            stats['all_configs'].extend(vless_list)
            stats['all_configs'].extend(trojan_list)
            stats['all_configs'].extend(hy2_list)
            if used_happ: stats['happ_success'] += 1

async def display_progress(stats):
    while True:
        processed = stats['processed']
        total = stats['total_sources']
        percent = (processed / total * 100) if total > 0 else 0
        bar_len = 20
        filled = int(bar_len * processed / total) if total > 0 else 0
        bar = '█' * filled + '░' * (bar_len - filled)
        v = stats['vless_count']; t = stats['trojan_count']; h = stats['hy2_count']
        subs = stats['base64'] + stats['json'] + stats['yaml']
        sys.stdout.write(
            f"\r|{bar}| {percent:.0f}% Скачано: {processed}/{total} | "
            f"VLESS: {v} | Trojan: {t} | Hysteria2: {h} | "
            f"Декодировано: {subs} | Happ: {stats['happ_success']} | Всего: {stats['total_configs']}")
        sys.stdout.flush()
        await asyncio.sleep(0.3)

async def load_http_sources():
    print("\n" + "=" * 60)
    print("Скачивание конфигураций из источников.")
    print("=" * 60)

    if not os.path.exists(SOURCES_FILE):
        print(f"Файл {SOURCES_FILE} не найден.")
        return [], [], {}

    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [line.strip() for line in f
                   if line.strip() and not line.startswith('#')]

    if not sources:
        print("Нет источников в sources.txt")
        return [], [], {}

    total_sources = len(sources)
    print(f"Источников для обработки: {total_sources}")

    my_configs = []
    if os.path.exists(MY_CONFIGS_FILE):
        async with aiofiles.open(MY_CONFIGS_FILE, 'r', encoding='utf-8') as f:
            async for line in f:
                cfg = line.strip()
                if cfg and is_valid_config(cfg):
                    my_configs.append(cfg)
        print(f"  Мои конфиги: {len(my_configs)}")

    stats = {
        'processed': 0, 'total_sources': total_sources,
        'vless_count': 0, 'trojan_count': 0, 'hy2_count': 0,
        'base64': 0, 'json': 0, 'yaml': 0,
        'total_configs': 0, 'all_configs': [], 'failed': [],
        'happ_success': 0, 'lock': asyncio.Lock(),
    }

    sem = asyncio.Semaphore(THREADS)
    connector = aiohttp.TCPConnector(limit=0, ssl=False)
    async with aiohttp.ClientSession(connector=connector,
                                     headers={"User-Agent": USER_AGENT}) as session:
        tasks = [process_source(session, url, sem, stats, stats['lock'])
                 for url in sources]
        progress_task = asyncio.create_task(display_progress(stats))
        await asyncio.gather(*tasks)
        progress_task.cancel()

    print()
    print("Загрузка источников завершена.")

    if stats['failed']:
        async with aiofiles.open(BLACKLIST_FILE, 'a', encoding='utf-8') as f:
            for bad_url in stats['failed']:
                await f.write(bad_url + '\n')
        remaining = [url for url in sources if url not in stats['failed']]
        async with aiofiles.open(SOURCES_FILE, 'w', encoding='utf-8') as f:
            for url in remaining:
                await f.write(url + '\n')
        print(f"Удалено неудачных источников: {len(stats['failed'])}")

    all_configs = stats['all_configs'] + my_configs
    if all_configs:
        async with aiofiles.open(CONFIGS_FILE, 'w', encoding='utf-8') as f:
            for cfg in all_configs:
                await f.write(cfg + '\n')
        print(f"Записано конфигов в {CONFIGS_FILE}: {len(all_configs)}")
    else:
        print("Конфигов не найдено.")

    print(f"\n  Обработано: {stats['processed']}/{total_sources}")
    print(f"  VLESS: {stats['vless_count']} | Trojan: {stats['trojan_count']} | Hysteria2: {stats['hy2_count']}")
    print(f"  Мои конфиги: {len(my_configs)}")
    return stats['all_configs'], my_configs, stats

# ============================================================================
# Proxy + парсер URI
# ============================================================================
@dataclass
class Proxy:
    raw: str = ""
    kind: str = ""
    params: dict = field(default_factory=dict)
    name: str = ""

    def dedup_key(self):
        p = self.params
        parts = [self.kind,
                 str(p.get("server", "")).strip().lower(),
                 str(p.get("port", "")),
                 str(p.get("uuid", "") or p.get("password", "")),
                 str(p.get("sni", "")).strip().lower(),
                 str(p.get("host", "")).strip().lower(),
                 str(p.get("path", "")),
                 str(p.get("network", "")),
                 str(p.get("security", ""))]
        if self.kind == "vmess":
            parts.append(str(p.get("alterId", "")))
        eh = _extra_hash(p.get("extra"))
        if eh: parts.append(eh)
        return "|".join(parts)

def _p_vmess(uri):
    d = _b64decode(uri[len("vmess://"):].strip())
    if not d: return None
    try: cfg = json.loads(d)
    except Exception: return None
    tls_on = (cfg.get("tls", "") or "").lower() in ("tls", "reality")
    return Proxy(raw=uri, kind="vmess", name=cfg.get("ps", ""), params={
        "server": cfg.get("add", ""), "port": _safe_int(cfg.get("port"), 443),
        "uuid": cfg.get("id", ""), "alterId": _safe_int(cfg.get("aid"), 0),
        "cipher": cfg.get("scy", "auto") or "auto",
        "network": cfg.get("net", "tcp") or "tcp",
        "type": cfg.get("type", "none") or "none",
        "host": cfg.get("host", ""), "path": cfg.get("path", ""),
        "tls": tls_on, "sni": cfg.get("sni", "") or cfg.get("host", ""),
        "fp": cfg.get("fp", ""), "alpn": cfg.get("alpn", ""),
        "security": "tls" if tls_on else "none",
        "extra": cfg.get("extra") or {},
    })

def _p_vless(uri):
    u = _safe_urlparse(uri)
    if u is None or not u.hostname: return None
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    extra = {}
    raw_extra = q.get("extra", "")
    if raw_extra:
        try: extra = json.loads(unquote(raw_extra))
        except Exception: extra = {}
    return Proxy(raw=uri, kind="vless",
                 name=unquote(u.fragment) if u.fragment else "",
                 params={
                     "server": u.hostname, "port": _safe_int(u.port, 443),
                     "uuid": unquote(u.username or ""), "flow": q.get("flow", ""),
                     "network": q.get("type", "tcp") or "tcp",
                     "security": q.get("security", "none") or "none",
                     "sni": q.get("sni", ""), "fp": q.get("fp", ""),
                     "pbk": q.get("pbk", ""), "sid": q.get("sid", ""),
                     "spx": q.get("spx", ""),
                     "path": q.get("path", ""), "host": q.get("host", ""),
                     "serviceName": q.get("serviceName", ""),
                     "alpn": q.get("alpn", ""), "extra": extra,
                 })

def _p_trojan(uri):
    u = _safe_urlparse(uri)
    if u is None or not u.hostname: return None
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    return Proxy(raw=uri, kind="trojan",
                 name=unquote(u.fragment) if u.fragment else "",
                 params={
                     "server": u.hostname, "port": _safe_int(u.port, 443),
                     "password": unquote(u.username or ""),
                     "network": q.get("type", "tcp") or "tcp",
                     "security": q.get("security", "tls") or "tls",
                     "sni": q.get("sni", ""), "fp": q.get("fp", ""),
                     "path": q.get("path", ""), "host": q.get("host", ""),
                     "serviceName": q.get("serviceName", ""),
                     "alpn": q.get("alpn", ""),
                 })

def _p_hy2(uri):
    u = _safe_urlparse(uri)
    if u is None or not u.hostname: return None
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    return Proxy(raw=uri, kind="hysteria2",
                 name=unquote(u.fragment) if u.fragment else "",
                 params={
                     "server": u.hostname, "port": _safe_int(u.port, 443),
                     "password": unquote(u.username or ""),
                     "sni": q.get("sni", ""), "insecure": q.get("insecure", "0") == "1",
                     "obfs": q.get("obfs", ""), "obfs-password": q.get("obfs-password", ""),
                 })

def parse_uri(uri: str) -> Optional[Proxy]:
    uri = uri.strip()
    if uri.startswith("vmess://"): return _p_vmess(uri)
    if uri.startswith("vless://"): return _p_vless(uri)
    if uri.startswith("trojan://"): return _p_trojan(uri)
    if uri.startswith(("hysteria2://", "hy2://")): return _p_hy2(uri)
    return None

def dump_to_uri(p: Proxy, override_name: str = "") -> str:
    if p.kind == "vless":
        return outbound_to_vless_url({"protocol": "vless", "tag": override_name or p.name,
            "settings": {"vnext": [{"address": p.params["server"], "port": p.params["port"],
            "users": [{"id": p.params["uuid"], "encryption": "none", "flow": p.params.get("flow", "")}]}]},
            "streamSettings": {"network": p.params.get("network", "tcp"), "security": p.params.get("security", "none"),
            "tlsSettings": {"serverName": p.params.get("sni", ""), "fingerprint": p.params.get("fp", ""),
            "alpn": p.params.get("alpn", "").split(",") if p.params.get("alpn") else []},
            "realitySettings": {"serverName": p.params.get("sni", ""), "publicKey": p.params.get("pbk", ""),
            "shortId": p.params.get("sid", ""), "fingerprint": p.params.get("fp", "")},
            "wsSettings": {"path": p.params.get("path", ""), "headers": {"Host": p.params.get("host", "")} if p.params.get("host") else {}},
            "grpcSettings": {"serviceName": p.params.get("serviceName", "")}}})
    elif p.kind == "trojan":
        return outbound_to_trojan_url({"protocol": "trojan", "tag": override_name or p.name,
            "settings": {"servers": [{"address": p.params["server"], "port": p.params["port"], "password": p.params["password"]}]},
            "streamSettings": {"network": p.params.get("network", "tcp"), "security": p.params.get("security", "tls"),
            "tlsSettings": {"serverName": p.params.get("sni", ""), "fingerprint": p.params.get("fp", ""),
            "alpn": p.params.get("alpn", "").split(",") if p.params.get("alpn") else []},
            "wsSettings": {"path": p.params.get("path", ""), "headers": {"Host": p.params.get("host", "")} if p.params.get("host") else {}},
            "grpcSettings": {"serviceName": p.params.get("serviceName", "")}}})
    elif p.kind == "hysteria2":
        return outbound_to_hysteria2_url({"protocol": "hysteria2", "tag": override_name or p.name,
            "settings": {"servers": [{"address": p.params["server"], "port": p.params["port"], "auth": p.params["password"]}]},
            "streamSettings": {"security": "tls", "tlsSettings": {"serverName": p.params.get("sni", ""),
            "allowInsecure": p.params.get("insecure", False)},
            "transport": {"hopConfig": {"obfs": p.params.get("obfs", ""), "password": p.params.get("obfs-password", "")} if p.params.get("obfs") else {}}}})
    return p.raw or ""

# ============================================================================
# Кэш
# ============================================================================
@dataclass
class CacheItem:
    proxy: Proxy
    status: str = "unknown"
    latency: Optional[int] = None
    latency_keepalive: Optional[int] = None
    download_mbps: Optional[float] = None
    upload_mbps: Optional[float] = None
    ip: str = ""
    country_code: str = ""
    country: str = ""
    test_url: str = ""
    error: str = ""
    elapsed: float = 0.0
    first_seen: str = field(default_factory=_now)
    last_checked: str = field(default_factory=_now)
    check_count: int = 0
    fail_count: int = 0
    consecutive_fails: int = 0
    consecutive_successes: int = 0
    sub_index: int = 0

class Cache:
    def __init__(self, path: Path):
        self.path = path
        self.items: dict[str, dict] = {}
        self.load()

    def load(self):
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and data.get("version") == CACHE_VERSION:
                    self.items = data.get("items", {})
            except Exception:
                pass

    def save(self):
        try:
            self.path.write_text(json.dumps({"version": CACHE_VERSION, "items": self.items},
                                            ensure_ascii=False, indent=1), encoding="utf-8")
        except Exception:
            pass

    def upsert(self, pr: Proxy, result: dict, sub_index: int):
        key = pr.dedup_key()
        now = _now()
        if key not in self.items:
            self.items[key] = {
                "raw": pr.raw, "kind": pr.kind, "params": pr.params, "name": pr.name,
                "status": "unknown", "first_seen": now, "check_count": 0, "fail_count": 0,
                "consecutive_fails": 0, "consecutive_successes": 0, "sub_index": sub_index,
            }
        it = self.items[key]
        it["last_checked"] = now
        it["check_count"] += 1
        it["sub_index"] = sub_index
        
        if result["ok"]:
            it["status"] = "working"
            it["consecutive_fails"] = 0
            it["consecutive_successes"] += 1
            it["fail_count"] = 0
            for k in ("latency", "latency_keepalive", "download_mbps", "upload_mbps",
                      "ip", "country_code", "country", "test_url", "elapsed"):
                if k in result and result[k] is not None:
                    it[k] = result[k]
        else:
            it["status"] = "unworking"
            it["consecutive_successes"] = 0
            it["consecutive_fails"] += 1
            it["fail_count"] += 1
            it["error"] = result.get("error", "")[:100]

    def to_proxy(self, it: dict) -> Proxy:
        return Proxy(raw=it.get("raw", ""), kind=it.get("kind", ""),
                     params=it.get("params", {}), name=it.get("name", ""))

    def classify(self, it: dict, stable_cfg: dict, new_cfg: dict) -> str:
        if new_cfg.get("enabled", True):
            try:
                last = datetime.fromisoformat(it.get("last_checked", "").replace("Z", "+00:00"))
                if (datetime.now(timezone.utc) - last).total_seconds() < new_cfg["recent_hours"] * 3600:
                    return "new"
            except Exception:
                pass
        if stable_cfg.get("enabled", True):
            if it.get("check_count", 0) >= stable_cfg["min_checks"]:
                rate = (it.get("consecutive_successes", 0) /
                        max(1, it.get("consecutive_successes", 0) + it.get("consecutive_fails", 0)))
                if rate >= stable_cfg["min_rate"] and it.get("consecutive_successes", 0) >= stable_cfg["min_consecutive"]:
                    return "stable"
        return "regular"

    def working_all(self) -> List[Proxy]:
        return [self.to_proxy(v) for v in self.items.values() if v.get("status") == "working"]

    def working_by_first_sub(self) -> dict[int, List[Proxy]]:
        res = defaultdict(list)
        for v in self.items.values():
            if v.get("status") == "working":
                res[v.get("sub_index", 0)].append(self.to_proxy(v))
        return res

    def stable_all(self, min_checks: int, min_rate: float, min_consecutive: int, recent_hours: float) -> List[Proxy]:
        out = []
        now = datetime.now(timezone.utc)
        for v in self.items.values():
            if v.get("status") != "working": continue
            if v.get("check_count", 0) < min_checks: continue
            if v.get("consecutive_successes", 0) < min_consecutive: continue
            rate = v.get("consecutive_successes", 0) / max(1, v.get("consecutive_successes", 0) + v.get("consecutive_fails", 0))
            if rate < min_rate: continue
            try:
                last = datetime.fromisoformat(v.get("last_checked", "").replace("Z", "+00:00"))
                if (now - last).total_seconds() > recent_hours * 3600:
                    continue
            except Exception:
                continue
            out.append(self.to_proxy(v))
        return out

    def new_all(self, recent_hours: float) -> List[Proxy]:
        out = []
        now = datetime.now(timezone.utc)
        for v in self.items.values():
            if v.get("status") != "working": continue
            try:
                first = datetime.fromisoformat(v.get("first_seen", "").replace("Z", "+00:00"))
                if (now - first).total_seconds() <= recent_hours * 3600:
                    out.append(self.to_proxy(v))
            except Exception:
                continue
        return out

    def unworking_all(self) -> List[Proxy]:
        return [self.to_proxy(v) for v in self.items.values() if v.get("status") == "unworking"]

    def blacklisted_keys(self) -> Set[str]:
        return {k for k, v in self.items.items() if v.get("fail_count", 0) >= BLACKLIST_FAIL_THRESHOLD}

    def blacklisted_items(self) -> List[dict]:
        return [v for v in self.items.values() if v.get("fail_count", 0) >= BLACKLIST_FAIL_THRESHOLD]

    def is_blacklisted(self, it: dict) -> bool:
        return it.get("fail_count", 0) >= BLACKLIST_FAIL_THRESHOLD

# ============================================================================
# Проверка прокси (ИСПРАВЛЕНА СТРУКТУРА JSON И ДЕФОЛТНЫЕ ПАРАМЕТРЫ)
# ============================================================================
def check_proxy(pr, xray, timeout=8.0, send_through=None,
                prior_cc="", server_timeout=None,
                speed_test=False, speed_timeout=5.0,
                min_down=0.05, min_up=0.02, require_upload=False):
    budget = server_timeout if server_timeout is not None else SERVER_TIMEOUT_DEFAULT
    t_start = time.time()
    def remaining():
        return max(0.0, budget - (time.time() - t_start))
    
    port = _free_port()
    ob = _outbound(pr)
    if send_through:
        ob.setdefault("streamSettings", {}).setdefault("sockopt", {})["sendThrough"] = send_through
    
    # ИСПРАВЛЕНИЕ: inbounds и outbounds вынесены на верхний уровень, а не внутрь dns
    cfg = {
        "log": {"loglevel": "warning"},
        "dns": {
            "queryStrategy": "UseIP",
            "servers": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]
        },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False}
        }],
        "outbounds": [ob]
    }
    
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False)
    cp = Path(f.name)
    proc = None
    try:
        proc = xray.run(cp)
        wait_budget = min(remaining(), 4.0)
        if wait_budget <= 0 or not _wait_port(port, wait_budget):
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
            return {"ok": False, "latency": None, "latency_keepalive": None,
                    "download_mbps": None, "upload_mbps": None,
                    "ip": None, "country_code": "", "country": "",
                    "test_url": None, "error": msg,
                    "elapsed": round(time.time() - t_start, 2)}
        
        session = requests.Session()
        session.proxies = {"http": f"socks5h://127.0.0.1:{port}",
                           "https": f"socks5h://127.0.0.1:{port}"}
        session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "keep-alive"})
        session.mount("http://", HTTPAdapter(max_retries=0))
        session.mount("https://", HTTPAdapter(max_retries=0))
        
        lat = None; working_url = None; last_err = "нет ответа"
        for url in TEST_URLS_FALLBACK:
            req_budget = min(remaining(), timeout)
            if req_budget <= 0.3:
                last_err = "бюджет исчерпан"
                break
            try:
                t0 = time.perf_counter()
                r1 = session.get(url, timeout=req_budget)
                dt = int((time.perf_counter() - t0) * 1000)
                if r1.status_code in (200, 204, 301, 302):
                    lat = dt; working_url = url; break
                last_err = f"HTTP {r1.status_code}"
            except requests.exceptions.RequestException as e:
                last_err = str(e)[:60]
                continue
        
        if working_url is None:
            session.close()
            return {"ok": False, "latency": None, "latency_keepalive": None,
                    "download_mbps": None, "upload_mbps": None,
                    "ip": None, "country_code": "", "country": "",
                    "test_url": None, "error": last_err,
                    "elapsed": round(time.time() - t_start, 2)}
        
        lat_ka = None
        ka_budget = min(remaining(), timeout)
        if ka_budget > 0.3:
            try:
                t0 = time.perf_counter()
                r2 = session.get(working_url, timeout=ka_budget)
                lat_ka = int((time.perf_counter() - t0) * 1000)
                if r2.status_code not in (200, 204, 301, 302):
                    lat_ka = None
            except Exception:
                lat_ka = None
        
        down_mbps = None; up_mbps = None
        if speed_test:
            down_mbps = _measure_download_speed(session, speed_timeout)
            if require_upload:
                up_mbps = _measure_upload_speed(session, speed_timeout)
            
            speed_ok = (down_mbps is not None and down_mbps >= min_down)
            if require_upload:
                speed_ok = speed_ok and (up_mbps is not None and up_mbps >= min_up)
            
            if not speed_ok:
                session.close()
                err = (f"dead/too slow: ↓{down_mbps} ↑{up_mbps} Mbps "
                       f"(min ↓{min_down} ↑{min_up})")
                return {"ok": False, "latency": lat, "latency_keepalive": lat_ka,
                        "download_mbps": down_mbps, "upload_mbps": up_mbps,
                        "ip": None, "country_code": "", "country": "",
                        "test_url": working_url, "error": err,
                        "elapsed": round(time.time() - t_start, 2)}
        
        cc, cn, ip = "", "", ""
        country_budget = min(remaining(), 3.0)
        if prior_cc:
            cc = prior_cc
        if country_budget > 0.3:
            try:
                r = session.get(IP_URL, timeout=country_budget)
                if r.status_code == 200:
                    ip = r.text.strip()
            except Exception:
                pass
        elif country_budget > 0.3:
            cc, cn, ip = _detect_country(session, country_budget)
            if not ip and remaining() > 0.3:
                try:
                    r = session.get(IP_URL, timeout=min(remaining(), 2.0))
                    if r.status_code == 200:
                        ip = r.text.strip()
                except Exception:
                    pass
        
        session.close()
        return {"ok": True, "latency": lat, "latency_keepalive": lat_ka,
                "download_mbps": down_mbps, "upload_mbps": up_mbps,
                "ip": ip, "country_code": cc, "country": cn,
                "test_url": working_url, "error": None,
                "elapsed": round(time.time() - t_start, 2)}
    finally:
        if proc:
            try:
                proc.terminate(); proc.wait(2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        cp.unlink(missing_ok=True)
        _release_port(port)

# ============================================================================
# Вспомогательные функции для Xray и портов
# ============================================================================
_PORT_POOL = set()
_PORT_LOCK = threading.Lock()

def _free_port():
    with _PORT_LOCK:
        for _ in range(100):
            p = random.randint(10000, 60000)
            if p not in _PORT_POOL:
                _PORT_POOL.add(p)
                return p
        return 0

def _release_port(port):
    with _PORT_LOCK:
        _PORT_POOL.discard(port)

def _wait_port(port: int, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.05)
    return False

def _get_iface_ip(iface_name: str) -> Optional[str]:
    import psutil
    try:
        addrs = psutil.net_if_addrs().get(iface_name, [])
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                return addr.address
    except Exception:
        pass
    return None

def _outbound(pr: Proxy) -> dict:
    if pr.kind == "vless":
        user = {"id": pr.params["uuid"], "encryption": "none"}
        if pr.params.get("flow"): user["flow"] = pr.params["flow"]
        return {"protocol": "vless", "settings": {"vnext": [{"address": pr.params["server"], "port": pr.params["port"], "users": [user]}]},
                "streamSettings": _stream(pr)}
    elif pr.kind == "trojan":
        return {"protocol": "trojan", "settings": {"servers": [{"address": pr.params["server"], "port": pr.params["port"], "password": pr.params["password"]}]},
                "streamSettings": _stream(pr)}
    elif pr.kind == "hysteria2":
        return {"protocol": "hysteria2", "settings": {"servers": [{"address": pr.params["server"], "port": pr.params["port"], "password": pr.params["password"]}]},
                "streamSettings": _stream(pr)}
    return {}

def _stream(pr: Proxy) -> dict:
    p = pr.params
    net = (p.get("network") or "tcp").lower()
    sec = (p.get("security") or "none").lower()
    st = {"network": net}
    
    if net == "ws":
        ws = {"path": p.get("path") or "/"}
        if p.get("host"): ws["headers"] = {"Host": p["host"]}
        st["wsSettings"] = ws
    elif net == "grpc":
        st["grpcSettings"] = {"serviceName": p.get("serviceName") or p.get("path") or ""}
        
    if sec == "tls":
        tls = {"serverName": p.get("sni") or p.get("host") or pr.params["server"], "allowInsecure": p.get("insecure", False)}
        if p.get("fp"): tls["fingerprint"] = p["fp"]
        if p.get("alpn"): tls["alpn"] = p["alpn"].split(",") if isinstance(p["alpn"], str) else p["alpn"]
        st["security"] = "tls"
        st["tlsSettings"] = tls
    elif sec == "reality":
        st["security"] = "reality"
        st["realitySettings"] = {
            "serverName": p.get("sni") or pr.params["server"],
            "fingerprint": p.get("fp") or "chrome",
            "publicKey": p.get("pbk") or "",
            "shortId": p.get("sid") or "",
        }
    else:
        st["security"] = "none"
    return st

class XrayManager:
    def __init__(self, xray_dir: str):
        self.dir = Path(xray_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.exe = self.dir / ("xray.exe" if platform.system() == "Windows" else "xray")

    def ensure(self):
        if self.exe.exists():
            return
        print("[i] Скачиваю Xray Core...")
        sys_arch = platform.machine().lower()
        if "arm" in sys_arch or "aarch" in sys_arch:
            arch = "arm64-v8a" if "64" in sys_arch else "arm32-v7a"
            zip_name = "Xray-linux-arm64-v8a.zip" if "64" in sys_arch else "Xray-linux-arm32-v7a.zip"
        elif "64" in sys_arch or "amd" in sys_arch:
            arch = "64"
            zip_name = "Xray-linux-64.zip" if platform.system() != "Windows" else "Xray-windows-64.zip"
        else:
            arch = "32"
            zip_name = "Xray-linux-32.zip" if platform.system() != "Windows" else "Xray-windows-32.zip"
        
        url = f"https://github.com/XTLS/Xray-core/releases/latest/download/{zip_name}"
        zip_path = self.dir / "xray.zip"
        
        try:
            import urllib.request
            urllib.request.urlretrieve(url, zip_path)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                for file in zip_ref.namelist():
                    if file.lower().endswith("xray") or file.lower().endswith("xray.exe"):
                        with zip_ref.open(file) as src, open(self.exe, 'wb') as dst:
                            dst.write(src.read())
            zip_path.unlink()
            if platform.system() != "Windows":
                os.chmod(self.exe, stat.S_IRWXU)
            print("[i] Xray Core успешно загружен.")
        except Exception as e:
            raise RuntimeError(f"Не удалось загрузить Xray: {e}")

    def run(self, cfg_path: Path):
        return _sp.Popen([str(self.exe), "run", "-c", str(cfg_path)],
                         stdout=_sp.DEVNULL, stderr=_sp.PIPE, start_new_session=True)

# ============================================================================
# Отчёты, OutputWriter
# ============================================================================
def _dedup(proxies):
    seen = set(); out = []
    for p in proxies:
        if not p or not p.params.get("server"): continue
        k = p.dedup_key()
        if k in seen: continue
        seen.add(k); out.append(p)
    return out

def _build_country_config(cc, cn, servers, cluster="regular", stable_cfg=None, new_cfg=None):
    flag = flag_from_cc(cc) if cc else "🏳️"
    name = cn or country_ru(cc)
    mark = marker_for(cluster, stable_cfg, new_cfg)
    prefix = f"{mark} " if mark else ""
    remarks = f"{prefix}{flag} {name} | @XelaraVpn"
    prefix_id = (cc or "xx").lower()

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

    domains_direct = ["vk.com", "yandex.ru", "mail.ru", "ok.ru", "gosuslugi.ru",
                      "kremlin.ru", "ozon.ru", "wildberries.ru", "vseinstrumenti.ru",
                      "max.ru", "dzen.ru", "rutube.ru", "avito.ru", "2gis.ru",
                      "kinopoisk.ru", "sberbank.ru", "tbank.ru", "rzd.ru",
                      "nalog.ru", "mchs.gov.ru", "minzdrav.gov.ru", "edu.gov.ru",
                      "mos.ru", "spb.ru"]

    return {
        "remarks": remarks, "_cluster": cluster,
        "log": {"loglevel": "warning"},
        "dns": {"queryStrategy": "UseIP",
                "servers": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]},
        "inbounds": [
            {"listen": "127.0.0.1", "port": 10808, "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True},
             "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True},
             "tag": "socks"},
            {"listen": "127.0.0.1", "port": 10809, "protocol": "http",
             "settings": {"allowTransparent": False},
             "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True},
             "tag": "http"},
        ],
        "outbounds": outbounds,
        "routing": {
            "domainMatcher": "hybrid", "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "domain": domains_direct, "outboundTag": "direct"},
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

class OutputWriter:
    def __init__(self, base):
        self.base = base
        self.working = base / "Working"
        self.unworking = base / "UnWorking"
        self.allworking = base / "AllWorking"
        self.logs = base / "logs"
        for d in (self.working, self.unworking, self.allworking, self.logs):
            d.mkdir(parents=True, exist_ok=True)

    def _write_lines(self, path, lines):
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    def _write_list(self, path, proxies):
        self._write_lines(path, [dump_to_uri(p) for p in proxies])

    def write_working_for_sub(self, sub_index, lines):
        self._write_lines(self.working / f"{sub_index}.txt", lines)

    def write_working_all(self, lines):
        self._write_lines(self.working / "all.txt", lines)

    def write_unworking_all(self, proxies):
        self._write_list(self.unworking / "all.txt", proxies)

    def write_blacklisted(self, items):
        lines = []
        for it in items:
            p = Proxy(raw=it.get("raw", ""), kind=it.get("kind", ""),
                      params=it.get("params") or {}, name=it.get("name", ""))
            if p.params.get("server"):
                lines.append(f"# fails={it.get('fail_count',0)}  last={it.get('last_checked','')}")
                lines.append(dump_to_uri(p))
        self._write_lines(self.unworking / "blacklisted.txt", lines)

    def write_speeds(self, lines):
        self._write_lines(self.allworking / "speeds.txt", lines)

    def write_top_fastest(self, cache, count=TOP_FASTEST_COUNT):
        rows = []
        for v in cache.items.values():
            if v.get("status") != "working":
                continue
            if not (v.get("params") or {}).get("server"):
                continue
            dn = v.get("download_mbps")
            lat = v.get("latency")
            if dn is None and lat is None:
                continue
            rows.append(v)
        if not rows:
            return None

        def sort_key(v):
            dn = v.get("download_mbps")
            lat = v.get("latency")
            if lat is None:
                lat = 999999
            if dn is not None:
                return (0, -dn, lat)
            return (1, 0, lat)

        rows.sort(key=sort_key)
        top = rows[:count]

        lines = []
        for i, v in enumerate(top, 1):
            p = cache.to_proxy(v)
            flag = resolve_flag(v)
            dn = v.get("download_mbps")
            up = v.get("upload_mbps")
            lat = v.get("latency")
            parts = []
            if dn is not None: parts.append(f"↓{dn}Mbps")
            if up is not None: parts.append(f"↑{up}Mbps")
            if lat is not None: parts.append(f"{lat}ms")
            stats = " ".join(parts) if parts else "no-stats"
            lines.append(dump_to_uri(p, override_name=f"{flag}{i} | {stats}"))

        path = self.allworking / "top150.txt"
        self._write_lines(path, lines)
        return path, top

    def write_versioned_all_working(self, lines):
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        snap = self.allworking / f"all_{ts}.txt"
        self._write_lines(snap, lines)
        latest = self.allworking / "latest.txt"
        try: shutil.copyfile(snap, latest)
        except Exception: self._write_lines(latest, lines)
        return snap, latest

    def write_latest_json(self, cache, stable_cfg=None, new_cfg=None):
        order = {"stable": 0, "new": 1, "regular": 2}
        groups = defaultdict(list)
        for v in cache.items.values():
            if v.get("status") != "working": continue
            if not (v.get("params") or {}).get("server"): continue
            cc = v.get("country_code") or ""
            cluster = cache.classify(v, stable_cfg, new_cfg)
            groups[(cc, cluster)].append((cache.to_proxy(v), {"latency": v.get("latency")}))

        configs = []
        for cc, cluster in sorted(groups.keys(),
                                  key=lambda k: (k[0], order.get(k[1], 3))):
            rows = groups[(cc, cluster)]
            if not rows: continue
            cfg = _build_country_config(cc, country_ru(cc), rows,
                                        cluster=cluster, stable_cfg=stable_cfg,
                                        new_cfg=new_cfg)
            cfg["_counts"] = {"cluster": cluster, "total": len(rows)}
            configs.append(cfg)

        latest = self.allworking / "latest.json"
        latest.write_text(json.dumps(configs, ensure_ascii=False, indent=1),
                          encoding="utf-8")
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        snap = self.allworking / f"all_{ts}.json"
        try: shutil.copyfile(latest, snap)
        except Exception: snap.write_text(json.dumps(configs), encoding="utf-8")
        return latest, snap

    def _write_cluster_bundle(self, name, cache, proxies, cluster,
                              stable_cfg=None, new_cfg=None):
        txt_path = self.allworking / f"{name}.txt"
        self._write_lines(txt_path,
            _named_lines(cache, proxies, stable_cfg=stable_cfg, new_cfg=new_cfg))

        by_country = defaultdict(list)
        for p in proxies:
            it = cache.items.get(p.dedup_key(), {})
            cc = it.get("country_code") or ""
            by_country[cc].append((p, {"latency": it.get("latency")}))

        configs = []
        for cc in sorted(by_country.keys()):
            configs.append(_build_country_config(
                cc, country_ru(cc), by_country[cc],
                cluster=cluster, stable_cfg=stable_cfg, new_cfg=new_cfg))

        js_path = self.allworking / f"{name}_latest.json"
        js_path.write_text(json.dumps(configs, ensure_ascii=False, indent=1),
                           encoding="utf-8")
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        snap = self.allworking / f"{name}_{ts}.json"
        try: shutil.copyfile(js_path, snap)
        except Exception: snap.write_text(json.dumps(configs), encoding="utf-8")
        return {"txt": txt_path, "json": js_path, "snap": snap}

    def write_stable(self, cache, proxies, stable_cfg=None, new_cfg=None):
        return self._write_cluster_bundle("stable", cache, proxies, "stable",
                                          stable_cfg, new_cfg)

    def write_new(self, cache, proxies, stable_cfg=None, new_cfg=None):
        return self._write_cluster_bundle("new", cache, proxies, "new",
                                          stable_cfg, new_cfg)

    def write_sub_logs(self, sub_index, working_now, unworking_now):
        d = self.logs / str(sub_index)
        d.mkdir(parents=True, exist_ok=True)
        self._write_list(d / "working_last_check.txt", working_now)
        self._write_list(d / "unworking_last_check.txt", unworking_now)
        self._append_union(d / "working_all_time.txt", working_now)
        self._append_union(d / "unworking_all_time.txt", unworking_now)

    def _append_union(self, path, new_proxies):
        ex = set()
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"): ex.add(line)
        for p in new_proxies:
            u = dump_to_uri(p)
            if u: ex.add(u)
        path.write_text("\n".join(sorted(ex)) + "\n" if ex else "", encoding="utf-8")

def _named_lines(cache, proxies, stable_cfg=None, new_cfg=None):
    lines = []
    for i, p in enumerate(proxies, 1):
        it = cache.items.get(p.dedup_key(), {})
        flag = resolve_flag(it)
        cluster = cache.classify(it, stable_cfg, new_cfg)
        mark = marker_for(cluster, stable_cfg, new_cfg)
        prefix = f"{mark} " if mark else ""
        lines.append(dump_to_uri(p, override_name=f"{prefix}{flag}{i}| @XelaraVpn"))
    return lines

# ============================================================================
# Параллельная проверка с батчингом
# ============================================================================
def _check_parallel(proxies, xray, timeout, ifaces, cache, sub_index,
                    concurrency, server_timeout=SERVER_TIMEOUT_DEFAULT,
                    speed_test=True, speed_timeout=5.0,
                    min_down=0.05, min_up=0.02, require_upload=True,
                    double_check=True, discard_failed=True,
                    discard_log=DISCARD_FILE,
                    max_batch=MAX_BATCH_SIZE):
    results = {k: [] for k in ifaces}

    if double_check and discard_failed and discard_log:
        try: Path(discard_log).write_text("", encoding="utf-8")
        except Exception: pass

    total = len(proxies)
    if total == 0: return results

    n_batches = (total + max_batch - 1) // max_batch
    if n_batches > 1:
        print(f"\n[i] {total} серверов → {n_batches} батчей по ≤ {max_batch}")
    t_all_start = time.time()

    for batch_idx in range(n_batches):
        start = batch_idx * max_batch
        end   = min(start + max_batch, total)
        batch = proxies[start:end]
        t_batch_start = time.time()

        if n_batches > 1:
            print(f"\n{'═'*70}")
            print(f"[i] БАТЧ {batch_idx + 1}/{n_batches} — серверы {start + 1}…{end} из {total}")
            print(f"{'═'*70}")

        for iface_key, iface_name in ifaces.items():
            send_through = None
            if iface_name:
                send_through = _get_iface_ip(iface_name)
                if not send_through:
                    print(f"[!] интерфейс '{iface_name}' не найден")
                    continue

            def _run_batch(sub_batch, pass_label):
                if not sub_batch: return []
                pairs = []
                lock = threading.Lock()
                done = [0]; tot = len(sub_batch)
                print_lock = threading.Lock()

                def _w(pr):
                    prior = ""
                    it = cache.items.get(pr.dedup_key(), {})
                    if it and it.get("country_code"): prior = it["country_code"]
                    r = check_proxy(pr, xray, timeout, send_through,
                                    prior_cc=prior, server_timeout=server_timeout,
                                    speed_test=speed_test, speed_timeout=speed_timeout,
                                    min_down=min_down, min_up=min_up,
                                    require_upload=require_upload)
                    cache.upsert(pr, r, sub_index)
                    with lock:
                        pairs.append((pr, r)); done[0] += 1
                        n = done[0]
                    label = pr.name or f"{pr.kind}://{pr.params.get('server')}"
                    with print_lock:
                        dn = r.get("download_mbps"); up = r.get("upload_mbps")
                        sp_s = ""
                        if dn is not None or up is not None:
                            sp_s = (f" ↓{dn if dn is not None else '—'}Mbps "
                                    f"↑{up if up is not None else '—'}Mbps")
                        if r["ok"]:
                            flag = flag_from_cc(r.get("country_code", ""))
                            cn = country_ru(r.get("country_code", ""))
                            ka = r.get("latency_keepalive")
                            ka_s = f"ka={ka}ms" if ka is not None else "ka=—"
                            el = r.get("elapsed")
                            el_s = f" {el}s" if el is not None else ""
                            print(f"  {pass_label} [{n}/{tot}] OK {flag} {cn} {r['latency']}ms "
                                  f"{ka_s}{sp_s}{el_s} ip={r['ip']} | {label}", flush=True)
                        else:
                            el = r.get("elapsed")
                            el_s = f" {el}s" if el is not None else ""
                            print(f"  {pass_label} [{n}/{tot}] FAIL{sp_s}{el_s} "
                                  f"{r['error']} | {label}", flush=True)

                with cf.ThreadPoolExecutor(max_workers=concurrency) as ex:
                    list(ex.map(_w, sub_batch))
                return pairs

            first_pairs = _run_batch(batch, "1st")
            final_pairs = [(pr, r) for pr, r in first_pairs if r["ok"]]
            failed = [pr for pr, r in first_pairs if not r["ok"]]

            if double_check and failed:
                print(f"\n  ⟳ Двойная проверка: {len(failed)} серверов...")
                retry_pairs = _run_batch(failed, "2nd")
                success_retry = [(pr, r) for pr, r in retry_pairs if r["ok"]]
                still_failed  = [(pr, r) for pr, r in retry_pairs if not r["ok"]]
                final_pairs.extend(success_retry)
                if still_failed:
                    if discard_failed:
                        for pr, r in still_failed:
                            cache.items.pop(pr.dedup_key(), None)
                            if discard_log:
                                try:
                                    with open(discard_log, "a", encoding="utf-8") as f:
                                        f.write(f"{pr.raw or pr.name}\t{r.get('error') or 'timeout'}\n")
                                except Exception: pass
                    else:
                        final_pairs.extend(still_failed)
            elif failed and not double_check:
                final_pairs.extend([(pr, r) for pr, r in first_pairs if not r["ok"]])

            results[iface_key].extend(final_pairs)

        if n_batches > 1:
            try:
                cache.save()
                dt_batch = time.time() - t_batch_start
                dt_all = time.time() - t_all_start
                eta = (dt_all / (batch_idx + 1)) * (n_batches - batch_idx - 1)
                print(f"\n[i] батч {batch_idx + 1}/{n_batches} за {dt_batch:.0f}s, "
                      f"кэш сохранён. ETA ~{eta/60:.0f} мин")
            except Exception as e:
                print(f"[!] кэш не сохранён: {e}")

    return results

# ============================================================================
# Финальная запись
# ============================================================================
def _write_final(cache, writer, sources_count, final_file="working.txt",
                 stable_cfg=None, new_cfg=None,
                 top_fastest_count=TOP_FASTEST_COUNT):
    print(f"\n[i] кэш сохранён: {len(cache.items)} записей")

    new_window = (new_cfg.get("recent_hours", 24.0)
                  if new_cfg and new_cfg.get("enabled", True) else None)
    new_proxies = []
    if new_window is not None:
        new_proxies = cache.new_all(recent_hours=new_window)
    new_keys = {p.dedup_key() for p in new_proxies}

    stable_proxies = []
    if stable_cfg and stable_cfg.get("enabled", True):
        stable_proxies = [
            p for p in cache.stable_all(
                min_checks=stable_cfg["min_checks"], min_rate=stable_cfg["min_rate"],
                min_consecutive=stable_cfg["min_consecutive"],
                recent_hours=stable_cfg["recent_hours"])
            if new_window is None or p.dedup_key() not in new_keys
        ]

    by_first = cache.working_by_first_sub()
    for sub_index in range(1, sources_count + 1):
        working = by_first.get(sub_index, [])
        lines = _named_lines(cache, working, stable_cfg, new_cfg)
        writer.write_working_for_sub(sub_index, lines)

    all_working = cache.working_all()
    lines_all = _named_lines(cache, all_working, stable_cfg, new_cfg)
    writer.write_working_all(lines_all)
    print(f"[i] Working/all.txt: {len(all_working)} рабочих "
          f"(⚡ {len(stable_proxies)}, 🟢 {len(new_proxies)})")

    speed_lines = []
    for v in cache.items.values():
        if v.get("status") != "working": continue
        dn = v.get("download_mbps"); up = v.get("upload_mbps")
        if dn is None and up is None: continue
        p = cache.to_proxy(v)
        cluster = cache.classify(v, stable_cfg, new_cfg)
        mark = marker_for(cluster, stable_cfg, new_cfg)
        pref = f"{mark} " if mark else ""
        speed_lines.append(f"{pref}↓{dn}Mbps\t↑{up}Mbps\t{v.get('latency')}ms\t{dump_to_uri(p)}")
    if speed_lines:
        writer.write_speeds(speed_lines)
        print(f"[i] speeds.txt: {len(speed_lines)} строк")

    try:
        result = writer.write_top_fastest(cache, top_fastest_count)
        if result:
            path, top = result
            print(f"[i] AllWorking/{path.name}: {len(top)} серверов "
                  f"(топ по скорости/пингу)")
            for i, v in enumerate(top[:5], 1):
                dn = v.get("download_mbps")
                up = v.get("upload_mbps")
                lat = v.get("latency")
                flag = resolve_flag(v)
                cc = country_ru(v.get("country_code", ""))
                s_dn = f"↓{dn}Mbps" if dn is not None else "↓—"
                s_up = f"↑{up}Mbps" if up is not None else "↑—"
                s_lat = f"{lat}ms" if lat is not None else "?ms"
                print(f"    #{i} {flag} {cc}: {s_dn} {s_up} {s_lat}")
        else:
            print("[i] top150.txt: нет данных (все серверы без скорости и пинга)")
    except Exception as e:
        print(f"[!] top150 ошибка: {e}")

    all_unworking = cache.unworking_all()
    writer.write_unworking_all(all_unworking)

    _blacklisted = cache.blacklisted_items()
    if _blacklisted:
        writer.write_blacklisted(_blacklisted)
        print(f"[i] UnWorking/all.txt: {len(all_unworking)} нерабочих "
              f"(из них {len(_blacklisted)} в блэклисте)")
        print(f"[i] UnWorking/blacklisted.txt: {len(_blacklisted)} серверов")
    else:
        print(f"[i] UnWorking/all.txt: {len(all_unworking)} нерабочих")

    snap_txt, _ = writer.write_versioned_all_working(lines_all)
    print(f"[i] AllWorking/{snap_txt.name} ({len(all_working)} рабочих)")

    try:
        latest_json, snap_json = writer.write_latest_json(cache, stable_cfg, new_cfg)
        print(f"[i] AllWorking/{latest_json.name}")
    except Exception as e:
        print(f"[!] latest.json ошибка: {e}")

    if stable_proxies:
        try:
            paths = writer.write_stable(cache, stable_proxies, stable_cfg, new_cfg)
            print(f"[i] stable.txt: {len(stable_proxies)} ⚡")
        except Exception as e:
            print(f"[!] stable ошибка: {e}")

    if new_proxies and new_cfg and new_cfg.get("output", True):
        try:
            paths = writer.write_new(cache, new_proxies, stable_cfg, new_cfg)
            print(f"[i] new.txt: {len(new_proxies)} 🟢")
        except Exception as e:
            print(f"[!] new ошибка: {e}")

    try:
        Path(final_file).write_text(
            "\n".join(lines_all) + ("\n" if lines_all else ""),
            encoding="utf-8")
        print(f"[i] {final_file}: {len(all_working)} рабочих")
    except Exception as e:
        print(f"[!] {final_file}: {e}")

def _collect_proxies_from_uris(uris):
    out = []
    for u in uris:
        u = u.strip()
        if not u or u.startswith("#"): continue
        p = parse_uri(u)
        if p and p.params.get("server"): out.append(p)
    return out

def _detect_country(session, timeout):
    with _COUNTRY_SEM:
        for url, name in COUNTRY_SOURCES:
            try:
                r = session.get(url, timeout=timeout)
                if r.status_code == 200:
                    data = r.json()
                    if name == "ip-api":
                        if data.get("status") == "success":
                            return data.get("countryCode", ""), data.get("country", ""), data.get("query", "")
                    elif name == "ipwho":
                        return data.get("country_code", ""), data.get("country", ""), data.get("ip", "")
                    elif name == "ipapi-co":
                        return data.get("country_code", ""), data.get("country_name", ""), data.get("ip", "")
                    elif name == "ipinfo":
                        return data.get("country", ""), data.get("country", ""), data.get("ip", "")
            except Exception:
                continue
    return "", "", ""

# ============================================================================
# main
# ============================================================================
def main():
    ap = argparse.ArgumentParser(
        description="Combined Source Loader + Xray Checker (batched, blacklist, split cache, top-fastest)")
    ap.add_argument("--no-load", action="store_true")
    ap.add_argument("-i", "--input", default=CONFIGS_FILE)
    ap.add_argument("-o", "--output-dir", default="output")
    ap.add_argument("--cache", default="cache.json")
    ap.add_argument("-c", "--concurrency", type=int, default=16)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--server-timeout", type=float, default=6.0)
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
    ap.add_argument("--include-blacklisted", action="store_true",
                    help=f"не пропускать серверы с fail_count >= {BLACKLIST_FAIL_THRESHOLD}")
    ap.add_argument("--reset-blacklist", action="store_true",
                    help="сбросить fail_count у всех серверов")
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
    ap.add_argument("--top-fastest", type=int, default=TOP_FASTEST_COUNT,
                    help=f"сколько серверов в topN (default: {TOP_FASTEST_COUNT})")

    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--only-new", action="store_true")
    mode.add_argument("--only-old", action="store_true")
    args = ap.parse_args()

    if args.concurrency < 1: args.concurrency = 1
    if args.concurrency > MAX_CONCURRENCY:
        print(f"[!] -c {args.concurrency} → {MAX_CONCURRENCY}")
        args.concurrency = MAX_CONCURRENCY
    if args.max_batch < 100:
        print(f"[!] --max-batch={args.max_batch} → 100")
        args.max_batch = 100

    check_kwargs = dict(
        server_timeout=args.server_timeout,
        speed_test=not args.no_speed,
        speed_timeout=args.speed_timeout,
        min_down=args.min_down,
        min_up=args.min_up,
        require_upload=not args.no_upload_check,
        double_check=not args.no_double_check,
        discard_failed=not args.keep_failed,
        discard_log=args.discard_log,
        max_batch=args.max_batch,
    )

    stable_cfg = {
        "enabled": not args.no_stable,
        "min_checks": args.stable_min_checks,
        "min_rate": args.stable_min_rate,
        "min_consecutive": args.stable_min_consecutive,
        "recent_hours": args.stable_recent_hours,
        "marker": args.stable_marker,
    }
    new_cfg = {
        "enabled": not args.no_new_marker,
        "recent_hours": args.new_recent_hours,
        "marker": args.new_marker,
        "output": not args.no_new_output,
    }

    cache = Cache(Path(args.cache))
    writer = OutputWriter(Path(args.output_dir))

    extra_uris_from_loader = []
    if not args.only_old and not args.no_load:
        loaded, my_cfgs, _stats = asyncio.run(load_http_sources())
        extra_uris_from_loader = list(loaded) + list(my_cfgs)
        src_path = Path(SOURCES_FILE)
        sources = []
        if src_path.exists():
            sources = [l.strip() for l in src_path.read_text(
                encoding="utf-8", errors="replace").splitlines()
                if l.strip() and not l.strip().startswith("#")]
    else:
        src_path = Path(SOURCES_FILE)
        sources = []
        if not args.only_old and src_path.exists():
            sources = [l.strip() for l in src_path.read_text(
                encoding="utf-8", errors="replace").splitlines()
                if l.strip() and not l.strip().startswith("#")]

    print(f"\n[i] режим: {'only-new' if args.only_new else 'only-old' if args.only_old else 'all'}")
    print(f"[i] источников: {len(sources)}")
    print(f"[i] параллельно: {args.concurrency} | бюджет: {args.server_timeout}s")
    print(f"[i] батч: ≤{args.max_batch}")
    print(f"[i] двойная: {'ВКЛ' if check_kwargs['double_check'] else 'ВЫКЛ'} "
          f"| выбрасывать: {'ДА' if check_kwargs['discard_failed'] else 'НЕТ'}")
    print(f"[i] скорость: {'ВКЛ' if check_kwargs['speed_test'] else 'ВЫКЛ'}")
    print(f"[i] стабильные: {'ВКЛ' if stable_cfg['enabled'] else 'ВЫКЛ'} "
          f"| новые: {'ВКЛ' if new_cfg['enabled'] else 'ВЫКЛ'}")
    print(f"[i] в кэше: {len(cache.items)} записей")
    _bl_count = len(cache.blacklisted_keys())
    if _bl_count:
        print(f"[i] в блэклисте: {_bl_count} серверов (fail_count >= {BLACKLIST_FAIL_THRESHOLD})")
    print(f"[i] порог разбиения кэша: {CACHE_SPLIT_THRESHOLD_MB} MB")
    print(f"[i] top-fastest: {args.top_fastest}")

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

    input_path = Path(args.input)
    file_uris = []
    if input_path.exists():
        for line in input_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                file_uris.append(line)

    if extra_uris_from_loader:
        all_uris = extra_uris_from_loader
    else:
        all_uris = file_uris

    if not all_uris and sources and (args.only_old or args.no_load):
        for s in sources:
            p = parse_uri(s)
            if p: all_uris.append(s)

    proxies = _collect_proxies_from_uris(all_uris)
    print(f"[i] распарсено URI: {len(all_uris)} → валидных Proxy: {len(proxies)}")

    if args.reset_blacklist:
        _n = 0
        for _v in cache.items.values():
            if int(_v.get("fail_count", 0)) > 0:
                _v["fail_count"] = 0
                _n += 1
        print(f"[i] blacklist сброшен у {_n} серверов")
        cache.save()

    if not args.include_blacklisted:
        _bl = cache.blacklisted_keys()
        if _bl:
            _before = len(proxies)
            proxies = [p for p in proxies if p.dedup_key() not in _bl]
            _skipped = _before - len(proxies)
            if _skipped:
                print(f"[i] пропущено блэклистнутых: {_skipped}")

    prev_final_proxies = []
    if not args.no_recheck_final and not args.only_new:
        paths = [s.strip() for s in args.recheck_files.split(",") if s.strip()]
        print(f"[i] recheck-files: {paths}")
        prev_final_proxies = _load_recheck_files(paths)
        if prev_final_proxies and not args.include_blacklisted:
            _bl = cache.blacklisted_keys()
            prev_final_proxies = [p for p in prev_final_proxies if p.dedup_key() not in _bl]
        if prev_final_proxies:
            print(f"[i] для перепроверки: {len(prev_final_proxies)}")

    if args.only_old:
        cached = []
        for it in cache.items.values():
            if not args.include_blacklisted and cache.is_blacklisted(it): continue
            p = cache.to_proxy(it)
            if p and p.params.get("server"): cached.append(p)
        cached.extend(prev_final_proxies)
        if not args.include_blacklisted:
            _bl = cache.blacklisted_keys()
            cached = [p for p in cached if p.dedup_key() not in _bl]
        uniq = _dedup(cached)
        print(f"[i] перепроверяю старые: {len(uniq)}")
        if uniq:
            _check_parallel(uniq, xray, args.timeout, ifaces, cache, sub_index=0,
                            concurrency=args.concurrency, **check_kwargs)
        cache.save()
        _write_final(cache, writer, 0, args.final_file,
                     stable_cfg=stable_cfg, new_cfg=new_cfg,
                     top_fastest_count=args.top_fastest)
        return

    if args.only_new:
        known = set(cache.items.keys())
        if args.include_blacklisted:
            known -= cache.blacklisted_keys()
        new_only = [p for p in proxies if p.dedup_key() not in known]
        print(f"[i] only-new: всего {len(proxies)}, новых {len(new_only)}")
        if new_only:
            _check_parallel(new_only, xray, args.timeout, ifaces, cache, sub_index=1,
                            concurrency=args.concurrency, **check_kwargs)
        cache.save()
        _write_final(cache, writer, len(sources) or 1, args.final_file,
                     stable_cfg=stable_cfg, new_cfg=new_cfg,
                     top_fastest_count=args.top_fastest)
        return

    uniq = _dedup(proxies)
    if uniq:
        print(f"\n{'='*70}\n=== Проверка {len(uniq)} серверов\n{'='*70}")
        _check_parallel(uniq, xray, args.timeout, ifaces, cache, sub_index=1,
                        concurrency=args.concurrency, **check_kwargs)

    if prev_final_proxies:
        print(f"\n{'='*70}\n=== Перепроверка файлов: {len(prev_final_proxies)}\n{'='*70}")
        uniq_re = _dedup(prev_final_proxies)
        results = _check_parallel(uniq_re, xray, args.timeout, ifaces, cache,
                                  sub_index=999, concurrency=args.concurrency,
                                  **check_kwargs)
        sub_w, sub_u = [], []
        for _, pairs in results.items():
            for pr, r in pairs:
                (sub_w if r["ok"] else sub_u).append(pr)
        writer.write_sub_logs(999, _dedup(sub_w), _dedup(sub_u))

    cache.save()
    _write_final(cache, writer, max(len(sources), 1), args.final_file,
                 stable_cfg=stable_cfg, new_cfg=new_cfg,
                 top_fastest_count=args.top_fastest)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nОстановлено пользователем")
