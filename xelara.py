#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Combined Source Loader + Xray Parser & Checker
============================================
Один скрипт, который:
 1) Читает источники из sources.txt и my_configs.txt
 2) Скачивает источники асинхронно (aiohttp + THREADS)
    - обычный GET, при неудаче — резервный Happ-метод
    - извлекает vless://, trojan://, hy2:// из текста, base64, JSON, YAML
    - неудачные источники уходят в blacklist_sources.txt и удаляются из sources.txt
    - всё найденное пишется в configs.txt
 3) Прогоняет все конфиги через Xray-core (Working/UnWorking/AllWorking)
 4) Формирует working.txt, output/AllWorking/latest.json (по странам),
    перепроверяет ранее собранные файлы (--recheck-files)
"""

# ============================================================================
# Bootstrap зависимостей
# ============================================================================
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

# ============================================================================
# Импорты
# ============================================================================
import argparse
import asyncio
import base64
import concurrent.futures as cf
import hashlib
import json
import os
import platform
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

THREADS         = 50
TIMEOUT_NORMAL  = 5
TIMEOUT_HAPP    = 5

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 combined/1.0")

HWID_STATIC = "d060e73eb61d1ba7"
HAPP_USER_AGENTS = ["Happ/3.18.3/Android/17771400994551771562"]

CACHE_VERSION = 4
SERVER_TIMEOUT_DEFAULT = 8.0

TEST_URLS_FALLBACK = ["https://www.gstatic.com/generate_204"]
IP_URL = "https://api.ipify.org"

COUNTRY_SOURCES = [
    ("http://ip-api.com/json/?fields=status,countryCode,country,query", "ip-api"),
    ("https://ipwho.is/", "ipwho"),
    ("https://ipapi.co/json/", "ipapi-co"),
    ("https://ipinfo.io/json", "ipinfo"),
]
_COUNTRY_SEM = threading.Semaphore(3)

# ============================================================================
# Регулярки
# ============================================================================
VLESS_REGEX   = re.compile(r"vless://[^\s#]+", re.IGNORECASE)
TROJAN_REGEX  = re.compile(r"trojan://[^\s#]+", re.IGNORECASE)
HY2_REGEX     = re.compile(r"(?:hysteria2|hy2)://[^\s#]+", re.IGNORECASE)
URL_REGEX     = re.compile(r'https?://[^\s<>"\'(){}|\\^`\[\]]+', re.IGNORECASE)
BASE64_REGEX  = re.compile(r'^[A-Za-z0-9+/]+=*$', re.MULTILINE)
UUID_REGEX    = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
URI_REGEX     = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s\"'<>]+")

# ============================================================================
# Русские названия стран
# ============================================================================
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

# ============================================================================
# Общие утилиты
# ============================================================================
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
# Конвертеры JSON/YAML → URI (из loader'а)
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
    if not vnext:
        return None
    first = vnext[0]
    address = first.get('address'); port = first.get('port')
    users = first.get('users', [])
    if not users:
        return None
    user = users[0]
    uuid = user.get('id')
    if not uuid:
        return None
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
    if not servers:
        return None
    s = servers[0]
    address = s.get('address'); port = s.get('port'); password = s.get('password')
    if not all([address, port, password]):
        return None
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
    if not servers:
        return None
    s = servers[0]
    address = s.get('address'); port = s.get('port'); auth = s.get('auth', '')
    if not address or not port:
        return None
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
    if not all([server, port, uuid]):
        return None
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
    if not all([server, port, password]):
        return None
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
    if not all([server, port]):
        return None
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
                    if not isinstance(out, dict):
                        continue
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
        if not data or not isinstance(data, dict):
            return []
        proxies = data.get('proxies', [])
        if not isinstance(proxies, list):
            return []
        for proxy in proxies:
            ptype = proxy.get('type')
            if ptype == 'vless':
                url = yaml_proxy_to_vless_url(proxy)
            elif ptype == 'trojan':
                url = yaml_proxy_to_trojan_url(proxy)
            elif ptype in ('hysteria2', 'hy2'):
                url = yaml_proxy_to_hysteria2_url(proxy)
            else:
                continue
            if url and is_valid_config(url):
                urls.append(url)
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
            if deeper[1]:
                matches.extend(deeper[1])
        return decoded, matches
    except Exception:
        return None, []

def extract_configs_from_text(text: str):
    """Возвращает (vless_list, trojan_list, hy2_list, b64_cnt, json_cnt, yaml_cnt)."""
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
# Резервный Happ-метод
# ============================================================================
def fetch_with_happ_method(url: str) -> Optional[str]:
    parsed = urllib.parse.urlparse(url)
    if 'hwid=' not in url:
        separator = '&' if parsed.query else '?'
        url_with_hwid = f"{url}{separator}hwid={HWID_STATIC}"
    else:
        url_with_hwid = url
    for try_url in [url_with_hwid, url]:
        for ua in HAPP_USER_AGENTS:
            try:
                headers = {
                    "User-Agent": ua,
                    "X-HWID": HWID_STATIC,
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive",
                }
                resp = requests.get(try_url, headers=headers, timeout=TIMEOUT_HAPP)
                resp.raise_for_status()
                content = resp.text.strip()
                if "<html" in content.lower():
                    continue
                if BASE64_REGEX.match(content.replace('\n', '').replace('\r', '')):
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                    if decoded:
                        content = decoded
                return content
            except Exception:
                continue
    return None

# ============================================================================
# Асинхронная загрузка источников
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
            if used_happ:
                stats['happ_success'] += 1

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
        total_cfgs = stats['total_configs']
        happ = stats['happ_success']
        sys.stdout.write(
            f"\r|{bar}| {percent:.0f}% Скачано: {processed}/{total} | "
            f"VLESS: {v} | Trojan: {t} | Hysteria2: {h} | "
            f"Декодировано: {subs} | Happ: {happ} | Всего: {total_cfgs}"
        )
        sys.stdout.flush()
        await asyncio.sleep(0.3)

async def load_http_sources():
    """Загружает sources.txt, извлекает конфиги, сохраняет в configs.txt.
    Возвращает (all_configs, my_configs, stats)."""
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
        print(f"  Мои конфиги: {len(my_configs)} (будут добавлены в итоговый файл)")

    stats = {
        'processed': 0,
        'total_sources': total_sources,
        'vless_count': 0, 'trojan_count': 0, 'hy2_count': 0,
        'base64': 0, 'json': 0, 'yaml': 0,
        'total_configs': 0,
        'all_configs': [],
        'failed': [],
        'happ_success': 0,
        'lock': asyncio.Lock(),
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
        print(f"Удалено неудачных источников: {len(stats['failed'])} "
              f"(добавлены в {BLACKLIST_FILE})")

    all_configs = stats['all_configs'] + my_configs
    if all_configs:
        async with aiofiles.open(CONFIGS_FILE, 'a', encoding='utf-8') as f:
            for cfg in all_configs:
                await f.write(cfg + '\n')
        print(f"Добавлено конфигов в {CONFIGS_FILE}: {len(all_configs)}")
    else:
        print("Конфигов не найдено.")

    print(f"\n  Обработано источников: {stats['processed']}/{total_sources}")
    print(f"Всего извлечено конфигов: {stats['total_configs']}")
    print(f"VLESS: {stats['vless_count']} | Trojan: {stats['trojan_count']} | "
          f"Hysteria2: {stats['hy2_count']}")
    print(f"Расшифровано подписок: {stats['base64']+stats['json']+stats['yaml']} "
          f"(Base64: {stats['base64']}, JSON: {stats['json']}, YAML: {stats['yaml']})")
    print(f"Обработано через Happ: {stats['happ_success']}")
    print(f"Мои конфиги: {len(my_configs)}")

    return stats['all_configs'], my_configs, stats

# ============================================================================
# Proxy dataclass + URI-парсер (xray_parser)
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
        "type": cfg.get("type", "none") or "none",
        "host": cfg.get("host", ""), "path": cfg.get("path", ""),
        "tls": tls_on, "sni": cfg.get("sni", "") or cfg.get("host", ""),
        "fp": cfg.get("fp", ""), "alpn": cfg.get("alpn", ""),
        "security": "tls" if tls_on else "none",
        "extra": cfg.get("extra") or {},
    })

def _p_vless(uri):
    u = urlparse(uri)
    if not u.hostname:
        return None
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    extra = {}
    raw_extra = q.get("extra", "")
    if raw_extra:
        try:
            extra = json.loads(unquote(raw_extra))
        except Exception:
            extra = {}
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
                     "serviceName": q.get("serviceName", ""), "alpn": q.get("alpn", ""),
                     "headerType": q.get("headerType", ""), "mode": q.get("mode", ""),
                     "extra": extra,
                 })

def _p_trojan(uri):
    u = urlparse(uri)
    if not u.hostname:
        return None
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    return Proxy(raw=uri, kind="trojan",
                 name=unquote(u.fragment) if u.fragment else "",
                 params={
                     "server": u.hostname, "port": _safe_int(u.port, 443),
                     "password": unquote(u.username or ""),
                     "sni": q.get("sni", ""), "fp": q.get("fp", ""),
                     "network": q.get("type", "tcp") or "tcp",
                     "security": q.get("security", "tls") or "tls",
                     "path": q.get("path", ""), "host": q.get("host", ""),
                     "serviceName": q.get("serviceName", ""), "alpn": q.get("alpn", ""),
                     "allowInsecure": q.get("allowInsecure", "0") == "1",
                 })

def _p_ss(uri):
    body = uri[len("ss://"):]
    tag = ""
    if "#" in body:
        body, tag = body.split("#", 1)
    tag = unquote(tag) if tag else ""
    if "@" not in body:
        d = _b64decode(body)
        if "@" not in d:
            return None
        method_pw, host_port = d.rsplit("@", 1)
    else:
        ui, host_port = body.rsplit("@", 1)
        method_pw = unquote(ui) if ":" in ui else _b64decode(ui)
    if ":" not in method_pw or ":" not in host_port:
        return None
    method, password = method_pw.split(":", 1)
    host, port = host_port.rsplit(":", 1)
    return Proxy(raw=uri, kind="ss", name=tag, params={
        "server": host.strip(), "port": _safe_int(port.strip(), 8388),
        "method": method.strip(), "password": password,
        "network": "tcp", "security": "none",
    })

_P = {"vmess://": _p_vmess, "vless://": _p_vless,
      "trojan://": _p_trojan, "ss://": _p_ss}

def parse_uri(uri):
    uri = uri.strip()
    if not uri or uri.startswith("#"):
        return None
    for p, fn in _P.items():
        if uri.startswith(p):
            return fn(uri)
    return None

def _extract_uris(text):
    return URI_REGEX.findall(text)

def _host_ws(ss):
    ws = ss.get("wsSettings") or {}
    if ws.get("host"):
        return ws["host"]
    hv = (ws.get("headers") or {}).get("Host")
    if isinstance(hv, list) and hv:
        return hv[0]
    return hv if isinstance(hv, str) else ""

def _parse_json_sub(text):
    try:
        data = json.loads(text)
    except Exception:
        return []
    obs = []
    if isinstance(data, dict):
        obs = data.get("outbounds") or []
        if not obs and "configs" in data:
            for c in data["configs"]:
                obs.extend(c.get("outbounds", []))
    elif isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            if "outbounds" in item:
                obs.extend(item.get("outbounds") or [])
            elif item.get("protocol"):
                obs.append(item)
    return [r for r in (_ob_to_proxy(o) for o in obs) if r]

def _ob_to_proxy(ob):
    proto = (ob.get("protocol") or "").lower()
    s = ob.get("settings") or {}
    ss = ob.get("streamSettings") or {}
    tag = ob.get("tag", "")
    net = (ss.get("network") or "tcp").lower()
    sec = (ss.get("security") or "none").lower()
    if proto == "vless":
        v = (s.get("vnext") or [{}])[0]; u = (v.get("users") or [{}])[0]
        tl = ss.get("tlsSettings") or ss.get("realitySettings") or {}
        xh = ss.get("xhttpSettings") or {}; ws = ss.get("wsSettings") or {}
        gr = ss.get("grpcSettings") or {}
        return Proxy(kind="vless", name=tag, params={
            "server": v.get("address", ""), "port": _safe_int(v.get("port"), 443),
            "uuid": u.get("id", ""), "flow": u.get("flow", ""),
            "network": net, "security": sec,
            "sni": tl.get("serverName", ""), "fp": tl.get("fingerprint", ""),
            "pbk": (ss.get("realitySettings") or {}).get("publicKey", ""),
            "sid": (ss.get("realitySettings") or {}).get("shortId", ""),
            "spx": (ss.get("realitySettings") or {}).get("spiderX", "/"),
            "path": ws.get("path", "") or xh.get("path", ""),
            "host": _host_ws(ss) or xh.get("host", "") or gr.get("authority", ""),
            "serviceName": gr.get("serviceName", ""), "mode": xh.get("mode", ""),
            "alpn": ",".join(tl.get("alpn", []) or []),
            "extra": xh.get("extra") or {},
        })
    if proto == "vmess":
        v = (s.get("vnext") or [{}])[0]; u = (v.get("users") or [{}])[0]
        tl = ss.get("tlsSettings") or {}; xh = ss.get("xhttpSettings") or {}
        return Proxy(kind="vmess", name=tag, params={
            "server": v.get("address", ""), "port": _safe_int(v.get("port"), 443),
            "uuid": u.get("id", ""), "alterId": _safe_int(u.get("alterId"), 0),
            "cipher": u.get("security", "auto"),
            "network": net, "security": sec,
            "sni": tl.get("serverName", ""), "fp": tl.get("fingerprint", ""),
            "host": _host_ws(ss) or xh.get("host", ""),
            "path": (ss.get("wsSettings") or {}).get("path", "") or xh.get("path", ""),
            "extra": xh.get("extra") or {},
        })
    if proto == "trojan":
        srv = (s.get("servers") or [{}])[0]; tl = ss.get("tlsSettings") or {}
        xh = ss.get("xhttpSettings") or {}
        return Proxy(kind="trojan", name=tag, params={
            "server": srv.get("address", ""), "port": _safe_int(srv.get("port"), 443),
            "password": srv.get("password", ""),
            "network": net, "security": sec or "tls",
            "sni": tl.get("serverName", ""), "fp": tl.get("fingerprint", ""),
            "host": _host_ws(ss) or xh.get("host", ""),
            "path": (ss.get("wsSettings") or {}).get("path", "") or xh.get("path", ""),
            "extra": xh.get("extra") or {},
        })
    if proto == "shadowsocks":
        srv = (s.get("servers") or [{}])[0]
        return Proxy(kind="ss", name=tag, params={
            "server": srv.get("address", ""), "port": _safe_int(srv.get("port"), 8388),
            "method": srv.get("method", ""), "password": srv.get("password", ""),
            "network": "tcp", "security": "none",
        })
    return None

def parse_response_body(body):
    body = body.strip()
    if not body:
        return []
    if body.lstrip().startswith(("{", "[")):
        return _parse_json_sub(body)
    uris = _extract_uris(body)
    if uris:
        return [p for p in (parse_uri(u) for u in uris) if p]
    d = _b64decode(re.sub(r"\s+", "", body))
    if d:
        dd = d.strip()
        if dd.lstrip().startswith(("{", "[")):
            jp = _parse_json_sub(dd)
            if jp:
                return jp
        return [p for p in (parse_uri(u) for u in _extract_uris(dd)) if p]
    return []

def dump_to_uri(pr, override_name=None):
    if override_name is None and pr.raw:
        return pr.raw
    name = override_name if override_name is not None else pr.name
    p = pr.params
    if pr.kind == "vless":
        q = []
        if p.get("security") and p["security"] != "none": q.append(f"security={p['security']}")
        if p.get("network") and p["network"] != "tcp":    q.append(f"type={p['network']}")
        for k in ("sni", "fp", "pbk", "sid", "spx", "flow", "path", "host", "mode", "serviceName"):
            if p.get(k):
                q.append(f"{k}={p[k]}")
        if p.get("alpn"):       q.append(f"alpn={p['alpn']}")
        if p.get("headerType"): q.append(f"headerType={p['headerType']}")
        if p.get("extra"):
            try:
                js = json.dumps(p["extra"], ensure_ascii=False, separators=(",", ":"))
                q.append(f"extra={quote(js, safe='')}")
            except Exception:
                pass
        frag = f"#{name}" if name else ""
        return f"vless://{p.get('uuid','')}@{p['server']}:{p['port']}?{'&'.join(q)}{frag}"
    if pr.kind == "trojan":
        q = []
        if p.get("sni"): q.append(f"sni={p['sni']}")
        if p.get("security") and p["security"] != "tls": q.append(f"security={p['security']}")
        frag = f"#{name}" if name else ""
        return f"trojan://{p.get('password','')}@{p['server']}:{p['port']}?{'&'.join(q)}{frag}"
    if pr.kind == "ss":
        ui = base64.b64encode(f"{p.get('method','')}:{p.get('password','')}".encode()).decode()
        frag = f"#{name}" if name else ""
        return f"ss://{ui}@{p['server']}:{p['port']}{frag}"
    if pr.kind == "vmess":
        obj = {"v": "2", "ps": name, "add": p["server"], "port": str(p["port"]),
               "id": p.get("uuid", ""), "aid": str(p.get("alterId", 0)),
               "scy": p.get("cipher", "auto"), "net": p.get("network", "tcp"),
               "type": "none", "host": p.get("host", ""), "path": p.get("path", ""),
               "tls": "tls" if p.get("tls") else "", "sni": p.get("sni", ""),
               "fp": p.get("fp", "")}
        if p.get("extra"):
            obj["extra"] = p["extra"]
        return "vmess://" + base64.b64encode(
            json.dumps(obj, ensure_ascii=False).encode()).decode()
    return pr.raw or ""

# ============================================================================
# Кэш
# ============================================================================
class Cache:
    def __init__(self, path):
        self.path = path
        self.items = {}
        self.lock = threading.Lock()
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                self.items = data.get("items", {}) or {}
            except Exception as e:
                print(f"[!] кэш не прочитан: {e}")

    def save(self):
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(
            {"version": CACHE_VERSION, "updated": _now(), "items": self.items},
            ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def upsert(self, pr, result, sub_index):
        key = pr.dedup_key()
        with self.lock:
            it = self.items.get(key)
            if not it:
                it = {"kind": pr.kind, "params": dict(pr.params),
                      "name": pr.name, "raw": pr.raw or dump_to_uri(pr),
                      "status": "unworking", "first_sub_index": sub_index,
                      "latency": None, "latency_keepalive": None,
                      "country_code": "", "country": "",
                      "ip": None, "test_url": None, "error": None,
                      "elapsed": None,
                      "first_seen": _now(), "last_checked": None,
                      "last_working": None, "fail_count": 0, "aliases": []}
            else:
                if pr.raw:
                    it["raw"] = pr.raw
                if pr.name and pr.name != it.get("name"):
                    al = it.setdefault("aliases", [])
                    if it["name"] and it["name"] not in al:
                        al.append(it["name"])
                    if pr.name not in al:
                        al.append(pr.name)
                    it["name"] = pr.name
                if "first_sub_index" not in it:
                    it["first_sub_index"] = sub_index

            it["last_checked"] = _now()
            it["latency"] = result.get("latency")
            it["latency_keepalive"] = result.get("latency_keepalive")
            it["ip"] = result.get("ip")
            it["error"] = result.get("error")
            it["elapsed"] = result.get("elapsed")
            it["country_code"] = result.get("country_code") or it.get("country_code", "") or ""
            it["country"]      = result.get("country")      or it.get("country", "")      or ""
            it["test_url"]     = result.get("test_url")
            if result.get("ok"):
                it["status"] = "working"
                it["last_working"] = _now()
                it["fail_count"] = 0
            else:
                it["status"] = "unworking"
                it["fail_count"] = int(it.get("fail_count", 0)) + 1
            self.items[key] = it
            return it

    def to_proxy(self, item):
        return Proxy(raw=item.get("raw", ""), kind=item.get("kind", ""),
                     params=item.get("params") or {}, name=item.get("name", ""))

    def working_all(self):
        return [self.to_proxy(v) for v in self.items.values()
                if v.get("status") == "working" and v.get("params", {}).get("server")]

    def unworking_all(self):
        return [self.to_proxy(v) for v in self.items.values()
                if v.get("status") == "unworking" and v.get("params", {}).get("server")]

    def working_by_first_sub(self):
        m = {}
        for v in self.items.values():
            if v.get("status") == "working" and v.get("params", {}).get("server"):
                m.setdefault(v.get("first_sub_index", 0), []).append(self.to_proxy(v))
        return m

# ============================================================================
# Xray Manager
# ============================================================================
def _download(url, dest, attempts=3, timeout=60):
    for i in range(1, attempts + 1):
        try:
            with requests.get(url, stream=True, timeout=timeout,
                              headers={"User-Agent": USER_AGENT}) as r:
                r.raise_for_status()
                total = int(r.headers.get("Content-Length", 0))
                got = 0
                with dest.open("wb") as f:
                    for chunk in r.iter_content(65536):
                        if not chunk:
                            continue
                        f.write(chunk)
                        got += len(chunk)
                        if total:
                            print(f"\r    [{i}/{attempts}] {int(got*100/total)}% "
                                  f"({got//1024}/{total//1024} KiB)", end="")
                print()
            return True
        except Exception as e:
            print(f"\n    [!] попытка {i}/{attempts}: {e}")
            if dest.exists():
                dest.unlink(missing_ok=True)
            if i < attempts:
                time.sleep(2)
    return False

class XrayManager:
    def __init__(self, work_dir="xray_bin"):
        self.dir = Path(work_dir)
        self.dir.mkdir(exist_ok=True)
        name = "xray.exe" if platform.system() == "Windows" else "xray"
        self.bin = self.dir / name

    def _asset(self):
        s = platform.system(); a = platform.machine().lower()
        if s == "Windows":
            if a in ("amd64", "x86_64"):  return "Xray-windows-64.zip"
            if a in ("arm64", "aarch64"): return "Xray-windows-arm64-v8a.zip"
            return "Xray-windows-32.zip"
        if s == "Linux":
            return "Xray-linux-arm64-v8a.zip" if a in ("aarch64", "arm64") else "Xray-linux-64.zip"
        if s == "Darwin":
            return "Xray-macos-arm64-v8a.zip" if a in ("aarch64", "arm64") else "Xray-macos-64.zip"
        raise RuntimeError(f"{s} {a}")

    def ensure(self):
        if self.bin.exists():
            print(f"[xray] готов: {self.bin}")
            return self.bin
        asset = self._asset()
        urls = [f"https://github.com/XTLS/Xray-core/releases/latest/download/{asset}",
                f"https://github.com/XTLS/Xray-core/releases/download/v1.8.24/{asset}"]
        z = self.dir / asset
        ok = False
        for u in urls:
            print(f"[xray] скачиваю: {u}")
            if _download(u, z):
                ok = True
                break
        if not ok:
            raise RuntimeError("Xray не скачался")
        with zipfile.ZipFile(z) as zf:
            zf.extractall(self.dir)
        z.unlink(missing_ok=True)
        if not self.bin.exists():
            for p in self.dir.iterdir():
                if p.is_file() and p.stem.lower() == "xray":
                    p.rename(self.bin)
                    break
        if not self.bin.exists():
            raise RuntimeError("xray не найден")
        if platform.system() != "Windows":
            self.bin.chmod(self.bin.stat().st_mode | stat.S_IEXEC)
        print(f"[xray] готов: {self.bin}")
        return self.bin

    def run(self, cfg):
        kw = {}
        if platform.system() == "Windows":
            kw["creationflags"] = _sp.CREATE_NO_WINDOW
        return _sp.Popen([str(self.bin), "run", "-config", str(cfg)],
                         stdout=_sp.PIPE, stderr=_sp.PIPE,
                         stdin=_sp.DEVNULL, **kw)

def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def _wait_port(port, timeout=6.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.3):
                return True
        except OSError:
            time.sleep(0.05)
    return False

# ============================================================================
# Checker
# ============================================================================
def _get_iface_ip(name):
    try:
        import psutil
    except ImportError:
        return None
    addrs = psutil.net_if_addrs()
    if name not in addrs:
        return None
    for a in addrs[name]:
        if a.family == socket.AF_INET and not a.address.startswith(("127.", "169.254.")):
            return a.address
    return None

def _stream_settings(p):
    net = (p.get("network") or "tcp").lower()
    sec = (p.get("security") or "").lower()
    extra = p.get("extra") or {}
    ss = {"network": net}
    if net == "ws":
        ws = {"path": p.get("path", "/") or "/"}
        if p.get("host"):
            ws["headers"] = {"Host": p["host"]}
        ss["wsSettings"] = ws
    elif net == "grpc":
        g = {}
        if p.get("serviceName"): g["serviceName"] = p["serviceName"]
        if p.get("host"):        g["authority"] = p["host"]
        ss["grpcSettings"] = g
    elif net == "httpupgrade":
        hu = {"path": p.get("path", "/") or "/"}
        if p.get("host"):
            hu["host"] = p["host"]
        ss["httpupgradeSettings"] = hu
    elif net == "xhttp":
        xh = {"path": p.get("path", "/") or "/",
              "mode": p.get("mode", "") or "auto"}
        if p.get("host"): xh["host"] = p["host"]
        if extra:         xh["extra"] = extra
        ss["xhttpSettings"] = xh
    elif net == "tcp" and p.get("headerType") == "http":
        ss["tcpSettings"] = {"header": {"type": "http",
            "request": {"path": [p.get("path", "/") or "/"],
                        "headers": {"Host": [p["host"]] if p.get("host") else []}}}}
    if sec == "tls":
        ss["security"] = "tls"
        tls = {}
        if p.get("sni"): tls["serverName"] = p["sni"]
        if p.get("fp"):  tls["fingerprint"] = p["fp"]
        if p.get("alpn"): tls["alpn"] = [a for a in p["alpn"].split(",") if a]
        if p.get("allowInsecure"): tls["allowInsecure"] = True
        ss["tlsSettings"] = tls
    elif sec == "reality":
        ss["security"] = "reality"
        rs = {"show": False, "fingerprint": p.get("fp") or "chrome",
              "spiderX": p.get("spx") or "/"}
        if p.get("sni"): rs["serverName"] = p["sni"]
        if p.get("pbk"): rs["publicKey"] = p["pbk"]
        if p.get("sid"): rs["shortId"] = p["sid"]
        ss["realitySettings"] = rs
    return ss

def _outbound(pr):
    p = pr.params; k = pr.kind
    if k == "vless":
        u = {"id": p.get("uuid", ""), "encryption": "none"}
        if p.get("flow"):
            u["flow"] = p["flow"]
        return {"protocol": "vless",
                "settings": {"vnext": [{"address": p["server"], "port": p["port"],
                                        "users": [u]}]},
                "streamSettings": _stream_settings(p)}
    if k == "vmess":
        return {"protocol": "vmess",
                "settings": {"vnext": [{"address": p["server"], "port": p["port"],
                    "users": [{"id": p.get("uuid", ""),
                               "alterId": p.get("alterId", 0),
                               "security": p.get("cipher", "auto")}]}]},
                "streamSettings": _stream_settings(p)}
    if k == "trojan":
        return {"protocol": "trojan",
                "settings": {"servers": [{"address": p["server"], "port": p["port"],
                                          "password": p.get("password", "")}]},
                "streamSettings": _stream_settings(p)}
    if k == "ss":
        return {"protocol": "shadowsocks",
                "settings": {"servers": [{"address": p["server"], "port": p["port"],
                                          "method": p.get("method", ""),
                                          "password": p.get("password", "")}]}}
    raise ValueError(k)

def _parse_country_response(name, data):
    if not isinstance(data, dict):
        return "", "", ""
    try:
        if name == "ip-api" and data.get("status") == "success":
            return data.get("countryCode", ""), data.get("country", ""), data.get("query", "")
        if name == "ipwho" and data.get("success"):
            return data.get("country_code", ""), data.get("country", ""), data.get("ip", "")
        if name == "ipapi-co" and data.get("country_code"):
            return data.get("country_code", ""), data.get("country_name", ""), data.get("ip", "")
        if name == "ipinfo" and data.get("country"):
            return data.get("country", ""), data.get("country", ""), data.get("ip", "")
    except Exception:
        pass
    return "", "", ""

def _detect_country(session, timeout):
    for url, name in COUNTRY_SOURCES:
        if not _COUNTRY_SEM.acquire(timeout=timeout):
            continue
        try:
            try:
                r = session.get(url, timeout=timeout)
                if r.status_code == 200:
                    cc, cn, ip = _parse_country_response(name, r.json())
                    if cc:
                        return cc, cn, ip
            except Exception:
                pass
        finally:
            _COUNTRY_SEM.release()
    return "", "", ""

def check_proxy(pr, xray, timeout=8.0, send_through=None,
                prior_cc="", server_timeout=None):
    budget = server_timeout if server_timeout is not None else SERVER_TIMEOUT_DEFAULT
    t_start = time.time()

    def remaining():
        return max(0.0, budget - (time.time() - t_start))

    port = _free_port()
    ob = _outbound(pr)
    if send_through:
        ob.setdefault("streamSettings", {}).setdefault("sockopt", {})["sendThrough"] = send_through
    cfg = {"log": {"loglevel": "warning"},
           "dns": {"queryStrategy": "UseIP",
                   "servers": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]},
           "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                         "settings": {"auth": "noauth", "udp": False}}],
           "outbounds": [ob]}

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                     encoding="utf-8") as f:
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
                    "ip": None, "country_code": "", "country": "",
                    "test_url": None, "error": msg,
                    "elapsed": round(time.time() - t_start, 2)}

        session = requests.Session()
        session.proxies = {"http": f"socks5h://127.0.0.1:{port}",
                           "https": f"socks5h://127.0.0.1:{port}"}
        session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*",
                                "Connection": "keep-alive"})
        session.mount("http://", HTTPAdapter(max_retries=0))
        session.mount("https://", HTTPAdapter(max_retries=0))

        lat = None
        working_url = None
        last_err = "нет ответа"
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
                    lat = dt
                    working_url = url
                    break
                last_err = f"HTTP {r1.status_code}"
            except requests.exceptions.RequestException as e:
                last_err = str(e)[:60]
                continue

        if working_url is None:
            session.close()
            return {"ok": False, "latency": None, "latency_keepalive": None,
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

# ============================================================================
# Утилиты для сборки отчётов
# ============================================================================
def fetch_url(url, timeout=20):
    try:
        s = requests.Session()
        s.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*",
                          "Accept-Encoding": "gzip, deflate, br"})
        s.mount("http://", HTTPAdapter(max_retries=2))
        s.mount("https://", HTTPAdapter(max_retries=2))
        r = s.get(url, timeout=timeout, allow_redirects=True)
        if r.status_code != 200:
            print(f"    [!] HTTP {r.status_code}")
            return None
        return r.text
    except requests.exceptions.SSLError:
        try:
            r = requests.get(url, timeout=timeout, verify=False,
                             headers={"User-Agent": USER_AGENT})
            if r.status_code == 200:
                return r.text
        except Exception:
            pass
        return None
    except Exception as e:
        print(f"    [!] {e}")
        return None

def _dedup(proxies):
    seen = set(); out = []
    for p in proxies:
        if not p or not p.params.get("server"):
            continue
        k = p.dedup_key()
        if k in seen:
            continue
        seen.add(k); out.append(p)
    return out

def _load_recheck_files(paths):
    result = []
    for path_str in paths:
        path_str = path_str.strip()
        if not path_str:
            continue
        p = Path(path_str)
        if not p.exists():
            print(f"[i] recheck: {path_str} — не найден, пропуск")
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"[!] recheck: не удалось прочитать {path_str}: {e}")
            continue

        parsed = parse_response_body(text)
        if not parsed:
            for u in _extract_uris(text):
                pr = parse_uri(u)
                if pr:
                    parsed.append(pr)
        print(f"[i] recheck: {path_str} → {len(parsed)} серверов")
        result.extend(parsed)
    return _dedup(result)

def _build_country_config(cc, cn, servers):
    flag = flag_from_cc(cc) if cc else "🏳️"
    name = cn or country_ru(cc)
    remarks = f"{flag} {name} | @XelaraVpn"
    prefix = (cc or "xx").lower()

    outbounds, tags = [], []
    for i, (pr, _r) in enumerate(servers, 1):
        tag = f"{prefix}-{i}"
        ob = _outbound(pr)
        ob["tag"] = tag
        outbounds.append(ob)
        tags.append(tag)
    outbounds.append({"protocol": "freedom", "tag": "direct"})
    outbounds.append({"protocol": "blackhole", "tag": "block"})

    balancer_tag = f"{prefix}-balancer"
    balancer = {
        "tag": balancer_tag,
        "selector": tags,
        "strategy": {"type": "leastLoad", "settings": {
            "maxRTT": "1s",
            "expected": min(2, max(1, len(tags))),
            "baselines": ["1s"],
            "tolerance": 0.01}},
    }

    domains_direct = [
        "vk.com", "yandex.ru", "mail.ru", "ok.ru", "gosuslugi.ru", "kremlin.ru",
        "ozon.ru", "wildberries.ru", "vseinstrumenti.ru", "max.ru", "dzen.ru",
        "rutube.ru", "avito.ru", "2gis.ru", "kinopoisk.ru", "sberbank.ru",
        "tbank.ru", "rzd.ru", "nalog.ru", "mchs.gov.ru", "minzdrav.gov.ru",
        "edu.gov.ru", "mos.ru", "spb.ru",
    ]

    return {
        "remarks": remarks,
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
            "domainMatcher": "hybrid",
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "domain": domains_direct, "outboundTag": "direct"},
                {"type": "field", "network": "tcp,udp", "balancerTag": balancer_tag},
            ],
            "balancers": [balancer],
        },
        "burstObservatory": {
            "pingConfig": {
                "timeout": "10s", "interval": "120s", "sampling": 5,
                "destination": "http://www.gstatic.com/generate_204",
            },
            "subjectSelector": tags,
        },
    }

# ============================================================================
# OutputWriter
# ============================================================================
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

    def write_versioned_all_working(self, lines):
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        snap = self.allworking / f"all_{ts}.txt"
        self._write_lines(snap, lines)
        latest = self.allworking / "latest.txt"
        try:
            shutil.copyfile(snap, latest)
        except Exception:
            self._write_lines(latest, lines)
        return snap, latest

    def write_latest_json(self, cache):
        by_country = defaultdict(list)
        for v in cache.items.values():
            if v.get("status") != "working":
                continue
            params = v.get("params") or {}
            if not params.get("server"):
                continue
            cc = v.get("country_code") or ""
            p = cache.to_proxy(v)
            by_country[cc].append((p, {"latency": v.get("latency")}))

        configs = []
        for cc in sorted(by_country.keys()):
            cn_ru = country_ru(cc)
            configs.append(_build_country_config(cc, cn_ru, by_country[cc]))

        latest = self.allworking / "latest.json"
        latest.write_text(json.dumps(configs, ensure_ascii=False, indent=1),
                          encoding="utf-8")
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        snap = self.allworking / f"all_{ts}.json"
        try:
            shutil.copyfile(latest, snap)
        except Exception:
            snap.write_text(json.dumps(configs), encoding="utf-8")
        return latest, snap

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
                if line and not line.startswith("#"):
                    ex.add(line)
        for p in new_proxies:
            u = dump_to_uri(p)
            if u:
                ex.add(u)
        path.write_text("\n".join(sorted(ex)) + "\n" if ex else "", encoding="utf-8")

def _named_lines(cache, proxies):
    lines = []
    for i, p in enumerate(proxies, 1):
        it = cache.items.get(p.dedup_key(), {})
        flag = resolve_flag(it)
        lines.append(dump_to_uri(p, override_name=f"{flag}{i}| @XelaraVpn"))
    return lines

# ============================================================================
# Параллельная проверка
# ============================================================================
def _check_parallel(proxies, xray, timeout, ifaces, cache, sub_index,
                    concurrency, server_timeout=SERVER_TIMEOUT_DEFAULT):
    results = {}
    for iface_key, iface_name in ifaces.items():
        send_through = None
        if iface_name:
            send_through = _get_iface_ip(iface_name)
            if not send_through:
                print(f"[!] интерфейс '{iface_name}' не найден — пропускаю")
                continue
        pairs = []; lock = threading.Lock()
        done = [0]; total = len(proxies)
        print_lock = threading.Lock()

        def _w(pr):
            prior = ""
            it = cache.items.get(pr.dedup_key(), {})
            if it and it.get("country_code"):
                prior = it["country_code"]
            r = check_proxy(pr, xray, timeout, send_through,
                            prior_cc=prior, server_timeout=server_timeout)
            cache.upsert(pr, r, sub_index)
            with lock:
                pairs.append((pr, r)); done[0] += 1; n = done[0]
            label = pr.name or f"{pr.kind}://{pr.params.get('server')}"
            with print_lock:
                if r["ok"]:
                    flag = flag_from_cc(r.get("country_code", ""))
                    cn = country_ru(r.get("country_code", ""))
                    ka = r.get("latency_keepalive")
                    ka_s = f"ka={ka}ms" if ka is not None else "ka=—"
                    el = r.get("elapsed")
                    el_s = f" {el}s" if el is not None else ""
                    print(f"  [{n}/{total}] OK {flag} {cn} {r['latency']}ms {ka_s}{el_s} "
                          f"ip={r['ip']} | {label}")
                else:
                    el = r.get("elapsed")
                    el_s = f" {el}s" if el is not None else ""
                    print(f"  [{n}/{total}] FAIL{el_s} {r['error']} | {label}")

        with cf.ThreadPoolExecutor(max_workers=concurrency) as ex:
            list(ex.map(_w, proxies))
        results[iface_key] = pairs
    return results

# ============================================================================
# Финальная запись
# ============================================================================
def _write_final(cache, writer, sources_count, final_file="working.txt"):
    print(f"\n[i] кэш сохранён: {len(cache.items)} записей")

    by_first = cache.working_by_first_sub()
    for sub_index in range(1, sources_count + 1):
        working = by_first.get(sub_index, [])
        lines = _named_lines(cache, working)
        writer.write_working_for_sub(sub_index, lines)

    all_working = cache.working_all()
    lines_all = _named_lines(cache, all_working)
    writer.write_working_all(lines_all)
    print(f"[i] Working/all.txt: {len(all_working)} рабочих")

    all_unworking = cache.unworking_all()
    writer.write_unworking_all(all_unworking)
    print(f"[i] UnWorking/all.txt: {len(all_unworking)} нерабочих")

    snap_txt, _ = writer.write_versioned_all_working(lines_all)
    print(f"[i] AllWorking/{snap_txt.name} ({len(all_working)} рабочих)")

    try:
        latest_json, snap_json = writer.write_latest_json(cache)
        print(f"[i] AllWorking/{latest_json.name}")
        print(f"[i] AllWorking/{snap_json.name}")
    except Exception as e:
        print(f"[!] latest.json ошибка: {e}")

    try:
        Path(final_file).write_text(
            "\n".join(lines_all) + ("\n" if lines_all else ""),
            encoding="utf-8")
        print(f"[i] {final_file}: {len(all_working)} рабочих")
    except Exception as e:
        print(f"[!] не удалось записать {final_file}: {e}")

# ============================================================================
# Объединённый main
# ============================================================================
def _collect_proxies_from_uris(uris):
    out = []
    for u in uris:
        u = u.strip()
        if not u or u.startswith("#"):
            continue
        p = parse_uri(u)
        if p and p.params.get("server"):
            out.append(p)
    return out

def main():
    ap = argparse.ArgumentParser(
        description="Combined Source Loader + Xray Checker")
    # Loader
    ap.add_argument("--no-load", action="store_true",
                    help="не скачивать sources.txt (только проверять уже собранное)")
    # Checker
    ap.add_argument("-i", "--input", default=CONFIGS_FILE,
                    help="файл с конфигами (по умолчанию configs.txt)")
    ap.add_argument("-o", "--output-dir", default="output")
    ap.add_argument("--cache", default="cache.json")
    ap.add_argument("-c", "--concurrency", type=int, default=16)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--server-timeout", type=float, default=6.0,
                    help="макс. секунд на один сервер, весь цикл (default: 6)")
    ap.add_argument("--wifi-iface", default=None)
    ap.add_argument("--mobile-iface", default=None)
    ap.add_argument("--xray-dir", default="xray_bin")
    ap.add_argument("--final-file", default="working.txt")
    ap.add_argument("--recheck-files",
                    default="working.txt,output/AllWorking/latest.txt,output/AllWorking/latest.json",
                    help="файлы для перепроверки (через запятую)")
    ap.add_argument("--no-recheck-final", action="store_true",
                    help="не перепроверять файлы из --recheck-files")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--only-new", action="store_true")
    mode.add_argument("--only-old", action="store_true")
    args = ap.parse_args()

    if args.concurrency < 1:  args.concurrency = 1
    if args.concurrency > 64: args.concurrency = 64

    cache = Cache(Path(args.cache))
    writer = OutputWriter(Path(args.output_dir))

    # ---------------------------------------------------------------
    # Фаза 1: Загрузка источников + my_configs → configs.txt
    # ---------------------------------------------------------------
    extra_uris_from_loader = []
    if not args.only_old and not args.no_load:
        loaded, my_cfgs, _stats = asyncio.run(load_http_sources())
        extra_uris_from_loader = list(loaded) + list(my_cfgs)
        # Источники (URL) — из sources.txt (уже обновлённого)
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
    print(f"[i] источников (URL): {len(sources)}")
    print(f"[i] параллельно: {args.concurrency} | бюджет на сервер: {args.server_timeout}s")
    print(f"[i] в кэше: {len(cache.items)} записей "
          f"(working={sum(1 for v in cache.items.values() if v.get('status')=='working')}, "
          f"unworking={sum(1 for v in cache.items.values() if v.get('status')=='unworking')})")

    xray = XrayManager(args.xray_dir)
    xray.ensure()

    ifaces = {"default": None}
    if args.wifi_iface:
        ifaces = {"wifi": args.wifi_iface}
    if args.mobile_iface:
        ifaces["mobile"] = args.mobile_iface
        ifaces.pop("default", None)

    # ---------------------------------------------------------------
    # Фаза 2: Сбор Proxy-объектов для проверки
    # ---------------------------------------------------------------
    # 2a. Из configs.txt / --input
    input_path = Path(args.input)
    file_uris = []
    if input_path.exists():
        for line in input_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                file_uris.append(line)

    # 2b. Из только что загруженных
    all_uris = file_uris + extra_uris_from_loader

    # 2c. Если есть только источники (URL), но нет конфигов и loader не запускался
    if not all_uris and sources and (args.only_old or args.no_load):
        for s in sources:
            p = parse_uri(s)
            if p:
                all_uris.append(s)

    proxies = _collect_proxies_from_uris(all_uris)
    print(f"[i] распарсено URI: {len(all_uris)} → валидных Proxy: {len(proxies)}")

    # 2d. Recheck файлов
    prev_final_proxies = []
    if not args.no_recheck_final and not args.only_new:
        paths = [s.strip() for s in args.recheck_files.split(",") if s.strip()]
        print(f"[i] recheck-files: {paths}")
        prev_final_proxies = _load_recheck_files(paths)
        if prev_final_proxies:
            print(f"[i] всего для перепроверки из файлов: {len(prev_final_proxies)}")

    # ---------------------------------------------------------------
    # Режимы
    # ---------------------------------------------------------------
    if args.only_old:
        cached = []
        for it in cache.items.values():
            p = cache.to_proxy(it)
            if p and p.params.get("server"):
                cached.append(p)
        cached.extend(prev_final_proxies)
        uniq = _dedup(cached)
        print(f"[i] перепроверяю старые: {len(uniq)}")
        if uniq:
            _check_parallel(uniq, xray, args.timeout, ifaces, cache,
                            sub_index=0, concurrency=args.concurrency,
                            server_timeout=args.server_timeout)
        cache.save()
        _write_final(cache, writer, 0, args.final_file)
        return

    if args.only_new:
        known = set(cache.items.keys())
        new_only = [p for p in proxies if p.dedup_key() not in known]
        print(f"[i] only-new: всего {len(proxies)}, новых {len(new_only)} "
              f"(старых {len(proxies)-len(new_only)})")
        if new_only:
            _check_parallel(new_only, xray, args.timeout, ifaces, cache,
                            sub_index=1, concurrency=args.concurrency,
                            server_timeout=args.server_timeout)
        cache.save()
        _write_final(cache, writer, len(sources) or 1, args.final_file)
        return

    # Режим all
    uniq = _dedup(proxies)
    if uniq:
        print(f"\n{'='*70}")
        print(f"=== Проверка {len(uniq)} серверов")
        print(f"{'='*70}")
        _check_parallel(uniq, xray, args.timeout, ifaces, cache,
                        sub_index=1, concurrency=args.concurrency,
                        server_timeout=args.server_timeout)

    if prev_final_proxies:
        print(f"\n{'='*70}")
        print(f"=== Перепроверка файлов: {len(prev_final_proxies)} серверов")
        print(f"{'='*70}")
        uniq_re = _dedup(prev_final_proxies)
        results = _check_parallel(uniq_re, xray, args.timeout, ifaces, cache,
                                  sub_index=999, concurrency=args.concurrency,
                                  server_timeout=args.server_timeout)
        sub_w, sub_u = [], []
        for _, pairs in results.items():
            for pr, r in pairs:
                (sub_w if r["ok"] else sub_u).append(pr)
        writer.write_sub_logs(999, _dedup(sub_w), _dedup(sub_u))

    cache.save()
    _write_final(cache, writer, max(len(sources), 1), args.final_file)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nОстановлено пользователем")