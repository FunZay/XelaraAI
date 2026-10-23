#!/usr/bin/env python3
"""
xray_sub_parser.py — single-file Xray subscription parser & health checker.

Запуск без аргументов — открывает интерактивное меню.
CLI-флаги остаются для автоматизации (cron, скрипты, CI).

  python xray_sub_parser.py            → меню
  python xray_sub_parser.py --menu     → меню (принудительно)
  python xray_sub_parser.py --sub ...  → прямой запуск без меню
  python xray_sub_parser.py --dry-run  → только парсинг

При первом запуске скрипт сам ставит Python-зависимости и скачивает Xray-core.
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

# ============================================================================
# Self-bootstrap: Python dependencies
# ============================================================================

def _bootstrap_python_deps() -> None:
    try:
        import requests  # noqa: F401
        import socks     # noqa: F401
        return
    except ImportError:
        pass

    print("[setup] устанавливаю Python-зависимости (requests[socks], PySocks)...", flush=True)
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "requests[socks]", "PySocks"],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as error:
        print(f"[setup] не удалось установить зависимости: {error}", file=sys.stderr)
        print("Поставьте вручную:  pip install 'requests[socks]' PySocks", file=sys.stderr)
        sys.exit(1)
    try:
        import requests  # noqa: F401
        import socks     # noqa: F401
    except ImportError:
        print("[setup] зависимости всё ещё отсутствуют — выходим.", file=sys.stderr)
        sys.exit(1)

_bootstrap_python_deps()

import requests  # noqa: E402

# ============================================================================
# Constants & static data
# ============================================================================

DEFAULT_TEST_URL = "https://www.gstatic.com/generate_204"
DEFAULT_BRAND = "@XELARAVPN"
TRACE_URL = "https://cloudflare.com/cdn-cgi/trace"
IP_API_URL = "http://ip-api.com/json/?fields=status,country,countryCode,query"

XRAY_RELEASES = "https://github.com/XTLS/Xray-core/releases/latest/download"

SUPPORTED_SCHEMES = {"vless", "vmess", "trojan", "ss", "hysteria2", "hy2"}
SKIPPED_SCHEMES = {"ssr", "tuic", "wireguard", "warp"}

_UA = {"User-Agent": "xray-sub-parser/1.3"}

RU_DOMAINS: list[str] = [
    "gosuslugi.ru", "mos.ru", "spb.ru", "kremlin.ru", "government.ru",
    "nalog.ru", "nalog.gov.ru", "mchs.gov.ru", "minzdrav.gov.ru",
    "edu.gov.ru", "pfr.gov.ru", "sfr.gov.ru", "fssp.gov.ru", "sledcom.ru",
    "genproc.gov.ru", "rkn.gov.ru", "roskomnadzor.gov.ru",
    "gosuslugi.mosreg.ru", "mosreg.ru", "prav.gov.ru",
    "sber.ru", "sberbank.ru", "sberbank.com", "sbol.ru", "online.sberbank.ru",
    "tbank.ru", "tinkoff.ru", "vtb.ru", "online.vtb.ru", "alfabank.ru",
    "alfa.ru", "gazprombank.ru", "raiffeisen.ru", "psbank.ru", "rosbank.ru",
    "otpbank.ru", "sovcombank.ru", "mtsbank.ru", "rncb.ru", "open.ru",
    "pochtabank.ru", "rshb.ru", "banki.ru", "cbr.ru",
    "yandex.ru", "ya.ru", "yandex.com", "yandex.net", "yandex.kz", "yandex.by",
    "market.yandex.ru", "market.yandex.com", "taxi.yandex.ru", "eda.yandex.ru",
    "delivery.yandex.ru", "lavka.yandex.ru", "music.yandex.ru",
    "music.yandex.com", "money.yandex.ru", "afisha.yandex.ru",
    "realty.yandex.ru", "mail.yandex.ru", "360.yandex.ru",
    "vk.com", "vk.ru", "mvk.com", "userapi.com", "vk.me", "vk.company",
    "vkvideo.ru", "vk.link", "vk.cc",
    "mail.ru", "bk.ru", "inbox.ru", "list.ru", "internet.ru", "my.mail.ru",
    "cloud.mail.ru", "calendar.mail.ru",
    "ozon.ru", "wildberries.ru", "vseinstrumenti.ru", "avito.ru", "auto.ru",
    "drom.ru", "sbermegamarket.ru", "megamarket.ru", "lamoda.ru", "kupivip.ru",
    "aliexpress.ru", "magnit.ru", "lenta.com", "auchan.ru", "pyaterochka.ru",
    "perekrestok.ru", "dixy.ru", "vkusvill.ru", "samokat.ru", "sbermarket.ru",
    "5ka.ru", "okmarket.ru", "mvideo.ru", "dns-shop.ru", "eldorado.ru",
    "citilink.ru", "technopark.ru", "detmir.ru", "dochkisinochki.ru",
    "delivery-club.ru", "dominos.ru", "pizzahut.ru", "kfc.ru",
    "burgerking.ru", "dodos.ru", "dodopizza.ru", "sushiwok.ru",
    "sitylink.ru", "sitylink.com", "taximaxim.ru", "maxim.ru", "gett.ru",
    "drivee.ru", "ria.ru", "tass.ru", "rbc.ru", "kommersant.ru", "kp.ru",
    "lenta.ru", "gazeta.ru", "iz.ru", "rg.ru", "vz.ru", "ng.ru", "rt.com",
    "russian.rt.com", "vesti.ru", "1tv.ru", "1tv.com", "smi.ru", "forbes.ru",
    "kinopoisk.ru", "ivi.ru", "okko.tv", "more.tv", "wink.ru", "premier.one",
    "start.ru", "kion.ru", "rutube.ru", "smotrim.ru", "vgtrk.ru", "matchtv.ru",
    "sportbox.ru", "box-tv.ru", "amediateka.ru", "zvuk.com", "max.ru", "ok.ru",
    "mts.ru", "megafon.ru", "beeline.ru", "tele2.ru", "yota.ru",
    "sbermobile.ru", "school.mos.ru", "mosobr.ru", "edu.ru", "schoolotv.ru",
    "uchi.ru", "skyeng.ru", "stepik.org", "hh.ru", "headhunter.ru",
    "rabota.ru", "zarplata.ru", "superjob.ru", "aeroflot.ru", "s7.ru",
    "utair.ru", "rzd.ru", "rzd.com", "mosmetro.ru", "transport.mos.ru",
    "2gis.ru", "2gis.com", "maps.yandex.ru", "russia.ru", "moscow.ru", "dzen.ru",
]

COUNTRY_NAMES_RU: dict[str, str] = {
    "AM": "Армения", "AT": "Австрия", "AU": "Австралия", "AZ": "Азербайджан",
    "AL": "Албания", "AR": "Аргентина", "AE": "ОАЭ", "BD": "Бангладеш",
    "BE": "Бельгия", "BG": "Болгария", "BH": "Бахрейн", "BA": "Босния и Герцеговина",
    "BO": "Боливия", "BR": "Бразилия", "BY": "Беларусь", "CA": "Канада",
    "CH": "Швейцария", "CL": "Чили", "CN": "Китай", "CO": "Колумбия",
    "CR": "Коста-Рика", "CY": "Кипр", "CZ": "Чехия", "DE": "Германия",
    "DK": "Дания", "DZ": "Алжир", "EC": "Эквадор", "EE": "Эстония",
    "EG": "Египет", "ES": "Испания", "ET": "Эфиопия", "FI": "Финляндия",
    "FR": "Франция", "GB": "Великобритания", "GE": "Грузия", "GH": "Гана",
    "GR": "Греция", "HK": "Гонконг", "HR": "Хорватия", "HU": "Венгрия",
    "ID": "Индонезия", "IE": "Ирландия", "IL": "Израиль", "IN": "Индия",
    "IQ": "Ирак", "IR": "Иран", "IS": "Исландия", "IT": "Италия",
    "JO": "Иордания", "JP": "Япония", "KE": "Кения", "KG": "Киргизия",
    "KH": "Камбоджа", "KR": "Южная Корея", "KW": "Кувейт", "KZ": "Казахстан",
    "LA": "Лаос", "LB": "Ливан", "LK": "Шри-Ланка", "LT": "Литва",
    "LU": "Люксембург", "LV": "Латвия", "LY": "Ливия", "MA": "Марокко",
    "MD": "Молдова", "ME": "Черногория", "MG": "Мадагаскар", "MK": "Северная Македония",
    "MM": "Мьянма", "MN": "Монголия", "MO": "Макао", "MT": "Мальта",
    "MU": "Маврикий", "MV": "Мальдивы", "MX": "Мексика", "MY": "Малайзия",
    "NG": "Нигерия", "NL": "Нидерланды", "NO": "Норвегия", "NP": "Непал",
    "NZ": "Новая Зеландия", "OM": "Оман", "PA": "Панама", "PE": "Перу",
    "PH": "Филиппины", "PK": "Пакистан", "PL": "Польша", "PR": "Пуэрто-Рико",
    "PS": "Палестина", "PT": "Португалия", "PY": "Парагвай", "QA": "Катар",
    "RO": "Румыния", "RS": "Сербия", "RU": "Россия", "SA": "Саудовская Аравия",
    "SC": "Сейшелы", "SD": "Судан", "SE": "Швеция", "SG": "Сингапур",
    "SI": "Словения", "SK": "Словакия", "SN": "Сенегал", "SO": "Сомали",
    "SY": "Сирия", "TH": "Таиланд", "TJ": "Таджикистан", "TM": "Туркменистан",
    "TN": "Тунис", "TR": "Турция", "TW": "Тайвань", "TZ": "Танзания",
    "UA": "Украина", "UG": "Уганда", "US": "США", "UY": "Уругвай",
    "UZ": "Узбекистан", "VE": "Венесуэла", "VN": "Вьетнам", "XK": "Косово",
    "YE": "Йемен", "ZA": "ЮАР",
}

def country_flag(code: str) -> str:
    code = (code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return "🏳️"
    return "".join(chr(0x1F1E6 + ord(char) - ord("A")) for char in code)

def country_name_ru(code: str) -> str:
    return COUNTRY_NAMES_RU.get((code or "").upper(), (code or "??").upper())

_PRINT_LOCK = threading.Lock()

def log(message: str) -> None:
    with _PRINT_LOCK:
        print(message, flush=True)

# ============================================================================
# Self-bootstrap: Xray-core binary
# ============================================================================

def _xray_executable_name() -> str:
    return "xray.exe" if os.name == "nt" else "xray"

def _xray_asset_name() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        if machine in ("x86_64", "amd64"):
            return "Xray-linux-64.zip"
        if machine in ("aarch64", "arm64"):
            return "Xray-linux-arm64-v8a.zip"
        if machine.startswith("arm"):
            return "Xray-linux-arm32-v7a.zip"
    if system == "darwin":
        if machine in ("x86_64", "amd64"):
            return "Xray-macos-64.zip"
        if machine in ("aarch64", "arm64"):
            return "Xray-macos-arm64-v8a.zip"
    if system == "windows":
        if machine in ("x86_64", "amd64"):
            return "Xray-windows-64.zip"
        if machine in ("aarch64", "arm64"):
            return "Xray-windows-arm64-v8a.zip"
    raise RuntimeError(f"нет сборки Xray для {system}/{machine}")

def _download_xray(destination: Path) -> None:
    from urllib.request import urlopen

    if os.name == "nt" and not str(destination).lower().endswith(".exe"):
        destination = destination.with_suffix(destination.suffix + ".exe")

    asset = _xray_asset_name()
    url = f"{XRAY_RELEASES}/{asset}"
    log(f"[setup] скачиваю Xray-core: {url}")

    try:
        with urlopen(url, timeout=180) as response:
            payload = response.read()
    except Exception as error:
        raise RuntimeError(
            f"не удалось скачать Xray-core: {error}. "
            f"Проверьте интернет или положите бинарник в ./bin/xray "
            f"и запустите с --xray /путь/к/xray"
        ) from error

    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        wanted = _xray_executable_name()
        member = next(
            (name for name in archive.namelist() if name == wanted or name.endswith("/" + wanted)),
            None,
        )
        if member is None:
            raise RuntimeError(f"{wanted} не найден в {asset}")
        destination.write_bytes(archive.read(member))

    destination.chmod(destination.stat().st_mode | stat.S_IEXEC)
    log(f"[setup] сохранено: {destination}")

def _is_executable(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.X_OK)

def ensure_xray(explicit: str | None = None) -> str:
    exe = _xray_executable_name()

    if explicit:
        if _is_executable(explicit):
            return os.path.abspath(explicit)
        target = Path(explicit)
        log(f"[setup] {explicit} не найден, скачиваю туда")
        _download_xray(target)
        return str(target.resolve())

    env = os.environ.get("XRAY_BINARY")
    if env and _is_executable(env):
        return os.path.abspath(env)

    for candidate in (f"./bin/{exe}", f"./{exe}"):
        if _is_executable(candidate):
            return os.path.abspath(candidate)

    found = shutil.which(exe)
    if found:
        return found

    target = Path("bin") / exe
    _download_xray(target)
    return str(target.resolve())

# ============================================================================
# Model
# ============================================================================

@dataclass
class Server:
    uri: str
    protocol: str
    address: str
    port: int
    remark: str = ""
    params: dict[str, Any] = field(default_factory=dict)

    country_code: str = ""
    country_name: str = ""
    exit_ip: str = ""
    latency_ms: int = 0
    cold_ms: int = 0
    http_status: int = 0
    working: bool = False
    error: str = ""

    @property
    def dedupe_key(self) -> tuple:
        return (
            self.protocol,
            self.address.lower(),
            self.port,
            self.uri.split("#", 1)[0],
        )

@dataclass
class SkipRecord:
    scheme: str
    uri: str
    reason: str

@dataclass
class SubStats:
    url: str
    status: int = 0
    bytes: int = 0
    content_type: str = ""
    base64_decoded: bool = False
    links: int = 0
    error: str = ""

# ============================================================================
# Subscription fetching
# ============================================================================

def b64decode_text(value: str) -> str:
    value = value.strip().replace("-", "+").replace("_", "/")
    value += "=" * (-len(value) % 4)
    return base64.b64decode(value).decode("utf-8", errors="replace")

def fetch_subscription(url: str, timeout: int = 30) -> tuple[str, SubStats]:
    stats = SubStats(url=url)

    response = requests.get(url, timeout=timeout, headers=_UA)
    stats.status = response.status_code
    stats.content_type = response.headers.get("content-type", "").split(";")[0].strip()
    stats.bytes = len(response.content)

    if response.status_code >= 400:
        stats.error = f"HTTP {response.status_code}"
        response.raise_for_status()

    text = response.text.strip()
    if not text:
        stats.error = "пустое тело ответа"
        return "", stats

    if "://" not in text:
        try:
            decoded = b64decode_text(text)
            if "://" in decoded:
                stats.base64_decoded = True
                text = decoded
        except Exception:
            pass

    stats.links = sum(1 for line in text.splitlines() if "://" in line)
    return text, stats

# ============================================================================
# Per-protocol parsers
# ============================================================================

def _parse_vless(uri: str) -> Server:
    parsed = urlparse(uri)
    if not parsed.username:
        raise ValueError("нет UUID в URL")
    if not parsed.hostname:
        raise ValueError("нет хоста")
    if not parsed.port:
        raise ValueError("нет порта")
    query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    params = {
        "id": parsed.username,
        "encryption": query.get("encryption", "none"),
        "flow": query.get("flow", ""),
        "type": query.get("type", "tcp"),
        "security": query.get("security", "none"),
        "sni": query.get("sni", ""),
        "fp": query.get("fp", ""),
        "pbk": query.get("pbk", ""),
        "sid": query.get("sid", ""),
        "spx": query.get("spx", "/"),
        "path": unquote(query.get("path", "/")),
        "host": query.get("host", ""),
        "serviceName": query.get("serviceName", ""),
        "alpn": query.get("alpn", ""),
        "allowInsecure": query.get("allowInsecure", "0") in ("1", "true"),
    }
    return Server(
        uri=uri, protocol="vless", address=parsed.hostname,
        port=parsed.port, remark=unquote(parsed.fragment), params=params,
    )

def _parse_vmess(uri: str) -> Server:
    try:
        data = json.loads(b64decode_text(uri[len("vmess://"):]))
    except Exception as error:
        raise ValueError(f"битый base64/JSON ({type(error).__name__})") from error

    host = str(data.get("add", "")).strip()
    if not host:
        raise ValueError("нет поля 'add'")
    try:
        port = int(data.get("port", 0) or 0)
    except (TypeError, ValueError) as error:
        raise ValueError("порт не число") from error
    if not port:
        raise ValueError("нет порта")
    if not data.get("id"):
        raise ValueError("нет поля 'id'")

    if host.count(":") == 1 and not host.startswith("["):
        maybe_host, _, maybe_port = host.rpartition(":")
        if maybe_port.isdigit():
            host, port = maybe_host, int(maybe_port)

    network = str(data.get("net", "tcp")).lower()
    tls_value = str(data.get("tls", "")).lower()
    params = {
        "id": str(data.get("id", "")),
        "aid": int(data.get("aid", 0) or 0),
        "scy": str(data.get("scy", "auto")),
        "type": network,
        "security": tls_value if tls_value else "none",
        "sni": str(data.get("sni", "")),
        "host": str(data.get("host", "")),
        "path": str(data.get("path", "/")),
        "serviceName": str(data.get("path", "")) if network == "grpc" else "",
        "alpn": str(data.get("alpn", "")),
        "fp": str(data.get("fp", "")),
        "allowInsecure": False,
    }
    return Server(
        uri=uri, protocol="vmess", address=host, port=port,
        remark=str(data.get("ps", "")), params=params,
    )

def _parse_trojan(uri: str) -> Server:
    parsed = urlparse(uri)
    if not parsed.username:
        raise ValueError("нет пароля в URL")
    if not parsed.hostname:
        raise ValueError("нет хоста")
    if not parsed.port:
        raise ValueError("нет порта")
    query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    params = {
        "password": unquote(parsed.username),
        "type": query.get("type", "tcp"),
        "security": query.get("security", "tls"),
        "sni": query.get("sni", "") or query.get("peer", ""),
        "alpn": query.get("alpn", ""),
        "fp": query.get("fp", ""),
        "path": unquote(query.get("path", "/")),
        "host": query.get("host", ""),
        "serviceName": query.get("serviceName", ""),
        "allowInsecure": query.get("allowInsecure", "0") in ("1", "true"),
    }
    return Server(
        uri=uri, protocol="trojan", address=parsed.hostname,
        port=parsed.port, remark=unquote(parsed.fragment), params=params,
    )

def _parse_ss(uri: str) -> Server:
    body = uri[len("ss://"):]
    fragment = ""
    if "#" in body:
        body, fragment = body.split("#", 1)
    if "?" in body:
        body = body.split("?", 1)[0]

    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        try:
            decoded = b64decode_text(userinfo)
            method, _, password = decoded.partition(":")
        except Exception:
            method, _, password = unquote(userinfo).partition(":")
    else:
        try:
            decoded = b64decode_text(body)
        except Exception as error:
            raise ValueError("битый base64 в теле ss://") from error
        method, _, rest = decoded.partition(":")
        password, _, hostport = rest.partition("@")

    if not method:
        raise ValueError("нет метода шифрования")
    host, _, port_text = hostport.rpartition(":")
    host = host.strip("[]")
    if not host:
        raise ValueError("нет хоста")
    if not port_text.isdigit():
        raise ValueError("порт не число или отсутствует")

    return Server(
        uri=uri, protocol="ss", address=host, port=int(port_text),
        remark=unquote(fragment),
        params={"method": method.strip(), "password": password},
    )

def _parse_hysteria2(uri: str) -> Server:
    parsed = urlparse(uri)
    if not parsed.hostname:
        raise ValueError("нет хоста")
    if not parsed.port:
        raise ValueError("нет порта")
    query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    auth = unquote(parsed.username or "")
    if parsed.password:
        auth = f"{auth}:{unquote(parsed.password)}"
    params = {
        "auth": auth,
        "sni": query.get("sni", ""),
        "insecure": query.get("insecure", "0") in ("1", "true"),
        "obfs": query.get("obfs", ""),
        "obfs-password": query.get("obfs-password", ""),
    }
    return Server(
        uri=uri, protocol="hysteria2", address=parsed.hostname,
        port=parsed.port, remark=unquote(parsed.fragment), params=params,
    )

def _preview(uri: str, limit: int = 90) -> str:
    return uri if len(uri) <= limit else uri[:limit] + "…"

def parse_subscription(text: str, verbose: bool = False) -> tuple[list[Server], list[SkipRecord]]:
    servers: list[Server] = []
    skipped: list[SkipRecord] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "://" not in line:
            continue
        scheme = line.split("://", 1)[0].lower()

        if scheme in SKIPPED_SCHEMES:
            reason = (
                f"схема '{scheme}' не поддерживается Xray Core "
                f"(распознана, но не тестируется и не экспортируется)"
            )
            skipped.append(SkipRecord(scheme=scheme, uri=line, reason=reason))
            if verbose:
                log(f"   SKIP  {_preview(line)}")
                log(f"         └─ {reason}")
            continue

        if scheme not in SUPPORTED_SCHEMES:
            reason = f"неизвестная схема '{scheme}'"
            skipped.append(SkipRecord(scheme=scheme, uri=line, reason=reason))
            if verbose:
                log(f"   SKIP  {_preview(line)}")
                log(f"         └─ {reason}")
            continue

        try:
            if scheme == "vless":
                server = _parse_vless(line)
            elif scheme == "vmess":
                server = _parse_vmess(line)
            elif scheme == "trojan":
                server = _parse_trojan(line)
            elif scheme == "ss":
                server = _parse_ss(line)
            else:
                server = _parse_hysteria2(line)
        except ValueError as error:
            skipped.append(SkipRecord(scheme=scheme, uri=line, reason=str(error)))
            if verbose:
                log(f"   SKIP  {_preview(line)}")
                log(f"         └─ {error}")
            continue
        except Exception as error:
            reason = f"{type(error).__name__}: {error}"
            skipped.append(SkipRecord(scheme=scheme, uri=line, reason=reason))
            if verbose:
                log(f"   SKIP  {_preview(line)}")
                log(f"         └─ {reason}")
            continue

        servers.append(server)
        if verbose:
            log(f"   OK    {_preview(line)}")
            log(f"         └─ {server.protocol} {server.address}:{server.port}")

    return servers, skipped

# ============================================================================
# Xray outbound builders
# ============================================================================

def _stream_settings(server: Server) -> dict:
    params = server.params
    network = str(params.get("type") or "tcp").lower()
    security = str(params.get("security") or "none").lower()

    stream: dict = {"network": network}

    if security == "tls":
        tls: dict = {}
        if params.get("sni"):
            tls["serverName"] = params["sni"]
        if params.get("fp"):
            tls["fingerprint"] = params["fp"]
        if params.get("alpn"):
            tls["alpn"] = [x.strip() for x in str(params["alpn"]).split(",") if x.strip()]
        if params.get("allowInsecure"):
            tls["allowInsecure"] = True
        stream["security"] = "tls"
        stream["tlsSettings"] = tls
    elif security == "reality":
        reality: dict = {"show": False}
        if params.get("sni"):
            reality["serverName"] = params["sni"]
        if params.get("fp"):
            reality["fingerprint"] = params["fp"]
        if params.get("pbk"):
            reality["publicKey"] = params["pbk"]
        if params.get("sid"):
            reality["shortId"] = params["sid"]
        reality["spiderX"] = params.get("spx") or "/"
        stream["security"] = "reality"
        stream["realitySettings"] = reality

    if network in ("ws", "websocket"):
        ws: dict = {"path": params.get("path") or "/"}
        if params.get("host"):
            ws["headers"] = {"Host": params["host"]}
        stream["wsSettings"] = ws
    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": params.get("serviceName") or params.get("path") or "",
            "authority": params.get("host") or "",
        }
    elif network in ("xhttp", "splithttp"):
        xhttp: dict = {"path": params.get("path") or "/", "mode": "auto"}
        if params.get("host"):
            xhttp["host"] = params["host"]
        stream["xhttpSettings"] = xhttp

    return stream

def build_outbound(server: Server, tag: str) -> dict:
    params = server.params
    outbound: dict = {"tag": tag}

    if server.protocol == "vless":
        user = {"id": params["id"], "encryption": params.get("encryption") or "none"}
        if params.get("flow"):
            user["flow"] = params["flow"]
        outbound["protocol"] = "vless"
        outbound["settings"] = {"vnext": [{"address": server.address, "port": server.port, "users": [user]}]}
        outbound["streamSettings"] = _stream_settings(server)

    elif server.protocol == "vmess":
        user = {
            "id": params["id"],
            "alterId": params.get("aid", 0),
            "security": params.get("scy") or "auto",
        }
        outbound["protocol"] = "vmess"
        outbound["settings"] = {"vnext": [{"address": server.address, "port": server.port, "users": [user]}]}
        outbound["streamSettings"] = _stream_settings(server)

    elif server.protocol == "trojan":
        outbound["protocol"] = "trojan"
        outbound["settings"] = {"servers": [{"address": server.address, "port": server.port, "password": params["password"]}]}
        outbound["streamSettings"] = _stream_settings(server)

    elif server.protocol == "ss":
        outbound["protocol"] = "shadowsocks"
        outbound["settings"] = {"servers": [{
            "address": server.address, "port": server.port,
            "method": params["method"], "password": params["password"],
        }]}

    elif server.protocol == "hysteria2":
        outbound["protocol"] = "hysteria"
        outbound["settings"] = {"version": 2, "address": server.address, "port": server.port}
        stream: dict = {
            "network": "hysteria",
            "security": "tls",
            "hysteriaSettings": {"version": 2, "auth": params.get("auth", "")},
            "tlsSettings": {},
        }
        if params.get("sni"):
            stream["tlsSettings"]["serverName"] = params["sni"]
        if params.get("insecure"):
            stream["tlsSettings"]["allowInsecure"] = True
        outbound["streamSettings"] = stream

    else:
        raise ValueError(f"unsupported protocol: {server.protocol}")

    return outbound

# ============================================================================
# Country detection
# ============================================================================

_IP_RE = re.compile(r"^ip=(.+)$", re.MULTILINE)
_LOC_RE = re.compile(r"^loc=(.+)$", re.MULTILINE)

def _parse_cloudflare_trace(text: str) -> tuple[str, str]:
    ip_match = _IP_RE.search(text)
    loc_match = _LOC_RE.search(text)
    return (
        ip_match.group(1).strip() if ip_match else "",
        (loc_match.group(1).strip() if loc_match else "").upper(),
    )

def probe_exit(session: requests.Session, timeout: int) -> tuple[str, str]:
    try:
        response = session.get(TRACE_URL, timeout=timeout)
        if response.ok:
            ip, country = _parse_cloudflare_trace(response.text)
            if country:
                return ip, country
    except Exception:
        pass
    try:
        response = session.get(IP_API_URL, timeout=timeout)
        if response.ok:
            payload = response.json()
            if payload.get("status") == "success":
                return (
                    str(payload.get("query", "")),
                    str(payload.get("countryCode", "")).upper(),
                )
    except Exception:
        pass
    return "", ""

# ============================================================================
# Tester
# ============================================================================

class XrayTester:
    def __init__(
        self,
        xray_bin: str,
        test_url: str = DEFAULT_TEST_URL,
        timeout: int = 10,
        concurrency: int = 12,
        batch_size: int = 15,
        base_port: int = 20000,
        verbose: bool = False,
    ) -> None:
        self.xray_bin = xray_bin
        self.test_url = test_url
        self.timeout = timeout
        self.concurrency = concurrency
        self.batch_size = max(1, batch_size)
        self.base_port = base_port
        self.verbose = verbose

    def test_all(self, servers: list[Server]) -> None:
        total = len(servers)
        for start in range(0, total, self.batch_size):
            batch = servers[start:start + self.batch_size]
            index = start // self.batch_size + 1
            log(f"[test] батч {index}: {len(batch)} узел(ов)")
            try:
                self._test_batch(batch)
            except Exception as batch_error:
                log(f"[test] батч {index} упал: {batch_error}; повторяю по одному")
                for server in batch:
                    try:
                        self._test_single(server)
                        self._report_node(server)
                    except Exception as single_error:
                        server.working = False
                        server.error = f"батч: {batch_error}; одиночный: {single_error}"
                        self._report_node(server)

    def _report_node(self, server: Server) -> None:
        tag = "OK  " if server.working else "FAIL"
        where = (
            f"{server.country_code or '??'} "
            if server.working and server.country_code else ""
        )
        latency = f"{server.latency_ms}ms" if server.working else ""
        reason = f"  ({server.error})" if not server.working and server.error else ""
        log(
            f"[test]   {tag} {server.protocol:8s} "
            f"{server.address}:{server.port:<6} "
            f"{where}{latency}{reason}"
        )

    def _test_batch(self, batch: list[Server]) -> None:
        base = self._free_base_port(len(batch))
        config, port_map = self._build_config(batch, base)
        process = self._start_xray(config, len(batch), base)
        try:
            self._probe_many(batch, port_map)
        finally:
            self._stop(process)

    def _build_config(self, batch: list[Server], base_port: int) -> tuple[dict, dict[int, int]]:
        inbounds: list[dict] = []
        outbounds: list[dict] = []
        rules: list[dict] = []
        port_map: dict[int, int] = {}

        for index, server in enumerate(batch):
            outbound_tag = f"s{index}"
            inbound_tag = f"in{index}"
            port = base_port + index
            port_map[index] = port
            inbounds.append({
                "listen": "127.0.0.1", "port": port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
                "tag": inbound_tag,
            })
            outbounds.append(build_outbound(server, outbound_tag))
            rules.append({
                "type": "field",
                "inboundTag": [inbound_tag],
                "outboundTag": outbound_tag,
            })

        outbounds.append({"protocol": "freedom", "tag": "direct"})
        outbounds.append({"protocol": "blackhole", "tag": "block"})

        config = {
            "log": {"loglevel": "warning"},
            "inbounds": inbounds,
            "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules},
        }
        return config, port_map

    def _start_xray(self, config: dict, node_count: int, base_port: int) -> subprocess.Popen:
        workdir = tempfile.mkdtemp(prefix="xray-probe-")
        config_path = os.path.join(workdir, "config.json")
        with open(config_path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)

        process = subprocess.Popen(
            [self.xray_bin, "run", "-c", config_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True, cwd=workdir,
        )

        try:
            self._wait_ports(process, base_port, node_count, timeout=12)
        except Exception:
            process.terminate()
            try:
                _, stderr = process.communicate(timeout=3)
            except Exception:
                process.kill()
                _, stderr = process.communicate()
            raise RuntimeError(((stderr or "xray не запустился").strip())[:800])

        return process

    @staticmethod
    def _wait_ports(process: subprocess.Popen, base_port: int, count: int, timeout: int) -> None:
        deadline = time.time() + timeout
        pending = set(range(base_port, base_port + count))
        while time.time() < deadline:
            if process.poll() is not None:
                raise RuntimeError("xray завершился до открытия портов")
            for port in list(pending):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        pending.discard(port)
                except OSError:
                    pass
            if not pending:
                return
            time.sleep(0.1)
        raise TimeoutError(f"порты не открылись: {sorted(pending)[:5]}")

    def _probe_many(self, batch: list[Server], port_map: dict[int, int]) -> None:
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = {
                pool.submit(self._probe_one, port_map[i], s): s
                for i, s in enumerate(batch)
            }
            for future in as_completed(futures):
                server = futures[future]
                try:
                    future.result()
                except Exception as error:
                    server.working = False
                    server.error = str(error)
                self._report_node(server)

    def _test_single(self, server: Server) -> None:
        base = self._free_base_port(1)
        config, port_map = self._build_config([server], base)
        process = self._start_xray(config, 1, base)
        try:
            self._probe_one(port_map[0], server)
        finally:
            self._stop(process)

    def _probe_one(self, port: int, server: Server) -> None:
        proxy = f"socks5h://127.0.0.1:{port}"
        session = requests.Session()
        session.trust_env = False
        session.proxies = {"http": proxy, "https": proxy}

        adapter = requests.adapters.HTTPAdapter(pool_connections=1, pool_maxsize=1)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        try:
            started = time.perf_counter()
            response = session.get(self.test_url, timeout=self.timeout, allow_redirects=False)
            server.cold_ms = max(int((time.perf_counter() - started) * 1000), 1)
            server.http_status = response.status_code
            _ = response.content

            try:
                started = time.perf_counter()
                warm = session.get(self.test_url, timeout=self.timeout, allow_redirects=False)
                server.latency_ms = max(int((time.perf_counter() - started) * 1000), 1)
                _ = warm.content
            except Exception:
                server.latency_ms = server.cold_ms

            server.working = response.status_code < 500
            if not server.working:
                server.error = f"HTTP {response.status_code}"

            exit_ip, cc = probe_exit(session, timeout=min(self.timeout, 8))
            server.exit_ip = exit_ip
            server.country_code = cc
            if cc:
                server.country_name = country_name_ru(cc)

        except Exception as error:
            server.working = False
            text = str(error) or error.__class__.__name__
            server.error = text[:200]
        finally:
            session.close()

    def _free_base_port(self, count: int) -> int:
        span = max(count, 1)
        for candidate in range(self.base_port, self.base_port + 400, span):
            if all(self._port_free(candidate + off) for off in range(count)):
                return candidate
        return self.base_port + (os.getpid() % 50) * span

    @staticmethod
    def _port_free(port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False

    @staticmethod
    def _stop(process: subprocess.Popen) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)

# ============================================================================
# Output builders
# ============================================================================

def write_working_txt(servers: list[Server], path: Path) -> None:
    lines = ["# country\tlatency_ms\tprotocol\turi"]
    ordered = sorted(servers, key=lambda s: (s.country_code or "ZZ", s.latency_ms))
    for s in ordered:
        lines.append(f"{s.country_code or '??'}\t{s.latency_ms}\t{s.protocol}\t{s.uri}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

def _inbounds() -> list[dict]:
    sniffing = {"destOverride": ["http", "tls", "quic"], "enabled": True}
    return [
        {
            "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": sniffing, "tag": "socks",
        },
        {
            "listen": "127.0.0.1", "port": 10809, "protocol": "http",
            "settings": {"allowTransparent": False},
            "sniffing": sniffing, "tag": "http",
        },
    ]

def _country_config(remarks: str, tags: list[str], outbounds: list[dict]) -> dict:
    balancer_tag = f"{tags[0].split('-', 1)[0]}-balancer" if tags else "balancer"
    expected = min(2, len(tags)) if tags else 1

    return {
        "remarks": remarks,
        "log": {"loglevel": "warning"},
        "dns": {
            "queryStrategy": "UseIP",
            "servers": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
        },
        "inbounds": _inbounds(),
        "outbounds": outbounds + [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {
            "domainMatcher": "hybrid",
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "domain": RU_DOMAINS, "outboundTag": "direct"},
                {"type": "field", "network": "tcp,udp", "balancerTag": balancer_tag},
            ],
            "balancers": [{
                "tag": balancer_tag,
                "selector": tags,
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "maxRTT": "1s",
                        "expected": expected,
                        "baselines": ["1s"],
                        "tolerance": 0.01,
                    },
                },
            }],
        },
        "burstObservatory": {
            "pingConfig": {
                "timeout": "10s",
                "interval": "300s",
                "sampling": 5,
                "destination": "http://www.gstatic.com/generate_204",
            },
            "subjectSelector": tags,
        },
    }

def build_country_configs(servers: list[Server], brand: str) -> list[dict]:
    groups: dict[str, list[Server]] = defaultdict(list)
    for s in servers:
        groups[(s.country_code or "XX").upper()].append(s)

    configs: list[dict] = []
    for code in sorted(groups):
        items = sorted(groups[code], key=lambda s: s.latency_ms)
        tags = [f"{code.lower()}-{i + 1}" for i in range(len(items))]
        outbounds = [build_outbound(s, t) for s, t in zip(items, tags)]
        remarks = f"{country_flag(code)} {country_name_ru(code)} | {brand}"
        configs.append(_country_config(remarks, tags, outbounds))
    return configs

def write_json(configs: list[dict], path: Path) -> None:
    path.write_text(json.dumps(configs, ensure_ascii=False, indent=2), encoding="utf-8")

def write_stats(
    servers: list[Server],
    skipped: list[SkipRecord],
    sub_stats: list[SubStats],
    path: Path,
) -> None:
    countries: dict[str, int] = {}
    for s in servers:
        if s.working:
            code = s.country_code or "XX"
            countries[code] = countries.get(code, 0) + 1

    by_reason = Counter(rec.reason.split(" — ", 1)[0] for rec in skipped)

    payload = {
        "parsed": len(servers),
        "skipped": len(skipped),
        "working": sum(1 for s in servers if s.working),
        "failed": sum(1 for s in servers if not s.working),
        "countries": countries,
        "skipped_reasons": dict(by_reason),
        "subscriptions": [
            {
                "url": st.url,
                "status": st.status,
                "bytes": st.bytes,
                "content_type": st.content_type,
                "base64": st.base64_decoded,
                "links": st.links,
                "error": st.error,
            }
            for st in sub_stats
        ],
        "skipped_samples": [
            {"scheme": rec.scheme, "uri": _preview(rec.uri, 120), "reason": rec.reason}
            for rec in skipped[:30]
        ],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

# ============================================================================
# Pipeline (used by CLI and by menu)
# ============================================================================

def run_pipeline(opts: argparse.Namespace) -> int:
    verbose = bool(getattr(opts, "verbose", False))

    urls = _collect_urls(opts)
    if not urls:
        print("ОШИБКА: нет источников подписок.", file=sys.stderr)
        print(f"  Создайте {opts.sub_file} с одной ссылкой на строку,",
              file=sys.stderr)
        print("  или передайте --sub URL.", file=sys.stderr)
        return 2

    all_servers: list[Server] = []
    all_skipped: list[SkipRecord] = []
    sub_stats: list[SubStats] = []

    print()
    print("┌─ Скачивание подписок ─────────────────────────────────────")
    for url in urls:
        log(f"│ [sub] {url}")
        try:
            text, stats = fetch_subscription(url, timeout=opts.timeout * 3)
        except requests.RequestException as error:
            log(f"│       ОШИБКА: {type(error).__name__}: {error}")
            continue

        sub_stats.append(stats)
        b64_marker = "base64" if stats.base64_decoded else "plain"
        log(
            f"│       HTTP {stats.status}  {stats.bytes}B  "
            f"type={stats.content_type or '?'}  {b64_marker}  "
            f"ссылок={stats.links}"
        )
        if stats.content_type.startswith("text/html"):
            log("│       ВНИМАНИЕ: content-type HTML — сервер вернул страницу "
                "ошибки вместо списка")
        if stats.links == 0:
            log("│       ВНИМАНИЕ: 0 ссылок в теле — проверьте URL/токен")

        if not text:
            continue

        servers, skipped = parse_subscription(text, verbose=verbose)
        log(f"│       распарсено={len(servers)}  пропущено={len(skipped)}")
        all_servers.extend(servers)
        all_skipped.extend(skipped)
    print("└───────────────────────────────────────────────────────────")

    unique_servers = _dedupe(all_servers)
    duplicates = len(all_servers) - len(unique_servers)

    print()
    print("┌─ Итоги парсинга ──────────────────────────────────────────")
    log(
        f"│ Всего узлов: {len(all_servers)}  |  "
        f"уникальных: {len(unique_servers)}  |  "
        f"дубликатов убрано: {duplicates}  |  "
        f"пропущено: {len(all_skipped)}"
    )
    if all_skipped:
        by_scheme = Counter(rec.scheme for rec in all_skipped)
        log("│ Пропущено по схемам: " +
            ", ".join(f"{s}={n}" for s, n in by_scheme.most_common()))
        by_reason = Counter(rec.reason.split(" — ", 1)[0] for rec in all_skipped)
        log("│ Причины пропусков:")
        for reason, count in by_reason.most_common():
            log(f"│   {count:4d} × {reason}")
        if not verbose:
            log("│ (детали по каждой ссылке — при запуске в подробном режиме)")
    print("└───────────────────────────────────────────────────────────")

    if not unique_servers:
        print("\nОШИБКА: нечего тестировать.", file=sys.stderr)
        return 1

    if opts.dry_run:
        print("\n[dry-run] Тестирование пропущено.")
        return 0

    try:
        xray_bin = ensure_xray(opts.xray)
    except Exception as error:
        print(f"ОШИБКА: {error}", file=sys.stderr)
        return 1
    log(f"\n[xray] {xray_bin}")

    tester = XrayTester(
        xray_bin=xray_bin,
        test_url=opts.test_url,
        timeout=opts.timeout,
        concurrency=opts.concurrency,
        batch_size=opts.batch_size,
        base_port=opts.base_port,
        verbose=verbose,
    )
    print()
    print("┌─ Проверка узлов через Xray ───────────────────────────────")
    tester.test_all(unique_servers)
    print("└───────────────────────────────────────────────────────────")

    working = [s for s in unique_servers if s.working]
    pct = (len(working) / len(unique_servers) * 100) if unique_servers else 0.0

    out_dir = Path(opts.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    write_working_txt(working, out_dir / "working_servers.txt")

    export = unique_servers if opts.keep_all else working
    configs = build_country_configs(export, opts.brand)
    write_json(configs, out_dir / "xray_config_by_country.json")
    write_stats(unique_servers, all_skipped, sub_stats, out_dir / "stats.json")

    by_country = Counter(s.country_code or "??" for s in working)
    failed_reasons = Counter(
        (s.error or "unknown")[:80]
        for s in unique_servers if not s.working
    )

    print()
    print("═══════════════════════════════════════════════════════════")
    print("  ГОТОВО")
    print("═══════════════════════════════════════════════════════════")
    print(f"  Рабочих узлов:       {len(working)} / {len(unique_servers)} ({pct:.1f}%)")
    print(f"  Стран в JSON:        {len(configs)}")
    print(f"  Пропущено при парсе: {len(all_skipped)}")
    if by_country:
        print("  Рабочие по странам: " +
              ", ".join(f"{code}={n}" for code, n in by_country.most_common()))
    if failed_reasons:
        print("  Топ причин падения узлов:")
        for reason, count in failed_reasons.most_common(8):
            print(f"    {count:4d} × {reason}")
    print("  Файлы:")
    print(f"    {out_dir / 'working_servers.txt'}")
    print(f"    {out_dir / 'xray_config_by_country.json'}")
    print(f"    {out_dir / 'stats.json'}")
    print("═══════════════════════════════════════════════════════════")
    return 0

def _collect_urls(opts: argparse.Namespace) -> list[str]:
    urls = list(opts.sub)
    sub_file = Path(opts.sub_file) if opts.sub_file else None
    if sub_file and sub_file.exists():
        content = sub_file.read_text(encoding="utf-8")
        urls.extend(
            line.strip() for line in content.splitlines()
            if line.strip() and not line.strip().startswith("#")
        )
    elif sub_file and not sub_file.exists() and not urls:
        log(f"[subs] {sub_file} не найден; создайте его (одна ссылка на строку)")
    return urls

def _dedupe(servers: list[Server]) -> list[Server]:
    seen: set[tuple] = set()
    unique: list[Server] = []
    for s in servers:
        if s.dedupe_key not in seen:
            seen.add(s.dedupe_key)
            unique.append(s)
    return unique

# ============================================================================
# Interactive menu
# ============================================================================

def _default_opts(verbose: bool = True, dry_run: bool = False) -> argparse.Namespace:
    return argparse.Namespace(
        sub=[],
        sub_file="subs.txt",
        xray=None,
        out="out",
        brand=DEFAULT_BRAND,
        test_url=DEFAULT_TEST_URL,
        timeout=10,
        concurrency=12,
        batch_size=15,
        base_port=20000,
        keep_all=False,
        dry_run=dry_run,
        quiet=False,
        verbose=verbose,
    )

def _open_editor(path: Path) -> None:
    if not path.exists():
        path.write_text(
            "# Впишите здесь ссылки на подписки — одна на строку\n"
            "# Строки с '#' в начале игнорируются\n\n",
            encoding="utf-8",
        )
        print(f"Создан файл {path}. Открываю редактор...")
    editor = os.environ.get("EDITOR") or os.environ.get("VISUAL")
    try:
        if editor:
            subprocess.call([editor, str(path)])
        elif os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.call(["open", str(path)])
        else:
            subprocess.call(["xdg-open", str(path)])
    except FileNotFoundError:
        print(f"Не удалось открыть редактор. Откройте вручную: {path.resolve()}")

def _show_last_stats() -> None:
    stats_path = Path("out") / "stats.json"
    if not stats_path.exists():
        print("Прошлых результатов нет. Сначала запустите проверку.")
        return
    try:
        payload = json.loads(stats_path.read_text(encoding="utf-8"))
    except Exception as error:
        print(f"Не удалось прочитать {stats_path}: {error}")
        return
    print()
    print("── Прошлый результат ─────────────────────────────────")
    print(f"  Распарсено:  {payload.get('parsed', 0)}")
    print(f"  Рабочих:     {payload.get('working', 0)}")
    print(f"  Пропущено:   {payload.get('skipped', 0)}")
    countries = payload.get("countries") or {}
    if countries:
        print("  По странам:  " +
              ", ".join(f"{c}={n}" for c, n in sorted(countries.items())))
    print("──────────────────────────────────────────────────────")

MENU_TEXT = """
═══════════════════════════════════════════════════════════
  Xray Sub Parser — интерактивный режим
═══════════════════════════════════════════════════════════
  1. Запустить с ПОДРОБНЫМ отчётом  (рекомендуется)
     — покажет каждую ссылку, каждый узел, все причины падений

  2. Запустить с кратким отчётом
     — итог по подпискам и узлам, без деталей по каждой ссылке

  3. Только проверить парсинг подписок (без теста Xray)
     — быстро: сколько ссылок, что распознано, что пропущено

  4. Открыть subs.txt (редактировать список подписок)

  5. Показать прошлый результат

  0. Выход
═══════════════════════════════════════════════════════════
"""

def interactive_menu() -> int:
    while True:
        print(MENU_TEXT)
        try:
            choice = input("Ваш выбор: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if choice == "0":
            return 0
        elif choice == "1":
            return run_pipeline(_default_opts(verbose=True))
        elif choice == "2":
            return run_pipeline(_default_opts(verbose=False))
        elif choice == "3":
            return run_pipeline(_default_opts(verbose=True, dry_run=True))
        elif choice == "4":
            _open_editor(Path("subs.txt"))
        elif choice == "5":
            _show_last_stats()
        else:
            print("Неизвестный выбор, попробуйте снова.")

# ============================================================================
# CLI
# ============================================================================

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Парсер подписок Xray с проверкой узлов через Xray Core. "
            "Без аргументов открывает интерактивное меню."
        )
    )
    p.add_argument("--menu", action="store_true", help="открыть интерактивное меню")
    p.add_argument("--sub", action="append", default=[], help="URL подписки (можно несколько)")
    p.add_argument("--sub-file", default="subs.txt", help="файл со списком URL (по умолчанию: subs.txt)")
    p.add_argument("--xray", help="путь к бинарнику xray (скачается, если отсутствует)")
    p.add_argument("--out", default="out", help="каталог результатов")
    p.add_argument("--brand", default=DEFAULT_BRAND, help="бренд в remarks")
    p.add_argument("--test-url", default=DEFAULT_TEST_URL, help="URL для проверки")
    p.add_argument("--timeout", type=int, default=10, help="таймаут запроса, с")
    p.add_argument("--concurrency", type=int, default=12, help="параллельных проверок в батче")
    p.add_argument("--batch-size", type=int, default=15, help="узлов на один временный Xray")
    p.add_argument("--base-port", type=int, default=20000, help="первый SOCKS-порт")
    p.add_argument("--keep-all", action="store_true", help="экспортировать и нерабочие узлы")
    p.add_argument("--dry-run", action="store_true", help="только парсинг, без теста")
    p.add_argument("--quiet", "-q", action="store_true", help="только предупреждения и ошибки")
    p.add_argument("--verbose", "-v", action="store_true", help="подробный отчёт по каждой ссылке")
    return p

def main() -> int:
    has_cli_args = len(sys.argv) > 1

    # Нет аргументов + интерактивный терминал → меню.
    if not has_cli_args and sys.stdin.isatty():
        return interactive_menu()

    args = build_argparser().parse_args()

    # Явно указан --menu → меню.
    if args.menu:
        return interactive_menu()

    return run_pipeline(args)

if __name__ == "__main__":
    sys.exit(main())
