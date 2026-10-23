#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import queue
import subprocess
import socket
import time
import urllib.parse as up
from concurrent.futures import ThreadPoolExecutor

import requests

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
SUBS_FILE = os.path.join(DATA, "subscriptions.txt")
DEAD_FILE = os.path.join(DATA, "dead.txt")
WORKING_TXT = os.path.join(DATA, "working.txt")
WORKER_TXT = os.path.join(DATA, "worker.txt")
STATE_FILE = os.path.join(DATA, "state.json")
XRAY_BIN = os.path.join(ROOT, "xray")
TMP_DIR = os.path.join(ROOT, "tmp")

PING_URL = "https://www.gstatic.com/generate_204"
PING_TIMEOUT = 7
PING_ATTEMPTS = 2
GEO_TIMEOUT = 10
CHECK_THREADS = int(os.environ.get("CHECK_THREADS", 20))
BASE_PORT = 20000

MAX_CHECKS = int(os.environ.get("MAX_CHECKS", 400))
TIME_BUDGET = int(os.environ.get("TIME_BUDGET", 1500))  # секунд на проверку

GEO_VERSION = 2  # при смене логики определения страны старые cc сбрасываются

PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://")
UA = "v2rayNG/1.8.5"

# Геосервисы вызываются ЧЕРЕЗ туннель: страна = страна выходного IP сервера
GEO_ENDPOINTS = [
    ("https://ipwho.is/",
     lambda d: (d.get("country_code"), d.get("country")) if d.get("success") else None),
    ("https://ipapi.co/json/",
     lambda d: (d.get("country_code"), d.get("country_name")) if d.get("country_code") else None),
]


# ---------- утилиты ----------

def b64dec(s):
    s = "".join(s.split()).replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "ignore")


def b64enc(s):
    return base64.b64encode(s.encode("utf-8")).decode()


def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def write_lines(path, lines):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
    os.replace(tmp, path)


def save_json_atomic(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def load_state():
    default = {"servers": {}, "geo_version": 0}
    if not os.path.exists(STATE_FILE):
        return default
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            text = f.read()
        if not text.strip():
            raise ValueError("файл пустой")
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("корень не является объектом")
    except (ValueError, OSError) as e:
        print(f"[!] state.json не читается ({e}), начинаю с пустого состояния")
        try:
            os.replace(STATE_FILE, STATE_FILE + ".broken")
        except OSError:
            pass
        return default

    data.setdefault("servers", {})
    data.setdefault("geo_version", 0)
    # миграция со старого формата (ключ "working")
    for k, v in data.pop("working", {}).items():
        data["servers"].setdefault(k, {
            "link": v.get("link", ""), "host": v.get("host", ""), "port": v.get("port", 0),
            "sub_id": v.get("sub_id", "x"), "sub_pos": v.get("sub_pos", 0),
            "status": "working", "ping": v.get("ping"), "last_checked": 0,
            "cc": None, "country": None,
        })
    data.pop("geo", None)
    return data


def flag(cc):
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "🏳️"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper())


# ---------- разбор ссылок ----------

def build_stream(q):
    net = (q.get("type") or "tcp").lower()
    if net in ("raw", ""):
        net = "tcp"
    if net == "http":
        net = "h2"
    if net == "splithttp":
        net = "xhttp"

    st = {"network": net,
          "sockopt": {"tcpKeepAliveIdle": 30, "tcpKeepAliveInterval": 15}}

    sec = (q.get("security") or "none").lower()
    if sec in ("tls", "reality"):
        st["security"] = sec
        sni = q.get("sni") or q.get("host") or ""
        if sec == "tls":
            tls = {"serverName": sni,
                   "allowInsecure": str(q.get("allowInsecure", "0")).lower() in ("1", "true")}
            if q.get("alpn"):
                tls["alpn"] = [a for a in q["alpn"].split(",") if a]
            if q.get("fp"):
                tls["fingerprint"] = q["fp"]
            st["tlsSettings"] = tls
        else:
            st["realitySettings"] = {
                "serverName": sni,
                "fingerprint": q.get("fp") or "chrome",
                "publicKey": q.get("pbk", ""),
                "shortId": q.get("sid", ""),
                "spiderX": q.get("spx", "/"),
            }

    host = q.get("host", "")
    path = q.get("path") or "/"

    if net == "ws":
        st["wsSettings"] = {"path": path, "headers": {"Host": host} if host else {}}
    elif net == "grpc":
        st["grpcSettings"] = {"serviceName": q.get("serviceName", ""),
                              "multiMode": q.get("mode") == "multi",
                              "authority": q.get("authority", "")}
    elif net == "h2":
        st["httpSettings"] = {"path": path, "host": [host] if host else []}
    elif net == "httpupgrade":
        st["httpupgradeSettings"] = {"path": path, "host": host}
    elif net == "xhttp":
        x = {"path": path}
        if host:
            x["host"] = host
        if q.get("mode"):
            x["mode"] = q["mode"]
        if q.get("extra"):
            try:
                x["extra"] = json.loads(q["extra"])
            except Exception:
                pass
        st["xhttpSettings"] = x
    elif net == "kcp":
        st["kcpSettings"] = {
            "mtu": 1350, "tti": 50, "uplinkCapacity": 5, "downlinkCapacity": 20,
            "congestion": False, "readBufferSize": 2, "writeBufferSize": 2,
            "header": {"type": q.get("headerType") or "none"},
            "seed": q.get("seed", ""),
        }
    elif net == "quic":
        st["quicSettings"] = {
            "security": q.get("quicSecurity") or "none",
            "key": q.get("key", ""),
            "header": {"type": q.get("headerType") or "none"},
        }
    elif net == "tcp":
        if (q.get("headerType") or "").lower() == "http":
            st["tcpSettings"] = {"header": {"type": "http", "request": {
                "path": [path], "headers": {"Host": [host] if host else []}}}}
    return st


def entry(proto, host, port, uid, ob, name, link):
    if not host or not port:
        return None
    key = hashlib.sha1(f"{proto}|{host.lower()}|{port}|{uid}".encode()).hexdigest()[:16]
    return {"key": key, "host": host, "port": port, "ob": ob, "name": name, "link": link}


def _parse_vmess(link):
    d = json.loads(b64dec(link[8:]))
    host = str(d.get("add", "")).strip()
    port = int(d.get("port"))
    uid = d.get("id", "")
    q = {
        "type": d.get("net") or "tcp",
        "headerType": d.get("type") or "",
        "host": d.get("host", ""),
        "path": d.get("path", ""),
        "serviceName": d.get("path", ""),
        "sni": d.get("sni", ""),
        "security": "tls" if d.get("tls") == "tls" else "none",
        "alpn": d.get("alpn", ""),
        "fp": d.get("fp", ""),
    }
    ob = {"protocol": "vmess",
          "settings": {"vnext": [{"address": host, "port": port,
                                  "users": [{"id": uid,
                                             "alterId": int(d.get("aid", 0) or 0),
                                             "security": d.get("scy") or "auto"}]}]},
          "streamSettings": build_stream(q)}
    return entry("vmess", host, port, uid, ob, d.get("ps", ""), link)


def _parse_vless(link):
    u = up.urlsplit(link)
    q = dict(up.parse_qsl(u.query, keep_blank_values=True))
    host, port = u.hostname, u.port
    uid = up.unquote(u.username or "")
    user = {"id": uid, "encryption": "none"}
    if q.get("flow") and (q.get("type") or "tcp") in ("tcp", "raw", ""):
        user["flow"] = q["flow"]
    ob = {"protocol": "vless",
          "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
          "streamSettings": build_stream(q)}
    return entry("vless", host, port, uid, ob, up.unquote(u.fragment), link)


def _parse_trojan(link):
    u = up.urlsplit(link)
    q = dict(up.parse_qsl(u.query, keep_blank_values=True))
    host, port = u.hostname, u.port
    pwd = up.unquote(u.username or "")
    if "security" not in q:
        q["security"] = "tls"
    ob = {"protocol": "trojan",
          "settings": {"servers": [{"address": host, "port": port, "password": pwd}]},
          "streamSettings": build_stream(q)}
    return entry("trojan", host, port, pwd, ob, up.unquote(u.fragment), link)


def _parse_ss(link):
    body = link[5:]
    name = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        name = up.unquote(frag)
    if "?" in body:
        body = body.split("?", 1)[0]
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        if ":" not in userinfo:
            userinfo = b64dec(userinfo)
    else:
        userinfo, hostport = b64dec(body).rsplit("@", 1)
    method, password = up.unquote(userinfo).split(":", 1)
    host, port = hostport.rsplit(":", 1)
    host = host.strip("[]")
    port = int(port)
    ob = {"protocol": "shadowsocks",
          "settings": {"servers": [{"address": host, "port": port,
                                    "method": method, "password": password}]}}
    return entry("ss", host, port, method + password, ob, name, link)


def parse_link(raw):
    link = raw.strip()
    try:
        if link.startswith("vmess://"):
            return _parse_vmess(link)
        if link.startswith("vless://"):
            return _parse_vless(link)
        if link.startswith("trojan://"):
            return _parse_trojan(link)
        if link.startswith("ss://"):
            return _parse_ss(link)
    except Exception:
        return None
    return None


def rename_link(link, name):
    try:
        if link.startswith("vmess://"):
            d = json.loads(b64dec(link[8:]))
            d["ps"] = name
            return "vmess://" + b64enc(json.dumps(d, ensure_ascii=False))
        return link.split("#")[0] + "#" + up.quote(name)
    except Exception:
        return link


def fetch_sub(url):
    try:
        r = requests.get(url, timeout=25, headers={"User-Agent": UA})
        text = r.text.strip()
        if not any(p in text for p in PROTOCOLS):
            text = b64dec(text)
        return [l.strip() for l in text.splitlines() if l.strip().startswith(PROTOCOLS)]
    except Exception as e:
        print(f"[!] подписка недоступна {url[:60]}: {e}")
        return []


# ---------- проверка через xray ----------

def wait_port(port, proc, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False  # xray упал (битый конфиг)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def exit_geo(session):
    """Страна выходного IP туннеля. None, если ни один геосервис не ответил."""
    for url, parse in GEO_ENDPOINTS:
        try:
            r = session.get(url, timeout=GEO_TIMEOUT)
            if r.status_code != 200:
                continue
            res = parse(r.json())
            if res and res[0] and len(res[0]) == 2:
                return res[0].upper(), res[1] or res[0].upper()
        except Exception:
            continue
    return None


def ping_keepalive(ob, port):
    """
    via Proxy GET + KeepAlive: один xray, одна сессия.
    Два GET-запроса (берём лучший результат), затем страна по выходному IP туннеля.
    Возвращает {"ping", "cc", "country"} или None (сервер мёртв).
    """
    os.makedirs(TMP_DIR, exist_ok=True)
    cfg = {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                      "settings": {"udp": False}}],
        "outbounds": [dict(ob, tag="proxy")],
    }
    path = os.path.join(TMP_DIR, f"cfg_{port}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)

    proc = subprocess.Popen([XRAY_BIN, "run", "-c", path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_port(port, proc):
            return None
        proxy = f"socks5h://127.0.0.1:{port}"
        timings = []
        with requests.Session() as s:
            s.proxies = {"http": proxy, "https": proxy}
            for _ in range(PING_ATTEMPTS):
                t0 = time.perf_counter()
                try:
                    r = s.get(PING_URL, timeout=PING_TIMEOUT)
                except requests.RequestException:
                    break
                if r.status_code != 204:
                    break
                timings.append((time.perf_counter() - t0) * 1000)
            if not timings:
                return None
            geo = exit_geo(s)
            if not geo:
                return None
        return {"ping": min(timings), "cc": geo[0], "country": geo[1]}
    finally:
        proc.kill()
        proc.wait()
        try:
            os.remove(path)
        except OSError:
            pass


def check_many(items, deadline):
    ports = queue.Queue()
    for i in range(CHECK_THREADS):
        ports.put(BASE_PORT + i)

    def job(it):
        if time.time() > deadline:
            return it["key"], "skip"
        port = ports.get()
        try:
            res = ping_keepalive(it["ob"], port)
        except Exception:
            res = None
        finally:
            ports.put(port)
        return it["key"], res

    results = {}
    with ThreadPoolExecutor(CHECK_THREADS) as ex:
        for k, v in ex.map(job, items):
            results[k] = v
    return results


# ---------- основной цикл ----------

def main():
    start = time.time()
    deadline = start + TIME_BUDGET
    os.makedirs(DATA, exist_ok=True)

    state = load_state()
    servers = state["servers"]

    # одноразовый сброс стран, определённых по IP хоста (неверно для CDN/anycast)
    if state.get("geo_version") != GEO_VERSION:
        for s in servers.values():
            s["cc"] = None
            s["country"] = None
        state["geo_version"] = GEO_VERSION
        print("[*] миграция: страны сброшены, будут определены через туннель")

    dead_lines = {}
    for line in read_lines(DEAD_FILE):
        dead_lines[line.split()[0]] = line
    dead = set(dead_lines)

    # 1. сбор серверов из подписок
    fresh = {}
    for url in read_lines(SUBS_FILE):
        sub_id = hashlib.sha1(url.encode()).hexdigest()[:8]
        links = fetch_sub(url)
        pos = 0
        for link in links:
            e = parse_link(link)
            if not e:
                continue
            pos += 1
            if e["key"] in dead or e["key"] in fresh:
                continue
            fresh[e["key"]] = (e, sub_id, pos)
        print(f"[+] {url[:60]}: {len(links)} ссылок")

    for k, (e, sub_id, pos) in fresh.items():
        if k in servers:
            servers[k]["link"] = e["link"]
        else:
            servers[k] = {
                "link": e["link"], "host": e["host"], "port": e["port"],
                "sub_id": sub_id, "sub_pos": pos, "status": "untested",
                "ping": None, "last_checked": 0, "cc": None, "country": None,
            }

    # 2. очередь: непроверенные, рабочие без страны, затем самые давние рабочие
    cands = [k for k in servers if k not in dead]
    cands.sort(key=lambda k: (
        servers[k]["status"] == "working",
        servers[k].get("cc") is not None,
        servers[k]["last_checked"],
        servers[k]["sub_pos"],
    ))

    batch = []
    for k in cands[:MAX_CHECKS]:
        e = parse_link(servers[k]["link"])
        if not e:
            dead.add(k)
            dead_lines[k] = f"{k} {servers[k]['host']}:{servers[k]['port']}"
            servers.pop(k, None)
            continue
        e["key"] = k
        batch.append(e)

    print(f"[*] известных {len(servers)}, кандидатов {len(cands)}, проверяю {len(batch)}")
    results = check_many(batch, deadline) if batch else {}

    now = int(time.time())
    ok = bad = skipped = 0
    for e in batch:
        k = e["key"]
        r = results.get(k, "skip")
        s = servers.get(k)
        if s is None or (isinstance(r, str) and r == "skip"):
            skipped += 1
            continue
        if r is None:
            # нет пинга или нет страны через туннель -> мёртв
            bad += 1
            dead.add(k)
            dead_lines[k] = f"{k} {s['host']}:{s['port']}"
            servers.pop(k, None)
        else:
            ok += 1
            s.update(status="working", ping=round(r["ping"]), last_checked=now,
                     cc=r["cc"], country=r["country"])
    print(f"[=] проверка: рабочих {ok}, мёртвых {bad}, не успели {skipped}")

    # 3. сохранение
    ordered = sorted([k for k, s in servers.items() if s["status"] == "working"],
                     key=lambda k: (servers[k]["sub_id"], servers[k]["sub_pos"]))
    write_lines(WORKING_TXT, [servers[k]["link"] for k in ordered])

    worker_lines = []
    counter, cur_sub = 0, None
    for k in ordered:
        s = servers[k]
        if not s.get("cc"):
            continue
        if s["sub_id"] != cur_sub:
            cur_sub, counter = s["sub_id"], 0
        counter += 1
        name = f"{flag(s['cc'])} №{counter} {s['country']}"
        worker_lines.append(rename_link(s["link"], name))
    write_lines(WORKER_TXT, worker_lines)

    write_lines(DEAD_FILE, sorted(dead_lines.values()))
    save_json_atomic(STATE_FILE, state)

    print(f"[=] рабочих: {len(ordered)}, для воркера: {len(worker_lines)}, "
          f"мёртвых всего: {len(dead_lines)}, время: {int(time.time() - start)} сек")


if __name__ == "__main__":
    main()
