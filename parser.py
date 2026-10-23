#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import queue
import socket
import subprocess
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

PING_URL = "https://www.gstatic.com/generate_204"  # https, чтобы было TLS как в приложении
PING_TIMEOUT = 7        # приложение позволяет 5–15 сек
PING_ATTEMPTS = 2        # как в приложении: два запроса, берём лучший
CHECK_THREADS = 10
BASE_PORT = 20000
GEO_DELAY = 1.5
PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://")


# ---------- утилиты ----------

def b64dec(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")


def b64enc(s):
    return base64.b64encode(s.encode("utf-8")).decode()


def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def write_lines(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


def flag(cc):
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "🏳️"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper())


# ---------- разбор ссылок ----------

def build_stream(q):
    net = q.get("type", "tcp")
    if net == "http":
        net = "h2"
    # KeepAlive на уровне сокета xray
    st = {"network": net,
          "sockopt": {"tcpKeepAliveIdle": 30, "tcpKeepAliveInterval": 15}}

    sec = q.get("security", "none")
    if sec in ("tls", "reality"):
        st["security"] = sec
        sni = q.get("sni") or q.get("host") or ""
        if sec == "tls":
            tls = {"serverName": sni, "allowInsecure": q.get("allowInsecure") == "1"}
            if q.get("alpn"):
                tls["alpn"] = q["alpn"].split(",")
            if q.get("fp"):
                tls["fingerprint"] = q["fp"]
            st["tlsSettings"] = tls
        else:
            st["realitySettings"] = {
                "serverName": sni,
                "fingerprint": q.get("fp", "chrome"),
                "publicKey": q.get("pbk", ""),
                "shortId": q.get("sid", ""),
                "spiderX": q.get("spx", "/"),
            }

    path = q.get("path", "/")
    host = q.get("host", "")
    if net == "ws":
        st["wsSettings"] = {"path": path, "headers": {"Host": host} if host else {}}
    elif net == "grpc":
        st["grpcSettings"] = {"serviceName": q.get("serviceName", ""),
                              "multiMode": q.get("mode") == "multi"}
    elif net == "h2":
        st["httpSettings"] = {"path": path, "host": [host] if host else []}
    return st


def parse_link(link):
    """Возвращает dict с key, ob (outbound для xray), name, host, port, link или None."""
    try:
        if link.startswith("vmess://"):
            d = json.loads(b64dec(link[8:]))
            name = d.get("ps", "")
            host, port = d["add"], int(d["port"])
            net = d.get("net", "tcp")
            q = {"type": net, "path": d.get("path", ""), "host": d.get("host", ""),
                 "serviceName": d.get("path", ""), "sni": d.get("sni", ""),
                 "security": "tls" if d.get("tls") == "tls" else "none",
                 "alpn": d.get("alpn", ""), "fp": d.get("fp", "")}
            ob = {"protocol": "vmess",
                  "settings": {"vnext": [{"address": host, "port": port,
                                          "users": [{"id": d["id"],
                                                     "alterId": int(d.get("aid", 0)),
                                                     "security": "auto"}]}]},
                  "streamSettings": build_stream(q)}

        else:
            u = up.urlsplit(link)
            name = up.unquote(u.fragment)
            q = dict(up.parse_qsl(u.query))

            if link.startswith("vless://"):
                host, port = u.hostname, u.port
                user = {"id": u.username, "encryption": "none"}
                if q.get("flow"):
                    user["flow"] = q["flow"]
                ob = {"protocol": "vless",
                      "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
                      "streamSettings": build_stream(q)}

            elif link.startswith("trojan://"):
                host, port = u.hostname, u.port
                ob = {"protocol": "trojan",
                      "settings": {"servers": [{"address": host, "port": port,
                                                "password": up.unquote(u.username)}]},
                      "streamSettings": build_stream(q)}

            else:  # ss://
                body = link[5:].split("#")[0].split("?")[0]
                if "@" in body:
                    userinfo, hostport = body.rsplit("@", 1)
                    if ":" not in userinfo:
                        userinfo = b64dec(userinfo)
                else:
                    userinfo, hostport = b64dec(body).rsplit("@", 1)
                method, password = userinfo.split(":", 1)
                host, port = hostport.rsplit(":", 1)
                port = int(port)
                ob = {"protocol": "shadowsocks",
                      "settings": {"servers": [{"address": host, "port": port,
                                                "method": method, "password": password}]}}

        # ключ = сам сервер (без имени), чтобы дубликаты не проверялись повторно
        ident = json.dumps({"p": ob["protocol"], "s": ob["settings"],
                            "st": ob.get("streamSettings")}, sort_keys=True)
        key = hashlib.sha1(ident.encode()).hexdigest()
        return {"key": key, "ob": ob, "name": name, "host": host,
                "port": port, "link": link}
    except Exception:
        return None


def rename_link(link, name):
    if link.startswith("vmess://"):
        d = json.loads(b64dec(link[8:]))
        d["ps"] = name
        return "vmess://" + b64enc(json.dumps(d, ensure_ascii=False))
    return link.split("#")[0] + "#" + up.quote(name)


def fetch_sub(url):
    try:
        r = requests.get(url, timeout=20, headers={"User-Agent": "Mozilla/5.0"})
        text = r.text.strip()
        if not text.startswith(PROTOCOLS):
            text = b64dec(text)
        return [l.strip() for l in text.splitlines() if l.strip().startswith(PROTOCOLS)]
    except Exception as e:
        print(f"[!] подписка недоступна {url}: {e}")
        return []


# ---------- проверка через xray ----------

def wait_port(port, timeout=5):
    """Ждём, пока xray начнёт слушать SOCKS-порт, вместо фиксированного sleep."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def ping_keepalive(ob, port):
    """
    Режим via Proxy GET + KeepAlive:
    одна сессия xray, один requests.Session (одно переиспользуемое соединение),
    два GET-запроса, результат - лучший из двух. Возвращает мс или None.
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
        if not wait_port(port):
            return None

        proxy = f"socks5h://127.0.0.1:{port}"
        timings = []
        # одна сессия на все запросы = переиспользование TCP/TLS-соединения
        with requests.Session() as s:
            s.proxies = {"http": proxy, "https": proxy}
            for _ in range(PING_ATTEMPTS):
                t0 = time.perf_counter()
                try:
                    r = s.get(PING_URL, timeout=PING_TIMEOUT)
                except requests.RequestException:
                    break
                elapsed = (time.perf_counter() - t0) * 1000
                if r.status_code != 204:
                    break
                timings.append(elapsed)
        return min(timings) if timings else None
    finally:
        proc.kill()
        proc.wait()
        try:
            os.remove(path)
        except OSError:
            pass


def check_many(servers):
    ports = queue.Queue()
    for i in range(CHECK_THREADS):
        ports.put(BASE_PORT + i)

    def job(s):
        port = ports.get()
        try:
            ping = ping_keepalive(s["ob"], port)
        finally:
            ports.put(port)
        return s["key"], ping

    with ThreadPoolExecutor(CHECK_THREADS) as ex:
        return dict(ex.map(job, servers))  # key -> ping (мс) или None


# ---------- определение страны ----------

def _ipapi(ip):
    d = requests.get(f"http://ip-api.com/json/{ip}?fields=status,countryCode,country",
                     timeout=10).json()
    return (d["countryCode"], d["country"]) if d.get("status") == "success" else None


def _ipwho(ip):
    d = requests.get(f"https://ipwho.is/{ip}", timeout=10).json()
    return (d["country_code"], d["country"]) if d.get("success") else None


def _ipapico(ip):
    d = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10).json()
    return (d["country_code"], d["country_name"]) if d.get("country_code") else None


GEO_SERVICES = [_ipapi, _ipwho, _ipapico]


def geolocate(host):
    """Пробует сервисы по очереди. Возвращает (cc, country) или None."""
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return None
    for svc in GEO_SERVICES:
        try:
            res = svc(ip)
            if res:
                return res
        except Exception:
            pass
        time.sleep(GEO_DELAY)
    return None


# ---------- основной цикл ----------

def main():
    os.makedirs(DATA, exist_ok=True)

    state = {"working": {}}
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, encoding="utf-8") as f:
            state = json.load(f)
    working = state["working"]  # key -> метаданные

    # нерабочие: key -> строка для dead.txt (никогда не очищаются)
    dead = {}
    for line in read_lines(DEAD_FILE):
        dead[line.split()[0]] = line

    # 1. Сбор серверов из подписок
    fresh = {}
    for sub_url in read_lines(SUBS_FILE):
        sub_id = hashlib.sha1(sub_url.encode()).hexdigest()[:8]
        links = fetch_sub(sub_url)
        print(f"[+] {sub_url}: {len(links)} ссылок")
        pos = 0
        for link in links:
            p = parse_link(link)
            if not p:
                continue
            pos += 1
            if p["key"] in fresh or p["key"] in dead:
                continue
            p["sub_id"], p["sub_pos"] = sub_id, pos
            fresh[p["key"]] = p

    # 2. Что проверять: новые (не рабочие и не нерабочие) + уже рабочие
    to_check = [p for k, p in fresh.items() if k not in working]
    for k, info in working.items():
        p = parse_link(info["link"])
        if p:
            p["sub_id"], p["sub_pos"] = info["sub_id"], info["sub_pos"]
            to_check.append(p)

    print(f"[*] к проверке: {len(to_check)}")
    results = check_many(to_check) if to_check else {}

    for p in to_check:
        k = p["key"]
        ping = results.get(k)
        if ping is not None:
            prev = working.get(k, {})
            working[k] = {
                "link": p["link"], "host": p["host"], "port": p["port"],
                "sub_id": p["sub_id"], "sub_pos": p["sub_pos"],
                "ping": round(ping),
                "cc": prev.get("cc"), "country": prev.get("country"),
            }
        else:
            working.pop(k, None)
            dead[k] = f"{k} {p['host']}:{p['port']}"

    # 3. Определение страны для рабочих
    for k, info in working.items():
        if info.get("cc"):
            continue
        geo = geolocate(info["host"])
        if geo:
            info["cc"], info["country"] = geo
            print(f"[geo] {info['host']} -> {geo[1]}")
        else:
            print(f"[geo] {info['host']} -> не удалось определить")

    # 4. Сохранение
    write_lines(DEAD_FILE, sorted(dead.values()))

    ordered = sorted(working.items(), key=lambda kv: (kv[1]["sub_id"], kv[1]["sub_pos"]))
    write_lines(WORKING_TXT, [info["link"] for _, info in ordered])

    worker_lines = []
    counter, cur_sub = 0, None
    for _, info in ordered:
        if not info.get("cc"):
            continue
        if info["sub_id"] != cur_sub:
            cur_sub, counter = info["sub_id"], 0
        counter += 1
        name = f"{flag(info['cc'])} №{counter} {info['country']}"
        worker_lines.append(rename_link(info["link"], name))
    write_lines(WORKER_TXT, worker_lines)

    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

    print(f"[=] рабочих: {len(working)}, для воркера: {len(worker_lines)}, "
          f"нерабочих всего: {len(dead)}")


if __name__ == "__main__":
    main()
