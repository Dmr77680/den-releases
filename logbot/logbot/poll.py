#!/usr/bin/env python3
"""DEN log bot, GitHub Actions edition: no server, only the Discord REST API.

Every few minutes it reads the latest messages of the watched channels, and for each message that
carries a log (.txt) and has no bot reply yet, it posts the analysis from denlog.py.
Stateless on purpose: "already answered" is read from Discord itself (the bot's own replies).

    DISCORD_BOT_TOKEN    required (GitHub secret)
    LOG_CHANNEL_IDS      required, comma separated channel ids
    LOG_POLL_INTERVAL    seconds between checks (default 120)
    LOG_POLL_MAX         stop after this many seconds (default 20400 = 5h40)
    LOG_LANGS            "fr,en" (default), "fr" or "en"
"""
import datetime
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request

import denlog

API = os.environ.get("DISCORD_API", "https://discord.com/api/v10")
UA = "DiscordBot (https://github.com/Dmr77680/den-releases, 1.0)"
MAX_BYTES = 30 * 1024 * 1024
MAX_AGE_S = 24 * 3600
ALLOWED_HOSTS = ("https://cdn.discordapp.com/", "https://media.discordapp.net/")
NOTE_FR = "\n_Analyse automatique. Si ça ne règle pas ton problème, décris-le ici et on regarde._"
NOTE_EN = "\n_Automatic analysis. If this does not solve your problem, describe it here._"


def call(method, path, token, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method, headers={
        "Authorization": "Bot " + token, "User-Agent": UA, "Content-Type": "application/json"})
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt == 0:
                try:
                    wait = float(json.loads(e.read()).get("retry_after", 2))
                except Exception:
                    wait = 2.0
                time.sleep(min(wait, 30))
                continue
            print(f"Discord {method} {path.split('?')[0]} -> HTTP {e.code}", flush=True)
            return None
        except Exception as e:  # network trouble: try again at the next round
            print(f"Discord {method} {path.split('?')[0]} failed: {type(e).__name__}", flush=True)
            return None
    return None


def is_log(att):
    n = att.get("filename", "").lower()
    return n.endswith(".txt") and ("log" in n or "eden" in n or "den" in n)


def download(url, dest):
    if not url.startswith(ALLOWED_HOSTS) and os.environ.get("LOG_ALLOW_ANY_HOST") != "1":
        return False
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    size = 0
    with urllib.request.urlopen(req, timeout=60) as r, open(dest, "wb") as out:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_BYTES:
                return False
            out.write(chunk)
    return True


def age_seconds(iso):
    t = datetime.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return (datetime.datetime.now(datetime.timezone.utc) - t).total_seconds()


def reply(token, channel, msg_id, text):
    return call("POST", f"/channels/{channel}/messages", token, {
        "content": text, "allowed_mentions": {"parse": []},
        "message_reference": {"message_id": msg_id, "fail_if_not_exists": False}})


def handle_channel(token, me, channel, langs):
    msgs = call("GET", f"/channels/{channel}/messages?limit=50", token)
    if not isinstance(msgs, list):
        return 0
    answered = {m["message_reference"]["message_id"] for m in msgs
                if m.get("author", {}).get("id") == me and m.get("message_reference")}
    done = 0
    for m in msgs:
        if m.get("author", {}).get("bot") or m["id"] in answered:
            continue
        if age_seconds(m["timestamp"]) > MAX_AGE_S:
            continue
        logs = [a for a in m.get("attachments", []) if is_log(a)]
        if not logs:
            continue
        att = logs[0]
        if att.get("size", 0) > MAX_BYTES:
            reply(token, channel, m["id"], "Ce fichier est trop gros (30 Mo max) / File too large (30 MB max).")
            done += 1
            continue
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "log.txt")
            try:
                ok = download(att["url"], path)
            except Exception as e:
                print(f"download failed: {type(e).__name__}", flush=True)
                continue
            if not ok:
                reply(token, channel, m["id"], "Je n'ai pas pu lire ce fichier / I could not read this file.")
                done += 1
                continue
            texts = []
            if "fr" in langs:
                texts.append(denlog.report(path, "fr", 1700) + NOTE_FR)
            if "en" in langs:
                texts.append(denlog.report(path, "en", 1700) + NOTE_EN)
        for t in texts:
            reply(token, channel, m["id"], t)
        print(f"answered message {m['id']} in channel {channel}", flush=True)
        done += 1
    return done


def one_round(token, channels, langs):
    me = call("GET", "/users/@me", token)
    if not me:
        print("cannot identify the bot (wrong token?)", flush=True)
        return 0
    return sum(handle_channel(token, me["id"], c, langs) for c in channels)


def main():
    token = os.environ.get("DISCORD_BOT_TOKEN", "")
    channels = [c for c in os.environ.get("LOG_CHANNEL_IDS", "").replace(" ", "").split(",") if c]
    if not token or not channels:
        sys.exit("DISCORD_BOT_TOKEN and LOG_CHANNEL_IDS must be set")
    langs = [x for x in os.environ.get("LOG_LANGS", "fr,en").replace(" ", "").split(",") if x]
    interval = float(os.environ.get("LOG_POLL_INTERVAL", "120"))
    limit = float(os.environ.get("LOG_POLL_MAX", "20400"))
    start = time.time()
    print(f"watching {len(channels)} channel(s), every {interval:.0f}s", flush=True)
    while True:
        one_round(token, channels, langs)
        if time.time() - start + interval >= limit:
            break
        time.sleep(interval)


if __name__ == "__main__":
    main()
