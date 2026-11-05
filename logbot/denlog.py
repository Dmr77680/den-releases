#!/usr/bin/env python3
"""DEN log analyzer: reads an eden_log.txt and explains the known problems in plain words.

No account id, token or personal path is ever printed. Usage:
    python3 denlog.py eden_log.txt [fr|en]
"""
import re
import sys

KNOWN_GAMES = {"0100152000022000": "Mario Kart 8 Deluxe"}

LINE_RE = re.compile(r"^\[\s*([0-9.]+)\]\s+(\S+)\s+<(\w+)>\s+(.*)$")


def _grab(pattern, text, flags=0):
    m = re.search(pattern, text, flags)
    return m.group(1).strip() if m else None


def parse(path):
    """One pass over the file: keep only what the rules need."""
    d = {
        "lines": 0, "version": None, "model": None, "api": None, "driver": None,
        "firmware": None, "firmware_hardcoded": False, "titles": [], "datadir": None,
        "linked": None, "nextendo_on": None, "memory": None, "started": False,
        "ca_missing": 0, "ssl_fail": 0, "ssl_paths": set(), "token_rejected": None,
        "token_noresp": 0, "unreachable": 0, "refresh_ok": 0, "readfail": 0,
        "vk_missing": [], "panic": [], "host_mem": [], "abandoned_at": [],
        "tex_assert": [], "applet_assert": [], "unimpl": [], "net_init": 0,
        "addr_in_use": 0, "end_time": 0.0,
    }
    with open(path, "r", errors="replace") as f:
        for raw in f:
            d["lines"] += 1
            m = LINE_RE.match(raw)
            if not m:
                continue
            t, cat, lvl, msg = float(m.group(1)), m.group(2), m.group(3), m.group(4)
            d["end_time"] = max(d["end_time"], t)
            if "eden Version:" in msg:
                d["version"] = msg.split("eden Version:")[1].strip()
            elif "Device Model -" in msg:
                d["model"] = msg.split("Device Model -")[1].strip()
            elif "Host OS:" in msg:
                d["api"] = _grab(r"API level (\d+)", msg)
            elif "Vulkan Driver:" in msg:
                d["driver"] = msg.split("Vulkan Driver:")[1].strip()
            elif "Installed firmware:" in msg:
                d["firmware"] = msg.split("Installed firmware:")[1].strip()
            elif "using hardcoded firmware version" in msg:
                d["firmware_hardcoded"] = True
            elif "Patching ExeFS for title_id=" in msg:
                tid = _grab(r"title_id=([0-9A-Fa-f]{16})", msg)
                if tid and not tid.startswith("0100000000") and tid.upper() not in d["titles"]:
                    d["titles"].append(tid.upper())
            elif "WriteGuestBridge" in msg:
                d["linked"] = "linked=true" in msg
            elif "Network.enable_nextendo:" in msg:
                d["nextendo_on"] = msg.rstrip().endswith("true")
            elif "[DEN] Memoire:" in msg:
                d["memory"] = msg.split("Memoire:")[1].strip()
            elif "RunEmulation: starting" in msg:
                d["started"] = True
            if d["datadir"] is None:
                dm = re.search(r"/Android/data/([A-Za-z0-9_.]+)/", msg)
                if dm:
                    d["datadir"] = dm.group(1)

            if "no known system CA bundle found" in msg:
                d["ca_missing"] += 1
            elif "SSL server verification
