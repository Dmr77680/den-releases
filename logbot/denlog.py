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
            elif "SSL server verification failed" in msg:
                d["ssl_fail"] += 1
                p = _grab(r"Send \w+ (/\S+):", msg)
                if p:
                    d["ssl_paths"].add(p)
            elif "FetchNexToken: rejected" in msg:
                d["token_rejected"] = msg
            elif "FetchNexToken: no response" in msg:
                d["token_noresp"] += 1
            elif "Could not reach the Nextendo account server" in msg or "no response (network)" in msg:
                d["unreachable"] += 1
            elif "session renewed" in msg:
                d["refresh_ok"] += 1
            elif "Failed to read connection" in msg and "nextendo_api" in msg:
                d["readfail"] += 1
            elif lvl == "Error" and cat == "Render.Vulkan" and "GetSuitability" in msg:
                mm = re.search(r"Missing required (feature|extension) (\S+)", msg)
                if mm:
                    d["vk_missing"].append(mm.group(2))
                elif "has to be" in msg:
                    d["vk_missing"].append(msg.split("GetSuitability:")[-1].strip()[:40])
            elif "Userspace PANIC" in msg or "Emulated program broke execution" in msg:
                d["panic"].append((t, msg[:160]))
            elif "BufferQueue has been abandoned" in msg:
                d["abandoned_at"].append(t)
            elif lvl == "Critical" and "host_memory.cpp" in msg:
                d["host_mem"].append(t)
            elif lvl == "Critical" and ("texture_cache" in msg or "format_lookup_table" in msg
                                        or "shader_environment" in msg):
                d["tex_assert"].append(t)
            elif lvl == "Critical" and ("applet_" in msg):
                d["applet_assert"].append(msg.split("applet_")[1].split(".cpp")[0])
            elif lvl == "Critical" and "Unknown / unimplemented function" in msg:
                fn = _grab(r"function '([^']+)'", msg)
                if fn and fn not in d["unimpl"]:
                    d["unimpl"].append(fn)
            elif "Network isn't initialized" in msg:
                d["net_init"] += 1
            elif "Address already in use" in msg:
                d["addr_in_use"] += 1
    return d


# (severity, French text, English text). Severity: 3 blocks online/launch, 2 problem, 1 note.
def findings(d):
    out = []
    add = lambda sev, fr, en: out.append((sev, fr, en))

    if d["datadir"] and d["datadir"].startswith("dev.eden"):
        add(2, "Ancienne version de DEN (avant la 0.7.0, identifiant « dev.eden… »). Installe la dernière version depuis le Discord ou la page du projet.",
               "Old DEN build (before 0.7.0, id « dev.eden… »). Install the latest version from the Discord or the project page.")

    if d["ca_missing"] and d["ssl_fail"]:
        add(3, "Connexion au serveur Nextendo impossible : DEN a démarré son réseau avant d'avoir préparé les certificats de sécurité de l'appareil, et garde cet état toute la session. Ferme complètement DEN (retire-le des applications récentes), relance-le. Si ça persiste après plusieurs essais, le correctif arrive dans la prochaine version.",
               "Cannot reach the Nextendo server: DEN started its network before preparing the device's security certificates and keeps that state all session. Fully close DEN (remove it from recent apps), reopen it. If it keeps happening after a few tries, the fix is coming in the next version.")
    elif d["ssl_fail"]:
        add(3, "Connexion sécurisée au serveur Nextendo refusée. Vérifie la date et l'heure du téléphone (automatiques), coupe VPN, DNS privé et bloqueurs de publicité, puis relance DEN.",
               "Secure connection to the Nextendo server refused. Check the phone date and time (automatic), turn off VPN, private DNS and ad blockers, then restart DEN.")

    if d["token_rejected"]:
        add(3, "Ta session Nextendo a expiré ou a été refusée par le serveur. Dans DEN, déconnecte puis reconnecte ton compte Nextendo.",
               "Your Nextendo session expired or was rejected. In DEN, sign out then sign in again with your Nextendo account.")
    elif d["token_noresp"] and not d["ssl_fail"]:
        add(3, "Le jeton de connexion en ligne n'a pas pu être récupéré (pas de réponse du serveur). Vérifie ta connexion internet puis réessaie.",
               "The online login token could not be fetched (no answer from the server). Check your internet connection and retry.")
    elif (d["unreachable"] or d["readfail"]) and not d["ssl_fail"]:
        add(2, "Le serveur de compte Nextendo n'a pas répondu. Vérifie internet (Wi-Fi/4G), coupe le VPN, puis réessaie plus tard si le problème continue.",
               "The Nextendo account server did not answer. Check your internet (Wi-Fi/4G), turn off VPN and retry later if it continues.")

    if d["linked"] is False:
        add(2, "Aucun compte Nextendo n'est lié à DEN. Connecte-toi depuis les réglages de DEN.",
               "No Nextendo account is linked to DEN. Sign in from DEN's settings.")

    if d["net_init"]:
        add(2, "Le jeu signale « réseau non initialisé » : vérifie que le Wi-Fi ou les données mobiles sont actifs avant de lancer le jeu.",
               "The game reports « network not initialized »: make sure Wi-Fi or mobile data is on before starting the game.")

    if d["vk_missing"] and not d["started"]:
        miss = ", ".join(sorted(set(d["vk_missing"]))[:5])
        add(3, f"Ton processeur graphique (ou son pilote) ne gère pas des fonctions exigées par DEN ({miss}). Essaie un autre pilote graphique dans les paramètres ; si l'appareil est trop ancien, il ne pourra pas faire tourner le jeu.",
               f"Your GPU (or its driver) lacks features DEN requires ({miss}). Try another graphics driver in the settings; very old devices cannot run the game.")

    if d["panic"]:
        t = d["panic"][0][0]
        add(3, f"Le jeu émulé a planté (plantage à {t:.0f} s). Essaie : vider le cache de shaders du jeu, changer de pilote graphique, désactiver les options « instables ». Si ça se reproduit, envoie le nom et la version du jeu.",
               f"The emulated game crashed (at {t:.0f} s). Try: clearing the game's shader cache, switching graphics driver, turning off unsafe options. If it repeats, send the game name and version.")

    if d["unimpl"]:
        add(3, f"Le jeu a demandé une fonction de la console que DEN ne sait pas encore faire ({', '.join(d['unimpl'][:3])}). Rien à régler de ton côté, c'est à signaler au développeur.",
               f"The game asked for a console function DEN does not support yet ({', '.join(d['unimpl'][:3])}). Nothing to fix on your side; report it to the developer.")

    if d["tex_assert"]:
        add(2, "Erreur graphique interne (textures/shaders). Essaie un autre pilote graphique et vide le cache de shaders ; signale le jeu concerné.",
               "Internal graphics error (textures/shaders). Try another graphics driver and clear the shader cache; report the game involved.")

    if d["applet_assert"]:
        add(2, "Le jeu a ouvert un menu système que DEN ne gère pas encore (" + ", ".join(sorted(set(d["applet_assert"]))) + ").",
               "The game opened a system menu DEN does not handle yet (" + ", ".join(sorted(set(d["applet_assert"]))) + ").")

    if d["host_mem"]:
        # In every log seen so far this assert fires while the game is being closed (pipeline cache
        # and config are written just before it), so it is a note, not a fault.
        add(1, "Erreur de mémoire interne à la fermeture du jeu : sans gravité, rien à faire.",
               "Internal memory error when the game closes: harmless, nothing to do.")

    if d["addr_in_use"]:
        add(1, "Un port réseau était déjà utilisé (une autre instance de DEN tourne peut-être). Ferme DEN complètement et relance.",
               "A network port was already in use (another DEN instance may be running). Fully close DEN and relaunch.")

    if d["firmware"] is None or d["firmware_hardcoded"]:
        add(2, "Aucun firmware Switch n'est installé : installe-le depuis les réglages de DEN.",
               "No Switch firmware is installed: install it from DEN's settings.")

    out.sort(key=lambda x: -x[0])
    return out


def clean(value, default="?", maxlen=40):
    """Strings come from a user's file: keep only harmless characters before showing them."""
    if not value:
        return default
    out = re.sub(r"[^A-Za-z0-9 ._+()\-]", "", str(value))[:maxlen].strip()
    return out or default


def report(path, lang="fr", limit=1900):
    d = parse(path)
    d["version"] = clean(d["version"])
    d["model"] = clean(d["model"])
    d["api"] = clean(d["api"])
    d["firmware"] = clean(d["firmware"], default="") or None
    d["titles"] = [clean(t, maxlen=16) for t in d["titles"]]
    fl = findings(d)
    fr = lang != "en"
    games = ", ".join(KNOWN_GAMES.get(t, t) for t in d["titles"][:3]) or "?"
    head = (f"**DEN log** — {d['version'] or '?'} · {d['model'] or '?'} (Android {d['api'] or '?'}) · "
            f"firmware {d['firmware'].split('for NX')[-1].strip() if d['firmware'] else ('absent' if fr else 'none')}\n"
            f"{'Jeu(x)' if fr else 'Game(s)'}: {games} · {d['lines']} lignes" if fr else
            f"**DEN log** — {d['version'] or '?'} · {d['model'] or '?'} (Android {d['api'] or '?'}) · "
            f"firmware {d['firmware'].split('for NX')[-1].strip() if d['firmware'] else 'none'}\n"
            f"Game(s): {games} · {d['lines']} lines")
    icons = {3: "🔴", 2: "🟠", 1: "🟢"}
    if not fl:
        body = ("✅ Rien d'anormal détecté dans ce log. Décris le problème (jeu, ce qui se passe, à quel moment)."
                if fr else "✅ Nothing abnormal found in this log. Describe the issue (game, what happens, when).")
    else:
        body = "\n".join(f"{icons[s]} {a if fr else b}" for s, a, b in fl[:5])
    text = head + "\n" + body
    return text if len(text) <= limit else text[: limit - 1] + "…"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: denlog.py <log> [fr|en]")
    print(report(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "fr"))

# --- fin du fichier ---
