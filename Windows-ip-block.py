#!/usr/bin/python3
# Wazuh Active Response - Windows Firewall IP Block (netsh)
# Rule ID: 60122
# Features: External whitelist via whitelist.json (place alongside the .exe)

import sys
import json
import subprocess
import datetime
import socket
import ipaddress
import os
from pathlib import PureWindowsPath, PurePosixPath

# ================= CONFIG =================

LOG_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

ADD_COMMAND = "add"
DELETE_COMMAND = "delete"

NETSH_PATH = r"C:\Windows\System32\netsh.exe"

# Tracks IPs already logged as ALREADY_BLOCKED to suppress duplicate log entries.
# Auto-managed alongside the exe.
def _get_base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

LOGGED_IPS_FILE = os.path.join(_get_base_dir(), "already_blocked_logged.json")

# ==========================================
# WHITELIST FILE
# Place "whitelist.json" in the same folder as this script / exe.
# To add new IPs, just edit whitelist.json - no recompile needed.
#
# whitelist.json format:
# {
#   "ips": ["192.168.1.1", "10.0.0.5"],
#   "subnets": ["192.168.0.0/24", "10.0.0.0/8"],
#   "comments": "Add any internal/trusted IPs or CIDR ranges here"
# }
# ==========================================

def get_whitelist_path():
    """Return the path to whitelist.json next to the exe or script."""
    if getattr(sys, 'frozen', False):
        # Running as compiled .exe (PyInstaller)
        base_dir = os.path.dirname(sys.executable)
    else:
        # Running as plain .py script
        base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, "whitelist.json")


def parse_forgiving_json(text):
    """
    Parse JSON that may contain:
      - // single-line comments
      - # single-line comments
      - /* block comments */
      - trailing commas before } or ]
    This makes hand-edited whitelist.json files more resilient.
    """
    import re
    # Remove block comments /* ... */
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    # Remove // line comments
    text = re.sub(r'//[^\n]*', '', text)
    # Remove # line comments (but not inside strings - simple heuristic)
    text = re.sub(r'(?<!")#[^\n]*', '', text)
    # Remove trailing commas before ] or }
    text = re.sub(r',\s*([\]}])', r'\1', text)
    return json.loads(text)


def load_whitelist(ar_name):
    """
    Load IP whitelist from whitelist.json.
    Returns a dict with keys 'ips' (set of str) and 'subnets' (list of network objects).
    Falls back to empty lists if file is missing or malformed.
    Supports trailing commas and // # comments in the JSON file.
    """
    path = get_whitelist_path()
    whitelist = {"ips": set(), "subnets": []}

    if not os.path.exists(path):
        log(ar_name, f"whitelist.json not found at {path} - using built-in safety checks only")
        return whitelist

    try:
        with open(path, "r", encoding="utf-8-sig") as f:  # utf-8-sig strips BOM if present
            raw = f.read()
        data = parse_forgiving_json(raw)

        # Load individual IPs
        for ip_str in data.get("ips", []):
            try:
                ipaddress.ip_address(ip_str.strip())   # validate format
                whitelist["ips"].add(ip_str.strip())
            except ValueError:
                log(ar_name, f"whitelist.json: invalid IP skipped: {ip_str}")

        # Load CIDR subnets
        for cidr in data.get("subnets", []):
            try:
                whitelist["subnets"].append(ipaddress.ip_network(cidr.strip(), strict=False))
            except ValueError:
                log(ar_name, f"whitelist.json: invalid subnet skipped: {cidr}")

        log(ar_name, f"Whitelist loaded: {len(whitelist['ips'])} IPs, {len(whitelist['subnets'])} subnets from {path}")

    except Exception as e:
        log(ar_name, f"Failed to load whitelist.json: {e} - continuing without external whitelist")

    return whitelist


def log(ar_name, msg):
    try:
        ar_name_posix = str(
            PurePosixPath(
                PureWindowsPath(ar_name[ar_name.find("active-response"):])
            )
        )
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(
                f"{datetime.datetime.now():%Y/%m/%d %H:%M:%S} "
                f"{ar_name_posix}: {msg}\n"
            )
    except Exception:
        pass


def read_line():
    return sys.stdin.readline().strip()


def send_json(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


# ---------------- SAFETY ------------------

def is_safe_ip(ip, whitelist):
    """
    Returns True (= skip blocking) if the IP is:
      - loopback / unspecified / link-local  (always protected)
      - one of this machine's own IPs        (always protected)
      - listed in whitelist.json IPs         (external whitelist)
      - within a subnet in whitelist.json    (external whitelist)
    """
    try:
        ip_obj = ipaddress.ip_address(ip)

        # --- Built-in always-safe checks ---
        if ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_link_local:
            return True

        local_ips = socket.gethostbyname_ex(socket.gethostname())[2]
        if ip in local_ips:
            return True

        # --- External whitelist: exact IPs ---
        if ip in whitelist["ips"]:
            return True

        # --- External whitelist: subnets ---
        for network in whitelist["subnets"]:
            if ip_obj in network:
                return True

    except Exception:
        # If anything goes wrong during validation, skip blocking to be safe
        return True

    return False


# ---------------- FIREWALL ----------------

def sanitize_rule_name(ip):
    """Convert IP to netsh-safe rule name (no dots)."""
    return f"WAZUH_BLOCK_{ip.replace('.', '_')}"


def rule_exists(rule_name, ar_name):
    """Check if firewall rule already exists."""
    try:
        cmd = [
            NETSH_PATH,
            "advfirewall", "firewall", "show", "rule",
            f"name={rule_name}"
        ]
        result = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and "No rules match" not in result.stdout:
            return True
        return False
    except Exception as e:
        log(ar_name, f"Error checking rule existence: {e}")
        return False


def run_cmd(cmd, ar_name, action, ip):
    try:
        result = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )
        log(ar_name, f"{action} {ip} rc={result.returncode}")
        if result.stdout.strip():
            log(ar_name, f"STDOUT: {result.stdout.strip()}")
        if result.stderr.strip():
            log(ar_name, f"STDERR: {result.stderr.strip()}")
        return result
    except Exception as e:
        log(ar_name, f"Exception running command: {e}")
        return subprocess.CompletedProcess(cmd, 1)


def load_logged_ips():
    """Load the set of IPs already logged as ALREADY_BLOCKED."""
    try:
        if os.path.exists(LOGGED_IPS_FILE):
            with open(LOGGED_IPS_FILE, "r", encoding="utf-8") as f:
                return set(json.load(f))
    except Exception:
        pass
    return set()


def save_logged_ip(ip):
    """Persist an IP to the already-logged set."""
    try:
        logged = load_logged_ips()
        logged.add(ip)
        with open(LOGGED_IPS_FILE, "w", encoding="utf-8") as f:
            json.dump(list(logged), f)
    except Exception:
        pass


def remove_logged_ip(ip):
    """Remove an IP from the already-logged set (called on unblock)."""
    try:
        if not os.path.exists(LOGGED_IPS_FILE):
            return
        logged = load_logged_ips()
        logged.discard(ip)
        with open(LOGGED_IPS_FILE, "w", encoding="utf-8") as f:
            json.dump(list(logged), f)
    except Exception:
        pass


def block_ip(ip, ar_name):
    rule_name = sanitize_rule_name(ip)
    if rule_exists(rule_name, ar_name):
        logged = load_logged_ips()
        if ip not in logged:
            log(ar_name, f"ALREADY_BLOCKED {ip} rc=0")
            save_logged_ip(ip)
        # else: silently skip — already logged once before
        return subprocess.CompletedProcess([], 0)
    cmd = [
        NETSH_PATH,
        "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in", "action=block",
        f"remoteip={ip}",
        "profile=any"
    ]
    return run_cmd(cmd, ar_name, "BLOCK", ip)


def unblock_ip(ip, ar_name):
    rule_name = sanitize_rule_name(ip)
    if not rule_exists(rule_name, ar_name):
        log(ar_name, f"Rule {rule_name} does not exist, nothing to unblock")
        return subprocess.CompletedProcess([], 0)
    remove_logged_ip(ip)  # Reset so ALREADY_BLOCKED logs again if re-blocked
    cmd = [
        NETSH_PATH,
        "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}"
    ]
    return run_cmd(cmd, ar_name, "UNBLOCK", ip)


# ---------------- MAIN --------------------

def main():
    ar_name = sys.argv[0]
    log(ar_name, "=== Started ===")

    # Load external IP whitelist from whitelist.json (next to exe/script)
    whitelist = load_whitelist(ar_name)

    # 1️⃣ Read first JSON
    first = read_line()
    if not first:
        log(ar_name, "No input received")
        sys.exit(0)

    try:
        data = json.loads(first)
    except Exception as e:
        log(ar_name, f"JSON parse error: {e}")
        sys.exit(1)

    command = data.get("command")

    # Extract rule id
    try:
        rule_id = data["parameters"]["alert"]["rule"]["id"]
    except Exception:
        rule_id = "60122"

    # Extract IP
    try:
        ip = data["parameters"]["alert"]["data"]["win"]["eventdata"]["ipAddress"]
    except Exception:
        ip = data.get("parameters", {}).get("alert", {}).get("data", {}).get("srcip")

    log(ar_name, f"Received command={command} ip={ip}")

    # 2️⃣ ADD
    if command == ADD_COMMAND:
        send_json({
            "version": 1,
            "origin": {"name": ar_name, "module": "active-response"},
            "command": "check_keys",
            "parameters": {"keys": [str(rule_id)]}
        })

        second = read_line()
        if not second:
            log(ar_name, "No key response")
            sys.exit(0)

        resp = json.loads(second)
        if resp.get("command") != "continue":
            log(ar_name, "Key check aborted")
            sys.exit(0)

        if not ip or is_safe_ip(ip, whitelist):
            log(ar_name, f"Skipping whitelisted/protected IP: {ip}")
            sys.exit(0)

        block_ip(ip, ar_name)

    # 3️⃣ DELETE
    elif command == DELETE_COMMAND:
        if ip:
            unblock_ip(ip, ar_name)

    log(ar_name, "=== Ended ===")
    sys.exit(0)


if __name__ == "__main__":
    main()
