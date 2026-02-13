#!/usr/bin/python3
# Wazuh Active Response - Windows Firewall IP Block (netsh)
# Rule ID: 60122

import sys
import json
import subprocess
import datetime
import socket
import ipaddress
from pathlib import PureWindowsPath, PurePosixPath

# ================= CONFIG =================

LOG_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

ADD_COMMAND = "add"
DELETE_COMMAND = "delete"

NETSH_PATH = r"C:\Windows\System32\netsh.exe"

# ==========================================

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
    except:
        pass


def read_line():
    return sys.stdin.readline().strip()


def send_json(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


# ---------------- SAFETY ------------------

def is_safe_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)

        if (
            ip_obj.is_loopback or
            ip_obj.is_unspecified or
            ip_obj.is_link_local
        ):
            return True

        local_ips = socket.gethostbyname_ex(socket.gethostname())[2]
        if ip in local_ips:
            return True

    except Exception:
        return True

    return False


# ---------------- FIREWALL ----------------

def sanitize_rule_name(ip):
    """Convert IP to netsh-safe rule name (no dots)"""
    return f"WAZUH_BLOCK_{ip.replace('.', '_')}"

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


def verify_rule(rule_name, ar_name, action):
    """Check if rule exists after add/delete"""
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
        log(ar_name, f"VERIFY {action}: Rule {rule_name} exists ✓")
    else:
        log(ar_name, f"VERIFY {action}: Rule {rule_name} not found ✗")


def block_ip(ip, ar_name):
    rule_name = sanitize_rule_name(ip)
    cmd = [
        NETSH_PATH,
        "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in", "action=block",
        f"remoteip={ip}",
        "profile=any"
    ]
    result = run_cmd(cmd, ar_name, "BLOCK", ip)
    verify_rule(rule_name, ar_name, "BLOCK")
    return result


def unblock_ip(ip, ar_name):
    rule_name = sanitize_rule_name(ip)
    cmd = [
        NETSH_PATH,
        "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}"
    ]
    result = run_cmd(cmd, ar_name, "UNBLOCK", ip)
    verify_rule(rule_name, ar_name, "UNBLOCK")
    return result


# ---------------- MAIN --------------------

def main():
    ar_name = sys.argv[0]
    log(ar_name, "=== Started ===")

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
    except:
        rule_id = "60122"

    # Extract IP
    try:
        ip = data["parameters"]["alert"]["data"]["win"]["eventdata"]["ipAddress"]
    except:
        ip = data.get("parameters", {}).get("alert", {}).get("srcip")

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

        if not ip or is_safe_ip(ip):
            log(ar_name, f"Skipping protected IP: {ip}")
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
