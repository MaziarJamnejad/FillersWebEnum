#!/usr/bin/env python3
"""
filler_web_enum.py (updated)

OSCP-friendly web enumeration command-pack generator.

Principles:
- CORE section = commands you can run on (almost) every box with low noise.
- CONDITIONAL modules = only use when you have indicators (CMS/app/service).
- Generates commands only; never executes them.
"""

from __future__ import annotations

from pathlib import Path
import re

CYAN = "\033[36m"
YELLOW = "\033[33m"
RESET = "\033[0m"


def prompt_nonempty(label: str) -> str:
    while True:
        v = input(f"{label}: ").strip()
        if v:
            return v


def prompt_optional(label: str) -> str:
    return input(f"{label} (leave blank if none): ").strip()


def parse_domains(raw: str) -> list[str]:
    if not raw.strip():
        return []
    parts = re.split(r"[,\s]+", raw.strip())
    return [p.strip() for p in parts if p.strip()]


def section(title: str) -> str:
    return f"{CYAN}# {title}{RESET}"


def warn(msg: str) -> str:
    return f"{YELLOW}# [NOTE] {msg}{RESET}"


def ip_filename(ip: str) -> str:
    safe = ip.replace(":", "_").replace("/", "_")
    return f"web_enum_{safe}.txt"


def build_pack(target_ip: str, primary_host: str, domains: list[str]) -> str:
    # Defaults (no prompts)
    HTTP_PORTS = [80, 8080]
    HTTPS_PORTS = [443, 8443]
    ALL_PORTS = [80, 443, 8080, 8443]

    WL_DIR_LIGHT = "/usr/share/wordlists/dirb/common.txt"
    WL_DIR_MED = "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"
    WL_VHOST_5K = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    WL_VHOST_BIG = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"

    NMAP_MIN_RATE = 3000
    GOBUSTER_THREADS = 30

    lines: list[str] = []

    # Header + vars
    lines.append(f"# Web enum command pack for: {target_ip}")
    lines.append("# Copy/paste as needed. This file does not execute anything.")
    lines.append("")
    lines.append("# Variables:")
    lines.append(f"export T={target_ip}")
    lines.append(f"export RHOST={target_ip}")
    lines.append(f"export HOST={primary_host}")
    if domains:
        lines.append(f"# Domains provided: {' '.join(domains)}")
    lines.append("")

    # -----------------------------
    # CORE (always-run, low-noise)
    # -----------------------------
    lines.append(section("CORE 1) Confirm common web services (Nmap)"))
    lines.append(f"nmap -p {','.join(str(p) for p in ALL_PORTS)} -sC -sV -Pn --min-rate {NMAP_MIN_RATE} $T")
    lines.append("")

    lines.append(section("CORE 2) Quick HTTP/HTTPS reachability + headers"))
    lines.append("# HTTP")
    for p in HTTP_PORTS:
        lines.append(f"curl -s -D - http://$T:{p}/ -o /dev/null | sed -n '1,25p'")
        lines.append(f"curl -s -L -i http://$T:{p}/ | sed -n '1,40p'")
    lines.append("")
    lines.append("# HTTPS (ignore cert issues in labs)")
    for p in HTTPS_PORTS:
        lines.append(f"curl -s -k -D - https://$T:{p}/ -o /dev/null | sed -n '1,25p'")
        lines.append(f"curl -s -k -L -i https://$T:{p}/ | sed -n '1,40p'")
    lines.append("")

    lines.append(section("CORE 3) Robots/sitemap/security.txt"))
    for p in HTTP_PORTS:
        lines.append(f"curl -s http://$T:{p}/robots.txt")
        lines.append(f"curl -s http://$T:{p}/sitemap.xml")
        lines.append(f"curl -s http://$T:{p}/sitemap_index.xml")
        lines.append(f"curl -s http://$T:{p}/.well-known/security.txt")
    for p in HTTPS_PORTS:
        lines.append(f"curl -s -k https://$T:{p}/robots.txt")
        lines.append(f"curl -s -k https://$T:{p}/sitemap.xml")
        lines.append(f"curl -s -k https://$T:{p}/sitemap_index.xml")
        lines.append(f"curl -s -k https://$T:{p}/.well-known/security.txt")
    lines.append("")

    lines.append(section("CORE 4) Fingerprinting (cheap)"))
    lines.append("whatweb http://$T/")
    lines.append("whatweb http://$T:8080/")
    lines.append(warn("If you have wappalyzer-cli installed, it can be handy: wappalyzer http://$T/"))
    lines.append("")

    lines.append(section("CORE 5) Quick content hints from homepage (forms/api/js/comments)"))
    for p in HTTP_PORTS:
        lines.append(f"curl -s http://$T:{p}/ | grep -iE \"<form|csrf|token|api|swagger|openapi|graphql|/api/|sourceMappingURL|\\.js\\b|generator|wp-\" | head")
        lines.append(f"curl -s http://$T:{p}/ | grep -i \"<!--\" | head")
    lines.append("")

    lines.append(section("CORE 6) Favicon grab (quick clue)"))
    for p in HTTP_PORTS:
        lines.append(f"curl -s -o favicon_{p}.ico http://$T:{p}/favicon.ico && file favicon_{p}.ico")
    for p in HTTPS_PORTS:
        lines.append(f"curl -s -k -o favicon_{p}.ico https://$T:{p}/favicon.ico && file favicon_{p}.ico")
    lines.append("")

    lines.append(section("CORE 7) Method probing (low cost)"))
    for p in HTTP_PORTS:
        lines.append(f"curl -i -X OPTIONS http://$T:{p}/ | sed -n '1,25p'")
        lines.append(f"curl -i -X TRACE http://$T:{p}/ | sed -n '1,25p'")
    for p in HTTPS_PORTS:
        lines.append(f"curl -i -k -X OPTIONS https://$T:{p}/ | sed -n '1,25p'")
        lines.append(f"curl -i -k -X TRACE https://$T:{p}/ | sed -n '1,25p'")
    lines.append("")

    lines.append(section("CORE 8) Directory discovery (light)"))
    for p in HTTP_PORTS:
        lines.append(f"gobuster dir -u http://$T:{p}/ -w {WL_DIR_LIGHT}")
        lines.append(f"ffuf -u http://$T:{p}/FUZZ -w {WL_DIR_LIGHT}")
        lines.append(f"ffuf -u http://$T:{p}/FUZZ -w {WL_DIR_LIGHT} -e .php,.txt,.bak,.old,.zip")
    for p in HTTPS_PORTS:
        lines.append(f"gobuster dir -k -u https://$T:{p}/ -w {WL_DIR_LIGHT}")
        lines.append(f"ffuf -k -u https://$T:{p}/FUZZ -w {WL_DIR_LIGHT}")
        lines.append(f"ffuf -k -u https://$T:{p}/FUZZ -w {WL_DIR_LIGHT} -e .php,.txt,.bak,.old,.zip")
    lines.append("")

    lines.append(section("CORE 9) High-value files (quick HEAD)"))
    candidates = [
        "README", "README.md", "CHANGELOG", "CHANGELOG.txt", "LICENSE", "version.txt",
        ".git/HEAD", ".env", "composer.json", "package.json"
    ]
    for p in HTTP_PORTS:
        for path in candidates:
            lines.append(f"curl -I http://$T:{p}/{path}")
    for p in HTTPS_PORTS:
        for path in candidates:
            lines.append(f"curl -k -I https://$T:{p}/{path}")
    lines.append("")

    lines.append(section("CORE 10) VHost workflow (only if behaviour suggests vhosts)"))
    lines.append(warn("Run this if you see redirects to a hostname, cert SAN names, or different responses by Host header."))
    lines.append(f"ffuf -u http://$T/ -H \"Host: FUZZ\" -w {WL_VHOST_5K}")
    lines.append(f"ffuf -u http://$T/ -H \"Host: FUZZ.<domain>\" -w {WL_VHOST_5K}")
    lines.append(warn("For bigger lists: add filtering like --fs/--fw/--fc once you have a baseline."))
    lines.append(f"wfuzz -u http://$HOST/ -H \"Host: FUZZ.$HOST\" -w {WL_VHOST_BIG} --hh <BASELINE_CHARS>")
    lines.append("")

    # -----------------------------
    # CONDITIONAL modules (only if detected)
    # -----------------------------
    lines.append(section("CONDITIONAL A) WordPress (only if WP indicators exist)"))
    lines.append("# Indicators: /wp-content/, wp-json, wordpress strings, generator=WordPress")
    lines.append("curl -I http://$HOST/wp-login.php")
    lines.append("curl -I http://$HOST/wp-admin/")
    lines.append(warn("WPScan is not 'always-run' (token/noise). Use when confident WP is present."))
    lines.append("wpscan --url http://$HOST --enumerate vp,vt,u --api-token <API_TOKEN>")
    lines.append(warn("Post-shell loot: /var/www/html/wp-config.php (or site root)/wp-config.php"))
    lines.append("")

    lines.append(section("CONDITIONAL B) Joomla (only if indicators exist)"))
    lines.append("# Indicators: /administrator/, joomla strings, templates/protostar")
    lines.append("curl -I http://$HOST/administrator/")
    lines.append("curl -s http://$HOST/ | grep -iE \"joomla|protostar|templates\" | head")
    lines.append("")

    lines.append(section("CONDITIONAL C) Drupal (only if indicators exist)"))
    lines.append("# Indicators: drupalSettings, /sites/default, /user/login (not unique)")
    lines.append("curl -I http://$HOST/user/login")
    lines.append("curl -s http://$HOST/ | grep -i drupal | head")
    lines.append(warn("Droopescan via docker is optional; only use if you already suspect Drupal."))
    lines.append("docker run --rm droope/droopescan scan drupal -u http://$HOST/")
    lines.append("")

    lines.append(section("CONDITIONAL D) Common admin apps (only if nmap/title hints)"))
    lines.append("# Tomcat")
    lines.append("curl -I http://$HOST/manager/html")
    lines.append("# Jenkins")
    lines.append("curl -I http://$HOST:8080/")
    lines.append("curl -I http://$HOST:8080/script")
    lines.append("# Webmin")
    lines.append("curl -k -I https://$HOST:10000/")
    lines.append("# phpMyAdmin")
    lines.append("curl -I http://$HOST/phpmyadmin/")
    lines.append("")

    lines.append(section("CONDITIONAL E) SQLi quick confirmation (only when you have a parameter)"))
    lines.append(warn("Do not run blind. Identify a parameter first (id/query/etc)."))
    lines.append("curl \"http://$HOST/page.php?id=1'\"")
    lines.append(warn("If it looks promising, switch to sqlmap with the exact URL/cookies/POST body."))
    lines.append("")

    lines.append(section("CONDITIONAL F) File upload probes (only when an upload endpoint exists)"))
    lines.append("curl -I http://$HOST/uploads/")
    lines.append("curl -F \"file=@test.jpg\" http://$HOST/upload")
    lines.append(warn("Only attempt server-side execution paths once you understand how uploads are handled."))
    lines.append("")

    # Domains: treat as new scopes (baseline)
    lines.append(section("IF YOU HAVE DOMAINS: treat each domain as new scope (baseline)"))
    if domains:
        for d in domains:
            lines.append(f"curl -i http://{d}/ | sed -n '1,25p'")
            lines.append(f"curl -I http://{d}/")
            lines.append(f"curl -k -i https://{d}/ | sed -n '1,25p'")
            lines.append(f"curl -k -I https://{d}/")
    else:
        lines.append("# (No domains provided)")
    lines.append("")

    # Optional: medium dir list
    lines.append(section("OPTIONAL: Directory discovery (medium list)"))
    lines.append(warn("Run when light pass finds something or the app is clearly deep."))
    for p in HTTP_PORTS:
        lines.append(f"gobuster dir -u http://$T:{p}/ -w {WL_DIR_MED} -x php,txt -t {GOBUSTER_THREADS}")
    for p in HTTPS_PORTS:
        lines.append(f"gobuster dir -k -u https://$T:{p}/ -w {WL_DIR_MED} -x php,txt -t {GOBUSTER_THREADS}")
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    print("FILLER WEB ENUM (minimal prompts, file output only)")

    target_ip = prompt_nonempty("Enter Target IP")
    primary_host = prompt_nonempty("Enter Primary Host (IP or hostname)")
    domains_raw = prompt_optional("Enter discovered domains (comma/space separated)")
    domains = parse_domains(domains_raw)

    out_name = ip_filename(target_ip)
    content = build_pack(target_ip, primary_host, domains)
    Path(out_name).write_text(content, encoding="utf-8")

    print(f"Wrote command pack to: {out_name}")


if __name__ == "__main__":
    main()
