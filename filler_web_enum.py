#!/usr/bin/env python3
"""
web_enum_syntax_filler.py

Minimal-prompt, OSCP-friendly web enumeration command-pack generator.

Design choices (per your spec):
- Prompts only for:
  1) Target IP
  2) Primary Host (IP/hostname for <HOST> contexts)
  3) Optional discovered domains (comma/space separated; blank allowed)
- Writes ONE .txt file in the current working directory (no mkdir, no auto-exec)
- Filename includes target IP
- Assumes SecLists installed at /usr/share/seclists (standard on Kali)
- Assumes kitchen-sink commands included (with exam warnings as comments)
- Explicitly handles common web ports (80/443/8080/8443)
- VHosts are first-class
- SSH/bruteforce/login automation scripts are excluded (parked for separate tool)

This script only GENERATES commands; it never executes anything.
"""

from __future__ import annotations

from pathlib import Path
import re


# ANSI escapes are allowed (your choice #2 = yes in earlier decision set)
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


def section(n: int, title: str) -> str:
    return f"{CYAN}# {n}. {title}{RESET}"


def warn(msg: str) -> str:
    return f"{YELLOW}# [EXAM WARNING] {msg}{RESET}"


def ip_filename(ip: str) -> str:
    safe = ip.replace(":", "_").replace("/", "_")
    return f"web_enum_{safe}.txt"


def build_pack(target_ip: str, primary_host: str, domains: list[str]) -> str:
    # Defaults (no prompts)
    HTTP_PORTS = [80, 8080]
    HTTPS_PORTS = [443, 8443]
    ALL_PORTS = [80, 443, 8080, 8443]

    # Defaults: wordlists (per your agreement)
    WL_DIR_LIGHT = "/usr/share/wordlists/dirb/common.txt"
    WL_DIR_MED = "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"
    WL_VHOST_5K = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    WL_VHOST_BIG = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
    WL_SPRING = "/usr/share/seclists/Discovery/Web-Content/spring-boot.txt"

    # Defaults: performance knobs (baked in)
    NMAP_MIN_RATE = 3000
    GOBUSTER_THREADS = 30

    lines: list[str] = []

    # Header + variables
    lines.append(f"# Web enum command pack for: {target_ip}")
    lines.append("# Copy/paste as needed. This file does not execute anything.")
    lines.append("")
    lines.append("# Variables:")
    lines.append(f"export T={target_ip}")
    lines.append(f"export HOST={primary_host}")
    if domains:
        lines.append(f"# Domains provided: {' '.join(domains)}")
    lines.append("")

    n = 1

    # 1) Nmap confirm / discover
    lines.append(section(n, "Confirm common web services (Nmap)"))
    n += 1
    lines.append(f"nmap -p {','.join(str(p) for p in ALL_PORTS)} -sC -sV -Pn --min-rate {NMAP_MIN_RATE} $T")
    lines.append("")

    # 2) nc quick confirm for HTTP ports
    lines.append(section(n, "Confirm HTTP reachability (nc)"))
    n += 1
    for p in HTTP_PORTS:
        lines.append(f"nc -nv $T {p}")
    lines.append("")

    # 3) Basic HTTP interaction (IP:port)
    lines.append(section(n, "Basic HTTP interaction (curl)"))
    n += 1
    lines.append("curl -i http://$T/")
    lines.append("curl -v http://$T/")
    lines.append("curl -I http://$T/")
    lines.append("curl -i http://$T:8080/")
    lines.append("curl -v http://$T:8080/")
    lines.append("curl -I http://$T:8080/")
    lines.append("")

    # 4) Headers
    lines.append(section(n, "Header enumeration"))
    n += 1
    lines.append("curl -i http://$T/ | sed -n '1,20p'")
    lines.append("curl -s -D - http://$T/ -o /dev/null")
    lines.append("curl -i http://$T:8080/ | sed -n '1,20p'")
    lines.append("curl -s -D - http://$T:8080/ -o /dev/null")
    lines.append("")

    # 5) Robots / sitemap
    lines.append(section(n, "Robots / sitemap / meta discovery (HTTP)"))
    n += 1
    lines.append("curl http://$T/robots.txt")
    lines.append("curl http://$T/sitemap.xml")
    lines.append("curl -s http://$T/ | grep -i robots")
    lines.append("curl http://$T:8080/robots.txt")
    lines.append("curl http://$T:8080/sitemap.xml")
    lines.append("curl -s http://$T:8080/ | grep -i robots")
    lines.append("")

    # 6) Directory discovery (light)
    lines.append(section(n, "Directory discovery (light)"))
    n += 1
    lines.append(f"gobuster dir -u http://$T/ -w {WL_DIR_LIGHT}")
    lines.append(f"ffuf -u http://$T/FUZZ -w {WL_DIR_LIGHT}")
    lines.append(f"gobuster dir -u http://$T:8080/ -w {WL_DIR_LIGHT}")
    lines.append(f"ffuf -u http://$T:8080/FUZZ -w {WL_DIR_LIGHT}")
    lines.append("")

    # 7) Extension discovery (light)
    lines.append(section(n, "File extension discovery (light)"))
    n += 1
    lines.append(f"ffuf -u http://$T/FUZZ -w {WL_DIR_LIGHT} -e .php,.txt,.bak,.old,.zip")
    lines.append(f"ffuf -u http://$T:8080/FUZZ -w {WL_DIR_LIGHT} -e .php,.txt,.bak,.old,.zip")
    lines.append("")

    # 8) Manual sensitive files
    lines.append(section(n, "Manual sensitive file checks"))
    n += 1
    sensitive = ["index.php", "login.php", "admin/", "config.php", ".git/", ".env"]
    for pfx in ("http://$T", "http://$T:8080"):
        for path in sensitive:
            lines.append(f"curl {pfx}/{path}")
    lines.append("")

    # 9) Cookies
    lines.append(section(n, "Cookie inspection"))
    n += 1
    lines.append("curl -i http://$T/ | grep -i set-cookie")
    lines.append("curl -i -H \"Cookie: test=1\" http://$T/")
    lines.append("curl -i http://$T:8080/ | grep -i set-cookie")
    lines.append("curl -i -H \"Cookie: test=1\" http://$T:8080/")
    lines.append("")

    # 10) Methods
    lines.append(section(n, "Method testing"))
    n += 1
    lines.append("curl -X OPTIONS -i http://$T/")
    lines.append("curl -X POST http://$T/ -d \"test=test\"")
    lines.append("curl -X OPTIONS -i http://$T:8080/")
    lines.append("curl -X POST http://$T:8080/ -d \"test=test\"")
    lines.append("")

    # 11) Auth boundary basics
    lines.append(section(n, "Auth boundary testing (basic)"))
    n += 1
    for pfx in ("http://$T", "http://$T:8080"):
        lines.append(f"curl -i {pfx}/admin")
        lines.append(f"curl -i {pfx}/admin/ -H \"X-Forwarded-For: 127.0.0.1\"")
    lines.append("")

    # 12) Source/comment review
    lines.append(section(n, "Source / comment review"))
    n += 1
    lines.append("curl -s http://$T/ | grep -i \"<!--\"")
    lines.append("wget -q -O - http://$T/ | less")
    lines.append("curl -s http://$T:8080/ | grep -i \"<!--\"")
    lines.append("wget -q -O - http://$T:8080/ | less")
    lines.append("")

    # 13) Fingerprinting
    lines.append(section(n, "Technology fingerprinting"))
    n += 1
    lines.append("whatweb http://$T/")
    lines.append("wappalyzer http://$T/")
    lines.append("whatweb http://$T:8080/")
    lines.append("wappalyzer http://$T:8080/")
    lines.append("")

    # 14) Nikto (noisy)
    lines.append(section(n, "Nikto (optional/noisy)"))
    n += 1
    lines.append(warn("Nikto is noisy; use only when appropriate."))
    lines.append("nikto -h http://$T")
    lines.append("nikto -h http://$T -p 8080")
    lines.append("nikto -h https://$T -ssl")
    lines.append("nikto -h https://$T -ssl -p 8443")
    lines.append("")

    # 15) HTTPS confirm
    lines.append(section(n, "Confirm HTTPS (nmap/openssl)"))
    n += 1
    lines.append("nmap -p 443,8443 -sC -sV $T")
    lines.append("openssl s_client -connect $T:443")
    lines.append("openssl s_client -connect $T:8443")
    lines.append("")

    # 16) Cert / SAN
    lines.append(section(n, "Certificate inspection + SAN extraction"))
    n += 1
    lines.append("nmap -p 443 --script ssl-cert $T")
    lines.append("openssl s_client -connect $T:443 </dev/null | openssl x509 -noout -text")
    lines.append("openssl s_client -connect $T:443 </dev/null | openssl x509 -noout -ext subjectAltName")
    lines.append("nmap -p 8443 --script ssl-cert $T")
    lines.append("openssl s_client -connect $T:8443 </dev/null | openssl x509 -noout -text")
    lines.append("openssl s_client -connect $T:8443 </dev/null | openssl x509 -noout -ext subjectAltName")
    lines.append("")

    # 17) hosts file (manual) + add provided domains
    lines.append(section(n, "Add discovered domains to /etc/hosts (manual)"))
    n += 1
    lines.append("sudo nano /etc/hosts")
    if domains:
        lines.append("")
        lines.append("# Add:")
        for d in domains:
            lines.append(f"# {target_ip} {d}")
    lines.append("")

    # 18) Domain baselines (if domains provided)
    lines.append(section(n, "Treat each domain as new scope (baseline)"))
    n += 1
    if domains:
        for d in domains:
            lines.append(f"curl -i http://{d}/")
            lines.append(f"curl -I http://{d}/")
            lines.append(f"curl -i https://{d}/")
            lines.append(f"curl -k -i https://{d}/")
            lines.append(f"curl -I https://{d}/")
    else:
        lines.append("# (No domains provided)")
    lines.append("")

    # 19) Redirect & HSTS checks (example domain if provided)
    lines.append(section(n, "Redirect & HSTS behaviour (per domain)"))
    n += 1
    if domains:
        for d in domains:
            lines.append(f"curl -I http://{d}")
            lines.append(f"curl -I https://{d}")
    else:
        lines.append("# (No domains provided)")
    lines.append("")

    # 20) VHost enumeration (first-class)
    lines.append(section(n, "Virtual host enumeration (ffuf)"))
    n += 1
    lines.append(f"ffuf -u https://$T/ -H \"Host: FUZZ.<domain>\" -w {WL_VHOST_5K}")
    lines.append(f"ffuf -u https://$T/ -H \"Host: FUZZ\" -w {WL_VHOST_5K}")
    lines.append("")

    # 21) VHost alternatives (wfuzz + gobuster vhost)
    lines.append(section(n, "Virtual host enumeration alternatives (wfuzz / gobuster)"))
    n += 1
    lines.append(warn("For wfuzz, baseline/filtering (--hh/--hw) is essential."))
    lines.append(f"wfuzz -u http://$HOST/ -H \"Host: FUZZ.$HOST\" -w {WL_VHOST_BIG}")
    lines.append(f"wfuzz -u http://$HOST/ -H \"Host: FUZZ.$HOST\" -w {WL_VHOST_BIG} --hh <BASELINE_CHARS>")
    lines.append(f"wfuzz -u https://$HOST/ -H \"Host: FUZZ.$HOST\" -w {WL_VHOST_BIG} --hh <BASELINE_CHARS>")
    lines.append(f"gobuster vhost -u http://$HOST -w {WL_VHOST_BIG} --threads 100")
    lines.append("")

    # 22) Directory discovery (SecLists medium) per port
    lines.append(section(n, "Directory discovery (SecLists medium) per port"))
    n += 1
    lines.append(f"gobuster dir -u http://$T/ -w {WL_DIR_MED} -x php,txt -t {GOBUSTER_THREADS}")
    lines.append(f"gobuster dir -u http://$T:8080/ -w {WL_DIR_MED} -x php,txt -t {GOBUSTER_THREADS}")
    lines.append(f"gobuster dir -u https://$T/ -k -w {WL_DIR_MED} -x php,txt -t {GOBUSTER_THREADS}")
    lines.append(f"gobuster dir -u https://$T:8443/ -k -w {WL_DIR_MED} -x php,txt -t {GOBUSTER_THREADS}")
    lines.append("")

    # 23) Gobuster filtering templates
    lines.append(section(n, "Gobuster filtering / stability templates"))
    n += 1
    lines.append(f"gobuster dir -u http://$T/ -w {WL_DIR_MED} -x php,txt -b 302")
    lines.append(f"gobuster dir -u http://$T:8080/ -w {WL_DIR_MED} -x php,txt -b 302")
    lines.append(f"gobuster dir -u http://$T/ -w {WL_DIR_MED} -x php,txt --exclude-length <LENGTH>")
    lines.append(f"gobuster dir -u http://$HOST -w {WL_DIR_MED} -x php,bak,old,zip,sql,txt -t 10")
    lines.append("")

    # 24) TLS checks
    lines.append(section(n, "TLS configuration checks"))
    n += 1
    lines.append(warn("testssl/sslscan can be slow/noisy; use judgement."))
    lines.append("sslscan $T")
    lines.append("testssl.sh $T")
    lines.append("")

    # 25) Redirect analysis (IP)
    lines.append(section(n, "Redirect behaviour analysis (IP)"))
    n += 1
    lines.append("curl -I http://$T/")
    lines.append("curl -i http://$T/")
    lines.append("curl -L -i http://$T/")
    lines.append("curl -L -v http://$T/")
    lines.append("")

    # 26) Pre-redirect path testing
    lines.append(section(n, "Test specific paths pre-redirect"))
    n += 1
    lines.append("curl -i http://$T/login")
    lines.append("curl -i http://$T/admin")
    lines.append("curl -i http://$T/api")
    lines.append("curl -i http://$T/index.php")
    lines.append("")

    # 27) Parameter handling across redirects
    lines.append(section(n, "Parameter handling across redirects"))
    n += 1
    lines.append("curl -i \"http://$T/login?test=1\"")
    lines.append("curl -i \"http://$T/login?next=/admin\"")
    lines.append("")

    # 28) POST before redirect
    lines.append(section(n, "POST before redirect"))
    n += 1
    lines.append("curl -i -X POST http://$T/login -d \"a=b\"")
    lines.append("curl -i -X POST http://$T/ -d \"test=test\"")
    lines.append("")

    # 29) Host header / scheme confusion
    lines.append(section(n, "Host header & scheme confusion checks"))
    n += 1
    lines.append("curl -i http://$T/ -H \"Host: evil.com\"")
    lines.append("curl -i http://$T/ -H \"Host: localhost\"")
    lines.append("curl -i -H \"X-Forwarded-Proto: http\" https://$T/")
    lines.append("curl -i -H \"X-Forwarded-Proto: https\" http://$T/")
    lines.append("")

    # 30) Bypass variants
    lines.append(section(n, "Bypass variants"))
    n += 1
    lines.append("curl -i http://$T/:443")
    lines.append("curl -i http://$T//login")
    lines.append("curl -i http://$T/./login")
    lines.append("")

    # 31) Client cert / HTTP2 / heartbleed
    lines.append(section(n, "Client cert / HTTP2 / Heartbleed quick checks"))
    n += 1
    lines.append("curl -k https://$T/")
    lines.append("openssl s_client -connect $T:443 -state")
    lines.append("openssl s_client -alpn h2,http/1.1 -connect $T:443")
    lines.append("curl -I --http2 https://$T/")
    lines.append("nmap -p 443 --script ssl-heartbleed $T")
    lines.append("")

    # 32) JS enumeration
    lines.append(section(n, "JavaScript enumeration"))
    n += 1
    lines.append("curl -s http://$T/ | grep -i \".js\"")
    lines.append("wget -r -np -nH --reject index.html http://$T/static/")
    lines.append("")

    # 33) Robots.txt confirm via nmap
    lines.append(section(n, "Robots.txt confirm via nmap"))
    n += 1
    lines.append("nmap -p 80,443 --script http-robots.txt $T")
    lines.append("")

    # 34) Disallowed path enum examples
    lines.append(section(n, "Disallowed path enumeration examples"))
    n += 1
    lines.append(f"gobuster dir -u http://$T/admin -w {WL_DIR_LIGHT}")
    lines.append(f"ffuf -u http://$T/backup/FUZZ -w {WL_DIR_LIGHT}")
    lines.append("")

    # 35) Sitemap discovery extras
    lines.append(section(n, "Sitemap discovery (extra locations)"))
    n += 1
    lines.append("curl http://$T/sitemap.xml")
    lines.append("curl http://$T/sitemap_index.xml")
    lines.append("curl http://$T/sitemap-index.xml")
    lines.append("curl http://$T/sitemap1.xml")
    lines.append("curl http://$T/sitemap/")
    lines.append("curl -k https://$T/sitemap.xml")
    lines.append("")

    # 36) Spring Boot checks (host-based)
    lines.append(section(n, "Spring Boot detection + enumeration"))
    n += 1
    lines.append("curl -i http://$HOST/")
    lines.append(f"gobuster dir -u http://$HOST -w {WL_SPRING}")
    lines.append("curl http://$HOST/actuator")
    lines.append("curl -s http://$HOST/actuator/mappings | jq .")
    lines.append("curl -s http://$HOST/actuator/sessions | jq .")
    lines.append("")

    # 37) CMS / version files quick hits (host-based)
    lines.append(section(n, "CMS / common version files (quick hits)"))
    n += 1
    lines.append("curl http://$HOST/readme.html")
    lines.append("curl http://$HOST/CHANGELOG.txt")
    lines.append("curl http://$HOST/version.txt")
    lines.append("curl http://$HOST/LICENSE")
    lines.append("curl -s http://$HOST/ | grep -i \"ver=\"")
    lines.append("")

    # 38) FFUF “patterns” (kitchen sink, but as templates)
    lines.append(section(n, "FFUF patterns (templates)"))
    n += 1
    lines.append(warn("ffuf is great in labs; in exam keep it targeted and log outputs cleanly."))
    lines.append("ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt")
    lines.append("ffuf -u http://target/FUZZ -w wordlist.txt -fc 404")
    lines.append("ffuf -u http://target/FUZZ -w wordlist.txt -fs 4242")
    lines.append("ffuf -u http://target/FUZZ -w wordlist.txt -mc 200,301,302")
    lines.append("ffuf -u http://target/FUZZ -w wordlist.txt -e .php,.txt,.bak,.old,.zip")
    lines.append("ffuf -u \"http://target/page.php?FUZZ=test\" -w params.txt")
    lines.append("ffuf -u http://target/login.php -X POST -d \"FUZZ=test&password=test\" -w params.txt")
    lines.append("ffuf -u http://target -H \"Host: FUZZ.target\" -w subdomains.txt")
    lines.append("ffuf -u http://target/FUZZ -w wordlist.txt -H \"Cookie: PHPSESSID=abcd1234\"")
    lines.append("ffuf -u http://target/FUZZ -w wordlist.txt -H \"Authorization: Basic YWRtaW46YWRtaW4=\"")
    lines.append("ffuf -u http://target/FUZZ -w wordlist.txt -t 10")
    lines.append("ffuf -u http://target/FUZZ -w wordlist.txt -p 0.2")
    lines.append("ffuf -u http://target/FUZZ -w wordlist.txt -o results.json -of json")
    lines.append("")

    # 39) WPScan (template)
    lines.append(section(n, "WordPress enumeration (if detected)"))
    n += 1
    lines.append(warn("wpscan can be noisy; use when WP indicators exist."))
    lines.append("wpscan --url http://$HOST --enumerate vp,vt,u")
    lines.append("curl http://$HOST/wp-includes/version.php")
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    print("WEB ENUM SYNTAX FILLER (minimal prompts, file output only)")

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
