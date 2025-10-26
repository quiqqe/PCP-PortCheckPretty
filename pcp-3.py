#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pretty async port scanner — maximum CVE audit helper.

Usage:
    python3 pcp-3.py -H <ip> -o results.json --about-port-info --vuln-check

Requires:
    pip install aiohttp rich

Notes:
    - Safe, read-only probes only (TCP connect, HTTP HEAD/GET snippets, Docker /version read).
    - CVE lookups: prefer NVD by CPE (if a plausible CPE can be formed), then NVD keyword search,
      then CIRCL (cve.circl.lu) as a fallback.
    - This tool performs only non-destructive, read-only network queries. Use responsibly.
"""
from __future__ import annotations
import argparse
import asyncio
import json
import re
import ssl
import time
from typing import List, Dict, Any, Tuple, Optional

import aiohttp
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn

# ----------------- CONFIG -----------------
DEFAULT_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135,
    137, 138, 139, 143, 161, 162, 179, 389, 443, 445, 465, 514,
    587, 631, 636, 993, 995, 1433, 1521, 2049, 2375, 27017, 3306,
    3389, 5432, 5900, 6379, 11211, 9200, 9300, 6443
]
SANITY_PORTS = [21, 22, 23, 25, 110, 143, 993, 995, 465, 587, 80, 443, 9200, 9300, 6443, 2375, 3306, 5432, 27017]
CONCURRENCY = 80      # conservative default for concurrent connect tasks
TIMEOUT = 3.0         # per-probe timeout (seconds)
RATE_LIMIT = 40       # requests per second limit (safer default)
BANNER_READ_BYTES = 2048
OUTPUT_DEFAULT = "port_scan_results_max_audit.json"
# NVD (official) and fallback circl.lu
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
CIRCL_SEARCH_URL = "https://cve.circl.lu/api/search/"
# ------------------------------------------

console = Console()

PORT_INFO: Dict[int, str] = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPC", 123: "NTP",
    135: "MS RPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 162: "SNMP Trap", 179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTP SSL", 514: "Syslog", 587: "SMTP", 631: "IPP", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2375: "Docker API", 27017: "MongoDB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    11211: "Memcached", 9200: "Elasticsearch", 9300: "Elasticsearch", 6443: "Kubernetes API"
}

# Known product -> base CPE vendor/product mapping (used to form cpe:2.3:a:<vendor>:<product>:<version>)
# Keys use a normalized product keyword (lowercase, no punctuation) so heuristic extraction can match them.
PRODUCT_TO_CPE_BASE: Dict[str, Tuple[str, str]] = {
    "nginx": ("nginx", "nginx"),
    "apache": ("apache", "http_server"),       # apache httpd
    "httpd": ("apache", "http_server"),
    "openssh": ("openssh", "openssh"),
    "pureftpd": ("pureftpd", "pureftpd"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "dovecot": ("dovecot", "dovecot"),
    "postfix": ("postfix", "postfix"),
    "exim": ("exim", "exim"),
    "mysql": ("mysql", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "mongodb": ("mongodb", "mongodb"),
    "redis": ("redis", "redis"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "kubernetes": ("kubernetes", "kubernetes"),
    "docker": ("docker", "docker"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "litespeed": ("litespeed", "litespeed"),
    "tomcat": ("apache", "tomcat"),
    "iis": ("microsoft", "iis")
}

# -------- helpers --------
class RateLimiter:
    def __init__(self, rate_per_sec: float):
        # Simple sequential rate limiter to space out requests.
        self.rate = float(rate_per_sec) if rate_per_sec and rate_per_sec > 0 else 0.0
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def wait(self):
        if self.rate <= 0:
            return
        async with self._lock:
            now = asyncio.get_running_loop().time()
            elapsed = now - self._last
            min_gap = 1.0 / self.rate
            if elapsed < min_gap:
                await asyncio.sleep(min_gap - elapsed)
            self._last = asyncio.get_running_loop().time()


async def probe_tcp(host: str, port: int, timeout: float) -> Tuple[bool, Optional[bytes], Optional[str]]:
    """Connect + attempt to read a banner (non-blocking read)."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except Exception as e:
        return False, None, str(e)
    banner = None
    try:
        data = await asyncio.wait_for(reader.read(BANNER_READ_BYTES), timeout=timeout)
        if data:
            banner = data
    except Exception:
        pass
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    return True, banner, None


async def probe_http_head(session: aiohttp.ClientSession, host: str, port: int, timeout: float, verify_ssl: bool = True) -> Tuple[Optional[int], Optional[Dict[str, str]], Optional[str]]:
    """
    Perform an HTTP HEAD request to the root path and return (status, headers, error).
    If verify_ssl is False, SSL certificate verification is disabled (used as fallback).
    """
    proto = "https" if port in (443, 6443) else "http"
    url = f"{proto}://{host}:{port}/"
    sslctx = None
    if proto == "https" and verify_ssl:
        sslctx = ssl.create_default_context()
    elif proto == "https" and not verify_ssl:
        sslctx = False
    try:
        async with session.head(url, timeout=timeout, ssl=sslctx) as resp:
            return resp.status, dict(resp.headers), None
    except Exception as e:
        return None, None, str(e)


async def probe_http_get_snippet(session: aiohttp.ClientSession, host: str, port: int, timeout: float, max_bytes: int = 2048, verify_ssl: bool = True) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """
    Perform an HTTP GET and return a small snippet of the response body (max_bytes).
    This is intentionally limited to avoid downloading large responses.
    """
    proto = "https" if port in (443, 6443) else "http"
    url = f"{proto}://{host}:{port}/"
    sslctx = None
    if proto == "https" and verify_ssl:
        sslctx = ssl.create_default_context()
    elif proto == "https" and not verify_ssl:
        sslctx = False
    try:
        async with session.get(url, timeout=timeout, ssl=sslctx) as resp:
            status = resp.status
            data = await resp.content.read(max_bytes)
            snippet = data.decode("utf-8", errors="replace")
            return status, snippet, None
    except Exception as e:
        return None, None, str(e)


async def probe_docker_version(session: aiohttp.ClientSession, host: str, port: int, timeout: float) -> Tuple[Optional[int], Optional[Dict[str, Any]], Optional[str]]:
    """
    Query the unauthenticated Docker API /version endpoint (port 2375) — read-only.
    Returns (status, parsed_json_or_raw, error).
    """
    url = f"http://{host}:{port}/version"
    try:
        async with session.get(url, timeout=timeout) as resp:
            status = resp.status
            try:
                j = await resp.json()
            except Exception:
                text = await resp.text()
                j = {"raw": text}
            return status, j, None
    except Exception as e:
        return None, None, str(e)


async def get_tls_info(host: str, port: int, timeout: float) -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[str, int, str]]]:
    """
    Try to establish a TLS connection and extract peer cert and cipher info.
    Returns (peercert, cipher_info) or (None, None).
    cipher_info is typically (cipher_name, version, bits) when available.
    """
    try:
        sslctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=sslctx), timeout=timeout)
        tr = writer.get_extra_info("ssl_object")
        peercert = tr.getpeercert() if tr is not None else None
        cipher = tr.cipher() if tr is not None else None
        writer.close()
        await writer.wait_closed()
        return peercert, cipher
    except Exception:
        return None, None


# ---------- CVE lookup ----------
async def lookup_cve_with_nvd(session: aiohttp.ClientSession, cpe: Optional[str], keyword: Optional[str]) -> List[str]:
    """
    Try NVD:
      - If cpe provided, try cpeName=cpe:2.3:... (precise)
      - Then try keyword search (less precise)
    Returns a list of short CVE summaries like "CVE-YYYY-NNNN: summary".
    """
    out: List[str] = []
    try:
        if cpe:
            params = {"cpeName": cpe, "resultsPerPage": 20}
            async with session.get(NVD_API_URL, params=params, timeout=12) as resp:
                if resp.status == 200:
                    j = await resp.json()
                    cve_items = j.get("result", {}).get("CVE_Items") or j.get("CVE_Items") or []
                    for it in cve_items[:10]:
                        try:
                            cve_id = it.get("cve", {}).get("CVE_data_meta", {}).get("ID")
                            descs = it.get("cve", {}).get("description", {}).get("description_data", [])
                            summary = descs[0].get("value")[:240] if descs else ""
                            if cve_id:
                                out.append(f"{cve_id}: {summary}")
                        except Exception:
                            continue
                    if out:
                        await asyncio.sleep(0.6)  # be polite to NVD
                        return out
        # fallback keyword search
        if keyword:
            params = {"keyword": keyword, "resultsPerPage": 20}
            async with session.get(NVD_API_URL, params=params, timeout=12) as resp:
                if resp.status == 200:
                    j = await resp.json()
                    cve_items = j.get("result", {}).get("CVE_Items") or j.get("CVE_Items") or []
                    for it in cve_items[:8]:
                        try:
                            cve_id = it.get("cve", {}).get("CVE_data_meta", {}).get("ID")
                            descs = it.get("cve", {}).get("description", {}).get("description_data", [])
                            summary = descs[0].get("value")[:240] if descs else ""
                            if cve_id:
                                out.append(f"{cve_id}: {summary}")
                        except Exception:
                            continue
                    if out:
                        await asyncio.sleep(0.6)
                        return out
    except Exception:
        return []
    return out


async def lookup_cve_with_circl(session: aiohttp.ClientSession, query: str) -> List[str]:
    """Fallback to circl.lu search where available (/api/search/{query})."""
    try:
        safe_q = query.replace(" ", "%20")
        url = CIRCL_SEARCH_URL + safe_q
        async with session.get(url, timeout=8) as resp:
            if resp.status != 200:
                return []
            j = await resp.json()
            results = []
            for item in j.get("results", [])[:8]:
                cid = item.get("id") or item.get("CVE") or item.get("cve")
                summary = item.get("summary") or item.get("detail") or ""
                if cid:
                    results.append(f"{cid}: {summary[:240]}")
            return results
    except Exception:
        return []


def sanitize_version_for_cpe(version: str) -> str:
    """Sanitize version to be appended to a CPE (remove spaces and odd characters)."""
    if not version:
        return ""
    v = version.strip()
    v = re.sub(r"[^0-9a-zA-Z\._\-]", "", v)
    return v


def build_cpe_candidates(product_keyword: str, version: Optional[str]) -> List[str]:
    """
    Build plausible CPE 2.3 strings using PRODUCT_TO_CPE_BASE and extracted version.
    Returns list of cpe candidates (most specific first).
    """
    candidates: List[str] = []
    key = (product_keyword or "").lower().strip()
    # normalize key to match PRODUCT_TO_CPE_BASE keys (remove punctuation)
    key = re.sub(r"[^a-z0-9]+", "", key)
    if key in PRODUCT_TO_CPE_BASE:
        vendor, prod = PRODUCT_TO_CPE_BASE[key]
        if version:
            v = sanitize_version_for_cpe(version)
            if v:
                candidates.append(f"cpe:2.3:a:{vendor}:{prod}:{v}:*:*:*:*:*:*:*")
        # generic product (no version)
        candidates.append(f"cpe:2.3:a:{vendor}:{prod}:*:*:*:*:*:*:*:*")
    else:
        # try naive product->cpe with product_keyword normalized as product
        prod = re.sub(r"[^a-z0-9_]+", "_", key)
        if version:
            v = sanitize_version_for_cpe(version)
            if v:
                candidates.append(f"cpe:2.3:a:{prod}:{prod}:{v}:*:*:*:*:*:*:*")
        candidates.append(f"cpe:2.3:a:{prod}:{prod}:*:*:*:*:*:*:*:*")
    return candidates


async def lookup_cve(session: aiohttp.ClientSession, product: str, version: Optional[str]) -> List[str]:
    """
    Master CVE lookup:
     - Try building CPE candidate list and query NVD by cpeName
     - If not found, try NVD keyword (product + version or product)
     - If still empty, fallback to circl.lu
    """
    # build cpe candidates
    cpe_candidates = build_cpe_candidates(product, version)
    # try each CPE
    for cpe in cpe_candidates:
        res = await lookup_cve_with_nvd(session, cpe, None)
        if res:
            return res
    # try NVD keyword
    keyword = f"{product} {version}".strip() if version else product
    res = await lookup_cve_with_nvd(session, None, keyword)
    if res:
        return res
    # fallback circl
    res2 = await lookup_cve_with_circl(session, keyword)
    return res2


# ---------- safe vuln probes ----------
async def safe_extract_product_and_version(banner_text: str, headers: Optional[Dict[str, str]] = None, port: Optional[int] = None) -> Tuple[Optional[str], Optional[str]]:
    """
    Heuristics that try to extract product and version from banner text or HTTP Server header.
    Returns (product_keyword, version) or (None, None).
    """
    if not banner_text and not headers:
        return None, None
    txt = (banner_text or "") + " "
    server_hdr = ""
    if headers:
        server_hdr = headers.get("Server") or headers.get("server") or ""
        txt = txt + server_hdr
    txt = txt.strip()

    # OpenSSH
    m = re.search(r"OpenSSH[_-]?([\d\.p]+)", txt, re.IGNORECASE)
    if m:
        return "openssh", m.group(1)

    # nginx / litespeed / apache / httpd
    m = re.search(r"(nginx|litespeed|apache|httpd)[/ ]?v?([\d\.]+)?", txt, re.IGNORECASE)
    if m:
        matched = m.group(1).lower()
        ver = m.group(2) if m.group(2) else None
        # normalize matched product names to our PRODUCT_TO_CPE_BASE keys
        if "nginx" in matched:
            product = "nginx"
        elif "litespeed" in matched:
            product = "litespeed"
        elif "apache" in matched or "httpd" in matched:
            product = "apache"
        else:
            product = matched
        return product, ver

    # Common server banners: Pure-FTPd, vsftpd, proftpd, dovecot, postfix, exim, tomcat, jetty
    m = re.search(r"(Pure-FTPd|vsftpd|proftpd|dovecot|postfix|exim|tomcat|jetty)[/ ]?v?([0-9\.]+)?", txt, re.IGNORECASE)
    if m:
        product = m.group(1).lower().replace("-", "")
        version = m.group(2) if m.group(2) else None
        # normalize product to match our mapping keys (remove non-alphanumeric)
        product = re.sub(r"[^a-z0-9]+", "", product)
        return product, version

    # Generic pattern: Name/1.2.3 or Name 1.2.3 (captures many banners)
    m = re.search(r"([A-Za-z0-9\-_]{3,})[ /_v]?([0-9]+\.[0-9]+(?:\.[0-9]+)*)", txt)
    if m:
        prod = m.group(1).lower()
        ver = m.group(2)
        # filter trivial matches and normalize product token (remove punctuation)
        if len(prod) >= 3:
            prod = re.sub(r"[^a-z0-9]+", "", prod)
            return prod, ver

    # fallback: if Server header exists, try to parse product/version there explicitly
    if server_hdr:
        m = re.search(r"([A-Za-z0-9\-_]+)[/ ]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)*)", server_hdr)
        if m:
            prod = m.group(1).lower()
            prod = re.sub(r"[^a-z0-9]+", "", prod)
            return prod, m.group(2)

    return None, None


async def vuln_sanity_check(host: str, port: int, banner: Optional[str], headers: Optional[Dict[str, str]], session: aiohttp.ClientSession) -> Dict[str, Any]:
    """
    Safe sanity checks for known ports. This enhanced version:
      - extracts product/version,
      - attempts to form CPE candidates,
      - performs CVE lookup (NVD / CIRCL) when possible,
      - collects TLS info for HTTPS ports,
      - queries Docker /version for port 2375.

    Note: This function performs only read-only operations.
    """
    result: Dict[str, Any] = {}
    banner_text = (banner or "")[:1500]
    result.update({"banner": banner_text})
    # try to get headers/snippet for HTTP-like services
    if port in (80, 443, 9200, 9300, 6443):
        if headers is None:
            # attempt HEAD first
            status, headers_res, herr = await probe_http_head(session, host, port, TIMEOUT, verify_ssl=True)
            headers = headers_res or {}
            result.update({"http_status": status, "http_headers": headers or {}})
            # attempt GET snippet; if there was a cert error, retry with verify_ssl=False
            st2, snippet, _ = await probe_http_get_snippet(session, host, port, TIMEOUT, verify_ssl=(herr is None))
            result["http_snippet"] = snippet
        else:
            result.update({"http_headers": headers})
        # TLS info for HTTPS-like ports
        if port in (443, 6443):
            peercert, cipher = await get_tls_info(host, port, TIMEOUT)
            result["tls_cert"] = peercert
            result["tls_cipher"] = cipher

    # Docker /version
    if port == 2375:
        status, j, derr = await probe_docker_version(session, host, port, TIMEOUT)
        result["docker_status"] = status
        result["docker_version_json"] = j

    # extract product & version heuristics
    product, version = await safe_extract_product_and_version(banner_text, headers=headers, port=port)
    if product:
        product_key = product.lower()
        result["detected_product"] = product_key
    if version:
        result["detected_version"] = version

    # Build cpe candidates if possible and perform CVE lookup
    cve_list: List[str] = []
    cpe_candidates = build_cpe_candidates(product or "", version)

    # Try NVD by CPE first, then keyword, then CIRCL fallback
    for cpe in cpe_candidates:
        if not cpe:
            continue
        found = await lookup_cve_with_nvd(session, cpe, None)
        if found:
            cve_list.extend(found)
            break
        await asyncio.sleep(0.3)
    # if still empty, try keyword search
    if not cve_list:
        key = f"{product or ''} {version or ''}".strip()
        if key:
            found2 = await lookup_cve_with_nvd(session, None, key)
            if found2:
                cve_list.extend(found2)
    # fallback circl
    if not cve_list:
        key2 = (product or "").strip() or ""
        if key2:
            found3 = await lookup_cve_with_circl(session, key2)
            if found3:
                cve_list.extend(found3)

    if cve_list:
        result["cves"] = cve_list[:10]

    return result


# ---------- worker + orchestrator ----------
async def worker(
    host: str,
    port: int,
    sem: asyncio.Semaphore,
    rate_limiter: RateLimiter,
    results: Dict[str, Any],
    progress: Progress,
    task_id: int,
    session: aiohttp.ClientSession,
    do_vuln_check: bool = False,
):
    """Worker: probe a single host:port and optionally run safe vuln checks."""
    try:
        async with sem:
            await rate_limiter.wait()
            entry: Dict[str, Any] = {
                "host": host,
                "port": port,
                "open": False,
                "banner": None,
                "extra": {},
                "error": None,
            }

            is_open, banner, err = await probe_tcp(host, port, TIMEOUT)
            entry["open"] = bool(is_open)
            if banner:
                try:
                    entry["banner"] = banner.decode("utf-8", errors="replace")
                except Exception:
                    entry["banner"] = str(banner)
            if err:
                entry["error"] = err

            # lightweight extra probes for known ports
            if entry["open"]:
                if port in (80, 443, 9200, 9300, 6443):
                    status, headers, herr = await probe_http_head(session, host, port, TIMEOUT, verify_ssl=True)
                    if status is None and herr and "certificate" in str(herr).lower():
                        # retry without SSL verification if the first try failed due to cert issues
                        status, headers, herr = await probe_http_head(session, host, port, TIMEOUT, verify_ssl=False)
                    entry["extra"].update({"http_status": status, "http_headers": headers or {}})
                    if herr:
                        entry.setdefault("errors", []).append(str(herr))
                elif port == 2375:
                    status, j, derr = await probe_docker_version(session, host, port, TIMEOUT)
                    entry["extra"].update({"docker_version_status": status, "docker_version_body": j})
                    if derr:
                        entry.setdefault("errors", []).append(str(derr))

            # optional safe vuln-checks (includes CVE lookup when version extracted)
            if do_vuln_check and port in SANITY_PORTS:
                try:
                    # pass current headers if available to save extra request
                    headers = entry.get("extra", {}).get("http_headers") if isinstance(entry.get("extra"), dict) else None
                    entry["vuln_check"] = await vuln_sanity_check(host, port, entry.get("banner"), headers, session)
                except Exception as e:
                    entry["vuln_check"] = {"error": f"vuln_check_failed: {e}"}

            results[f"{host}:{port}"] = entry

            try:
                progress.update(task_id, advance=1)
            except Exception:
                pass
    except Exception as e:
        results[f"{host}:{port}"] = {
            "host": host,
            "port": port,
            "open": False,
            "banner": None,
            "extra": {},
            "error": f"worker_exception: {e}",
        }
        try:
            progress.update(task_id, advance=1)
        except Exception:
            pass


async def run_scan(hosts: List[str], ports: List[int], out_file: str, do_vuln_check: bool) -> Dict[str, Any]:
    sem = asyncio.Semaphore(CONCURRENCY)
    rate_limiter = RateLimiter(RATE_LIMIT)
    results: Dict[str, Any] = {}

    total_tasks = len(hosts) * len(ports)
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    )

    async with aiohttp.ClientSession() as session:
        with progress:
            task_id = progress.add_task("[cyan]Scanning ports...", total=total_tasks)
            tasks = [
                worker(host, port, sem, rate_limiter, results, progress, task_id, session, do_vuln_check)
                for host in hosts
                for port in ports
            ]
            await asyncio.gather(*tasks)

    # Save results
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    return results


# ---------- output ----------
def print_summary(results: Dict[str, Any], about_port_info: bool = False, show_vuln: bool = False) -> None:
    table = Table(title="Scan summary", show_lines=False, title_style="bold magenta")
    table.add_column("Host:Port", style="cyan", no_wrap=True)
    table.add_column("Open", style="green", no_wrap=True)
    if about_port_info:
        table.add_column("Port Info", style="magenta", no_wrap=True)
    table.add_column("Service / Banner", style="yellow")
    table.add_column("Extra (concise)", style="blue")
    if show_vuln:
        table.add_column("Safe Probe", style="red")

    for k, v in sorted(results.items()):
        open_s = "[green]YES[/green]" if v.get("open") else "[red]NO[/red]"
        banner = (v.get("banner") or "")[:60].replace("\n", " ")
        extra_short = ""
        extra = v.get("extra") or {}
        if isinstance(extra, dict):
            if "docker_version_body" in extra:
                dv = extra["docker_version_body"]
                extra_short = (str(dv)[:40]) if dv else ""
            elif "http_status" in extra:
                headers = extra.get("http_headers") or {}
                server = headers.get("Server") or headers.get("server") or ""
                extra_short = f"HTTP {extra.get('http_status')} {server}"
            else:
                extra_short = (str(extra)[:40]) if extra else ""
        else:
            extra_short = str(extra)[:40]

        safe = ""
        if show_vuln:
            vuln = v.get("vuln_check")
            if isinstance(vuln, dict):
                parts = []
                if vuln.get("note"):
                    parts.append(vuln["note"])
                if vuln.get("detected_product"):
                    parts.append(vuln["detected_product"])
                if vuln.get("detected_version"):
                    parts.append(vuln["detected_version"])
                if vuln.get("cves"):
                    parts.append(f"{len(vuln['cves'])} CVE(s)")
                if vuln.get("http_status"):
                    parts.append(f"HTTP{vuln.get('http_status')}")
                safe = " | ".join([p for p in parts if p])
            else:
                safe = str(vuln)[:40] if vuln else ""

        if about_port_info and show_vuln:
            table.add_row(k, open_s, PORT_INFO.get(v.get("port"), ""), banner, extra_short, safe)
        elif about_port_info:
            table.add_row(k, open_s, PORT_INFO.get(v.get("port"), ""), banner, extra_short)
        elif show_vuln:
            table.add_row(k, open_s, banner, extra_short, safe)
        else:
            table.add_row(k, open_s, banner, extra_short)

    console.print(table)


def print_panels(results: Dict[str, Any], about_port_info: bool = False, show_vuln: bool = False) -> None:
    open_items = [(k, v) for k, v in sorted(results.items()) if v.get("open")]
    if not open_items:
        console.print("[green]No open ports found.[/green]")
        return

    for k, v in open_items:
        title = f"[bold]{k}[/bold] — [green]OPEN[/green]"
        body_lines: List[str] = []
        if v.get("banner"):
            body_lines.append(f"[yellow]Banner:[/yellow] {v.get('banner')}")
        if v.get("extra"):
            try:
                extra_json = json.dumps(v.get("extra"), ensure_ascii=False, indent=2)
            except Exception:
                extra_json = str(v.get("extra"))
            body_lines.append(f"[blue]Extra:[/blue]\n{extra_json}")
        if show_vuln and v.get("vuln_check"):
            try:
                vuln_json = json.dumps(v.get("vuln_check"), ensure_ascii=False, indent=2)
            except Exception:
                vuln_json = str(v.get("vuln_check"))
            body_lines.append(f"[red]Safe probe:[/red]\n{vuln_json}")
        if about_port_info:
            body_lines.append(f"[magenta]Port info:[/magenta] {PORT_INFO.get(v.get('port'), 'Unknown')}")
        if v.get("error"):
            body_lines.append(f"[red]Error:[/red] {v.get('error')}")
        if not body_lines:
            body_lines.append("[italic]No additional data[/italic]")

        panel = Panel("\n\n".join(body_lines), title=title, expand=False, border_style="bright_black")
        console.print(panel)


# ---------- CLI ----------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Safe port scanner + maximal audit for CVE lookup")
    p.add_argument("--hosts", "-H", nargs="+", required=True, help="Target hosts (IP or hostname).")
    p.add_argument("--ports", "-p", nargs="*", type=int, help="Ports to check. If omitted, uses default set.")
    p.add_argument("--out", "-o", default=OUTPUT_DEFAULT, help="Output JSON file")
    p.add_argument("--about-port-info", "-a", action="store_true", help="Show service info for ports")
    p.add_argument("--vuln-check", "-v", action="store_true", help="Run safe read-only vulnerability sanity checks (includes CVE lookup when possible)")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    ports = args.ports if args.ports else DEFAULT_PORTS
    console.rule("[bold green]Port scan start")
    console.print(f"Targets: {args.hosts}", style="bold cyan")
    console.print(f"Ports: {ports}", style="bold cyan")
    console.print(f"Concurrency={CONCURRENCY}, timeout={TIMEOUT}s, rate={RATE_LIMIT}/s\n", style="dim")

    start = time.time()
    results = asyncio.run(run_scan(args.hosts, ports, args.out, do_vuln_check=args.vuln_check))
    elapsed = time.time() - start

    console.rule("[bold green]Scan complete")
    console.print(f"Elapsed: {elapsed:.2f}s — results saved to [bold]{args.out}[/bold]\n", style="bold")

    print_summary(results, about_port_info=args.about_port_info, show_vuln=args.vuln_check)
    console.print()
    print_panels(results, about_port_info=args.about_port_info, show_vuln=args.vuln_check)

    open_count = sum(1 for v in results.values() if v.get("open"))
    console.print()
    console.print(f"[bold]{open_count} open ports found[/bold]", style="red" if open_count else "green")
    console.rule()


if __name__ == "__main__":
    main()
