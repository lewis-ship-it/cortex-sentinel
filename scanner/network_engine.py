# scanner/network_engine.py

import asyncio
import socket
import ssl
import logging
import subprocess
import json
import re
from datetime import datetime
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)

SERVICE_VULNS = {
    "openssh": [
        {"cve": "CVE-2023-38408", "severity": "Critical", "desc": "Remote code execution via ssh-agent"},
        {"cve": "CVE-2016-6210",  "severity": "Medium",   "desc": "User enumeration via timing attack"},
    ],
    "apache": [
        {"cve": "CVE-2021-41773", "severity": "Critical", "desc": "Path traversal and RCE (Apache 2.4.49)"},
        {"cve": "CVE-2021-42013", "severity": "Critical", "desc": "Path traversal bypass (Apache 2.4.50)"},
    ],
    "nginx": [
        {"cve": "CVE-2021-23017", "severity": "High", "desc": "1-byte memory overwrite via DNS resolver"},
    ],
    "vsftpd": [
        {"cve": "CVE-2011-2523", "severity": "Critical", "desc": "Backdoor in vsftpd 2.3.4"},
    ],
    "mysql": [
        {"cve": "CVE-2012-2122", "severity": "High", "desc": "Authentication bypass with repeated attempts"},
    ],
    "redis": [
        {"cve": "CVE-2022-0543", "severity": "Critical", "desc": "Lua sandbox escape / RCE"},
    ],
    "smb": [
        {"cve": "CVE-2017-0144", "severity": "Critical", "desc": "EternalBlue - RCE via SMBv1"},
    ],
    "rdp": [
        {"cve": "CVE-2019-0708", "severity": "Critical", "desc": "BlueKeep - RCE pre-auth via RDP"},
    ],
}

PORT_SERVICE_MAP = {
    21:    "ftp",
    22:    "openssh",
    23:    "telnet",
    25:    "smtp",
    53:    "dns",
    80:    "http",
    110:   "pop3",
    139:   "smb",
    143:   "imap",
    443:   "https",
    445:   "smb",
    1433:  "mssql",
    1521:  "oracle",
    3306:  "mysql",
    3389:  "rdp",
    5432:  "postgresql",
    5900:  "vnc",
    6379:  "redis",
    8080:  "http-alt",
    8443:  "https-alt",
    8888:  "jupyter",
    9200:  "elasticsearch",
    27017: "mongodb",
}

DANGEROUS_PORTS = {23, 21, 139, 445, 3389, 5900, 6379, 9200, 27017, 8888}
COMMON_PORTS    = list(PORT_SERVICE_MAP.keys())
EXTENDED_PORTS  = COMMON_PORTS + list(range(8000, 8100))


class NetworkEngine:

    def __init__(self, timeout=3, max_concurrent=50):
        self.timeout   = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def scan(self, target, port_range=None):
        host     = self._extract_host(target)
        ports    = port_range or COMMON_PORTS
        findings = []

        logging.info(f"[NET] Starting scan: {host} | {len(ports)} ports")

        open_ports = await self._port_scan(host, ports)
        logging.info(f"[NET] Open ports: {open_ports}")

        services = await self._banner_grab_all(host, open_ports)

        for port, info in services.items():
            service = info.get("service", "unknown")
            banner  = info.get("banner", "")

            if port in DANGEROUS_PORTS:
                findings.append(self._finding(
                    ftype="Exposed Dangerous Port",
                    severity="High",
                    host=host, port=port, service=service,
                    desc=f"Port {port} ({service}) is publicly accessible and should not be exposed.",
                    evidence=banner[:120] if banner else f"Port {port} open",
                ))

            for cve in self._match_cves(service, banner):
                findings.append(self._finding(
                    ftype="Known CVE",
                    severity=cve["severity"],
                    host=host, port=port, service=service,
                    desc=f"{cve['cve']}: {cve['desc']}",
                    evidence=f"Detected service: {banner[:100]}" if banner else service,
                    cve=cve["cve"],
                ))

        ssl_ports = [
            p for p in open_ports
            if p in (443, 8443) or services.get(p, {}).get("service", "") in ("https", "https-alt")
        ]
        for port in ssl_ports:
            findings.extend(await self._ssl_audit(host, port))

        findings.extend(await self._check_unauthenticated(host, services))

        if 53 in open_ports:
            findings.extend(await self._dns_enum(host))

        logging.info(f"[NET] Scan complete. {len(findings)} findings.")
        return findings

    # ── Port scanner ──────────────────────────────────────────────────────
    async def _port_scan(self, host, ports):
        tasks   = [self._check_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks)
        return [port for port, open_ in zip(ports, results) if open_]

    async def _check_port(self, host, port):
        async with self.semaphore:
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                return True
            except Exception:
                return False

    # ── Banner grabbing ───────────────────────────────────────────────────
    async def _banner_grab_all(self, host, open_ports):
        results = {}
        for port in open_ports:
            banner  = await self._grab_banner(host, port)
            service = PORT_SERVICE_MAP.get(port, self._guess_service(banner))
            results[port] = {"banner": banner, "service": service}
        return results

    async def _grab_banner(self, host, port):
        async with self.semaphore:
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
                banner = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                return banner.decode(errors="ignore").strip()
            except Exception:
                return ""

    def _guess_service(self, banner):
        if not banner:
            return "unknown"
        bl = banner.lower()
        for name in ["ssh", "ftp", "smtp", "http", "mysql", "redis", "mongodb"]:
            if name in bl:
                return name
        return "unknown"

    # ── CVE matching ──────────────────────────────────────────────────────
    def _match_cves(self, service, banner):
        hits     = []
        combined = f"{service} {banner}".lower()
        for keyword, vulns in SERVICE_VULNS.items():
            if keyword in combined:
                hits.extend(vulns)
        return hits

    # ── SSL / TLS audit ───────────────────────────────────────────────────
    async def _ssl_audit(self, host, port):
        findings = []
        try:
            context = ssl.create_default_context()
            # FIX: asyncio.get_event_loop() is deprecated in Python 3.10+
            loop    = asyncio.get_running_loop()

            def _connect():
                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        return {
                            "version": ssock.version(),
                            "cipher":  ssock.cipher(),
                            "cert":    ssock.getpeercert(),
                        }

            info = await loop.run_in_executor(None, _connect)

            if info["version"] in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                findings.append(self._finding(
                    ftype="Weak TLS Version", severity="High",
                    host=host, port=port, service="ssl",
                    desc=f"Server supports deprecated protocol: {info['version']}",
                    evidence=info["version"],
                ))

            cipher_name = info["cipher"][0] if info["cipher"] else ""
            if any(w in cipher_name.upper() for w in ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]):
                findings.append(self._finding(
                    ftype="Weak TLS Cipher", severity="High",
                    host=host, port=port, service="ssl",
                    desc=f"Weak cipher suite negotiated: {cipher_name}",
                    evidence=cipher_name,
                ))

            cert = info["cert"]
            if cert:
                not_after = cert.get("notAfter", "")
                if not_after:
                    expiry    = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.utcnow()).days
                    if days_left < 0:
                        findings.append(self._finding(
                            ftype="Expired TLS Certificate", severity="Critical",
                            host=host, port=port, service="ssl",
                            desc=f"Certificate expired {abs(days_left)} days ago.",
                            evidence=not_after,
                        ))
                    elif days_left < 30:
                        findings.append(self._finding(
                            ftype="TLS Certificate Expiring Soon", severity="Medium",
                            host=host, port=port, service="ssl",
                            desc=f"Certificate expires in {days_left} days.",
                            evidence=not_after,
                        ))

        except ssl.SSLError as e:
            findings.append(self._finding(
                ftype="SSL Error", severity="High",
                host=host, port=port, service="ssl",
                desc=f"SSL handshake failed: {str(e)}",
                evidence=str(e),
            ))
        except Exception as e:
            logging.warning(f"[SSL] {host}:{port} -> {e}")

        return findings

    # ── Unauthenticated service checks ────────────────────────────────────
    async def _check_unauthenticated(self, host, services):
        findings = []

        for port, info in services.items():
            service = info.get("service", "")
            banner  = info.get("banner", "")

            if service == "redis" and "redis" in banner.lower():
                if await self._probe_redis(host, port):
                    findings.append(self._finding(
                        ftype="Unauthenticated Redis", severity="Critical",
                        host=host, port=port, service="redis",
                        desc="Redis is accessible without authentication. Full read/write access possible.",
                        evidence="PING returned PONG with no credentials",
                    ))

            if service == "elasticsearch":
                if await self._probe_http_endpoint(host, port, "/"):
                    findings.append(self._finding(
                        ftype="Unauthenticated Elasticsearch", severity="Critical",
                        host=host, port=port, service="elasticsearch",
                        desc="Elasticsearch is publicly accessible with no authentication.",
                        evidence=f"http://{host}:{port}/ returned 200",
                    ))

            if service == "mongodb":
                findings.append(self._finding(
                    ftype="Exposed MongoDB", severity="Critical",
                    host=host, port=port, service="mongodb",
                    desc="MongoDB port is publicly reachable. Verify authentication is enforced.",
                    evidence=f"Port {port} open and accepting connections",
                ))

            if service == "telnet":
                findings.append(self._finding(
                    ftype="Telnet Enabled", severity="Critical",
                    host=host, port=port, service="telnet",
                    desc="Telnet transmits credentials in plaintext. Replace with SSH immediately.",
                    evidence=banner[:100] if banner else "Port 23 open",
                ))

            if service == "jupyter":
                if await self._probe_http_endpoint(host, port, "/api"):
                    findings.append(self._finding(
                        ftype="Exposed Jupyter Notebook", severity="Critical",
                        host=host, port=port, service="jupyter",
                        desc="Jupyter Notebook is publicly accessible. Allows arbitrary code execution.",
                        evidence=f"http://{host}:{port}/api returned 200",
                    ))

        return findings

    async def _probe_redis(self, host, port):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            writer.write(b"PING\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.read(128), timeout=self.timeout)
            writer.close()
            return b"PONG" in response
        except Exception:
            return False

    async def _probe_http_endpoint(self, host, port, path):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            writer.write(f"GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            await writer.drain()
            response = await asyncio.wait_for(reader.read(512), timeout=self.timeout)
            writer.close()
            return b"200" in response
        except Exception:
            return False

    # ── DNS enumeration ───────────────────────────────────────────────────
    async def _dns_enum(self, host):
        findings = []
        try:
            # FIX: asyncio.get_event_loop() → asyncio.get_running_loop()
            loop = asyncio.get_running_loop()

            def _axfr_check():
                result = subprocess.run(
                    ["dig", "AXFR", host, f"@{host}"],
                    capture_output=True, text=True, timeout=10,
                )
                return result.stdout

            output = await loop.run_in_executor(None, _axfr_check)

            if "Transfer failed" not in output and len(output.strip()) > 50:
                findings.append(self._finding(
                    ftype="DNS Zone Transfer Allowed", severity="High",
                    host=host, port=53, service="dns",
                    desc="DNS server allows AXFR zone transfer. Full domain records are exposed.",
                    evidence=output[:300],
                ))

        except FileNotFoundError:
            logging.warning("[DNS] 'dig' not found. Skipping zone transfer check.")
        except Exception as e:
            logging.error(f"[DNS] {e}")

        return findings

    # ── Helpers ───────────────────────────────────────────────────────────
    def _finding(self, ftype, severity, host, port, service, desc, evidence="", cve=None):
        f = {
            "type":        ftype,
            "severity":    severity,
            "url":         f"{host}:{port}",
            "host":        host,
            "port":        port,
            "service":     service,
            "description": desc,
            "evidence":    evidence,
            "confidence":  0.85,
        }
        if cve:
            f["cve"] = cve
        return f

    def _extract_host(self, target):
        if target.startswith("http"):
            return urlparse(target).netloc.split(":")[0]
        return target.split(":")[0]
