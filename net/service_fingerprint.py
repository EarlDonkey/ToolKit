"""
Banner grabbing and light service fingerprinting.
"""

import asyncio
import re
import ssl

from core.output import info, success, warn
from net.util import ProgressBar, PRINT_LOCK


HTTP_PORTS = {80, 8080, 8000, 8008, 8081, 8088, 8090, 8888, 9000}
HTTPS_PORTS = {443, 8443, 9443, 10443}
SSH_PORTS = {22, 2222}
TLS_PORTS = HTTPS_PORTS | {993, 995, 465, 587, 636, 989, 990, 5986, 8443}

BANNER_READ_BYTES = 2048
BANNER_TIMEOUT = 3.0
PORT_CONCURRENCY = 8


VERSION_PATTERNS = {
    "ssh": re.compile(r"SSH-([0-9.]+)-([^\s]+)"),
    "http": re.compile(r"Server:\s*([^\r\n]+)", re.IGNORECASE),
    "ftp": re.compile(r"220[- ](.+)", re.IGNORECASE),
    "smtp": re.compile(r"220[- ](.+)", re.IGNORECASE),
    "mysql": re.compile(rb"([0-9]+\.[0-9]+\.[0-9]+)"),
    "postgres": re.compile(rb"([0-9]+\.[0-9]+)"),
    "redis": re.compile(rb"redis_version:([0-9.]+)"),
}


async def _read_banner(ip, port, timeout=BANNER_TIMEOUT):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout)
    except Exception:
        return ""

    banner = b""
    try:
        banner = await asyncio.wait_for(reader.read(BANNER_READ_BYTES),
                                        timeout=timeout)
    except asyncio.TimeoutError:
        pass
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    return banner.decode("utf-8", errors="replace")


async def _http_probe(ip, port, use_tls=False, timeout=BANNER_TIMEOUT):
    """Send a minimal HTTP/1.0 GET and return (status_line, headers, title)."""
    result = {"status_line": "", "headers": {}, "title": "",
              "cert_invalid": False}

    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx), timeout=timeout)
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout)
    except ssl.SSLCertVerificationError:
        result["cert_invalid"] = True
        return None, {}, ""
    except Exception:
        return None, {}, ""

    try:
        req = (f"GET / HTTP/1.0\r\nHost: {ip}\r\n"
               f"User-Agent: toolkit/0.1\r\nConnection: close\r\n\r\n")
        writer.write(req.encode("ascii"))
        await writer.drain()

        raw = b""
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                raw += chunk
                if len(raw) > 16384:
                    break
        except asyncio.TimeoutError:
            pass

        text = raw.decode("utf-8", errors="replace")
        head, _, body = text.partition("\r\n\r\n")
        lines = head.split("\r\n")
        if lines:
            result["status_line"] = lines[0]
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                result["headers"][k.strip().lower()] = v.strip()

        m = re.search(r"<title[^>]*>(.*?)</title>", body,
                      re.IGNORECASE | re.DOTALL)
        if m:
            result["title"] = m.group(1).strip()[:120]
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    return result["status_line"], result["headers"], result["title"]


async def _tls_info(ip, port, timeout=BANNER_TIMEOUT):
    """Grab the server's TLS certificate info. Also records issuer/subject."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx), timeout=timeout)
        try:
            cert = writer.get_extra_info("peercert")
            cipher = writer.get_extra_info("cipher")
            ssl_obj = writer.get_extra_info("ssl_object")
            version = ssl_obj.version() if ssl_obj else None

            # Get the binary cert for subject/issuer parsing
            issuer = subject = None
            if ssl_obj:
                try:
                    der = ssl_obj.getpeercert(binary_form=True)
                    if der:
                        import ssl as _ssl
                        cert_dict = _ssl._ssl._test_decode_cert  # not public API
                except Exception:
                    pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        return {"cert": cert, "cipher": cipher, "version": version}
    except Exception:
        return None


async def _fingerprint_port(ip, port, timeout=BANNER_TIMEOUT):
    """Fingerprint one (ip, port). Returns a service dict."""
    service = {"ip": ip, "port": port, "service": "unknown",
               "banner": "", "version": ""}

    # HTTP / HTTPS
    if port in HTTP_PORTS or port in HTTPS_PORTS:
        use_tls = port in HTTPS_PORTS
        status, headers, title = await _http_probe(ip, port, use_tls=use_tls,
                                                   timeout=timeout)
        if status:
            service["service"] = "https" if use_tls else "http"
            service["banner"] = status
            server = headers.get("server", "")
            if server:
                service["version"] = server
            if title:
                service["title"] = title
            if headers:
                service["headers"] = headers
            if use_tls:
                tls = await _tls_info(ip, port, timeout=timeout)
                if tls:
                    service["tls"] = {
                        "version": tls["version"],
                        "cipher": tls["cipher"][0] if tls["cipher"] else None,
                    }
            return service

    # Raw banner grab
    banner = await _read_banner(ip, port, timeout=timeout)
    if banner:
        service["banner"] = banner[:400].replace("\n", " ").strip()
        first_line = banner.split("\n", 1)[0].strip()

        if port in SSH_PORTS or first_line.startswith("SSH-"):
            service["service"] = "ssh"
            m = VERSION_PATTERNS["ssh"].search(banner)
            if m:
                service["version"] = f"{m.group(2)} {m.group(1)}"
        elif first_line.startswith("220") and port in {21, 2121}:
            service["service"] = "ftp"
            m = VERSION_PATTERNS["ftp"].search(banner)
            if m:
                service["version"] = m.group(1).strip()
        elif first_line.startswith("220") and port in {25, 587, 465}:
            service["service"] = "smtp"
            m = VERSION_PATTERNS["smtp"].search(banner)
            if m:
                service["version"] = m.group(1).strip()
        elif port == 3306:
            service["service"] = "mysql"
            m = VERSION_PATTERNS["mysql"].search(
                banner.encode("utf-8", errors="ignore"))
            if m:
                service["version"] = m.group(1).decode()
        elif port == 6379:
            service["service"] = "redis"
        else:
            service["service"] = "tcp"
    else:
        # No banner — try TLS on common TLS ports
        if port in TLS_PORTS:
            tls = await _tls_info(ip, port, timeout=timeout)
            if tls:
                service["service"] = "tls"
                service["tls"] = {
                    "version": tls["version"],
                    "cipher": tls["cipher"][0] if tls["cipher"] else None,
                }
            else:
                service["service"] = "tcp"
        else:
            service["service"] = "tcp"

    return service


async def fingerprint_host(ip, ports, timeout=BANNER_TIMEOUT, verbose=False):
    """Fingerprint every open port on one host, in parallel."""
    sem = asyncio.Semaphore(PORT_CONCURRENCY)

    async def one(port):
        async with sem:
            return await _fingerprint_port(ip, port, timeout=timeout)

    services = await asyncio.gather(*[one(p) for p in ports])
    if verbose:
        for svc in services:
            version = f" {svc['version']}" if svc.get("version") else ""
            info(f"  {ip}:{svc['port']} → {svc['service']}{version}")
    return list(services)


async def fingerprint_many(host_port_map, timeout=BANNER_TIMEOUT,
                           show_progress=True, verbose=False):
    """host_port_map: {ip: [ports]}. Returns {ip: [service_dicts]}."""
    results = {}
    total = sum(len(p) for p in host_port_map.values())
    bar = ProgressBar(total, prefix="Fingerprint", enabled=show_progress)
    done = 0

    for ip, ports in host_port_map.items():
        services = await fingerprint_host(ip, ports, timeout=timeout,
                                          verbose=verbose)
        results[ip] = services
        done += len(ports)
        with PRINT_LOCK:
            bar.update(done)

    bar.finish()
    return results


async def run(target, ports_arg=None, top=100, timeout=BANNER_TIMEOUT,
              verbose=False):
    from net.port_scanner import run as port_run, _parse_ports

    ports = _parse_ports(ports_arg, top)
    info(f"fingerprinting services on {target} (ports={len(ports)})")

    open_map = await port_run(target, ports_arg=ports_arg, top=top,
                              verbose=verbose)
    if not open_map:
        warn("no open ports to fingerprint")
        return {}

    results = await fingerprint_many(open_map, timeout=timeout, verbose=verbose)

    print()
    total = sum(len(v) for v in results.values())
    success(f"identified {total} service(s)")
    for ip, services in sorted(results.items()):
        for svc in services:
            version = f" {svc['version']}" if svc.get("version") else ""
            print(f"  {ip}:{svc['port']:<6} {svc['service']}{version}")
            if svc.get("title"):
                print(f"      title: {svc['title']}")

    return results