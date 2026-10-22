"""
Evasion library.

Current contents:
  - waf_bypass: SQL and XSS tamper sets, WAF fingerprinting,
                mutation application engine.
  - av_bypass:  AMSI and ETW bypass techniques, compiled as
                .NET Framework 4.8 assemblies.
  - chains:     Combine multiple bypass techniques into one
                assembly, invoked with a single call.
  - delivery:   Wrap a PowerShell script with an in-memory AMSI
                bypass, producing a single-line loader.
"""

from evade.waf_bypass import (
    SQL_TAMPERS,
    XSS_TAMPERS,
    TAMPER_CATEGORIES,
    fingerprint_waf,
    pick_tampers_for_fingerprint,
    apply_single_tamper,
    apply_tamper_chain,
    enumerate_tamper_sequences,
)

from evade.av_bypass import (
    TECHNIQUES,
    WORKING_TECHNIQUES,
    CAUGHT_TECHNIQUES,
    compile as compile_av_bypass,
    compile_all as compile_all_av_bypass,
    loader_ps1,
    list_techniques,
)

from evade.chains import (
    CHAIN_PRESETS,
    MODERN_PRESETS,
    Chain,
    compile_chain,
    loader_ps1 as chain_loader_ps1,
    list_presets,
    resolve_chain,
)

from evade.delivery import (
    DEFAULT_BYPASS,
    wrap_script,
    wrap_command,
    wrap_script_file,
    wrap_chain,
    write_payload,
)

__all__ = [
    # WAF
    "SQL_TAMPERS", "XSS_TAMPERS", "TAMPER_CATEGORIES",
    "fingerprint_waf", "pick_tampers_for_fingerprint",
    "apply_single_tamper", "apply_tamper_chain",
    "enumerate_tamper_sequences",

    # AV bypass techniques
    "TECHNIQUES", "WORKING_TECHNIQUES", "CAUGHT_TECHNIQUES",
    "compile_av_bypass", "compile_all_av_bypass",
    "loader_ps1", "list_techniques",

    # Chains
    "CHAIN_PRESETS", "MODERN_PRESETS", "Chain",
    "compile_chain", "chain_loader_ps1",
    "list_presets", "resolve_chain",

    # Delivery
    "DEFAULT_BYPASS", "wrap_script", "wrap_command",
    "wrap_script_file", "wrap_chain", "write_payload",
]