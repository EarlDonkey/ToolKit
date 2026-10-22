import base64
import random


def _rand_case(s: str) -> str:
    """Randomly uppercase/lowercase letters in a string."""
    return "".join(
        c.upper() if random.random() < 0.5 else c.lower() if c.isalpha() else c
        for c in s
    )


def bash_octal(payload: str) -> str:
    """
    Wrap a bash payload so it's built from $'\\xNN' escapes.
    The command runs the same but doesn't appear literally in the source.
    """
    hexed = "".join(f"\\x{ord(c):02x}" for c in payload)
    return f"$'{hexed}'"


def bash_eval(payload: str) -> str:
    """Split payload into chunks and eval the concatenation."""
    chunks = [payload[i:i + 8] for i in range(0, len(payload), 8)]
    parts = " ".join(f"'{c}'" for c in chunks)
    return f"eval $(echo {parts} | tr -d ' ')"


def powershell_charcodes(payload: str) -> str:
    """
    Convert a PowerShell payload into a [char] array concatenated
    and passed to iex. This is the classic basic PowerShell obfuscation.
    """
    codes = ",".join(str(ord(c)) for c in payload)
    return f"iex ([char[]]({codes}) -join '')"


def powershell_concat(payload: str) -> str:
    """Split the payload into chunks, join with '+'."""
    chunks = [payload[i:i + 6] for i in range(0, len(payload), 6)]
    inner = " + ".join(f"'{c}'" for c in chunks)
    return f"iex ({inner})"


def powershell_base64_encoded(payload: str) -> str:
    """
    Produce the -EncodedCommand form. PowerShell expects UTF-16LE base64.
    """
    encoded = base64.b64encode(payload.encode("utf-16-le")).decode()
    return f"powershell -nop -w hidden -EncodedCommand {encoded}"


def randomize_keywords(payload: str, keywords: list[str]) -> str:
    """Randomize case of keyword occurrences (bash/php are case-sensitive; Windows shells aren't)."""
    for kw in keywords:
        idx = 0
        out = []
        while True:
            found = payload.lower().find(kw.lower(), idx)
            if found == -1:
                out.append(payload[idx:])
                break
            out.append(payload[idx:found])
            out.append(_rand_case(payload[found:found + len(kw)]))
            idx = found + len(kw)
        payload = "".join(out)
    return payload


# Dispatch table by payload language
OBFUSCATORS = {
    "bash": {
        "octal": bash_octal,
        "eval": bash_eval,
    },
    "powershell": {
        "charcodes": powershell_charcodes,
        "concat": powershell_concat,
        "base64": powershell_base64_encoded,
    },
}


def obfuscate(payload: str, shell_type: str, method: str) -> str:
    """Apply an obfuscation method to a payload. Falls back to identity."""
    table = OBFUSCATORS.get(shell_type, {})
    fn = table.get(method)
    if fn is None:
        return payload
    return fn(payload)


def list_methods(shell_type: str) -> list[str]:
    return list(OBFUSCATORS.get(shell_type, {}).keys())