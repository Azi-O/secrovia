import re
from decode import decodeescaped, lualiteral
from clean import cleanlua
from extract import extractloadstring
from detect import matchcandidate

def deobfuscatechaoticgood(code):
    if not matchcandidate(code):
        return None
    decoded = _deobfuscate(code)
    if not decoded:
        return None
    payload = extractloadstring(decoded)
    if payload:
        return cleanlua(payload)
    return cleanlua(decoded)

def _deobfuscate(content):
    pat = re.compile(r'v7\s*\(\s*"((?:\\.|[^"])*)"\s*,\s*"((?:\\.|[^"])*)"\s*\)')
    matches = list(pat.finditer(content))
    if not matches:
        return None
    reps = {}
    for m in matches:
        enc = decodeescaped(m.group(1)).encode("latin1", errors="ignore")
        key = decodeescaped(m.group(2)).encode("latin1", errors="ignore")
        if not enc or not key:
            continue
        dec = bytes(
            b ^ key[i % len(key)] for i, b in enumerate(enc, 1)
        ).decode("utf-8", errors="replace")
        reps[m.group(0)] = lualiteral(dec)
    if not reps:
        return None
    out = content
    for src, dst in reps.items():
        out = out.replace(src, dst)
    out = out.strip()
    out = re.sub(r'\blocal\s+v\d+\s*=\s*string\.(?:char|byte|sub)\s*;?', "", out)
    out = re.sub(r'\blocal\s+v\d+\s*=\s*bit32\s+or\s+bit\s*;?', "", out)
    out = re.sub(r'\blocal\s+v\d+\s*=\s*v\d+\.bxor\s*;?', "", out)
    out = re.sub(r'\blocal\s+v\d+\s*=\s*table\.(?:concat|insert)\s*;?', "", out)
    out = re.sub(r'\blocal\s+function\s+v7\s*\([^)]*\).*?end\s*', "", out, flags=re.DOTALL)
    out = re.sub(r'\n{3,}', "\n\n", out).strip()
    print_calls = re.findall(r'\bprint\s*\([^;\n]*\)', out)
    if print_calls:
        return "\n".join(print_calls)
    return out if out else None
