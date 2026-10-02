import re

def renameids(code):
    mapping = {}
    counter = 1
    idpat = re.compile(r"\b(?:v|var|value|f|fn|func|function|t|tbl|table|s|str|string|n|num|number|l|local|a|b|c|d|x|y|z)\d+\b")
    tokpat = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    ls = re.compile(r"\[(=*)\[")
    def repl(m):
        nonlocal counter
        ident = m.group(0)
        if ident not in mapping:
            mapping[ident] = f"v{counter}"
            counter += 1
        return mapping[ident]
    out = []
    i = 0
    n = len(code)
    prev = ""
    while i < n:
        ch = code[i]
        if ch in ("'",'"'):
            q = ch
            s = i
            i += 1
            while i < n:
                if code[i] == "\\":
                    i += 2
                    continue
                if code[i] == q:
                    i += 1
                    break
                i += 1
            out.append(code[s:i])
            prev = q
            continue
        if ch == "[":
            m = ls.match(code, i)
            if m:
                op = m.group(0)
                cl = "]" + m.group(1) + "]"
                e = code.find(cl, i + len(op))
                if e == -1:
                    out.append(code[i:])
                    break
                e += len(cl)
                out.append(code[i:e])
                i = e
                prev = "]"
                continue
        m = tokpat.match(code, i)
        if m:
            ident = m.group(0)
            if prev in (".", ":"):
                out.append(ident)
            else:
                out.append(idpat.sub(repl, ident))
            prev = ident[-1]
            i += len(ident)
            continue
        out.append(ch)
        if not ch.isspace():
            prev = ch
        i += 1
    return "".join(out)
