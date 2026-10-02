import re
import json

def decodeescaped(value):
    out = []
    i = 0
    esc = {"a":"\x07","b":"\x08","f":"\x0c","n":"\n","r":"\r","t":"\t","v":"\x0b","\\":"\\",'"':'"',"'":"'"}
    while i < len(value):
        c = value[i]
        if c != "\\":
            out.append(c); i += 1; continue
        i += 1
        if i >= len(value):
            out.append("\\"); break
        e = value[i]
        if e.isdigit():
            d = [e]; i += 1
            while i < len(value) and len(d) < 3 and value[i].isdigit():
                d.append(value[i]); i += 1
            out.append(chr(int("".join(d),10)%256))
            continue
        if e == "x" and i+2 < len(value):
            h = value[i+1:i+3]
            if re.fullmatch(r"[0-9a-fA-F]{2}",h):
                out.append(chr(int(h,16))); i += 3; continue
        out.append(esc.get(e,e)); i += 1
    return "".join(out)

def lualiteral(value):
    return json.dumps(value, ensure_ascii=False).replace("</","<\\/")
