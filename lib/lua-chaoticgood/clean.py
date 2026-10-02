import re
from rename import renameids

CREDIT = """--[[
Deobfuscated by Axomic LuaObfuscator ChaoticGood Deobfuscator
Our Discord : https://discord.gg/Sps39CydcZ
Our YouTube : https://youtube.com/@axos0022
]]"""

def stripheader(code):
    code = code.lstrip()
    if not code:
        return code
    m = re.match(r'--\[(=*)\[', code)
    if m:
        opener = m.group(0)
        closer = ']' + m.group(1) + ']'
        end = code.find(closer, len(opener))
        if end != -1:
            after = code[end + len(closer):].lstrip()
            return after
        else:
            return ''
    if code.startswith('--'):
        end = code.find('\n')
        if end != -1:
            after = code[end:].lstrip()
            return after
        else:
            return ''
    return code

def cleanlua(code):
    code = renameids(code.strip())
    code = stripheader(code)
    return (CREDIT + "\n" + code).strip()
