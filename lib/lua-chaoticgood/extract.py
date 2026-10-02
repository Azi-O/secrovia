import re
from decode import decodeescaped

def extractloadstring(code):
    pat = re.compile(r'\b(?:loadstring|load)\s*\(\s*(["\'])((?:\\.|[^\\\'"])*?)\1\s*[,)]', re.DOTALL)
    m = pat.search(code)
    if m:
        return decodeescaped(m.group(2))
    longpat = re.compile(r'\b(?:loadstring|load)\s*\(\s*\[(=*)\[([\s\S]*?)\]\1\]\s*[,)]')
    lm = longpat.search(code)
    if lm:
        return lm.group(2)
    return None
