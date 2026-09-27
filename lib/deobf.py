import re
import sys
import os
import base64
import struct
import json
import argparse
import hashlib
import math
import zlib
import binascii
import itertools
import copy
import string
import random
import time
import ast
import logging
import tempfile
import subprocess
import shutil
from typing import Optional, Dict, List, Tuple, Any, Union, Callable, Set
from dataclasses import dataclass, field
from enum import IntEnum, auto
from collections import defaultdict, Counter
from functools import reduce

try:
    import networkx as nx
except ImportError:
    nx = None

VERSION = "1.0.0"
BANNER = r"""
   _____ ______ _____ _____   ____     _______          
  / ____|  ____/ ____|  __ \ / __ \   |  __ \ \    / / /\   

 | (___ | |__ | |    | |__) | |  | |  | |__) \ \  / / /  \  
  \___ \|  __|| |    |  _  /| |  | |  |  _  / \ \/ / / /\ \ 
  ____) | |___| |____| | \ \| |__| |  | | \ \  \  / / ____ \

 |_____/|______\_____|_|  \_\\____/   |_|  \_\  \/ /_/    \_\
"""


class BracketMatcher:
    def __init__(self, source: str):
        self.source = source
        self.n = len(source)

    def _skip_string(self, i: int) -> int:
        q = self.source[i]
        i += 1
        while i < self.n:
            c = self.source[i]
            if c == "\\":
                i += 2
                continue
            if c == q:
                return i + 1
            if c == "\n":
                return i
            i += 1
        return self.n

    def _skip_long_bracket(self, i: int) -> int:
        if i >= self.n or self.source[i] != "[":
            return i
        j = i + 1
        eq = 0
        while j < self.n and self.source[j] == "=":
            eq += 1
            j += 1
        if j >= self.n or self.source[j] != "[":
            return i
        close = "]" + "=" * eq + "]"
        end = self.source.find(close, j + 1)
        return end + len(close) if end >= 0 else self.n

    def _skip_comment(self, i: int) -> int:
        if self.source[i:i + 2] != "--":
            return i
        i += 2
        if i < self.n and self.source[i] == "[":
            end = self._skip_long_bracket(i)
            if end > i + 1:
                return end
        while i < self.n and self.source[i] != "\n":
            i += 1
        return i

    def _scan_forward(self, i: int) -> int:
        c = self.source[i]
        if c in "\"'":
            return self._skip_string(i)
        if c == "-" and i + 1 < self.n and self.source[i + 1] == "-":
            return self._skip_comment(i)
        if c == "[":
            end = self._skip_long_bracket(i)
            if end > i + 1:
                return end
        return i + 1

    def match_brace(self, start: int) -> int:
        return self._match(start, "{", "}")

    def match_paren(self, start: int) -> int:
        return self._match(start, "(", ")")

    def match_bracket(self, start: int) -> int:
        return self._match(start, "[", "]")

    def _match(self, start: int, open_ch: str, close_ch: str) -> int:
        if start >= self.n or self.source[start] != open_ch:
            return -1
        depth = 0
        i = start
        while i < self.n:
            c = self.source[i]
            if c in "\"'":
                i = self._skip_string(i)
                continue
            if c == "-" and i + 1 < self.n and self.source[i + 1] == "-":
                i = self._skip_comment(i)
                continue
            if c == "[" and open_ch != "[":
                skip = self._skip_long_bracket(i)
                if skip > i + 1:
                    i = skip
                    continue
            if c == open_ch:
                depth += 1
            elif c == close_ch:
                depth -= 1
                if depth == 0:
                    return i
            i += 1
        return -1

    def find_block_end(self, start: int, opener_kws: Tuple[str, ...] = ("do", "then", "function", "repeat")) -> int:
        i = start
        depth = 0
        s = self.source
        while i < self.n:
            c = s[i]
            if c in "\"'":
                i = self._skip_string(i)
                continue
            if c == "-" and i + 1 < self.n and s[i + 1] == "-":
                i = self._skip_comment(i)
                continue
            if c.isalpha() or c == "_":
                ws = i
                while i < self.n and (s[i].isalnum() or s[i] == "_"):
                    i += 1
                w = s[ws:i]
                if w in opener_kws:
                    depth += 1
                elif w in ("end", "until"):
                    if depth <= 0:
                        return ws
                    depth -= 1
                    if depth == 0:
                        return ws
                continue
            i += 1
        return -1


class ConstantTracker:
    def __init__(self):
        self.known_values = {
            "var_18": 256,
            "var_12": 3,
            "var_16": 16,
            "var_10": 10,
        }

    def get_value(self, var: str) -> str:
        return str(self.known_values.get(var, var))


class DecoyDetector:
    def __init__(self):
        self.patterns = {
            "string_decoys": [
                (r'\.\.\s*("?\\\d{2,}[a-zA-Z][^",]*)', "Invalid concatenated escape"),
                (r',\s*"[^"]*"\.\.\\\d{2,}[a-zA-Z][^"]*"', "Invalid table entry"),
                (r",\s*,", ","),
            ],
            "arithmetic_decoys": [
                (r"\b-?0x[\dA-Fa-f]+[g-z]\b", "Invalid hex suffix"),
                (r"\b\d+[A-Za-z]+\s*=", "Invalid numeric assignment"),
            ],
            "control_flow_decoys": [
                (r"<\s*-?\d+[a-zA-Z]", "Bogus numeric condition"),
                (r"==\s*-\d+[a-fA-F]+\b", "Invalid comparison literal"),
            ],
            "type_conversion_decoys": [
                (r"0\s*\.\s*read\s*=", "Fake read operation"),
                (r"\w+\s*=\s*\w+\s*-\s*\w+[b-df-hj-np-tv-z]", "Invalid unit suffix"),
            ],
            "unreachable_ops": [
                (r"if\s+[\w.]+\s*==\s*-\d+[a-zA-Z]+\s+then", "Unreachable condition"),
                (r"/\s*\(\s*\)", "Empty operation"),
            ],
            "error_handling_decoys": [
                (r"\berror\(\s*,", "Malformed error call"),
                (r"\bpcall\(\s*\d+[a-zA-Z]+\s*\)", "Invalid pcall argument"),
            ],
            "api_decoys": [
                (r"\b(get|set)metatable\(\s*[^,]+,\s*\{\.?\s*\}\)", "Invalid metatable arguments"),
                (r"\b(setmetatable|pcall)\(\s*\d+[a-zA-Z]+\b", "Bogus API parameter"),
            ],
            "string_ops_decoys": [
                (r"\bstring\s*\.\s*\d+\s*=", "Invalid string method assignment"),
                (r"\bstring\.[a-z]+\s*=\s*[^(\n]+$", "Type mismatch in string ops"),
            ],
            "memory_decoys": [
                (r"\b(memory|pointer|versan)\s*=\s*nil\b.*[=/]\s*\b(byte|table)\.", "Nonsense memory ops"),
                (r"\bchar\s*=\s*\w+\s*[+%]\s*\w+\s*%\s*\w+", "Dead result calculation"),
                (r"\bmemory\s*=\s*nil\s*table\.\s*list\s*=\s*table\.insert\s*/\s*byte", "Nonsense memory table ops"),
                (r"\bchar\s*=\s*global\s*\+\s*versan\s*global\s*=\s*char\s*%\s*global", "Dead memory calculation"),
            ],
            "bitwise_decoys": [
                (r"\bbit32\.\w+\(\s*,\s*\[", "Empty bitwise operation"),
                (r"\b0\s*\.\s*read\s*%\s*[^;\n]+$", "Incomplete bitwise expression"),
            ],
            "function_decoys": [
                (r"function\s*\(([^)]*,){5,}[^)]*\)", "Excessive unused parameters"),
                (r"\bfunction\b.*;\s*(for|string|error)\b", "Invalid parameter syntax"),
            ],
            "goto_decoys": [
                (r"\bgoto\s*=\s*[^;\n]+$", "Invalid goto assignment"),
            ],
            "table_ops_decoys": [
                (r"\b(table|array)\s*\.\s*insert\s*=\s*[^;\n]+$", "Invalid table.insert assignment"),
            ],
        }

    def remove_decoys(self, code: str) -> Tuple[str, Dict[str, int]]:
        removed: Dict[str, int] = defaultdict(int)
        for category, patterns in self.patterns.items():
            for pattern, desc in patterns:
                try:
                    count = len(re.findall(pattern, code))
                except re.error:
                    count = 0
                if count:
                    code = re.sub(pattern, "", code)
                    removed[desc] += count
        return code, removed


class StringCharEliminator:
    @staticmethod
    def eliminate(source: str) -> str:
        prev = None
        rounds = 0
        while prev != source and rounds < 10:
            prev = source
            source = StringCharEliminator._fold_simple(source)
            source = StringCharEliminator._fold_concat(source)
            source = StringCharEliminator._fold_in_table(source)
            source = StringCharEliminator._fold_escape_sequences(source)
            source = StringCharEliminator._fold_byte_string(source)
            source = StringCharEliminator._fold_chr_concat(source)
            rounds += 1
        return source

    @staticmethod
    def _fold_simple(source: str) -> str:
        def repl(m):
            try:
                nums = [int(x.strip()) for x in m.group(1).split(",") if x.strip()]
                if not nums or any(n < 0 or n > 255 for n in nums):
                    return m.group(0)
                chars = "".join(chr(n) for n in nums)
                if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in chars):
                    esc = chars.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
                    return '"' + esc + '"'
            except Exception:
                pass
            return m.group(0)
        return re.sub(r"string\.char\(\s*((?:\d+\s*,\s*)*\d+)\s*\)", repl, source)

    @staticmethod
    def _fold_concat(source: str) -> str:
        pattern = re.compile(r"(?:string\.char\(\s*\d+\s*\)\s*\.\.\s*)+string\.char\(\s*\d+\s*\)")
        def repl(m):
            nums = re.findall(r"string\.char\(\s*(\d+)\s*\)", m.group(0))
            try:
                chars = "".join(chr(int(n) & 0xFF) for n in nums)
                if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in chars):
                    esc = chars.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
                    return '"' + esc + '"'
            except Exception:
                pass
            return m.group(0)
        return pattern.sub(repl, source)

    @staticmethod
    def _fold_in_table(source: str) -> str:
        def repl(m):
            inner = m.group(1)
            if "string.char" not in inner:
                return m.group(0)
            def sub_repl(sm):
                nums = [int(x.strip()) for x in sm.group(1).split(",") if x.strip()]
                if not nums or any(n < 0 or n > 255 for n in nums):
                    return sm.group(0)
                chars = "".join(chr(n) for n in nums)
                if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in chars):
                    esc = chars.replace("\\", "\\\\").replace('"', '\\"')
                    return '"' + esc + '"'
                return sm.group(0)
            return "{" + re.sub(r"string\.char\(\s*((?:\d+\s*,\s*)*\d+)\s*\)", sub_repl, inner) + "}"
        return re.sub(r"\{([^{}]*string\.char[^{}]*)\}", repl, source)

    @staticmethod
    def _fold_escape_sequences(source: str) -> str:
        def repl(m):
            content = m.group(1)
            if len(re.findall(r"\\\d{1,3}", content)) < 4:
                return m.group(0)
            def sub_repl(sm):
                n = int(sm.group(1))
                if 32 <= n < 127:
                    return chr(n)
                return sm.group(0)
            decoded = re.sub(r"\\(\d{1,3})", sub_repl, content)
            if decoded != content and "\\" not in decoded:
                return '"' + decoded + '"'
            return m.group(0)
        return re.sub(r'"((?:\\\d{1,3}){4,})"', repl, source)

    @staticmethod
    def _fold_byte_string(source: str) -> str:
        def repl(m):
            try:
                raw = m.group(1)
                hexes = re.findall(r"\\x([0-9a-fA-F]{2})", raw)
                if not hexes or len(hexes) < 4:
                    return m.group(0)
                chars = "".join(chr(int(h, 16)) for h in hexes)
                if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in chars):
                    esc = chars.replace("\\", "\\\\").replace('"', '\\"')
                    return '"' + esc + '"'
            except Exception:
                pass
            return m.group(0)
        return re.sub(r'"((?:\\x[0-9a-fA-F]{2}){4,})"', repl, source)

    @staticmethod
    def _fold_chr_concat(source: str) -> str:
        def repl(m):
            return m.group(1) + m.group(2)
        prev = None
        rounds = 0
        while prev != source and rounds < 4:
            prev = source
            source = re.sub(r'("(?:[^"\\]|\\.)*")\s*\.\.\s*("(?:[^"\\]|\\.)*")', repl, source)
            rounds += 1
        return source


class JunkCodeEliminator:
    def __init__(self, source: str):
        self.source = source

    def eliminate(self) -> str:
        src = self.source
        prev = None
        rounds = 0
        while prev != src and rounds < 8:
            prev = src
            src = self._remove_empty_functions(src)
            src = self._remove_self_assignments(src)
            src = self._remove_never_true(src)
            src = self._remove_always_true(src)
            src = self._remove_dead_loops(src)
            src = self._remove_noop_ops(src)
            src = self._remove_unused_locals(src)
            src = self._remove_redundant_blocks(src)
            src = self._remove_nil_assigns(src)
            src = self._remove_double_negation(src)
            src = self._remove_redundant_parens(src)
            rounds += 1
        return src

    def _remove_empty_functions(self, src: str) -> str:
        src = re.sub(r"local\s+function\s+\w+\s*\(\s*\)\s*\n?\s*end\s*\n?", "", src)
        src = re.sub(r"local\s+\w+\s*=\s*function\s*\([^)]*\)\s*\n?\s*end\s*\n?", "", src)
        return src

    def _remove_self_assignments(self, src: str) -> str:
        src = re.sub(r"^\s*(\w+)\s*=\s*\1\s*;?\s*\n", "", src, flags=re.MULTILINE)
        src = re.sub(r"(\w+)\s*=\s*\1\s*;", "", src)
        return src

    def _remove_never_true(self, src: str) -> str:
        patterns = [
            r"if\s+nil\s+then[\s\S]*?\bend\b",
            r"if\s+false\s+then[\s\S]*?\bend\b",
            r"if\s+0\s*==\s*1\s+then[\s\S]*?\bend\b",
            r"if\s+1\s*==\s*0\s+then[\s\S]*?\bend\b",
            r"if\s+not\s+true\s+then[\s\S]*?\bend\b",
            r'if\s+""\s+then[\s\S]*?\bend\b',
            r"if\s+\(\s*nil\s*\)\s+then[\s\S]*?\bend\b",
            r"if\s+\(\s*false\s*\)\s+then[\s\S]*?\bend\b",
            r"if\s+0\s+then[\s\S]*?\bend\b",
        ]
        for p in patterns:
            src = re.sub(p, "", src, flags=re.DOTALL)
        return src

    def _remove_always_true(self, src: str) -> str:
        patterns = [
            r"if\s+true\s+then([\s\S]*?)\bend\b",
            r"if\s+1\s*==\s*1\s+then([\s\S]*?)\bend\b",
            r"if\s+not\s+nil\s+then([\s\S]*?)\bend\b",
            r"if\s+not\s+false\s+then([\s\S]*?)\bend\b",
            r"if\s+\(\s*true\s*\)\s+then([\s\S]*?)\bend\b",
        ]
        for p in patterns:
            src = re.sub(p, r"\1", src, flags=re.DOTALL)
        return src

    def _remove_dead_loops(self, src: str) -> str:
        src = re.sub(r"while\s+false\s+do[\s\S]*?\bend\b", "", src, flags=re.DOTALL)
        src = re.sub(r"while\s+nil\s+do[\s\S]*?\bend\b", "", src, flags=re.DOTALL)
        src = re.sub(r"while\s+0\s+do[\s\S]*?\bend\b", "", src, flags=re.DOTALL)
        src = re.sub(r"for\s+\w+\s*=\s*1\s*,\s*0\s+do[\s\S]*?\bend\b", "", src, flags=re.DOTALL)
        src = re.sub(r"for\s+\w+\s*=\s*1\s*,\s*-1\s+do[\s\S]*?\bend\b", "", src, flags=re.DOTALL)
        return src

    def _remove_noop_ops(self, src: str) -> str:
        src = re.sub(r"(\w+)\s*=\s*\1\s*\.\.\s*[\"'][\"']", r"\1 = \1", src)
        src = re.sub(r"(\w+)\s*=\s*\1\s*\+\s*0\b(?!\d)", r"\1 = \1", src)
        src = re.sub(r"(\w+)\s*=\s*\1\s*-\s*0\b(?!\d)", r"\1 = \1", src)
        src = re.sub(r"(\w+)\s*=\s*\1\s*\*\s*1\b(?!\d)", r"\1 = \1", src)
        src = re.sub(r"(\w+)\s*=\s*\1\s*\/\s*1\b(?!\d)", r"\1 = \1", src)
        src = re.sub(r"(\w+)\s*=\s*\1\s*\^\s*1\b(?!\d)", r"\1 = \1", src)
        src = re.sub(r"(\w+)\s*=\s*\1\s*and\s*true\b", r"\1 = \1", src)
        src = re.sub(r"(\w+)\s*=\s*\1\s*or\s*false\b", r"\1 = \1", src)
        return src

    def _remove_unused_locals(self, src: str) -> str:
        for _ in range(3):
            decls = list(re.finditer(r"local\s+(\w+)\s*=\s*[^\n;]+", src))
            for m in reversed(decls):
                name = m.group(1)
                before = src[:m.start()]
                after = src[m.end():]
                stripped = before.rstrip()
                if stripped.endswith("local function") or "local function" in src[max(0, m.start() - 8):m.start() + 20]:
                    continue
                if not re.search(r"\b" + re.escape(name) + r"\b", after):
                    end = m.end()
                    if end < len(src) and src[end] == "\n":
                        end += 1
                    src = src[:m.start()] + src[end:]
        return src

    def _remove_redundant_blocks(self, src: str) -> str:
        src = re.sub(r"\bdo\s+(local\s+[^\n]+)\s+end\b", r"\1", src)
        src = re.sub(r"\bdo\s+end\b", "", src)
        src = re.sub(r"\bthen\s+do\s+end\s+end\b", "then end", src)
        return src

    def _remove_nil_assigns(self, src: str) -> str:
        src = re.sub(r"^\s*local\s+\w+\s*=\s*nil\s*;?\s*\n", "", src, flags=re.MULTILINE)
        return src

    def _remove_double_negation(self, src: str) -> str:
        src = re.sub(r"not\s+not\s+(\w+)", r"\1", src)
        src = re.sub(r"not\s+\(\s*not\s+(\w+)\s*\)", r"\1", src)
        return src

    def _remove_redundant_parens(self, src: str) -> str:
        prev = None
        rounds = 0
        while prev != src and rounds < 4:
            prev = src
            src = re.sub(r"\(\((\w+)\)\)", r"(\1)", src)
            src = re.sub(r"\(\s*(\w+)\s*\)", r"\1", src)
            rounds += 1
        return src


class VMOpcodeSemantics:
    NOP = "nop"
    MOVE = "move"
    LOADK = "loadk"
    LOADBOOL = "loadbool"
    LOADNIL = "loadnil"
    GETUPVAL = "getupval"
    SETUPVAL = "setupval"
    GETGLOBAL = "getglobal"
    SETGLOBAL = "setglobal"
    GETTABLE = "gettable"
    SETTABLE = "settable"
    NEWTABLE = "newtable"
    SELF = "self"
    ADD = "add"
    SUB = "sub"
    MUL = "mul"
    DIV = "div"
    MOD = "mod"
    POW = "pow"
    IDIV = "idiv"
    BAND = "band"
    BOR = "bor"
    BXOR = "bxor"
    SHL = "shl"
    SHR = "shr"
    UNM = "unm"
    NOT = "not"
    LEN = "len"
    BNOT = "bnot"
    CONCAT = "concat"
    JMP = "jmp"
    EQ = "eq"
    LT = "lt"
    LE = "le"
    TEST = "test"
    TESTSET = "testset"
    CALL = "call"
    TAILCALL = "tailcall"
    RETURN = "return"
    FORLOOP = "forloop"
    FORPREP = "forprep"
    TFORLOOP = "tforloop"
    TFORPREP = "tforprep"
    SETLIST = "setlist"
    CLOSE = "close"
    CLOSURE = "closure"
    VARARG = "vararg"
    CONCAT_MULTI = "concat_multi"


VM_OPCODE_ALIASES: Dict[str, str] = {
    "OP_MOVE": VMOpcodeSemantics.MOVE,
    "OP_LOADK": VMOpcodeSemantics.LOADK,
    "OP_LOADKX": VMOpcodeSemantics.LOADK,
    "OP_LOADBOOL": VMOpcodeSemantics.LOADBOOL,
    "OP_LOADNIL": VMOpcodeSemantics.LOADNIL,
    "OP_GETUPVAL": VMOpcodeSemantics.GETUPVAL,
    "OP_SETUPVAL": VMOpcodeSemantics.SETUPVAL,
    "OP_GETGLOBAL": VMOpcodeSemantics.GETGLOBAL,
    "OP_SETGLOBAL": VMOpcodeSemantics.SETGLOBAL,
    "OP_GETTABUP": VMOpcodeSemantics.GETTABLE,
    "OP_SETTABUP": VMOpcodeSemantics.SETTABLE,
    "OP_GETTABLE": VMOpcodeSemantics.GETTABLE,
    "OP_SETTABLE": VMOpcodeSemantics.SETTABLE,
    "OP_NEWTABLE": VMOpcodeSemantics.NEWTABLE,
    "OP_SELF": VMOpcodeSemantics.SELF,
    "OP_ADD": VMOpcodeSemantics.ADD,
    "OP_SUB": VMOpcodeSemantics.SUB,
    "OP_MUL": VMOpcodeSemantics.MUL,
    "OP_DIV": VMOpcodeSemantics.DIV,
    "OP_MOD": VMOpcodeSemantics.MOD,
    "OP_POW": VMOpcodeSemantics.POW,
    "OP_IDIV": VMOpcodeSemantics.IDIV,
    "OP_BAND": VMOpcodeSemantics.BAND,
    "OP_BOR": VMOpcodeSemantics.BOR,
    "OP_BXOR": VMOpcodeSemantics.BXOR,
    "OP_SHL": VMOpcodeSemantics.SHL,
    "OP_SHR": VMOpcodeSemantics.SHR,
    "OP_UNM": VMOpcodeSemantics.UNM,
    "OP_NOT": VMOpcodeSemantics.NOT,
    "OP_LEN": VMOpcodeSemantics.LEN,
    "OP_BNOT": VMOpcodeSemantics.BNOT,
    "OP_CONCAT": VMOpcodeSemantics.CONCAT,
    "OP_JMP": VMOpcodeSemantics.JMP,
    "OP_EQ": VMOpcodeSemantics.EQ,
    "OP_LT": VMOpcodeSemantics.LT,
    "OP_LE": VMOpcodeSemantics.LE,
    "OP_TEST": VMOpcodeSemantics.TEST,
    "OP_TESTSET": VMOpcodeSemantics.TESTSET,
    "OP_CALL": VMOpcodeSemantics.CALL,
    "OP_TAILCALL": VMOpcodeSemantics.TAILCALL,
    "OP_RETURN": VMOpcodeSemantics.RETURN,
    "OP_FORLOOP": VMOpcodeSemantics.FORLOOP,
    "OP_FORPREP": VMOpcodeSemantics.FORPREP,
    "OP_TFORLOOP": VMOpcodeSemantics.TFORLOOP,
    "OP_TFORCALL": VMOpcodeSemantics.TFORLOOP,
    "OP_SETLIST": VMOpcodeSemantics.SETLIST,
    "OP_CLOSE": VMOpcodeSemantics.CLOSE,
    "OP_CLOSURE": VMOpcodeSemantics.CLOSURE,
    "OP_VARARG": VMOpcodeSemantics.VARARG,
    "OP_EXTRAARG": VMOpcodeSemantics.NOP,
}


VM_PATTERN_TABLE: List[Tuple[str, List[str], float, int]] = [
    (VMOpcodeSemantics.MOVE, [
        r"\bR[A-Z]\s*=\s*R[A-Z]\b",
        r"\bStack\[A\]\s*=\s*Stack\[B\]",
        r"\bReg\[A\]\s*=\s*Reg\[B\]",
        r"\b[A-Z]\s*=\s*[A-Z]\s*;?\s*$",
        r"\bvm_reg\[A\]\s*=\s*vm_reg\[B\]",
    ], 0.90, 0),
    (VMOpcodeSemantics.LOADK, [
        r"Stack\[A\]\s*=\s*Const(?:ant)?s?\[B(?:x)?\]",
        r"Reg\[A\]\s*=\s*K\[B(?:x)?\]",
        r"Reg\[A\]\s*=\s*Constants\[",
        r"\b[A-Z]\s*=\s*K\[",
        r"\bR\[A\]\s*=\s*K\[",
        r"\bConstants\[\w+\]",
        r"\bconst\s*\[\s*\w+\s*\]",
    ], 0.85, 0),
    (VMOpcodeSemantics.LOADBOOL, [
        r"\bStack\[A\]\s*=\s*(?:true|false)",
        r"\bReg\[A\]\s*=\s*(?:true|false)",
        r"=\s*true\b",
        r"=\s*false\b",
    ], 0.80, 0),
    (VMOpcodeSemantics.LOADNIL, [
        r"\bStack\[A\]\s*=\s*nil",
        r"\bReg\[A\]\s*=\s*nil",
        r"=\s*nil\b",
        r"\bnil\s*;?\s*$",
    ], 0.75, 0),
    (VMOpcodeSemantics.GETUPVAL, [
        r"[Uu]pval(?:ue)?s?\[",
        r"\bUpValue\[",
        r"\bupval\b",
    ], 0.85, 0),
    (VMOpcodeSemantics.SETUPVAL, [
        r"[Uu]pval(?:ue)?s?\[[^\]]+\]\s*=",
        r"\bUpValue\[[^\]]+\]\s*=",
    ], 0.85, 0),
    (VMOpcodeSemantics.GETGLOBAL, [
        r"_ENV\[",
        r"getfenv\s*\(",
        r"getglobal\s*\(",
        r"_G\[",
    ], 0.80, 0),
    (VMOpcodeSemantics.SETGLOBAL, [
        r"_ENV\[[^\]]+\]\s*=",
        r"_G\[[^\]]+\]\s*=",
    ], 0.80, 0),
    (VMOpcodeSemantics.GETTABLE, [
        r"Stack\[A\]\s*=\s*Stack\[B\]\[",
        r"Reg\[A\]\s*=\s*Reg\[B\]\[",
        r"gettable\s*\(",
        r"\.\s*gettable",
    ], 0.88, 0),
    (VMOpcodeSemantics.SETTABLE, [
        r"Stack\[A\]\[[^\]]+\]\s*=",
        r"Reg\[A\]\[[^\]]+\]\s*=",
        r"settable\s*\(",
    ], 0.88, 0),
    (VMOpcodeSemantics.NEWTABLE, [
        r"Stack\[A\]\s*=\s*\{\s*\}",
        r"Reg\[A\]\s*=\s*\{\s*\}",
        r"newtable",
        r"table\.create",
    ], 0.85, 0),
    (VMOpcodeSemantics.SELF, [
        r"\bself\b",
        r"Stack\[A\]\s*=\s*Stack\[B\]\[[^\]]+\]\s*;?\s*Stack\[A\+1\]\s*=",
        r"method",
    ], 0.75, 0),
    (VMOpcodeSemantics.ADD, [
        r"Stack\[A\]\s*=\s*Stack\[B\]\s*\+\s*Stack\[C\]",
        r"Reg\[A\]\s*=\s*Reg\[B\]\s*\+\s*Reg\[C\]",
        r"\bArith(?:metic)?\s*\(\s*['\"]\+",
        r"op\s*==\s*['\"]\+",
        r"case\s*['\"]\+",
        r"op\s*=\s*['\"]\+",
        r"\badd\b",
    ], 0.92, -1),
    (VMOpcodeSemantics.SUB, [
        r"Stack\[A\]\s*=\s*Stack\[B\]\s*-\s*Stack\[C\]",
        r"Reg\[A\]\s*=\s*Reg\[B\]\s*-\s*Reg\[C\]",
        r"\bArith(?:metic)?\s*\(\s*['\"]-",
        r"op\s*==\s*['\"]-",
        r"case\s*['\"]-",
        r"\bsub\b",
    ], 0.92, -1),
    (VMOpcodeSemantics.MUL, [
        r"Stack\[A\]\s*=\s*Stack\[B\]\s*\*\s*Stack\[C\]",
        r"Reg\[A\]\s*=\s*Reg\[B\]\s*\*\s*Reg\[C\]",
        r"\bArith(?:metic)?\s*\(\s*['\"]\*",
        r"op\s*==\s*['\"]\*",
        r"case\s*['\"]\*",
        r"\bmul\b",
    ], 0.92, -1),
    (VMOpcodeSemantics.DIV, [
        r"Stack\[A\]\s*=\s*Stack\[B\]\s*/\s*Stack\[C\]",
        r"Reg\[A\]\s*=\s*Reg\[B\]\s*/\s*Reg\[C\]",
        r"\bArith(?:metic)?\s*\(\s*['\"]/",
        r"op\s*==\s*['\"]/",
        r"case\s*['\"]/",
        r"\bdiv\b",
    ], 0.92, -1),
    (VMOpcodeSemantics.MOD, [
        r"Stack\[A\]\s*=\s*Stack\[B\]\s*%\s*Stack\[C\]",
        r"Reg\[A\]\s*=\s*Reg\[B\]\s*%\s*Reg\[C\]",
        r"\bArith(?:metic)?\s*\(\s*['\"]%",
        r"op\s*==\s*['\"]%",
        r"\bmod\b",
    ], 0.92, -1),
    (VMOpcodeSemantics.POW, [
        r"Stack\[A\]\s*=\s*Stack\[B\]\s*\^\s*Stack\[C\]",
        r"Reg\[A\]\s*=\s*Reg\[B\]\s*\^\s*Reg\[C\]",
        r"\bArith(?:metic)?\s*\(\s*['\"]\^",
        r"\bpow\b",
        r"math\.pow",
    ], 0.92, -1),
    (VMOpcodeSemantics.UNM, [
        r"Stack\[A\]\s*=\s*-\s*Stack\[B\]",
        r"Reg\[A\]\s*=\s*-\s*Reg\[B\]",
        r"\bunm\b",
        r"unary\s*-",
    ], 0.88, 0),
    (VMOpcodeSemantics.NOT, [
        r"Stack\[A\]\s*=\s*not\s+Stack",
        r"Reg\[A\]\s*=\s*not\s+Reg",
        r"\bnot\s+Reg",
        r"\bnot\s+Stack",
    ], 0.88, 0),
    (VMOpcodeSemantics.LEN, [
        r"Stack\[A\]\s*=\s*#\s*Stack",
        r"Reg\[A\]\s*=\s*#\s*Reg",
        r"#\s*Stack\[",
        r"#\s*Reg\[",
    ], 0.88, 0),
    (VMOpcodeSemantics.CONCAT, [
        r"\.\.\s*Stack",
        r"\.\.\s*Reg",
        r"stack_concat",
        r"table\.concat",
        r"concat\s*\(",
    ], 0.85, -1),
    (VMOpcodeSemantics.JMP, [
        r"\bPC\s*=\s*PC\s*[+\-]",
        r"\bPC\s*=\s*\w+\s*[+\-]",
        r"\bIP\s*=\s*IP\s*[+\-]",
        r"\bpc\s*=\s*pc\s*[+\-]",
        r"goto\s+",
        r"\bJump\s*\(",
        r"\bjmp\b",
    ], 0.90, 0),
    (VMOpcodeSemantics.EQ, [
        r"Stack\[B\]\s*==\s*Stack\[C\]",
        r"Reg\[B\]\s*==\s*Reg\[C\]",
        r"\beq\b",
        r"compare\s*==",
        r"operator\s*==\s*['\"]==",
    ], 0.85, 0),
    (VMOpcodeSemantics.LT, [
        r"Stack\[B\]\s*<\s*Stack\[C\]",
        r"Reg\[B\]\s*<\s*Reg\[C\]",
        r"\blt\b",
        r"operator\s*==\s*['\"]<",
    ], 0.85, 0),
    (VMOpcodeSemantics.LE, [
        r"Stack\[B\]\s*<=\s*Stack\[C\]",
        r"Reg\[B\]\s*<=\s*Reg\[C\]",
        r"\ble\b",
        r"operator\s*==\s*['\"]<=",
    ], 0.85, 0),
    (VMOpcodeSemantics.TEST, [
        r"\bTEST\b",
        r"\btest\s*\(",
        r"\bTest\s*\(",
    ], 0.80, 0),
    (VMOpcodeSemantics.TESTSET, [
        r"\bTESTSET\b",
        r"\btestset\s*\(",
    ], 0.80, 0),
    (VMOpcodeSemantics.CALL, [
        r"\bStack\[A\]\s*\(.*\)",
        r"\bReg\[A\]\s*\(.*\)",
        r"\bCall\s*\(",
        r"\bcall\s*\(",
        r"\bpcall\s*\(",
    ], 0.85, -1),
    (VMOpcodeSemantics.TAILCALL, [
        r"return\s+Stack\[A\]\s*\(",
        r"return\s+Reg\[A\]\s*\(",
        r"tailcall",
        r"TailCall",
    ], 0.90, 0),
    (VMOpcodeSemantics.RETURN, [
        r"\breturn\b",
        r"\bRETURN\b",
    ], 0.80, 0),
    (VMOpcodeSemantics.FORLOOP, [
        r"FORLOOP",
        r"forloop",
        r"Stack\[A\]\s*=\s*Stack\[A\]\s*\+\s*Stack\[A\+2\]",
        r"numeric\s*for",
        r"step.*loop",
    ], 0.90, 0),
    (VMOpcodeSemantics.FORPREP, [
        r"FORPREP",
        r"forprep",
        r"Stack\[A\]\s*=\s*Stack\[A\]\s*-\s*Stack\[A\+2\]",
    ], 0.90, 0),
    (VMOpcodeSemantics.TFORLOOP, [
        r"TFORLOOP",
        r"tforloop",
        r"generic\s*for",
    ], 0.85, 0),
    (VMOpcodeSemantics.SETLIST, [
        r"SETLIST",
        r"setlist",
        r"list\s*assign",
    ], 0.85, 0),
    (VMOpcodeSemantics.CLOSE, [
        r"\bCLOSE\b",
        r"\bclose\s*\(",
        r"close\s*upvals?",
    ], 0.80, 0),
    (VMOpcodeSemantics.CLOSURE, [
        r"CLOSURE",
        r"closure",
        r"Proto(?:type)?s?\[",
    ], 0.88, 0),
    (VMOpcodeSemantics.VARARG, [
        r"VARARG",
        r"vararg",
        r"\.\.\.",
    ], 0.75, 0),
]


@dataclass
class VMInstruction:
    opcode: int
    A: int = 0
    B: int = 0
    C: int = 0
    Bx: int = 0
    sBx: int = 0
    raw: int = 0
    semantic: Optional[str] = None
    confidence: float = 0.0
    index: int = 0

    def __str__(self):
        tag = self.semantic or f"OP_{self.opcode}"
        return f"{tag}(A={self.A}, B={self.B}, C={self.C}, Bx={self.Bx}, sBx={self.sBx})"


@dataclass
class VMHandlerInfo:
    case_num: int
    raw_text: str = ""
    semantic: Optional[str] = None
    confidence: float = 0.0
    reads: List[int] = field(default_factory=list)
    writes: List[int] = field(default_factory=list)
    const_refs: List[int] = field(default_factory=list)
    upvalue_refs: List[int] = field(default_factory=list)
    jump_delta: Optional[int] = None
    is_jump: bool = False
    is_call: bool = False
    is_return: bool = False
    is_conditional: bool = False
    stack_effect: int = 0
    reads_a: bool = False
    reads_b: bool = False
    reads_c: bool = False
    writes_a: bool = False
    uses_const_b: bool = False
    uses_const_c: bool = False
    uses_bx: bool = False
    uses_sbx: bool = False
    offset_start: int = 0
    offset_end: int = 0

    def __repr__(self):
        return f"VMHandlerInfo(case={self.case_num}, sem={self.semantic}, conf={self.confidence:.2f})"


class VMSplitter:
    def __init__(self, source: str):
        self.source = source
        self.n = len(source)
        self.instruction_array: Optional[str] = None
        self.instruction_array_name: Optional[str] = None
        self.instruction_array_body: Optional[str] = None
        self.instruction_arrays: List[Dict[str, Any]] = []
        self.constant_pool: Optional[str] = None
        self.constant_pool_name: Optional[str] = None
        self.constant_pools: List[Dict[str, Any]] = []
        self.dispatcher: Optional[str] = None
        self.dispatchers: List[Dict[str, Any]] = []
        self.handlers: Dict[int, str] = {}
        self.handler_infos: Dict[int, VMHandlerInfo] = {}
        self.handler_offsets: Dict[int, Tuple[int, int]] = {}
        self.handler_function_name: Optional[str] = None
        self.pc_var: Optional[str] = None
        self.stack_var: Optional[str] = None
        self.const_var: Optional[str] = None
        self.opcode_var: Optional[str] = None
        self.instr_var: Optional[str] = None
        self.reg_var: Optional[str] = None
        self.jump_graph: Dict[int, List[int]] = {}
        self.register_reads: Dict[int, List[int]] = {}
        self.register_writes: Dict[int, List[int]] = {}
        self.const_refs: Dict[int, List[int]] = {}
        self.opcode_map: Dict[int, str] = {}
        self.decode_loop: Optional[str] = None
        self.case_table: Optional[str] = None
        self.matcher = BracketMatcher(source)
        self.vm_register_convention: Dict[str, str] = {}
        self.instruction_word_size: int = 4
        self.instruction_endian: str = "little"
        self.opcode_bit_width: int = 6
        self.opcode_shift: int = 0
        self.a_shift: int = 6
        self.a_width: int = 8
        self.b_shift: int = 23
        self.b_width: int = 9
        self.c_shift: int = 14
        self.c_width: int = 9

    def split(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        self._detect_vm_vars()
        self._find_instruction_arrays(result)
        self._find_constant_pools(result)
        self._find_decode_loops(result)
        self._find_case_tables(result)
        self._find_dispatchers(result)
        self._detect_instruction_word_size()
        if self.dispatchers:
            self._extract_all_handlers()
            self._analyze_handler_flow()
            self._infer_opcode_map()
            self._infer_register_convention()
        result["handler_count"] = len(self.handlers)
        result["dispatcher_count"] = len(self.dispatchers)
        result["handlers"] = sorted(self.handlers.keys())
        result["pc_var"] = self.pc_var
        result["stack_var"] = self.stack_var
        result["const_var"] = self.const_var
        result["opcode_var"] = self.opcode_var
        result["instr_var"] = self.instr_var
        result["reg_var"] = self.reg_var
        result["jump_graph"] = self.jump_graph
        result["opcode_map"] = self.opcode_map
        result["register_reads"] = self.register_reads
        result["register_writes"] = self.register_writes
        result["constant_refs"] = self.const_refs
        result["instruction_arrays"] = [a.get("name") for a in self.instruction_arrays]
        result["constant_pools"] = [p.get("name") for p in self.constant_pools]
        result["register_convention"] = self.vm_register_convention
        result["word_size"] = self.instruction_word_size
        result["endian"] = self.instruction_endian
        result["opcode_bits"] = {
            "opcode_width": self.opcode_bit_width,
            "opcode_shift": self.opcode_shift,
            "a_shift": self.a_shift,
            "a_width": self.a_width,
            "b_shift": self.b_shift,
            "b_width": self.b_width,
            "c_shift": self.c_shift,
            "c_width": self.c_width,
        }
        return result

    def _detect_instruction_word_size(self):
        widths = [4, 8, 2, 1]
        for w in widths:
            if re.search(rf"byte\s*\(\s*\w+\s*,\s*\w+\s*\+\s*{w}\b", self.source):
                self.instruction_word_size = w
                return
            if re.search(rf">>\s*{8 * w}\b", self.source):
                self.instruction_word_size = w
                return
        if re.search(r"byte\s*\(\s*\w+\s*,\s*\w+\s*\+\s*3", self.source):
            self.instruction_word_size = 4
        if re.search(r"bit32\.(band|bor|bxor|rshift|lshift)\b", self.source):
            self.instruction_word_size = 4
        self._infer_opcode_bit_layout()

    def _infer_opcode_bit_layout(self):
        m = re.search(r"bit32\.rshift\s*\(\s*\w+\s*,\s*(\d+)\s*\)\s*,?\s*(\d+)", self.source)
        if m:
            self.opcode_shift = int(m.group(1))
            self.opcode_bit_width = int(m.group(2))
        m2 = re.search(r"%\s*(\d+)", self.source)
        if m2:
            try:
                mask = int(m2.group(1))
                if 0 < mask <= 0xFFFF:
                    self.opcode_bit_width = max(1, mask.bit_length() - 1)
            except Exception:
                pass

    def _detect_vm_vars(self):
        pc_patterns = [
            r"local\s+(\w+)\s*=\s*1\s*;?\s*while\s+true\s+do",
            r"local\s+(\w+)\s*=\s*1\s*;?\s*while\s+\w+\s*<",
            r"local\s+(\w+)\s*=\s*1\s*;?\s*repeat",
            r"local\s+(\w+)\s*=\s*1\s*;?\s*for\s+\w+\s*=\s*1\s*,\s*#",
            r"local\s+(\w+)\s*=\s*0\s*;?\s*while\s+\w+\s*<",
            r"local\s+(\w+)\s*=\s*0\s*;?\s*repeat",
            r"\b(?:local\s+)?(\w+)\s*=\s*1\s*while\s+\1\s*<=",
        ]
        for p in pc_patterns:
            m = re.search(p, self.source, re.DOTALL)
            if m:
                self.pc_var = m.group(1)
                break

        stack_patterns = [
            r"local\s+(\w+)\s*=\s*\{\s*\}[\s\S]{0,400}?local\s+\w+\s*=\s*1",
            r"local\s+(\w+)\s*=\s*\{\s*\}[\s\S]{0,400}?while",
            r"local\s+(\w+)\s*=\s*\{\s*\}\s*local\s+\w+\s*=\s*\{",
            r"local\s+(\w+)\s*=\s*\{\s*\}\s*for\s+\w+\s*=",
            r"local\s+(\w+)\s*=\s*\{\s*\}\s*local\s+(\w+)\s*=\s*1",
        ]
        for p in stack_patterns:
            m = re.search(p, self.source, re.DOTALL)
            if m:
                self.stack_var = m.group(1)
                break

        const_patterns = [
            r"local\s+(\w+)\s*=\s*\{[^}]{80,}\}\s*;?\s*local\s+\w+\s*=\s*1",
            r"local\s+(\w+)\s*=\s*\{[^}]{80,}\}\s*;?\s*local\s+\w+\s*=\s*\{\s*\}",
            r"local\s+(\w+)\s*=\s*\{[^}]{80,}\}\s*;?\s*for\s+\w+\s*=",
        ]
        for p in const_patterns:
            m = re.search(p, self.source, re.DOTALL)
            if m:
                self.const_var = m.group(1)
                break

        op_patterns = [
            r"local\s+(\w+)\s*=\s*\w+\[(\w+)\]\s*;?\s*(?:repeat|while|for)",
            r"for\s+\w+\s*=\s*1\s*,\s*#\w+\s+do\s*local\s+(\w+)\s*=",
            r"local\s+(\w+)\s*=\s*\w+\s*%\s*\d+\s*;?\s*(?:if|repeat|while)",
        ]
        for p in op_patterns:
            m = re.search(p, self.source, re.DOTALL)
            if m:
                self.opcode_var = m.group(1)
                break

        reg_pat = re.search(r"\b(?:Reg|R|Register)\s*\[", self.source)
        if reg_pat:
            self.reg_var = reg_pat.group(0).rstrip("[").strip()

    def _find_instruction_arrays(self, result: Dict[str, Any]):
        candidates: List[Dict[str, Any]] = []
        for m in re.finditer(r"local\s+(\w+)\s*=\s*\{", self.source):
            name = m.group(1)
            brace_start = m.end() - 1
            brace_end = self.matcher.match_brace(brace_start)
            if brace_end <= brace_start:
                continue
            body = self.source[brace_start + 1:brace_end]
            nums = re.findall(r"\b\d+\b|0x[0-9a-fA-F]+", body)
            if len(nums) < 20:
                continue
            numeric_count = 0
            for tok in nums:
                try:
                    v = int(tok, 0)
                    if 0 <= v <= 0xFFFFFFFF:
                        numeric_count += 1
                except Exception:
                    pass
            if numeric_count < 20:
                continue
            depth = body.count("{")
            non_numeric = len(body) - sum(len(n) for n in nums)
            hex_count = len(re.findall(r"0x[0-9a-fA-F]+", body))
            candidates.append({
                "name": name,
                "start": brace_start,
                "end": brace_end,
                "body": body,
                "size": numeric_count,
                "depth": depth,
                "text": m.group(0) + body + "}",
                "surplus": non_numeric,
                "hex_count": hex_count,
            })
        candidates.sort(key=lambda c: (-c["size"], c["surplus"]))
        self.instruction_arrays = candidates[:8]
        if candidates:
            self.instruction_array = candidates[0]["text"]
            self.instruction_array_name = candidates[0]["name"]
            self.instruction_array_body = candidates[0]["body"]
            self.instr_var = candidates[0]["name"]
            result["instruction_array"] = candidates[0]["text"]
            result["instruction_array_name"] = candidates[0]["name"]
            result["instruction_array_size"] = candidates[0]["size"]

    def _find_constant_pools(self, result: Dict[str, Any]):
        candidates: List[Dict[str, Any]] = []
        for m in re.finditer(r"local\s+(\w+)\s*=\s*\{", self.source):
            name = m.group(1)
            brace_start = m.end() - 1
            brace_end = self.matcher.match_brace(brace_start)
            if brace_end <= brace_start:
                continue
            body = self.source[brace_start + 1:brace_end]
            if len(body) < 200:
                continue
            commas = body.count(",")
            strings = len(re.findall(r'"[^"]*"|\'[^\']*\'', body))
            numbers = len(re.findall(r"\b\d+\b|0x[0-9a-fA-F]+", body))
            nested = body.count("{")
            if name == self.instruction_array_name:
                continue
            score = strings * 3 + commas + nested * 2
            if score < 40 and numbers < 40:
                continue
            candidates.append({
                "name": name,
                "start": brace_start,
                "end": brace_end,
                "body": body,
                "score": score,
                "size": len(body),
                "strings": strings,
                "numbers": numbers,
                "nested": nested,
                "text": m.group(0) + body + "}",
            })
        candidates.sort(key=lambda c: (-c["score"], -c["size"]))
        self.constant_pools = candidates[:10]
        if candidates:
            best = candidates[0]
            self.constant_pool = best["text"]
            self.constant_pool_name = best["name"]
            self.const_var = self.const_var or best["name"]
            result["constant_pool"] = best["text"]
            result["constant_pool_name"] = best["name"]
            result["constant_pool_size"] = best["size"]
            result["constant_pool_strings"] = best["strings"]

    def _find_decode_loops(self, result: Dict[str, Any]):
        loop_patterns = [
            r"for\s+\w+\s*=\s*1\s*,\s*#\w+\s+do\s*[\s\S]{0,400}?end",
            r"for\s+\w+\s*=\s*1\s*,\s*#?\w+\s*-\s*1\s+do\s*[\s\S]{0,400}?end",
            r"while\s+\w+\s*<=\s*#\w+\s+do\s*[\s\S]{0,400}?end",
        ]
        best = None
        best_score = 0
        for p in loop_patterns:
            for m in re.finditer(p, self.source, re.DOTALL):
                body = m.group(0)
                if not re.search(r"\^|~|bit32\.|bit\.", body):
                    continue
                score = len(re.findall(r"\^|bit32\.|bit\.", body))
                if score > best_score:
                    best_score = score
                    best = body
        if best:
            self.decode_loop = best
            result["decode_loop"] = best
            result["decode_loop_xor_ops"] = best_score

    def _find_case_tables(self, result: Dict[str, Any]):
        for m in re.finditer(r"local\s+(\w+)\s*=\s*\{\s*\}\s*;?\s*[\w\s]*?(\w+)\[(\d+)\]\s*=\s*function", self.source, re.DOTALL):
            self.case_table = m.group(1)
            result["case_table"] = m.group(1)
            return

    def _find_dispatchers(self, result: Dict[str, Any]):
        candidates: List[Dict[str, Any]] = []
        for m in re.finditer(r"\bwhile\b", self.source):
            i = m.start()
            after = self.source[i:i + 400]
            if not re.search(r"while\s+(?:true|\w+\s*<|\w+\s*~=)[\s\S]{0,120}?\bdo\b", after):
                continue
            do_pos = re.search(r"\bdo\b", after)
            if not do_pos:
                continue
            block_end = self.matcher.find_block_end(i + do_pos.end())
            if block_end <= 0:
                continue
            body = self.source[i:block_end]
            branch_count = len(re.findall(r"\belseif\b", body))
            if_count = len(re.findall(r"\bif\b", body))
            if branch_count < 3 and if_count < 3:
                continue
            case_nums = re.findall(r"==\s*(0x[0-9a-fA-F]+|\d+)", body)
            unique_cases = set()
            for c in case_nums:
                try:
                    unique_cases.add(int(c, 0))
                except Exception:
                    pass
            candidates.append({
                "start": i,
                "end": block_end,
                "text": body,
                "branch_count": branch_count,
                "case_count": len(unique_cases),
                "cases": unique_cases,
            })

        for m in re.finditer(r"\brepeat\b", self.source):
            i = m.start()
            body_start = m.end()
            until_match = re.search(r"\buntil\b", self.source[body_start:body_start + 20000])
            if not until_match:
                continue
            body_end = body_start + until_match.start()
            body = self.source[body_start:body_end]
            branch_count = len(re.findall(r"\belseif\b", body))
            if_count = len(re.findall(r"\bif\b", body))
            if branch_count < 3 and if_count < 3:
                continue
            case_nums = re.findall(r"==\s*(0x[0-9a-fA-F]+|\d+)", body)
            unique_cases = set()
            for c in case_nums:
                try:
                    unique_cases.add(int(c, 0))
                except Exception:
                    pass
            candidates.append({
                "start": body_start,
                "end": body_end,
                "text": body,
                "branch_count": branch_count,
                "case_count": len(unique_cases),
                "cases": unique_cases,
            })

        for m in re.finditer(r"for\s+\w+\s*=\s*1\s*,\s*#\w+\s+do", self.source):
            i = m.start()
            do_pos = re.search(r"\bdo\b", self.source[i:i + 200])
            if not do_pos:
                continue
            block_end = self.matcher.find_block_end(i + do_pos.end())
            if block_end <= 0:
                continue
            body = self.source[i:block_end]
            branch_count = len(re.findall(r"\belseif\b", body))
            if_count = len(re.findall(r"\bif\b", body))
            if branch_count < 3 and if_count < 3:
                continue
            case_nums = re.findall(r"==\s*(0x[0-9a-fA-F]+|\d+)", body)
            unique_cases = set()
            for c in case_nums:
                try:
                    unique_cases.add(int(c, 0))
                except Exception:
                    pass
            candidates.append({
                "start": i,
                "end": block_end,
                "text": body,
                "branch_count": branch_count,
                "case_count": len(unique_cases),
                "cases": unique_cases,
            })

        candidates.sort(key=lambda c: (-c["case_count"], -c["branch_count"]))
        self.dispatchers = candidates[:6]
        if candidates:
            self.dispatcher = candidates[0]["text"]
            result["dispatcher"] = candidates[0]["text"]
            result["dispatcher_cases"] = candidates[0]["case_count"]
            result["dispatcher_branches"] = candidates[0]["branch_count"]

    def _extract_all_handlers(self):
        seen: Set[int] = set()
        for disp in self.dispatchers:
            body = disp["text"]
            self._extract_handlers_from_text(body, disp["start"])
        if self.handlers:
            self.handler_function_name = None

    def _extract_handlers_from_text(self, text: str, global_offset: int):
        i = 0
        n = len(text)
        while i < n:
            m = re.search(r"\b(if|elseif)\b", text[i:])
            if not m:
                break
            kw_start = i + m.start()
            kw = m.group(1)
            cond_start = kw_start + len(kw)
            eq_match = re.search(r"==\s*(0x[0-9a-fA-F]+|\d+)", text[cond_start:cond_start + 200])
            if not eq_match:
                i = kw_start + len(kw)
                continue
            num_str = eq_match.group(1)
            try:
                case_num = int(num_str, 0)
            except Exception:
                i = kw_start + len(kw)
                continue
            then_match = re.search(r"\bthen\b", text[cond_start:cond_start + 400])
            if not then_match:
                i = kw_start + len(kw)
                continue
            body_start = cond_start + then_match.end()
            depth = 0
            j = body_start
            end_pos = -1
            s = text
            while j < n:
                c = s[j]
                if c in "\"'":
                    j = self._skip_local_string(s, j)
                    continue
                if c == "-" and j + 1 < n and s[j + 1] == "-":
                    while j < n and s[j] != "\n":
                        j += 1
                    continue
                if c.isalpha() or c == "_":
                    ws = j
                    while j < n and (s[j].isalnum() or s[j] == "_"):
                        j += 1
                    w = s[ws:j]
                    if w in ("if", "for", "while", "function", "do", "repeat", "then"):
                        depth += 1
                    elif w in ("end", "until"):
                        if depth == 0:
                            end_pos = ws
                            break
                        depth -= 1
                        if depth == 0:
                            end_pos = ws
                            break
                    continue
                j += 1
            if end_pos < 0:
                i = kw_start + len(kw)
                continue
            handler_body = text[body_start:end_pos].strip()
            if case_num not in self.handlers or len(handler_body) > len(self.handlers.get(case_num, "")):
                self.handlers[case_num] = handler_body
                self.handler_offsets[case_num] = (global_offset + body_start, global_offset + end_pos)
            i = end_pos + 3

    @staticmethod
    def _skip_local_string(s: str, i: int) -> int:
        q = s[i]
        i += 1
        while i < len(s):
            if s[i] == "\\":
                i += 2
                continue
            if s[i] == q:
                return i + 1
            if s[i] == "\n":
                return i
            i += 1
        return len(s)

    def _analyze_handler_flow(self):
        for case_num, body in self.handlers.items():
            info = VMHandlerInfo(case_num=case_num, raw_text=body)
            for m in re.finditer(r"(\w+)\[(\d+)\]\s*=", body):
                try:
                    info.writes.append(int(m.group(2)))
                except Exception:
                    pass
            for m in re.finditer(r"=\s*\w+\[(\d+)\]", body):
                try:
                    info.reads.append(int(m.group(1)))
                except Exception:
                    pass
            for m in re.finditer(r"\[(\d+)\]", body):
                try:
                    info.reads.append(int(m.group(1)))
                except Exception:
                    pass
            for m in re.finditer(r"\{[^{}]*\}", body):
                inner = m.group(0)
                nums = re.findall(r"\b\d+\b", inner)
                for x in nums[:20]:
                    try:
                        info.const_refs.append(int(x))
                    except Exception:
                        pass
            if re.search(r"\bA\b", body):
                info.reads_a = True
                if re.search(r"\bA\b\s*=", body) or re.search(r"\[\s*A\s*\]\s*=", body):
                    info.writes_a = True
            if re.search(r"\bB\b", body):
                info.reads_b = True
                if re.search(r"\[[^\]]*\bB\b[^\]]*\]\s*=", body) or re.search(r"\bB\b\s*=", body):
                    info.writes_a = True
            if re.search(r"\bC\b", body):
                info.reads_c = True
            if re.search(r"\bBx\b", body):
                info.uses_bx = True
            if re.search(r"\bsBx\b|\bSBx\b|\bsbx\b", body):
                info.uses_sbx = True
            if re.search(r"Const(?:ant)?s?\s*\[\s*Bx?\s*\]", body) or re.search(r"K\[\s*Bx?\s*\]", body):
                info.uses_const_b = True
                if re.search(r"\[\s*Bx\s*\]", body):
                    info.uses_const_b = True
                    info.uses_const_c = True
            info.reads = sorted(set(info.reads))
            info.writes = sorted(set(info.writes))
            info.const_refs = sorted(set(info.const_refs))
            self.register_reads[case_num] = info.reads
            self.register_writes[case_num] = info.writes
            self.const_refs[case_num] = info.const_refs

            jm = re.search(r"(?:PC|IP|pc|ip)\s*=\s*(?:PC|IP|pc|ip)?\s*([+\-])\s*(\d+)", body)
            if jm:
                self.jump_graph.setdefault(case_num, [])
                try:
                    delta = int(jm.group(2))
                    if jm.group(1) == "-":
                        delta = -delta
                    info.jump_delta = delta
                    info.is_jump = True
                    self.jump_graph[case_num].append(case_num + delta)
                except Exception:
                    pass

            if re.search(r"\breturn\b", body):
                info.is_return = True
            if re.search(r"Stack\[A\]\s*\(|Reg\[A\]\s*\(|\bcall\s*\(|Call\s*\(", body):
                info.is_call = True
            if re.search(r"==\s*|~=\s*|<\s|>", body) and re.search(r"\bif\b", body):
                info.is_conditional = True

            sem = self._classify_handler_semantic(body)
            info.semantic = sem[0]
            info.confidence = sem[1]
            info.stack_effect = sem[2]
            self.handler_infos[case_num] = info

    def _classify_handler_semantic(self, text: str) -> Tuple[Optional[str], float, int]:
        best_sem: Optional[str] = None
        best_score = 0.0
        best_eff = 0
        for sem, patterns, base_conf, eff in VM_PATTERN_TABLE:
            score = 0.0
            for pat in patterns:
                try:
                    if re.search(pat, text, re.IGNORECASE):
                        score += 1.0
                except re.error:
                    pass
            if score > 0:
                conf = min(base_conf + 0.03 * (score - 1), 0.99)
                if conf > best_score:
                    best_score = conf
                    best_sem = sem
                    best_eff = eff
        return best_sem, best_score, best_eff

    def _infer_opcode_map(self):
        for case_num, info in self.handler_infos.items():
            if info.semantic:
                self.opcode_map[case_num] = info.semantic

    def _infer_register_convention(self):
        conv: Dict[str, str] = {}
        if self.stack_var:
            conv["stack"] = self.stack_var
        if self.const_var:
            conv["const"] = self.const_var
        if self.pc_var:
            conv["pc"] = self.pc_var
        m = re.search(r"(\w+)\s*\[\s*(\w+)\s*\]\s*=\s*(\w+)\s*\[\s*(\w+)\s*\]\s*([+\-*/%])\s*(\w+)\s*\[\s*(\w+)\s*\]", self.source)
        if m:
            conv["arith_var"] = m.group(1)
        self.vm_register_convention = conv

    def get_handler_body(self, case_num: int) -> Optional[str]:
        return self.handlers.get(case_num)

    def get_handler_info(self, case_num: int) -> Optional[VMHandlerInfo]:
        return self.handler_infos.get(case_num)

    def isolate_components(self) -> Tuple[str, str, str]:
        dispatch = self.dispatcher or ""
        arr = self.instruction_array or ""
        pool = self.constant_pool or ""
        return dispatch, arr, pool

    def get_handler_offset(self, case_num: int) -> Optional[Tuple[int, int]]:
        return self.handler_offsets.get(case_num)


class VMBytecodeDecoder:
    def __init__(
        self,
        opcode_map: Dict[int, str],
        word_size: int = 4,
        endian: str = "little",
        opcode_width: int = 6,
        opcode_shift: int = 0,
        a_shift: int = 6,
        a_width: int = 8,
        b_shift: int = 23,
        b_width: int = 9,
        c_shift: int = 14,
        c_width: int = 9,
    ):
        self.opcode_map = opcode_map
        self.word_size = word_size
        self.endian = endian
        self.opcode_width = opcode_width
        self.opcode_shift = opcode_shift
        self.a_shift = a_shift
        self.a_width = a_width
        self.b_shift = b_shift
        self.b_width = b_width
        self.c_shift = c_shift
        self.c_width = c_width
        self.opcode_mask = (1 << opcode_width) - 1
        self.a_mask = (1 << a_width) - 1
        self.b_mask = (1 << b_width) - 1
        self.c_mask = (1 << c_width) - 1

    def decode(self, data: bytes) -> List[VMInstruction]:
        fmt_map = {1: "B", 2: "H", 4: "I", 8: "Q"}
        if self.word_size not in fmt_map:
            self.word_size = 4
        fmt = ("<" if self.endian == "little" else ">") + fmt_map[self.word_size]
        word_count = len(data) // self.word_size
        instructions: List[VMInstruction] = []
        for i in range(word_count):
            chunk = data[i * self.word_size:(i + 1) * self.word_size]
            try:
                raw = struct.unpack(fmt, chunk)[0]
            except Exception:
                continue
            op = (raw >> self.opcode_shift) & self.opcode_mask
            A = (raw >> self.a_shift) & self.a_mask
            B = (raw >> self.b_shift) & self.b_mask
            C = (raw >> self.c_shift) & self.c_mask
            Bx = (raw >> self.c_shift) & ((1 << (self.b_width + self.c_width)) - 1)
            sBx = Bx - ((1 << (self.b_width + self.c_width - 1)) - 1)
            instr = VMInstruction(
                opcode=op, A=A, B=B, C=C, Bx=Bx, sBx=sBx, raw=raw, index=i,
            )
            instr.semantic = self.opcode_map.get(op)
            if instr.semantic:
                instr.confidence = 0.85
            instructions.append(instr)
        return instructions

    def decode_with_rotation(self, data: bytes, rotation: int = 0) -> List[VMInstruction]:
        if rotation:
            key = list(range(len(data)))
            for i in range(len(data)):
                key[i] = data[(i + rotation) % len(data)]
            data = bytes(key)
        return self.decode(data)


class VMEmulator:
    def __init__(
        self,
        instructions: List[VMInstruction],
        handler_infos: Dict[int, VMHandlerInfo],
        constants: List[Any],
        max_registers: int = 256,
        max_steps: int = 500000,
    ):
        self.instructions = instructions
        self.handler_infos = handler_infos
        self.constants = constants
        self.registers: List[Any] = [None] * max_registers
        self.upvalues: List[Any] = [None] * 256
        self.pc = 0
        self.stack: List[Any] = []
        self.output_lines: List[str] = []
        self.max_steps = max_steps
        self.last_emitted_values: Dict[int, str] = {}
        self.var_counter = 0
        self.control_stack: List[Tuple[str, int]] = []
        self._opcode_to_semantic: Dict[int, str] = {}
        for case_num, info in handler_infos.items():
            if info.semantic:
                self._opcode_to_semantic[case_num] = info.semantic
        self.for_loops: List[Dict[str, Any]] = []
        self.current_for: Optional[Dict[str, Any]] = None

    def _new_var(self, prefix: str = "v") -> str:
        self.var_counter += 1
        return f"{prefix}{self.var_counter}"

    def _emit(self, line: str):
        if not line:
            return
        self.output_lines.append(line)

    def _reg_repr(self, idx: int) -> str:
        if 0 <= idx < len(self.registers):
            v = self.registers[idx]
            if isinstance(v, str):
                return v
            if v is None:
                return "nil"
            return repr(v)
        return f"R{idx}"

    def _const_repr(self, idx: int) -> str:
        if 0 <= idx < len(self.constants):
            v = self.constants[idx]
            return repr(v)
        return f"K[{idx}]"

    def _semantic_of(self, instr: VMInstruction) -> Optional[str]:
        if instr.semantic:
            return instr.semantic
        return self._opcode_to_semantic.get(instr.opcode)

    def _resolve_index(self, idx: int) -> Any:
        if idx < 0:
            return None
        if idx < len(self.registers) and isinstance(self.registers[idx], (int, float, str)):
            return self.registers[idx]
        return None

    def execute(self) -> List[str]:
        steps = 0
        while 0 <= self.pc < len(self.instructions) and steps < self.max_steps:
            instr = self.instructions[self.pc]
            sem = self._semantic_of(instr)
            try:
                self._execute_instruction(instr, sem)
            except Exception:
                pass
            steps += 1
            if sem in (VMOpcodeSemantics.JMP, VMOpcodeSemantics.FORLOOP, VMOpcodeSemantics.FORPREP):
                continue
            self.pc += 1
        return self.output_lines

    def _execute_instruction(self, instr: VMInstruction, sem: Optional[str]):
        A, B, C, Bx, sBx = instr.A, instr.B, instr.C, instr.Bx, instr.sBx
        if sem == VMOpcodeSemantics.MOVE:
            self.registers[A] = self.registers[B] if B < len(self.registers) else None
        elif sem == VMOpcodeSemantics.LOADK:
            val = self._const_repr(Bx)
            self.registers[A] = val
        elif sem == VMOpcodeSemantics.LOADBOOL:
            self.registers[A] = bool(B)
        elif sem == VMOpcodeSemantics.LOADNIL:
            for r in range(A, min(B + 1, len(self.registers))):
                self.registers[r] = None
        elif sem == VMOpcodeSemantics.GETUPVAL:
            self.registers[A] = self.upvalues[B] if B < len(self.upvalues) else None
        elif sem == VMOpcodeSemantics.SETUPVAL:
            self.upvalues[B] = self.registers[A]
        elif sem == VMOpcodeSemantics.GETGLOBAL:
            self.registers[A] = f"_ENV[{self._const_repr(Bx)}]"
        elif sem == VMOpcodeSemantics.SETGLOBAL:
            self._emit(f"_ENV[{self._const_repr(Bx)}] = {self._reg_repr(A)}")
        elif sem == VMOpcodeSemantics.GETTABLE:
            key = self._const_repr(C) if C >= 256 else self._reg_repr(C)
            self.registers[A] = f"{self._reg_repr(B)}[{key}]"
        elif sem == VMOpcodeSemantics.SETTABLE:
            key = self._const_repr(B) if B >= 256 else self._reg_repr(B)
            val = self._const_repr(C) if C >= 256 else self._reg_repr(C)
            self._emit(f"{self._reg_repr(A)}[{key}] = {val}")
        elif sem == VMOpcodeSemantics.NEWTABLE:
            self.registers[A] = "{}"
        elif sem == VMOpcodeSemantics.SELF:
            self.registers[A] = self._reg_repr(B)
            self.registers[A + 1] = self._reg_repr(B)
        elif sem == VMOpcodeSemantics.ADD:
            self.registers[A] = f"({self._reg_repr(B)} + {self._reg_repr(C)})"
        elif sem == VMOpcodeSemantics.SUB:
            self.registers[A] = f"({self._reg_repr(B)} - {self._reg_repr(C)})"
        elif sem == VMOpcodeSemantics.MUL:
            self.registers[A] = f"({self._reg_repr(B)} * {self._reg_repr(C)})"
        elif sem == VMOpcodeSemantics.DIV:
            self.registers[A] = f"({self._reg_repr(B)} / {self._reg_repr(C)})"
        elif sem == VMOpcodeSemantics.MOD:
            self.registers[A] = f"({self._reg_repr(B)} % {self._reg_repr(C)})"
        elif sem == VMOpcodeSemantics.POW:
            self.registers[A] = f"({self._reg_repr(B)} ^ {self._reg_repr(C)})"
        elif sem == VMOpcodeSemantics.IDIV:
            self.registers[A] = f"({self._reg_repr(B)} // {self._reg_repr(C)})"
        elif sem == VMOpcodeSemantics.BAND:
            self.registers[A] = f"({self._reg_repr(B)} & {self._reg_repr(C)})"
        elif sem == VMOpcodeSemantics.BOR:
            self.registers[A] = f"({self._reg_repr(B)} | {self._reg_repr(C)})"
        elif sem == VMOpcodeSemantics.BXOR:
            self.registers[A] = f"({self._reg_repr(B)} ~ {self._reg_repr(C)})"
        elif sem == VMOpcodeSemantics.SHL:
            self.registers[A] = f"({self._reg_repr(B)} << {self._reg_repr(C)})"
        elif sem == VMOpcodeSemantics.SHR:
            self.registers[A] = f"({self._reg_repr(B)} >> {self._reg_repr(C)})"
        elif sem == VMOpcodeSemantics.UNM:
            self.registers[A] = f"(-{self._reg_repr(B)})"
        elif sem == VMOpcodeSemantics.NOT:
            self.registers[A] = f"(not {self._reg_repr(B)})"
        elif sem == VMOpcodeSemantics.LEN:
            self.registers[A] = f"#{self._reg_repr(B)}"
        elif sem == VMOpcodeSemantics.BNOT:
            self.registers[A] = f"(~{self._reg_repr(B)})"
        elif sem == VMOpcodeSemantics.CONCAT:
            parts = [self._reg_repr(r) for r in range(B, min(C + 1, len(self.registers)))]
            self.registers[A] = "(" + " .. ".join(parts) + ")" if parts else '""'
        elif sem == VMOpcodeSemantics.JMP:
            target = self.pc + 1 + sBx
            self.pc = max(0, min(target, len(self.instructions)))
            return
        elif sem == VMOpcodeSemantics.EQ:
            self._emit(f"if not ({self._reg_repr(B)} == {self._reg_repr(C)}) then goto L{self.pc + 2} end")
        elif sem == VMOpcodeSemantics.LT:
            self._emit(f"if not ({self._reg_repr(B)} < {self._reg_repr(C)}) then goto L{self.pc + 2} end")
        elif sem == VMOpcodeSemantics.LE:
            self._emit(f"if not ({self._reg_repr(B)} <= {self._reg_repr(C)}) then goto L{self.pc + 2} end")
        elif sem == VMOpcodeSemantics.TEST:
            self._emit(f"if {self._reg_repr(A)} then goto L{self.pc + 2} end")
        elif sem == VMOpcodeSemantics.TESTSET:
            self.registers[A] = self._reg_repr(B)
        elif sem == VMOpcodeSemantics.CALL:
            args = [self._reg_repr(r) for r in range(A + 1, min(A + B, len(self.registers)))]
            nret = C - 1 if C > 0 else 0
            call_expr = f"{self._reg_repr(A)}({', '.join(args)})"
            if nret == 0:
                self._emit(call_expr)
            elif nret == 1:
                self.registers[A] = call_expr
            else:
                rets = ", ".join(self._reg_repr(A + i) for i in range(nret))
                self._emit(f"{rets} = {call_expr}")
        elif sem == VMOpcodeSemantics.TAILCALL:
            args = [self._reg_repr(r) for r in range(A + 1, min(A + B, len(self.registers)))]
            self._emit(f"return {self._reg_repr(A)}({', '.join(args)})")
        elif sem == VMOpcodeSemantics.RETURN:
            if B <= 1:
                self._emit("return")
            else:
                vals = [self._reg_repr(r) for r in range(A, min(A + B - 1, len(self.registers)))]
                self._emit(f"return {', '.join(vals)}")
        elif sem == VMOpcodeSemantics.FORPREP:
            start = self._reg_repr(A)
            self._emit(f"for _i_{A} = {start}, {self._reg_repr(A + 1)}, {self._reg_repr(A + 2)} do")
            self.current_for = {"A": A, "reg": A + 3}
            self.registers[A + 3] = f"_i_{A}"
        elif sem == VMOpcodeSemantics.FORLOOP:
            if self.current_for:
                self._emit("end")
                self.current_for = None
        elif sem == VMOpcodeSemantics.TFORLOOP:
            pass
        elif sem == VMOpcodeSemantics.SETLIST:
            for i in range(1, B + 1):
                if A + i < len(self.registers):
                    self.registers[A] = self._reg_repr(A)
        elif sem == VMOpcodeSemantics.CLOSE:
            pass
        elif sem == VMOpcodeSemantics.CLOSURE:
            self.registers[A] = f"<closure_{Bx}>"
        elif sem == VMOpcodeSemantics.VARARG:
            if B <= 1:
                self.registers[A] = "..."
            else:
                for i in range(B - 1):
                    self.registers[A + i] = f"select({i + 1}, ...)"
        else:
            self.registers[A] = f"R{B}"

    def get_output(self) -> str:
        return "\n".join(self.output_lines)


class VMLifter:
    def __init__(
        self,
        source: str,
        splitter: VMSplitter,
        bytecode: Optional[List[int]] = None,
    ):
        self.source = source
        self.splitter = splitter
        self.bytecode = bytecode
        self.output: List[str] = []

    def lift(self) -> Optional[str]:
        if not self.splitter.handler_infos:
            return None
        opcode_map = {k: v.semantic for k, v in self.splitter.handler_infos.items() if v.semantic}
        if not opcode_map:
            return None

        constants = self._extract_constants()
        raw_bytes = self._extract_raw_bytes()
        if raw_bytes is None:
            return None

        bit_layout = {
            "word_size": self.splitter.instruction_word_size,
            "endian": self.splitter.instruction_endian,
            "opcode_width": self.splitter.opcode_bit_width,
            "opcode_shift": self.splitter.opcode_shift,
            "a_shift": self.splitter.a_shift,
            "a_width": self.splitter.a_width,
            "b_shift": self.splitter.b_shift,
            "b_width": self.splitter.b_width,
            "c_shift": self.splitter.c_shift,
            "c_width": self.splitter.c_width,
        }

        best_output: Optional[str] = None
        best_score = 0.0
        for rotation in [0] + list(range(1, 32)):
            try:
                decoder = VMBytecodeDecoder(opcode_map, **bit_layout)
                if rotation:
                    instrs = decoder.decode_with_rotation(raw_bytes, rotation)
                else:
                    instrs = decoder.decode(raw_bytes)
            except Exception:
                continue
            if not instrs:
                continue
            recognized = sum(1 for i in instrs if i.semantic)
            coverage = recognized / len(instrs)
            if coverage < 0.30:
                continue
            emulator = VMEmulator(instrs, self.splitter.handler_infos, constants)
            try:
                lines = emulator.execute()
            except Exception:
                continue
            score = coverage * 100 + len(lines)
            if score > best_score:
                best_score = score
                best_output = "\n".join(lines)
        return best_output

    def _extract_constants(self) -> List[Any]:
        consts: List[Any] = []
        if not self.splitter.constant_pool:
            return consts
        body = self.splitter.constant_pool
        for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', body):
            try:
                s = bytes(m.group(1), "utf-8").decode("unicode_escape")
                consts.append(s)
            except Exception:
                consts.append(m.group(1))
        for m in re.finditer(r"'((?:[^'\\]|\\.)*)'", body):
            consts.append(m.group(1))
        for m in re.finditer(r"\b(0x[0-9a-fA-F]+|\d+)\b", body):
            try:
                consts.append(int(m.group(1), 0))
            except Exception:
                pass
        return consts

    def _extract_raw_bytes(self) -> Optional[bytes]:
        if self.bytecode:
            try:
                return bytes([b & 0xFF for b in self.bytecode])
            except Exception:
                return None
        if not self.splitter.instruction_array_body:
            return None
        raw_nums = re.findall(r"0x[0-9a-fA-F]+|\d+", self.splitter.instruction_array_body)
        if len(raw_nums) < 16:
            return None
        try:
            vals = [int(x, 0) & 0xFF for x in raw_nums]
            return bytes(vals)
        except Exception:
            return None


class AdvancedCleanup:
    @staticmethod
    def fix_operator_misuse(code: str) -> str:
        code = re.sub(r'=\s*\.\s*([^"\w])', r'= \1', code)
        code = re.sub(r'(\W)\.(\W)', r'\1\2', code)
        code = re.sub(r'=\s*"\s*\+\s*([^+"]+)\+\s*"', r'= "\1"..', code)
        code = re.sub(r'("\s*)\.\.(\s*")', r'\1+\2', code)
        code = re.sub(r'(\w+)\s*\.\.=\s*(\w+)', r'\1 = \1 .. \2', code)
        code = re.sub(r'(?<!\.)\.\.(?!\.)', ' .. ', code)
        code = re.sub(r'(\S)\.\.(\S)', r'\1 .. \2', code)
        return code

    @staticmethod
    def fix_table_syntax(code: str) -> str:
        code = re.sub(r"\[\\(\d+)\]", lambda m: f'["{chr(int(m.group(1)))}"]', code)
        code = re.sub(
            r"(\w+)\s*=\s*{\s*([^=]+)=\s*([^,}]+)(\s*[^,}]+)(,|})",
            lambda m: f"{m.group(1)} = {{{m.group(2)} = {m.group(3)},{m.group(4)}{m.group(5)}}}",
            code,
        )
        code = re.sub(r",\s*(for|end|do|while)", r"; \1", code)
        return code

    @staticmethod
    def detect_and_fix_syntax_errors(code: str) -> str:
        error_corrections = {
            r'("\w+")\s*(\[[^]]+\])\s*([^,{])': r'\1\2,\3',
            r'(\]\s*=\s*[^,]+)\s+("[^"]+"|\w+)': r'\1,\2',
            r'{\s*"(\w+)"\s*([^=])': r'{["\1"] \2',
            r',\s*(\s*[}\]])': r'\1',
        }
        return reduce(lambda c, t: re.sub(t[0], t[1], c), error_corrections.items(), code)

    @staticmethod
    def fix_duplicate_locals(code: str) -> str:
        return re.sub(r"\blocal\s+local\b", "local", code)

    @staticmethod
    def demangle_variables(code: str) -> str:
        code = re.sub(r'\bfunct0n\b', 'function', code)
        code = re.sub(
            r"\b(?!function\b)(\w+)(\d)(\w*)\b",
            lambda m: f"{m.group(1)}{chr(ord(m.group(2)) + 49)}{m.group(3)}",
            code,
        )
        return code

    @staticmethod
    def handle_number_obfuscation(code: str) -> str:
        patterns = [
            (r"\bvar_18\b", "256"),
            (r"\bvar_12\b", "3"),
            (r"\bvar_15\b", "1"),
            (r"\bvar_6\b", "2"),
            (r"64\s*\^\s*\(\s*\(\s*3\s*\*\s*1\s*\)\s*-\s*0\s*\)", "262144"),
        ]
        return reduce(lambda c, p: re.sub(p[0], p[1], c), patterns, code)

    @staticmethod
    def evaluate_arithmetic(code: str) -> str:
        code = re.sub(r"(\w+)\s+(\w+)(?=\s*\^)", r"\1*\2", code)
        code = re.sub(r"(\d+)\s+(\d+)", r"\1*\2", code)
        return re.sub(r"(\w+)\s*([+-])\s*(\w+)\s*(\^)", r"(\1 \2 \3)\4", code)

    @staticmethod
    def detect_arithmetic_obfuscation(code: str) -> str:
        def _div(m: re.Match) -> str:
            try:
                return str(int(eval(m.group(1)) // int(m.group(2))))
            except Exception:
                return m.group(0)

        def _band_xor(m: re.Match) -> str:
            try:
                return str((int(m.group(1)) & int(m.group(2))) ^ int(m.group(3)))
            except Exception:
                return m.group(0)

        code = re.sub(r"math\.floor\(([^)]+)\s*/\s*(\d{5,})\)", _div, code)
        code = re.sub(
            r"bit32\.bxor\(bit32\.band\(([^,]+),\s*(\d+)\)\s*,\s*(\d+)\)",
            _band_xor,
            code,
        )
        return code

    @staticmethod
    def reconstruct_array_initialization(code: str) -> str:
        code = re.sub(
            r"\{\s*(\w+)\s*=\s*(\w+),?\s*(\d+)\s*=\s*(\d+),?",
            r"{\1 = \2, [\3] = \4}",
            code,
        )
        return re.sub(r"\[\"\\049\"\]", r"[1]", code)

    @staticmethod
    def resolve_metatable_ops(code: str) -> str:
        return re.sub(
            r"getmetatable\(([\w.]+(\s*\([^)]*\))?)\)\[(__index|__newindex)\]",
            lambda m: f"{re.sub(r'\\W', '_', m.group(1))}_metatable[{m.group(3)}]",
            code,
        )

    @staticmethod
    def simplify_arithmetic_masks(code: str) -> str:
        mask_patterns = {
            r"% 256": "& 0xFF",
            r"% 65536": "& 0xFFFF",
            r"% var_4": "& 0xFFFFFFFF",
        }
        for pattern, replacement in mask_patterns.items():
            code = code.replace(pattern, replacement)
        return code

    @staticmethod
    def handle_accumulator_patterns(code: str) -> str:
        def _convert_loop(match: re.Match) -> str:
            loop_body = match.group(1)
            array_match = re.search(r"local\s+(\w+)\s*=\s*(\w+)\[accumulator\]", loop_body)
            if array_match:
                var_name, array_name = array_match.groups()
                return f"for {var_name} in ipairs({array_name}) do\n{loop_body}\nend"
            return match.group(0)

        patterns = [
            (r"accumulator\s*=\s*\(accumulator\s+and\s+(\w+)\s+or\s+(\w+)\)",
             lambda m: f"if {m.group(1)} then accumulator else {m.group(2)} end"),
            (r"accumulator\s*=\s*for\s+(-\d+)", lambda m: f"break"),
            (r"accumulator\s*=\s*math\.max", "pcall() wrapper removed"),
            (r"\(-\s*(\w+)\)", lambda m: f"-{m.group(1)}"),
            (r"while\s+accumulator\s+do\s+(local\s+\w+\s*=\s*\w+\[\s*accumulator\s*\]\s*;.*?)\s*end",
             _convert_loop),
        ]
        return reduce(lambda c, p: re.sub(p[0], p[1], c, flags=re.DOTALL), patterns, code)

    @staticmethod
    def track_buffer_permutations(code: str) -> str:
        patterns = [
            (r"\b(buffer)\s*=\s*for\s*\(\s*(\w+)\s*([/%])\s*(\w+)\s*\)",
             lambda m: f"{m.group(2)} {m.group(3)} {m.group(4)}"),
            (r"\b(buffer)\s*([%\/])\s*(\w+)", lambda m: f"{m.group(1)} {m.group(2)} {m.group(3)}"),
            (r"\bbuffer\s*\[\s*(\w+)\s*\]", lambda m: f"buffer[{m.group(1)}]"),
            (r"buffer\[([^\]]+)\],\s*buffer\[([^\]]+)\]\s*=\s*buffer\[\2\],\s*buffer\[\1\]",
             lambda m: f"buffer[{m.group(1)}], buffer[{m.group(2)}] = buffer[{m.group(2)}], buffer[{m.group(1)}]"),
            (r"buffer\[([^\]]+)\],\s*buffer\[([^\]]+)\],([^=]*)=\s*buffer\[\2\],\s*buffer\[\1\],([^\n]+)",
             lambda m: f"buffer[{m.group(1)}], buffer[{m.group(2)}],{m.group(3)}= buffer[{m.group(2)}], buffer[{m.group(1)}],{m.group(4)}"),
            (r"buffer\s*[%\/]\s*(-?\d{6,})", lambda m: f"buffer {m.group(0).split()[-1]}"),
        ]
        for pattern, handler in patterns:
            code = re.sub(pattern, handler, code, flags=re.IGNORECASE)
        return code

    @staticmethod
    def reverse_array_permutations(code: str) -> str:
        return re.sub(
            r"buffer\[(\d+)\],\s*buffer\[(\d+)\]\s*=\s*buffer\[\2\],\s*buffer\[\1\]",
            lambda m: f"buffer[{m.group(1)}], buffer[{m.group(2)}] = buffer[{m.group(2)}], buffer[{m.group(1)}]",
            code,
        )

    @staticmethod
    def resolve_buffer_indices(code: str) -> str:
        index_mappings = {
            "var_4": "DWORD_INDEX",
            "var_8": "QWORD_INDEX",
            "var_16": "ARRAY_START",
        }
        return re.sub(
            r"buffer\[(\w+)\[(\w+)\]\]",
            lambda m: f"buffer[{index_mappings.get(m.group(2), m.group(2) + '_CALCULATED')}]",
            code,
        )

    @staticmethod
    def prune_dead_code(code: str) -> str:
        dead_code_patterns = [
            r"if current_phase < PHASE_\d+ then.*?end",
            r"var_\d+ = var_\d+ % \d+.*?end",
            r"buffer\[\d+\].*?end",
        ]
        for pattern in dead_code_patterns:
            code = re.sub(pattern, "", code, flags=re.DOTALL)
        return code

    @staticmethod
    def propagate_constants_simple(code: str) -> str:
        const_map = {
            "var_18": "256",
            "var_3": "1",
            "var_12": "6",
            "var_15": "1",
            "io": "0",
        }
        for var, value in const_map.items():
            code = code.replace(var, value)
        return code

    @staticmethod
    def resolve_library_aliases(code: str) -> str:
        aliases = {
            r"\bflag\s*=\s*table\.insert\b": "",
            r"\bgoto\s*=\s*math\.floor\b": "",
            r"\bstring\s*=\s*table\.concat\b": "",
        }
        for pattern, replacement in aliases.items():
            code = re.sub(pattern, replacement, code)
        return code

    @staticmethod
    def fix_table_declarations(code: str) -> str:
        code = re.sub(r",\s*(\d+)\s*=", lambda m: f", [{m.group(1)}] = ", code)
        code = re.sub(r"\[\\(\d+)\"\]", lambda m: f'["\\{m.group(1)}"]', code)
        code = re.sub(r";(\s*\w+\s*=)", r"\1", code)
        return re.sub(r"\b(for|while|do|end)\s*=", lambda m: f'["{m.group(1)}"] =', code)

    @staticmethod
    def simplify_numeric_operations(code: str) -> str:
        code = re.sub(r"0x100\b", "256", code)
        code = re.sub(r"\bvar_18\b", "256", code)
        return re.sub(r"(\w+)\s+(\w+)(?=\s*[\^\%])", r"\1*\2", code)

    @staticmethod
    def remove_invalid_chars(code: str) -> str:
        return re.sub(r"[\x00-\x1F\x7F-\x9F]", "", code)

    @staticmethod
    def defragment_strings(code: str) -> str:
        return re.sub(
            r'(".*?")\s*\n\s*"(.*?")',
            lambda m: f'"{m.group(1)[1:-1]}{m.group(2)[1:-1]}"',
            code,
        )

    @staticmethod
    def normalize_string_ops(code: str) -> str:
        code = re.sub(r'==\s*,\s*"([^"]+)"', r'== "\1"', code)
        return re.sub(r'"\s*\.\.\s*[A-Za-z0-9]+\s*\.\.\s*"', 'CONCAT_B64_CHUNK', code)

    @staticmethod
    def resolve_string_sub_calls(code: str) -> str:
        code = re.sub(r'string \.sub', 'string.sub', code)
        return re.sub(
            r'string\.sub\(([^,]+),\s*([^,]+),\s*([^)]+)\)',
            lambda m: f'string_sub({m.group(1)}, {m.group(2)}, {m.group(3)})',
            code,
        )

    @staticmethod
    def resolve_array_jumps(code: str) -> str:
        return re.sub(r'string\[goto\[(\w+)\]\]', lambda m: f'string_block_{m.group(1)}', code)

    @staticmethod
    def resolve_vm_dispatches(code: str) -> str:
        return re.sub(
            r"if accumulator < (\w+) then([\s\S]*?)elseif",
            lambda m: f"if accumulator < {m.group(1)} then{m.group(2)}elseif",
            code,
            flags=re.DOTALL,
        )

    @staticmethod
    def normalize_loop_structures(code: str) -> str:
        return re.sub(
            r"do\s+while\s+(\w+)\s*<=\s*(\w+)\s+do\s+(.*?)\bend\b",
            r"for \1 = 1, \2 do\n\3\nend",
            code,
            flags=re.DOTALL,
        )

    @staticmethod
    def collapse_double_brackets(code: str) -> str:
        return re.sub(r"\[\[([^\[\]]+)\]\]", r"[\1]", code)

    @staticmethod
    def fold_numeric_constants(code: str) -> str:
        def fold(m):
            try:
                return str(eval(m.group(0)))
            except Exception:
                return m.group(0)
        return re.sub(r"\b\d+\s*[\+\-\*\/\%]\s*\d+\b", fold, code)

    @staticmethod
    def strip_redundant_semicolons(code: str) -> str:
        code = re.sub(r";\s*;", ";", code)
        code = re.sub(r";\s*\n", "\n", code)
        code = re.sub(r"\n\s*\n\s*\n+", "\n\n", code)
        return code


class Utils:
    @staticmethod
    def reverse_string_permutation(code: str) -> str:
        patterns = [(r'"\s*\+\s*"', ""), (r'\[,""\]\s*=\s*\d+,', "")]
        return reduce(lambda c, p: re.sub(p[0], p[1], c), patterns, code)

    def decode_prometheus_payload(self, payload: str) -> str:
        try:
            decoded = base64.b64decode(payload)
            decompressed = zlib.decompress(decoded)
            key = self.detect_xor_key(decompressed)
            return "".join(chr(b ^ key) for b in decompressed)
        except Exception:
            return payload

    def unpack_nested_encodings(self, code: str) -> str:
        return reduce(
            lambda c, _: re.sub(
                r'loadstring\((["\'])([A-Za-z0-9+/=]+)\1\)',
                lambda m: self.decode_prometheus_payload(m.group(2)),
                c,
            ),
            range(3),
            code,
        )

    def detect_xor_key(self, data: bytes) -> int:
        lua_freq = {"a": 8.2, "e": 12.7, "i": 6.9, "o": 7.5, "u": 2.8}
        return max(
            range(256),
            key=lambda k: sum(
                lua_freq.get(chr(byte ^ k).lower(), 0) for byte in data[:1000]
            ),
        )

    def decrypt_random_strings(self, code: str) -> str:
        code = re.sub(
            r'["\']([a-zA-Z0-9_$]{4,})["\']',
            lambda m: f'"{self.decode_random_string(m.group(1))}"',
            re.sub(
                r"\b(?:randomString|genStr|randStr|createStr)[A-Za-z0-9]*\([^)]*\)",
                '""',
                code,
            ),
        )
        return code

    def decode_random_string(self, s: str) -> str:
        charset = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890"
        return "".join([c if c in charset else f"\\{ord(c)}" for c in s])

    def reconstruct_final_string(self, code: str) -> str:
        def _decode_match(m: re.Match) -> str:
            try:
                parts = re.findall(r'(?:"([A-Za-z0-9+/=]*)")|([a-zA-Z0-9+=]+)', m.group(0))
                combined = []
                for p in parts:
                    if p[0]:
                        combined.append(p[0])
                    elif p[1]:
                        if p[1].startswith(("0x", "0X")):
                            translated = str(int(p[1], 16))
                        elif "\\0" in p[1]:
                            translated = p[1].replace("\\0", "\x00")
                        else:
                            translated = p[1].translate(str.maketrans("pqr", "+-*"))
                        combined.append(str(eval(translated)))
                full_string = "".join(combined)
                if len(full_string) % 4 == 0 and re.match(r"^[A-Za-z0-9+/=]+$", full_string):
                    decoded = base64.b64decode(full_string).decode("utf-8", "replace")
                    decoded = decoded.replace("\x00", "").replace("\\0", "").replace("\\x00", "")
                    return f'"{decoded}"'
                return f'"{full_string}"'
            except Exception:
                return m.group(0)

        code = re.sub(r'("[\w+/=]+"\s*\.\.\s*)+[\w+]+==?', _decode_match, code)
        return re.sub(r'("\w+=")\s*\.\.\s*(\w+)', lambda m: f'"{m.group(1)[1:-1]}{m.group(2)}"', code)


class LuaOpcode(IntEnum):
    OP_MOVE = 0
    OP_LOADK = 1
    OP_LOADBOOL = 2
    OP_LOADNIL = 3
    OP_GETUPVAL = 4
    OP_GETGLOBAL = 5
    OP_GETTABLE = 6
    OP_SETGLOBAL = 7
    OP_SETUPVAL = 8
    OP_SETTABLE = 9
    OP_NEWTABLE = 10
    OP_SELF = 11
    OP_ADD = 12
    OP_SUB = 13
    OP_MUL = 14
    OP_DIV = 15
    OP_MOD = 16
    OP_POW = 17
    OP_UNM = 18
    OP_NOT = 19
    OP_LEN = 20
    OP_CONCAT = 21
    OP_JMP = 22
    OP_EQ = 23
    OP_LT = 24
    OP_LE = 25
    OP_TEST = 26
    OP_TESTSET = 27
    OP_CALL = 28
    OP_TAILCALL = 29
    OP_RETURN = 30
    OP_FORLOOP = 31
    OP_FORPREP = 32
    OP_TFORLOOP = 33
    OP_SETLIST = 34
    OP_CLOSE = 35
    OP_CLOSURE = 36
    OP_VARARG = 37


OPCODE_NAMES = {v: k for k, v in LuaOpcode.__members__.items()}

OPCODE_FORMATS = {
    LuaOpcode.OP_MOVE: "ABC",
    LuaOpcode.OP_LOADK: "ABx",
    LuaOpcode.OP_LOADBOOL: "ABC",
    LuaOpcode.OP_LOADNIL: "ABC",
    LuaOpcode.OP_GETUPVAL: "ABC",
    LuaOpcode.OP_GETGLOBAL: "ABx",
    LuaOpcode.OP_GETTABLE: "ABC",
    LuaOpcode.OP_SETGLOBAL: "ABx",
    LuaOpcode.OP_SETUPVAL: "ABC",
    LuaOpcode.OP_SETTABLE: "ABC",
    LuaOpcode.OP_NEWTABLE: "ABC",
    LuaOpcode.OP_SELF: "ABC",
    LuaOpcode.OP_ADD: "ABC",
    LuaOpcode.OP_SUB: "ABC",
    LuaOpcode.OP_MUL: "ABC",
    LuaOpcode.OP_DIV: "ABC",
    LuaOpcode.OP_MOD: "ABC",
    LuaOpcode.OP_POW: "ABC",
    LuaOpcode.OP_UNM: "ABC",
    LuaOpcode.OP_NOT: "ABC",
    LuaOpcode.OP_LEN: "ABC",
    LuaOpcode.OP_CONCAT: "ABC",
    LuaOpcode.OP_JMP: "sBx",
    LuaOpcode.OP_EQ: "ABC",
    LuaOpcode.OP_LT: "ABC",
    LuaOpcode.OP_LE: "ABC",
    LuaOpcode.OP_TEST: "ABC",
    LuaOpcode.OP_TESTSET: "ABC",
    LuaOpcode.OP_CALL: "ABC",
    LuaOpcode.OP_TAILCALL: "ABC",
    LuaOpcode.OP_RETURN: "ABC",
    LuaOpcode.OP_FORLOOP: "AsBx",
    LuaOpcode.OP_FORPREP: "AsBx",
    LuaOpcode.OP_TFORLOOP: "ABC",
    LuaOpcode.OP_SETLIST: "ABC",
    LuaOpcode.OP_CLOSE: "ABC",
    LuaOpcode.OP_CLOSURE: "ABx",
    LuaOpcode.OP_VARARG: "ABC",
}

LUA_KEYWORDS = {
    "and", "break", "do", "else", "elseif", "end",
    "false", "for", "function", "if", "in", "local",
    "nil", "not", "or", "repeat", "return", "then",
    "true", "until", "while",
}

LUA_BUILTINS = {
    "print", "pairs", "ipairs", "next", "type", "tostring", "tonumber",
    "select", "rawget", "rawset", "rawequal", "rawlen", "setmetatable",
    "getmetatable", "pcall", "xpcall", "error", "assert", "unpack",
    "require", "load", "loadstring", "loadfile", "dofile", "collectgarbage",
    "coroutine", "string", "table", "math", "io", "os", "debug", "bit",
    "bit32", "utf8", "_G", "_ENV", "_VERSION", "arg", "newproxy",
    "getfenv", "setfenv", "gcinfo", "module", "package", "jit",
}

COMMON_STRINGS = {
    "local", "function", "return", "end", "then", "if", "else", "elseif",
    "while", "for", "do", "repeat", "until", "break", "nil", "true", "false",
    "and", "or", "not", "in", "print", "pairs", "ipairs", "tostring",
    "tonumber", "type", "string", "table", "math", "coroutine", "require",
    "assert", "error", "pcall", "xpcall", "select", "rawget", "rawset",
    "getmetatable", "setmetatable", "game", "workspace", "script",
    "Instance", "wait", "spawn", "tick", "Vector3", "CFrame", "Color3",
}


@dataclass
class LuaInstruction:
    opcode: int
    A: int = 0
    B: int = 0
    C: int = 0
    Bx: int = 0
    sBx: int = 0
    raw: int = 0
    original_opcode: int = 0
    line: int = 0

    def __str__(self):
        name = OPCODE_NAMES.get(self.opcode, f"OP_{self.opcode}")
        fmt = OPCODE_FORMATS.get(self.opcode, "ABC")
        if fmt == "ABx":
            return f"{name:<16} {self.A} {self.Bx}"
        elif fmt in ("sBx", "AsBx"):
            return f"{name:<16} {self.A} {self.sBx}"
        else:
            return f"{name:<16} {self.A} {self.B} {self.C}"


@dataclass
class LuaConstant:
    type_id: int
    value: Any

    def __str__(self):
        if self.type_id == 0:
            return "nil"
        elif self.type_id == 1:
            return "true" if self.value else "false"
        elif self.type_id == 3:
            if isinstance(self.value, float) and self.value.is_integer():
                return str(int(self.value))
            return repr(self.value)
        elif self.type_id == 4:
            return json.dumps(self.value)
        return repr(self.value)


@dataclass
class LuaProto:
    source: str = ""
    line_defined: int = 0
    last_line_defined: int = 0
    num_upvalues: int = 0
    num_params: int = 0
    is_vararg: int = 0
    max_stack_size: int = 0
    instructions: List[LuaInstruction] = field(default_factory=list)
    constants: List[LuaConstant] = field(default_factory=list)
    protos: List["LuaProto"] = field(default_factory=list)
    upvalues: List[str] = field(default_factory=list)
    locals: List[Tuple[str, int, int]] = field(default_factory=list)
    lines: List[int] = field(default_factory=list)


class ASTNode:
    def __init__(self, node_type: str, **kwargs):
        self.type = node_type
        self.children: List["ASTNode"] = []
        self.attrs: Dict[str, Any] = kwargs
        self.line: int = 0

    def add_child(self, child: "ASTNode"):
        self.children.append(child)
        return self

    def walk(self):
        yield self
        for c in self.children:
            yield from c.walk()

    def __repr__(self):
        return f"ASTNode({self.type}, {self.attrs})"


class TokenType(IntEnum):
    NUMBER = auto()
    STRING = auto()
    NAME = auto()
    KEYWORD = auto()
    OP = auto()
    PUNCT = auto()
    EOF = auto()
    COMMENT = auto()


@dataclass
class Token:
    ttype: TokenType
    value: Any
    line: int = 0
    col: int = 0


class LuaLexer:
    def __init__(self, src: str):
        self.src = src
        self.pos = 0
        self.line = 1
        self.col = 1
        self.tokens: List[Token] = []

    def peek(self, n=0) -> str:
        p = self.pos + n
        return self.src[p] if p < len(self.src) else ""

    def advance(self) -> str:
        c = self.src[self.pos]
        self.pos += 1
        if c == "\n":
            self.line += 1
            self.col = 1
        else:
            self.col += 1
        return c

    def skip_whitespace(self):
        while self.pos < len(self.src) and self.src[self.pos] in " \t\r\n":
            self.advance()

    def read_long_string(self) -> Optional[str]:
        level = 0
        while self.peek() == "=":
            level += 1
            self.advance()
        if self.peek() != "[":
            return None
        self.advance()
        if self.peek() == "\n":
            self.advance()
        buf = []
        close = "]" + "=" * level + "]"
        while self.pos < len(self.src):
            if self.src[self.pos:self.pos + len(close)] == close:
                self.pos += len(close)
                return "".join(buf)
            buf.append(self.advance())
        return "".join(buf)

    def read_string(self, quote: str) -> str:
        buf = []
        while self.pos < len(self.src):
            c = self.advance()
            if c == quote:
                break
            if c == "\\":
                if self.pos >= len(self.src):
                    break
                esc = self.advance()
                if esc == "n":
                    buf.append("\n")
                elif esc == "t":
                    buf.append("\t")
                elif esc == "r":
                    buf.append("\r")
                elif esc == "a":
                    buf.append("\a")
                elif esc == "b":
                    buf.append("\b")
                elif esc == "f":
                    buf.append("\f")
                elif esc == "v":
                    buf.append("\v")
                elif esc == "\\":
                    buf.append("\\")
                elif esc == "'":
                    buf.append("'")
                elif esc == '"':
                    buf.append('"')
                elif esc == "\n":
                    buf.append("\n")
                elif esc == "0":
                    buf.append("\0")
                elif esc.isdigit():
                    num = esc
                    for _ in range(2):
                        if self.pos < len(self.src) and self.src[self.pos].isdigit():
                            num += self.advance()
                    buf.append(chr(int(num) & 0xFF))
                elif esc == "x":
                    hex_val = ""
                    for _ in range(2):
                        if self.pos < len(self.src) and self.src[self.pos] in "0123456789abcdefABCDEF":
                            hex_val += self.advance()
                    if hex_val:
                        buf.append(chr(int(hex_val, 16)))
                elif esc == "z":
                    while self.pos < len(self.src) and self.src[self.pos] in " \t\r\n":
                        self.advance()
                else:
                    buf.append(esc)
            else:
                buf.append(c)
        return "".join(buf)

    def read_number(self) -> Any:
        start = self.pos - 1
        is_hex = False
        if self.src[start] == "0" and self.pos < len(self.src) and self.src[self.pos].lower() == "x":
            is_hex = True
            self.advance()
            while self.pos < len(self.src) and (self.src[self.pos] in "0123456789abcdefABCDEF"):
                self.advance()
            if self.pos < len(self.src) and self.src[self.pos] == ".":
                self.advance()
                while self.pos < len(self.src) and (self.src[self.pos] in "0123456789abcdefABCDEF"):
                    self.advance()
            if self.pos < len(self.src) and self.src[self.pos] in "pP":
                self.advance()
                if self.pos < len(self.src) and self.src[self.pos] in "+-":
                    self.advance()
                while self.pos < len(self.src) and self.src[self.pos].isdigit():
                    self.advance()
        else:
            while self.pos < len(self.src) and (self.src[self.pos].isdigit() or self.src[self.pos] in "."):
                self.advance()
            if self.pos < len(self.src) and self.src[self.pos] in "eE":
                self.advance()
                if self.pos < len(self.src) and self.src[self.pos] in "+-":
                    self.advance()
                while self.pos < len(self.src) and self.src[self.pos].isdigit():
                    self.advance()
        raw = self.src[start:self.pos]
        try:
            if is_hex:
                if "." in raw or "p" in raw.lower():
                    return float.fromhex(raw)
                return int(raw, 16)
            elif "." in raw or "e" in raw.lower():
                return float(raw)
            else:
                return int(raw)
        except ValueError:
            return 0

    def tokenize(self) -> List[Token]:
        while self.pos < len(self.src):
            self.skip_whitespace()
            if self.pos >= len(self.src):
                break
            line = self.line
            col = self.col
            c = self.src[self.pos]

            if c == "-" and self.peek(1) == "-":
                self.advance()
                self.advance()
                if self.peek() == "[":
                    saved = self.pos
                    self.advance()
                    ls = self.read_long_string()
                    if ls is not None:
                        self.tokens.append(Token(TokenType.COMMENT, ls, line, col))
                        continue
                    self.pos = saved
                start = self.pos
                while self.pos < len(self.src) and self.src[self.pos] != "\n":
                    self.advance()
                self.tokens.append(Token(TokenType.COMMENT, self.src[start:self.pos], line, col))
                continue

            if c == "[" and (self.peek(1) == "[" or self.peek(1) == "="):
                saved = self.pos
                self.advance()
                ls = self.read_long_string()
                if ls is not None:
                    self.tokens.append(Token(TokenType.STRING, ls, line, col))
                    continue
                self.pos = saved

            if c in ('"', "'"):
                self.advance()
                s = self.read_string(c)
                self.tokens.append(Token(TokenType.STRING, s, line, col))
                continue

            if c.isdigit() or (c == "." and self.peek(1).isdigit()):
                self.advance()
                n = self.read_number()
                self.tokens.append(Token(TokenType.NUMBER, n, line, col))
                continue

            if c.isalpha() or c == "_":
                start = self.pos
                while self.pos < len(self.src) and (self.src[self.pos].isalnum() or self.src[self.pos] == "_"):
                    self.advance()
                word = self.src[start:self.pos]
                ttype = TokenType.KEYWORD if word in LUA_KEYWORDS else TokenType.NAME
                self.tokens.append(Token(ttype, word, line, col))
                continue

            three = self.src[self.pos:self.pos + 3]
            if three == "...":
                self.pos += 3
                self.col += 3
                self.tokens.append(Token(TokenType.OP, "...", line, col))
                continue

            two = self.src[self.pos:self.pos + 2]
            if two in ("==", "~=", "<=", ">=", "..", "::", "<<", ">>", "//"):
                self.pos += 2
                self.col += 2
                tt = TokenType.OP if two not in ("::",) else TokenType.PUNCT
                self.tokens.append(Token(tt, two, line, col))
                continue

            self.advance()
            if c in "+-*/^%#<>=~&|":
                self.tokens.append(Token(TokenType.OP, c, line, col))
            elif c in "(){}[];:,.":
                self.tokens.append(Token(TokenType.PUNCT, c, line, col))
            continue

        self.tokens.append(Token(TokenType.EOF, None, self.line, self.col))
        return self.tokens


class LuaParser:
    def __init__(self, tokens: List[Token]):
        self.tokens = [t for t in tokens if t.ttype != TokenType.COMMENT]
        self.pos = 0

    def peek(self, n=0) -> Token:
        p = self.pos + n
        if p < len(self.tokens):
            return self.tokens[p]
        return Token(TokenType.EOF, None)

    def advance(self) -> Token:
        t = self.tokens[self.pos]
        self.pos += 1
        return t

    def expect(self, ttype: TokenType, value=None) -> Token:
        t = self.advance()
        if t.ttype != ttype:
            raise SyntaxError(f"Expected {ttype} got {t.ttype} '{t.value}' at line {t.line}")
        if value is not None and t.value != value:
            raise SyntaxError(f"Expected '{value}' got '{t.value}' at line {t.line}")
        return t

    def check(self, ttype: TokenType, value=None) -> bool:
        t = self.peek()
        if t.ttype != ttype:
            return False
        if value is not None and t.value != value:
            return False
        return True

    def match(self, ttype: TokenType, value=None) -> Optional[Token]:
        if self.check(ttype, value):
            return self.advance()
        return None

    def parse_block(self) -> ASTNode:
        block = ASTNode("Block")
        block.line = self.peek().line
        while True:
            t = self.peek()
            if t.ttype == TokenType.EOF:
                break
            if t.ttype == TokenType.KEYWORD and t.value in ("end", "else", "elseif", "until"):
                break
            stmt = self.parse_statement()
            if stmt:
                block.add_child(stmt)
            self.match(TokenType.PUNCT, ";")
        return block

    def parse_statement(self) -> Optional[ASTNode]:
        t = self.peek()

        if t.ttype == TokenType.KEYWORD:
            if t.value == "local":
                return self.parse_local()
            elif t.value == "function":
                return self.parse_function_stat()
            elif t.value == "if":
                return self.parse_if()
            elif t.value == "while":
                return self.parse_while()
            elif t.value == "repeat":
                return self.parse_repeat()
            elif t.value == "for":
                return self.parse_for()
            elif t.value == "do":
                return self.parse_do()
            elif t.value == "return":
                return self.parse_return()
            elif t.value == "break":
                self.advance()
                n = ASTNode("Break")
                n.line = t.line
                return n
            elif t.value == "goto":
                self.advance()
                name = self.expect(TokenType.NAME)
                n = ASTNode("Goto", name=name.value)
                n.line = t.line
                return n

        if t.ttype == TokenType.PUNCT and t.value == "::":
            self.advance()
            name = self.expect(TokenType.NAME)
            self.expect(TokenType.PUNCT, "::")
            n = ASTNode("Label", name=name.value)
            n.line = t.line
            return n

        return self.parse_expr_stat()

    def parse_local(self) -> ASTNode:
        t = self.advance()
        if self.check(TokenType.KEYWORD, "function"):
            self.advance()
            name = self.expect(TokenType.NAME)
            func = self.parse_func_body()
            n = ASTNode("LocalFunction", name=name.value)
            n.line = t.line
            n.add_child(func)
            return n
        names = [self.expect(TokenType.NAME).value]
        while self.match(TokenType.PUNCT, ","):
            names.append(self.expect(TokenType.NAME).value)
        exprs = []
        if self.match(TokenType.OP, "="):
            exprs = self.parse_expr_list()
        n = ASTNode("Local", names=names)
        n.line = t.line
        for e in exprs:
            n.add_child(e)
        return n

    def parse_function_stat(self) -> ASTNode:
        t = self.advance()
        name = self.expect(TokenType.NAME).value
        while self.match(TokenType.PUNCT, "."):
            name += "." + self.expect(TokenType.NAME).value
        method = None
        if self.match(TokenType.PUNCT, ":"):
            method = self.expect(TokenType.NAME).value
        func = self.parse_func_body()
        n = ASTNode("FunctionStat", name=name, method=method)
        n.line = t.line
        n.add_child(func)
        return n

    def parse_func_body(self) -> ASTNode:
        self.expect(TokenType.PUNCT, "(")
        params = []
        vararg = False
        if not self.check(TokenType.PUNCT, ")"):
            while True:
                if self.check(TokenType.OP, "..."):
                    self.advance()
                    vararg = True
                    break
                params.append(self.expect(TokenType.NAME).value)
                if not self.match(TokenType.PUNCT, ","):
                    break
        self.expect(TokenType.PUNCT, ")")
        body = self.parse_block()
        self.expect(TokenType.KEYWORD, "end")
        n = ASTNode("FuncBody", params=params, vararg=vararg)
        n.add_child(body)
        return n

    def parse_if(self) -> ASTNode:
        t = self.advance()
        cond = self.parse_expr()
        self.expect(TokenType.KEYWORD, "then")
        body = self.parse_block()
        n = ASTNode("If")
        n.line = t.line
        n.add_child(cond)
        n.add_child(body)
        while self.check(TokenType.KEYWORD, "elseif"):
            self.advance()
            ec = self.parse_expr()
            self.expect(TokenType.KEYWORD, "then")
            eb = self.parse_block()
            ei = ASTNode("ElseIf")
            ei.add_child(ec)
            ei.add_child(eb)
            n.add_child(ei)
        if self.match(TokenType.KEYWORD, "else"):
            eb = self.parse_block()
            el = ASTNode("Else")
            el.add_child(eb)
            n.add_child(el)
        self.expect(TokenType.KEYWORD, "end")
        return n

    def parse_while(self) -> ASTNode:
        t = self.advance()
        cond = self.parse_expr()
        self.expect(TokenType.KEYWORD, "do")
        body = self.parse_block()
        self.expect(TokenType.KEYWORD, "end")
        n = ASTNode("While")
        n.line = t.line
        n.add_child(cond)
        n.add_child(body)
        return n

    def parse_repeat(self) -> ASTNode:
        t = self.advance()
        body = self.parse_block()
        self.expect(TokenType.KEYWORD, "until")
        cond = self.parse_expr()
        n = ASTNode("Repeat")
        n.line = t.line
        n.add_child(body)
        n.add_child(cond)
        return n

    def parse_for(self) -> ASTNode:
        t = self.advance()
        name = self.expect(TokenType.NAME).value
        if self.match(TokenType.OP, "="):
            start = self.parse_expr()
            self.expect(TokenType.PUNCT, ",")
            stop = self.parse_expr()
            step = None
            if self.match(TokenType.PUNCT, ","):
                step = self.parse_expr()
            self.expect(TokenType.KEYWORD, "do")
            body = self.parse_block()
            self.expect(TokenType.KEYWORD, "end")
            n = ASTNode("NumericFor", var=name)
            n.line = t.line
            n.add_child(start)
            n.add_child(stop)
            if step:
                n.add_child(step)
            n.add_child(body)
        else:
            names = [name]
            while self.match(TokenType.PUNCT, ","):
                names.append(self.expect(TokenType.NAME).value)
            self.expect(TokenType.KEYWORD, "in")
            iters = self.parse_expr_list()
            self.expect(TokenType.KEYWORD, "do")
            body = self.parse_block()
            self.expect(TokenType.KEYWORD, "end")
            n = ASTNode("GenericFor", vars=names)
            n.line = t.line
            for i in iters:
                n.add_child(i)
            n.add_child(body)
        return n

    def parse_do(self) -> ASTNode:
        t = self.advance()
        body = self.parse_block()
        self.expect(TokenType.KEYWORD, "end")
        n = ASTNode("Do")
        n.line = t.line
        n.add_child(body)
        return n

    def parse_return(self) -> ASTNode:
        t = self.advance()
        exprs = []
        if not (
            self.check(TokenType.KEYWORD, "end")
            or self.check(TokenType.KEYWORD, "else")
            or self.check(TokenType.KEYWORD, "elseif")
            or self.check(TokenType.KEYWORD, "until")
            or self.check(TokenType.EOF)
            or self.check(TokenType.PUNCT, ";")
        ):
            exprs = self.parse_expr_list()
        self.match(TokenType.PUNCT, ";")
        n = ASTNode("Return")
        n.line = t.line
        for e in exprs:
            n.add_child(e)
        return n

    def parse_expr_stat(self) -> Optional[ASTNode]:
        e = self.parse_suffixed_expr()
        if e is None:
            return None
        if self.check(TokenType.OP, "=") or self.check(TokenType.PUNCT, ","):
            targets = [e]
            while self.match(TokenType.PUNCT, ","):
                targets.append(self.parse_suffixed_expr())
            self.expect(TokenType.OP, "=")
            values = self.parse_expr_list()
            n = ASTNode("Assign")
            n.line = e.line
            for t2 in targets:
                n.add_child(t2)
            for v in values:
                n.add_child(v)
            return n
        if e.type in ("Call", "MethodCall"):
            n = ASTNode("ExprStat")
            n.line = e.line
            n.add_child(e)
            return n
        return ASTNode("ExprStat")

    def parse_expr_list(self) -> List[ASTNode]:
        exprs = [self.parse_expr()]
        while self.match(TokenType.PUNCT, ","):
            exprs.append(self.parse_expr())
        return exprs

    def parse_expr(self) -> ASTNode:
        return self.parse_or_expr()

    def parse_or_expr(self) -> ASTNode:
        left = self.parse_and_expr()
        while self.check(TokenType.KEYWORD, "or"):
            op = self.advance()
            right = self.parse_and_expr()
            n = ASTNode("BinOp", op="or")
            n.line = op.line
            n.add_child(left)
            n.add_child(right)
            left = n
        return left

    def parse_and_expr(self) -> ASTNode:
        left = self.parse_cmp_expr()
        while self.check(TokenType.KEYWORD, "and"):
            op = self.advance()
            right = self.parse_cmp_expr()
            n = ASTNode("BinOp", op="and")
            n.line = op.line
            n.add_child(left)
            n.add_child(right)
            left = n
        return left

    def parse_cmp_expr(self) -> ASTNode:
        left = self.parse_bitor_expr()
        while self.peek().ttype == TokenType.OP and self.peek().value in ("<", ">", "<=", ">=", "==", "~="):
            op = self.advance()
            right = self.parse_bitor_expr()
            n = ASTNode("BinOp", op=op.value)
            n.line = op.line
            n.add_child(left)
            n.add_child(right)
            left = n
        return left

    def parse_bitor_expr(self) -> ASTNode:
        left = self.parse_bitxor_expr()
        while self.peek().ttype == TokenType.OP and self.peek().value == "|":
            op = self.advance()
            right = self.parse_bitxor_expr()
            n = ASTNode("BinOp", op="|")
            n.line = op.line
            n.add_child(left)
            n.add_child(right)
            left = n
        return left

    def parse_bitxor_expr(self) -> ASTNode:
        left = self.parse_bitand_expr()
        while self.peek().ttype == TokenType.OP and self.peek().value == "~":
            op = self.advance()
            right = self.parse_bitand_expr()
            n = ASTNode("BinOp", op="~")
            n.line = op.line
            n.add_child(left)
            n.add_child(right)
            left = n
        return left

    def parse_bitand_expr(self) -> ASTNode:
        left = self.parse_shift_expr()
        while self.peek().ttype == TokenType.OP and self.peek().value == "&":
            op = self.advance()
            right = self.parse_shift_expr()
            n = ASTNode("BinOp", op="&")
            n.line = op.line
            n.add_child(left)
            n.add_child(right)
            left = n
        return left

    def parse_shift_expr(self) -> ASTNode:
        left = self.parse_concat_expr()
        while self.peek().ttype == TokenType.OP and self.peek().value in ("<<", ">>"):
            op = self.advance()
            right = self.parse_concat_expr()
            n = ASTNode("BinOp", op=op.value)
            n.line = op.line
            n.add_child(left)
            n.add_child(right)
            left = n
        return left

    def parse_concat_expr(self) -> ASTNode:
        left = self.parse_add_expr()
        if self.check(TokenType.OP, ".."):
            op = self.advance()
            right = self.parse_concat_expr()
            n = ASTNode("BinOp", op="..")
            n.line = op.line
            n.add_child(left)
            n.add_child(right)
            return n
        return left

    def parse_add_expr(self) -> ASTNode:
        left = self.parse_mul_expr()
        while self.peek().ttype == TokenType.OP and self.peek().value in ("+", "-"):
            op = self.advance()
            right = self.parse_mul_expr()
            n = ASTNode("BinOp", op=op.value)
            n.line = op.line
            n.add_child(left)
            n.add_child(right)
            left = n
        return left

    def parse_mul_expr(self) -> ASTNode:
        left = self.parse_unary_expr()
        while self.peek().ttype == TokenType.OP and self.peek().value in ("*", "/", "%", "//"):
            op = self.advance()
            right = self.parse_unary_expr()
            n = ASTNode("BinOp", op=op.value)
            n.line = op.line
            n.add_child(left)
            n.add_child(right)
            left = n
        return left

    def parse_unary_expr(self) -> ASTNode:
        t = self.peek()
        if t.ttype == TokenType.KEYWORD and t.value == "not":
            self.advance()
            e = self.parse_unary_expr()
            n = ASTNode("UnOp", op="not")
            n.line = t.line
            n.add_child(e)
            return n
        if t.ttype == TokenType.OP and t.value in ("-", "#", "~"):
            self.advance()
            e = self.parse_unary_expr()
            n = ASTNode("UnOp", op=t.value)
            n.line = t.line
            n.add_child(e)
            return n
        return self.parse_pow_expr()

    def parse_pow_expr(self) -> ASTNode:
        base = self.parse_suffixed_expr()
        if base and self.check(TokenType.OP, "^"):
            op = self.advance()
            exp = self.parse_unary_expr()
            n = ASTNode("BinOp", op="^")
            n.line = op.line
            n.add_child(base)
            n.add_child(exp)
            return n
        return base

    def parse_suffixed_expr(self) -> Optional[ASTNode]:
        base = self.parse_primary_expr()
        if base is None:
            return None
        while True:
            t = self.peek()
            if t.ttype == TokenType.PUNCT and t.value == ".":
                self.advance()
                field = self.expect(TokenType.NAME)
                n = ASTNode("Index", field=field.value)
                n.line = t.line
                n.add_child(base)
                base = n
            elif t.ttype == TokenType.PUNCT and t.value == "[":
                self.advance()
                idx = self.parse_expr()
                self.expect(TokenType.PUNCT, "]")
                n = ASTNode("IndexExpr")
                n.line = t.line
                n.add_child(base)
                n.add_child(idx)
                base = n
            elif t.ttype == TokenType.PUNCT and t.value == ":":
                self.advance()
                method = self.expect(TokenType.NAME)
                args = self.parse_call_args()
                n = ASTNode("MethodCall", method=method.value)
                n.line = t.line
                n.add_child(base)
                for a in args:
                    n.add_child(a)
                base = n
            elif (t.ttype == TokenType.PUNCT and t.value in ("(", "{")) or t.ttype == TokenType.STRING:
                args = self.parse_call_args()
                n = ASTNode("Call")
                n.line = t.line
                n.add_child(base)
                for a in args:
                    n.add_child(a)
                base = n
            else:
                break
        return base

    def parse_call_args(self) -> List[ASTNode]:
        t = self.peek()
        if t.ttype == TokenType.PUNCT and t.value == "(":
            self.advance()
            args = []
            if not self.check(TokenType.PUNCT, ")"):
                args = self.parse_expr_list()
            self.expect(TokenType.PUNCT, ")")
            return args
        elif t.ttype == TokenType.PUNCT and t.value == "{":
            return [self.parse_table_constructor()]
        elif t.ttype == TokenType.STRING:
            tok = self.advance()
            n = ASTNode("String", value=tok.value)
            n.line = tok.line
            return [n]
        return []

    def parse_primary_expr(self) -> Optional[ASTNode]:
        t = self.peek()
        if t.ttype == TokenType.NAME:
            self.advance()
            n = ASTNode("Name", value=t.value)
            n.line = t.line
            return n
        if t.ttype == TokenType.PUNCT and t.value == "(":
            self.advance()
            e = self.parse_expr()
            self.expect(TokenType.PUNCT, ")")
            n = ASTNode("Paren")
            n.line = t.line
            n.add_child(e)
            return n
        if t.ttype == TokenType.NUMBER:
            self.advance()
            n = ASTNode("Number", value=t.value)
            n.line = t.line
            return n
        if t.ttype == TokenType.STRING:
            self.advance()
            n = ASTNode("String", value=t.value)
            n.line = t.line
            return n
        if t.ttype == TokenType.KEYWORD and t.value in ("true", "false", "nil"):
            self.advance()
            n = ASTNode("Literal", value=t.value)
            n.line = t.line
            return n
        if t.ttype == TokenType.OP and t.value == "...":
            self.advance()
            n = ASTNode("Vararg")
            n.line = t.line
            return n
        if t.ttype == TokenType.KEYWORD and t.value == "function":
            self.advance()
            func = self.parse_func_body()
            func.line = t.line
            return func
        if t.ttype == TokenType.PUNCT and t.value == "{":
            return self.parse_table_constructor()
        return None

    def parse_table_constructor(self) -> ASTNode:
        t = self.advance()
        n = ASTNode("Table")
        n.line = t.line
        while not self.check(TokenType.PUNCT, "}"):
            if self.check(TokenType.PUNCT, "["):
                self.advance()
                key = self.parse_expr()
                self.expect(TokenType.PUNCT, "]")
                self.expect(TokenType.OP, "=")
                val = self.parse_expr()
                field = ASTNode("TableField", kind="expr")
                field.add_child(key)
                field.add_child(val)
                n.add_child(field)
            elif self.check(TokenType.NAME) and self.peek(1).value == "=":
                name = self.advance()
                self.advance()
                val = self.parse_expr()
                field = ASTNode("TableField", kind="name", key=name.value)
                field.add_child(val)
                n.add_child(field)
            else:
                val = self.parse_expr()
                field = ASTNode("TableField", kind="positional")
                field.add_child(val)
                n.add_child(field)
            if not (self.match(TokenType.PUNCT, ",") or self.match(TokenType.PUNCT, ";")):
                break
        self.expect(TokenType.PUNCT, "}")
        return n

    def parse(self) -> ASTNode:
        root = ASTNode("Chunk")
        root.add_child(self.parse_block())
        return root


class VMFingerprint:
    MOONSEC_V3 = "moonsec_v3"
    MOONSEC_V2 = "moonsec_v2"
    MOONSEC_V1 = "moonsec_v1"
    IRONBREW2 = "ironbrew2"
    IRONBREW = "ironbrew"
    PROMETHEUS = "prometheus"
    MOONVEIL = "moonveil"
    LURAPH = "luraph"
    LURAPH_V11 = "luraph_v11"
    LURAPH_V13 = "luraph_v13"
    LURAPH_V14 = "luraph_v14"
    LUAOBFUSCATOR = "luaobfuscator"
    BORONIDE = "boronide"
    BYTECODE_LUA = "bytecode_lua"
    AZTUPBREW = "aztupbrew"
    XFUSCATOR = "xfuscator"
    HYPERION = "hyperion"
    PSU = "psu"
    WEAREDEVS = "wearedevs"
    LUACC = "luacc"
    SIMPLE = "simple"
    UNKNOWN = "unknown"

    COMMENT_SIGNATURES = {
        MOONSEC_V3: [
            r"moonsec", r"MoonSec", r"MoonSecurity",
            r"MoonSec\s*V3", r"MoonSecV3", r"moonsec_v3",
        ],
        MOONSEC_V2: [r"MoonSec\s*V2", r"MoonSecV2", r"moonsec_v2"],
        MOONSEC_V1: [r"MoonSec\s*V1", r"MoonSecV1", r"moonsec_v1"],
        IRONBREW2: [
            r"IronBrew", r"Wrapped by IronBrew", r"IronBrew2",
            r"ironbrew-2", r"ironbrew2",
        ],
        IRONBREW: [r"ironbrew-", r"IronBrew\s*1", r"IronBrewV1"],
        PROMETHEUS: [
            r"Prometheus", r"prometheus_vm", r"Prometheus Obfuscator",
            r"prometheus-", r"prometheusv",
        ],
        MOONVEIL: [r"MoonVeil", r"moonveil", r"moonveil_wrap", r"moonveil-"],
        LURAPH_V13: [r"Luraph\s*[vV]13", r"luraph_v13", r"LuraphV13", r"Luraph13"],
        LURAPH_V11: [
            r"Luraph\s*[vV]11", r"luraph_v11", r"Fvh3n",
            r"Luraph\s*11\.", r"Luraph11",
        ],
        LURAPH_V14: [
            r"Luraph\s*[vV]14", r"luraph_v14", r"LuraphV14",
            r"Luraph14", r"Luraph\s*14\.",
        ],
        LURAPH: [r"Luraph", r"luraph\.net", r"luraph-"],
        LUAOBFUSCATOR: [
            r"luaobfuscator\.com", r"LuaObfuscator",
            r"Obfuscated with LuaObfuscator", r"luaobfuscator-",
        ],
        BORONIDE: [
            r"boronide", r"Boronide", r"Boron Obfuscator",
            r"BoronObf", r"boron-",
        ],
        AZTUPBREW: [r"AztupBrew", r"aztupbrew", r"Aztup"],
        XFUSCATOR: [r"XFuscator", r"xfuscator", r"x-fuscator"],
        HYPERION: [r"Hyperion", r"hyperion_obf", r"HyperionObf"],
        PSU: [r"PSU\s*Obfuscator", r"psu_obf", r"PSU4|PSU5"],
        WEAREDEVS: [r"WeAreDevs", r"wearedevs\.net", r"WRD"],
        LUACC: [r"Luacc", r"luacc_obf"],
    }

    STRUCTURAL_SIGNATURES = {
        MOONSEC_V3: [
            (r"local\s+\w+\s*=\s*\{[^\}]{800,}\}", 1.4),
            (r"for\s+\w+\s*=\s*1\s*,\s*#\w+\s*do\s*\w+\[\w+\]\s*=\s*\w+\[\w+\]\s*~\s*\w+", 1.2),
            (r"local\s+\w+\s*=\s*\(\s*function\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)", 1.1),
            (r"string\.byte\s*\(\s*\w+\s*,\s*\w+\s*\)\s*[%\^]\s*\d+", 1.0),
            (r"bit\.bxor|bit32\.bxor", 0.9),
            (r"local\s+\w+\s*=\s*\{[^\}]{2000,}\}\s*local\s+\w+\s*=\s*\{", 1.1),
            (r"\w+\s*=\s*\w+\s*-\s*\d+\s*\w+\s*=\s*\w+\s*%\s*256", 0.9),
        ],
        MOONSEC_V2: [
            (r"local\s+\w+\s*=\s*\{(?:\s*\d+\s*,\s*){100,}\}", 1.3),
            (r"string\.char\(string\.byte", 1.0),
            (r"local\s+\w+\s*=\s*\"\\\d+\"", 0.9),
            (r"for\s+\w+\s*=\s*1\s*,\s*#\w+\s*do\s*\w+\s*=\s*\w+\s*\+\s*\w+", 0.8),
        ],
        MOONSEC_V1: [
            (r"local\s+\w+\s*=\s*\{\s*\d+\s*,\s*\d+\s*,\s*\d+", 0.8),
            (r"string\.char\s*\(\s*\w+\s*\)", 0.7),
        ],
        IRONBREW2: [
            (r"local\s+\w+\s*=\s*\(function\(\)", 1.4),
            (r"Stack\s*=\s*\{\}", 1.3),
            (r"Opcode|opcode\s*=\s*\w+\[\w+\]", 1.2),
            (r"local\s+\w+\s*=\s*\{\s*\d+\s*,\s*\d+\s*,\s*\d+", 0.9),
            (r"while\s+true\s+do\s*local\s+\w+\s*=\s*\w+\[\w+\]", 1.0),
            (r"InstructionPointer|Instruction\s*Pointer|\bIP\b", 0.9),
        ],
        IRONBREW: [
            (r"local\s+\w+\s*=\s*\(function\(\)\s*local\s+\w+\s*=", 0.9),
            (r"\bif\s+\w+\s*==\s*0\s*then\s*return", 0.8),
        ],
        PROMETHEUS: [
            (r"PrometheusSettings", 1.5),
            (r"local\s+\w+\s*=\s*\{\s*\d+\s*;\s*\d+\s*;\s*\d+", 1.0),
            (r"local\s+Prometheus", 1.3),
            (r"Prometheus\s*=\s*\{\}", 1.4),
            (r"Prometheus\s*\.\s*\w+\s*=", 1.1),
        ],
        MOONVEIL: [
            (r"local\s+\w+\s*=\s*\{[0-9,\s]{200,}\}", 1.3),
            (r"local\s+\w+\s*=\s*\{\s*\d+\s*,\s*\d+\s*\}\s*local", 0.8),
            (r"Moonveil|moonveil", 1.5),
        ],
        LURAPH_V13: [
            (r"local\s+\w+\s*=\s*\{(?:\s*\d+\s*,\s*){300,}\d+\s*\}", 1.5),
            (r"bit\s*\.\s*bxor\s*\(\s*\w+\s*,\s*\w+\s*\)\s*%\s*256", 1.2),
            (r"local\s+\w+\s*=\s*\{(?:\s*\d+\s*,\s*){200,}\}", 1.4),
        ],
        LURAPH_V11: [
            (r"local\s+\w+\s*=\s*\{(?:\s*\d+\s*,\s*){200,}\d+\s*\}", 1.5),
            (r"for\s+\w+\s*=\s*0\s*,\s*#\w+\s*-\s*1\s*do\s*\w+\[\w+\]\s*=\s*\w+\[\w+\+1\]\s*~\s*\w+\[\w+\s*%\s*#\w+\s*\+\s*1\]", 1.5),
            (r"local\s+\w+\s*=\s*\{\s*(?:\d+\s*,\s*){30,}\d+\s*\}\s*local\s+\w+\s*=\s*\"[A-Za-z0-9+/]{20,}", 1.3),
            (r"bit\s*\.\s*bxor\s*\(\s*\w+\s*,\s*\w+\s*\)\s*%\s*256", 1.2),
            (r"string\.byte\s*\(\s*\w+\s*,\s*\w+\s*\)\s*[%\^]\s*\d+", 1.0),
            (r"local\s+\w+\s*=\s*\{(?:\s*\d+\s*,\s*){150,}\}", 1.4),
            (r"\w+\[\w+\]\s*=\s*\w+\[\w+\]\s*-\s*\w+", 0.8),
        ],
        LURAPH_V14: [
            (r"local\s+\w+\s*=\s*\{(?:\s*\d+\s*,\s*){400,}\d+\s*\}", 1.6),
            (r"local\s+\w+\s*=\s*\{[^\}]+\}\s*local\s+\w+\s*=\s*\{[^\}]+\}\s*local\s+\w+\s*=\s*loadstring", 1.4),
            (r"for\s+\w+\s*=\s*1\s*,\s*#\w+\s*do\s*\w+\[\w+\]\s*=\s*\w+\[\w+\]\s*~\s*\w+\[\w+\s*%\s*#\w+\s*\+\s*1\]", 1.3),
            (r"local\s+\w+\s*=\s*\(\s*function\s*\([^)]{0,50}\)\s*local\s+\w+\s*=\s*\{\s*(?:\d+\s*,\s*){100,}", 1.2),
            (r"bit\s*\.\s*bxor\s*\(\s*\w+\s*,\s*\w+\s*\)\s*%\s*256", 1.0),
            (r"local\s+\w+\s*=\s*\{(?:\s*\d+\s*,\s*){300,}\}", 1.5),
            (r"\w+\s*=\s*\w+\s*~\s*\w+\s*%\s*256", 0.9),
            (r"local\s+\w+\s*=\s*\{[^\}]{5000,}\}", 1.2),
        ],
        LURAPH: [
            (r"local\s+\w+\s*=\s*\{(?:[0-9]+,\s*){50,}[0-9]+\}", 1.0),
            (r"Fvh3n", 0.8),
            (r"Luraph", 1.0),
        ],
        LUAOBFUSCATOR: [
            (r"local\s+[lI]{6,}\s*=", 1.4),
            (r"string\.char\(\s*(?:\d+\s*,\s*){5,}\d+\s*\)", 1.2),
            (r"function\s+[lI1O0]{5,}\s*\(", 1.3),
            (r"\bloadstring\s*\(\s*\w+\s*\(\s*\w+\s*,\s*\w+\s*\)\s*\)", 1.1),
            (r"rawget\s*\(\s*getfenv\s*\(", 0.9),
            (r"local\s+[lI]{4,}\s*=\s*\{", 1.0),
        ],
        BORONIDE: [
            (r"local\s+\w+\s*=\s*\{\s*(?:0x[0-9a-fA-F]+\s*,\s*){20,}", 1.4),
            (r"string\.byte\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)", 1.0),
            (r"bit32\.(bxor|band|bor|bnot|rshift|lshift)", 1.2),
            (r"local\s+\w+\s*=\s*loadstring\s*or\s*load", 1.0),
            (r"table\.concat\s*\(\s*\w+\s*,\s*[\"']\s*[\"']\s*\)", 1.1),
        ],
        BYTECODE_LUA: [
            (r"\x1bLua", 2.0),
            (r"\\27Lua|\\x1bLua", 1.5),
            (r"local\s+\w+\s*=\s*\{\s*27\s*,\s*76\s*,\s*117\s*,\s*97", 1.4),
            (r"loadstring\s*\(\s*string\.char\s*\(\s*27\s*,\s*76\s*,\s*117\s*,\s*97", 1.6),
        ],
        AZTUPBREW: [
            (r"local\s+\w+\s*=\s*\{(?:\s*\d+\s*,\s*){100,}\}\s*local\s+\w+\s*=\s*\{(?:\s*\d+\s*,\s*){10,}", 1.3),
            (r"string\.char\s*\(\s*\w+\s*%\s*256", 1.0),
        ],
        XFUSCATOR: [
            (r"local\s+\w+\s*=\s*\{\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+", 1.0),
            (r"XFuscator|xfuscator", 1.5),
        ],
        HYPERION: [
            (r"Hyperion|hyperion", 1.5),
            (r"__HYPERION", 1.5),
        ],
        PSU: [
            (r"PSU|psu_obf", 1.3),
            (r"local\s+\w+\s*=\s*require\s*\(\s*\"psu", 1.2),
        ],
        WEAREDEVS: [
            (r"wearedevs|WeAreDevs", 1.5),
            (r"WRD\s*Obfuscator", 1.4),
        ],
        LUACC: [
            (r"luacc|Luacc", 1.3),
        ],
    }

    @classmethod
    def identify(cls, source: str) -> str:
        comment_scores: Dict[str, float] = defaultdict(float)
        for vm_type, patterns in cls.COMMENT_SIGNATURES.items():
            for p in patterns:
                try:
                    if re.search(p, source, re.IGNORECASE):
                        comment_scores[vm_type] += 2.5
                except re.error:
                    pass

        if comment_scores:
            best_comment = max(comment_scores, key=lambda k: comment_scores[k])
            if comment_scores[best_comment] >= 2.5:
                if best_comment == cls.LURAPH:
                    if re.search(r"luraph_v14|LuraphV14|Luraph\s*[vV]14", source, re.IGNORECASE):
                        return cls.LURAPH_V14
                    if re.search(r"luraph_v13|LuraphV13|Luraph\s*[vV]13", source, re.IGNORECASE):
                        return cls.LURAPH_V13
                    if re.search(r"luraph_v11|Luraph\s*[vV]11", source, re.IGNORECASE):
                        return cls.LURAPH_V11
                    if re.search(r"Luraph14|14\.\d", source):
                        return cls.LURAPH_V14
                return best_comment

        scores: Dict[str, float] = defaultdict(float)
        for vm_type, patterns in cls.STRUCTURAL_SIGNATURES.items():
            for p, weight in patterns:
                try:
                    matches = re.findall(p, source, re.DOTALL)
                    if matches:
                        scores[vm_type] += weight * min(len(matches), 3)
                except re.error:
                    pass

        if not scores:
            return cls.UNKNOWN

        best = max(scores, key=lambda k: scores[k])

        if best == cls.LURAPH:
            if scores.get(cls.LURAPH_V14, 0) > scores.get(cls.LURAPH_V11, 0):
                return cls.LURAPH_V14 if scores.get(cls.LURAPH_V14, 0) > 0 else cls.LURAPH
            if scores.get(cls.LURAPH_V13, 0) > 0:
                return cls.LURAPH_V13
            if scores.get(cls.LURAPH_V11, 0) > 0:
                return cls.LURAPH_V11

        if best == cls.LURAPH_V14:
            return cls.LURAPH_V14
        if best == cls.LURAPH_V13:
            return cls.LURAPH_V13
        if best == cls.LURAPH_V11:
            return cls.LURAPH_V11

        return best

    @classmethod
    def identify_all(cls, source: str) -> List[str]:
        scores: Dict[str, float] = defaultdict(float)
        for vm_type, patterns in cls.COMMENT_SIGNATURES.items():
            for p in patterns:
                try:
                    if re.search(p, source, re.IGNORECASE):
                        scores[vm_type] += 2.5
                except re.error:
                    pass
        for vm_type, patterns in cls.STRUCTURAL_SIGNATURES.items():
            for p, weight in patterns:
                try:
                    if re.search(p, source, re.DOTALL):
                        scores[vm_type] += weight
                except re.error:
                    pass
        detected = sorted([k for k, v in scores.items() if v > 0], key=lambda k: -scores[k])
        return detected if detected else [cls.UNKNOWN]


class RC4:
    @staticmethod
    def ksa(key: bytes) -> List[int]:
        S = list(range(256))
        j = 0
        klen = len(key)
        if klen == 0:
            return S
        for i in range(256):
            j = (j + S[i] + key[i % klen]) & 0xFF
            S[i], S[j] = S[j], S[i]
        return S

    @staticmethod
    def prga(S: List[int], length: int) -> bytes:
        out = bytearray()
        i = 0
        j = 0
        for _ in range(length):
            i = (i + 1) & 0xFF
            j = (j + S[i]) & 0xFF
            S[i], S[j] = S[j], S[i]
            out.append(S[(S[i] + S[j]) & 0xFF])
        return bytes(out)

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        S = RC4.ksa(key)
        keystream = RC4.prga(S, len(data))
        return bytes(a ^ b for a, b in zip(data, keystream))


class XTEA:
    DELTA = 0x9E3779B9

    @staticmethod
    def decrypt_block(v0: int, v1: int, key: List[int], rounds: int = 32) -> Tuple[int, int]:
        v0 &= 0xFFFFFFFF
        v1 &= 0xFFFFFFFF
        s = (XTEA.DELTA * rounds) & 0xFFFFFFFF
        for _ in range(rounds):
            v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + key[(s >> 11) & 3]))) & 0xFFFFFFFF
            s = (s - XTEA.DELTA) & 0xFFFFFFFF
            v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + key[s & 3]))) & 0xFFFFFFFF
        return v0, v1

    @staticmethod
    def decrypt(data: bytes, key: List[int]) -> bytes:
        if len(data) % 8 != 0:
            data = data + b"\x00" * (8 - len(data) % 8)
        out = bytearray()
        for i in range(0, len(data), 8):
            v0 = struct.unpack("<I", data[i:i + 4])[0]
            v1 = struct.unpack("<I", data[i + 4:i + 8])[0]
            dv0, dv1 = XTEA.decrypt_block(v0, v1, key)
            out += struct.pack("<I", dv0)
            out += struct.pack("<I", dv1)
        return bytes(out)


class TEA:
    DELTA = 0x9E3779B9

    @staticmethod
    def decrypt_block(v0: int, v1: int, key: List[int], rounds: int = 32) -> Tuple[int, int]:
        v0 &= 0xFFFFFFFF
        v1 &= 0xFFFFFFFF
        s = (TEA.DELTA * rounds) & 0xFFFFFFFF
        for _ in range(rounds):
            v1 = (v1 - ((((v0 << 4) + key[2]) ^ (v0 + s) ^ ((v0 >> 5) + key[3])))) & 0xFFFFFFFF
            v0 = (v0 - ((((v1 << 4) + key[0]) ^ (v1 + s) ^ ((v1 >> 5) + key[1])))) & 0xFFFFFFFF
            s = (s - TEA.DELTA) & 0xFFFFFFFF
        return v0, v1

    @staticmethod
    def decrypt(data: bytes, key: List[int]) -> bytes:
        if len(data) % 8 != 0:
            data = data + b"\x00" * (8 - len(data) % 8)
        out = bytearray()
        for i in range(0, len(data), 8):
            v0 = struct.unpack("<I", data[i:i + 4])[0]
            v1 = struct.unpack("<I", data[i + 4:i + 8])[0]
            dv0, dv1 = TEA.decrypt_block(v0, v1, key)
            out += struct.pack("<I", dv0)
            out += struct.pack("<I", dv1)
        return bytes(out)


class XXTEA:
    DELTA = 0x9E3779B9

    @staticmethod
    def mx(sum_: int, y: int, z: int, p: int, e: int, k: List[int]) -> int:
        return (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum_ ^ y) + (k[(p & 3) ^ e] ^ z))) & 0xFFFFFFFF

    @staticmethod
    def decrypt(data: bytes, key: List[int]) -> bytes:
        if len(data) < 8:
            return data
        v = list(struct.unpack("<" + "I" * (len(data) // 4), data[:len(data) // 4 * 4]))
        n = len(v)
        if n < 2:
            return data
        k = key + [0] * (4 - len(key))
        q = 6 + 52 // n
        sum_ = (q * XXTEA.DELTA) & 0xFFFFFFFF
        y = v[0]
        while sum_ != 0:
            e = (sum_ >> 2) & 3
            for p in range(n - 1, 0, -1):
                z = v[p - 1]
                v[p] = (v[p] - XXTEA.mx(sum_, y, z, p, e, k)) & 0xFFFFFFFF
                y = v[p]
            z = v[n - 1]
            v[0] = (v[0] - XXTEA.mx(sum_, y, z, 0, e, k)) & 0xFFFFFFFF
            y = v[0]
            sum_ = (sum_ - XXTEA.DELTA) & 0xFFFFFFFF
        out = bytearray()
        for val in v:
            out += struct.pack("<I", val)
        return bytes(out)


class VMHandler:
    def __init__(self, case_num: int, ast: Optional[ASTNode], raw_text: str, line: int = 0):
        self.case_num = case_num
        self.ast = ast
        self.raw_text = raw_text
        self.line = line
        self.std_opcode: Optional[int] = None
        self.semantic: Optional[str] = None
        self.confidence: float = 0.0
        self.register_reads: List[int] = []
        self.register_writes: List[int] = []
        self.const_indices: List[int] = []
        self.upvalue_refs: List[int] = []
        self.is_jump: bool = False
        self.is_call: bool = False
        self.is_return: bool = False
        self.semantic_tags: List[str] = []
        self.jump_targets: List[int] = []
        self.offset_start: int = 0
        self.offset_end: int = 0
        self.bytes_size: int = 0
        self.jump_delta: Optional[int] = None
        self.stack_effect: int = 0

    def __repr__(self):
        return f"VMHandler(case={self.case_num}, sem={self.semantic}, std={self.std_opcode}, tags={self.semantic_tags})"


class VMExtractor:
    def __init__(self, source: str, ast: Optional[ASTNode] = None):
        self.source = source
        self.ast = ast
        self.matcher = BracketMatcher(source)
        self.dispatcher_var: Optional[str] = None
        self.pc_var: Optional[str] = None
        self.stack_var: Optional[str] = None
        self.const_var: Optional[str] = None
        self.opcode_table_var: Optional[str] = None
        self.handlers: Dict[int, VMHandler] = {}
        self.vm_functions: List[ASTNode] = []
        self.instruction_count: int = 0
        self.jump_targets: Dict[int, int] = {}
        self.dispatchers: List[Dict[str, Any]] = []
        self.handler_offsets: Dict[int, Tuple[int, int]] = {}
        self.opcode_map: Dict[int, str] = {}
        self.semantic_map: Dict[int, str] = {}

    def extract(self) -> Dict[str, Any]:
        self._detect_vm_variables()
        self._find_dispatchers_structural()
        self._analyze_instruction_format()
        return {
            "dispatcher_var": self.dispatcher_var,
            "pc_var": self.pc_var,
            "stack_var": self.stack_var,
            "const_var": self.const_var,
            "handlers": self.handlers,
            "instruction_count": self.instruction_count,
            "dispatchers": self.dispatchers,
            "handler_offsets": self.handler_offsets,
            "opcode_map": self.opcode_map,
            "semantic_map": self.semantic_map,
        }

    def _detect_vm_variables(self):
        patterns = {
            "pc": [
                r"local\s+(\w+)\s*=\s*1\s*;?\s*while\s+true\s+do",
                r"local\s+(\w+)\s*=\s*1\s*;?\s*repeat",
                r"local\s+(\w+)\s*=\s*1\s*;?\s*for\s+\w+\s*=\s*1\s*,\s*#",
                r"local\s+(\w+)\s*=\s*0\s*;?\s*while",
            ],
            "stack": [
                r"local\s+(\w+)\s*=\s*\{\s*\}[\s\S]{0,400}?while",
                r"local\s+(\w+)\s*=\s*\{\s*\}\s*local\s+\w+\s*=\s*\{",
            ],
            "const": [
                r"local\s+(\w+)\s*=\s*\{[^}]{80,}\}\s*;?\s*local\s+\w+\s*=",
                r"local\s+(\w+)\s*=\s*\{[^}]{80,}\}",
            ],
            "opcode_table": [
                r"local\s+(\w+)\s*=\s*\{\s*(?:0x[0-9a-fA-F]+|\d+)(?:\s*,\s*(?:0x[0-9a-fA-F]+|\d+)){5,}",
                r"local\s+(\w+)\s*=\s*\{[^}]{50,}\}\s*;?\s*local\s+\w+\s*=\s*1",
            ],
        }
        for role, pats in patterns.items():
            for p in pats:
                m = re.search(p, self.source, re.DOTALL)
                if m:
                    name = m.group(1)
                    if role == "pc":
                        self.pc_var = name
                    elif role == "stack":
                        self.stack_var = name
                    elif role == "const":
                        self.const_var = name
                    elif role == "opcode_table":
                        self.opcode_table_var = name
                    break

    def _find_dispatchers_structural(self):
        if self.ast is not None:
            found: List[ASTNode] = []
            for node in self.ast.walk():
                if node.type == "While" or node.type == "Repeat":
                    for child in node.children:
                        if child.type == "Block":
                            for stmt in child.children:
                                if stmt.type == "If" and self._count_branches(stmt) >= 3:
                                    found.append(stmt)
                                    self._extract_handlers_from_dispatcher(stmt)
                                    break
            if found:
                self.dispatchers = [{"ast": f} for f in found]

        disp_matches = list(re.finditer(
            r"(?:while\s+(?:true|\w+\s*<[^\n]+)\s+do|repeat|for\s+\w+\s*=\s*1\s*,\s*#\w+\s+do)",
            self.source,
        ))
        for dm in disp_matches:
            start = dm.start()
            if dm.group(0).startswith("while"):
                do_m = re.search(r"\bdo\b", self.source[start:start + 200])
                if not do_m:
                    continue
                body_start = start + do_m.end()
                end_pos = self.matcher.find_block_end(body_start)
                if end_pos <= 0:
                    continue
                body = self.source[start:end_pos]
                branches = len(re.findall(r"\belseif\b", body))
                if branches >= 3:
                    self._extract_handlers_from_text(body, start)
            elif dm.group(0).startswith("repeat"):
                body_start = dm.end()
                until_m = re.search(r"\buntil\b", self.source[body_start:body_start + 30000])
                if not until_m:
                    continue
                body = self.source[body_start:body_start + until_m.start()]
                branches = len(re.findall(r"\belseif\b", body))
                if branches >= 3:
                    self._extract_handlers_from_text(body, start)
            elif dm.group(0).startswith("for"):
                do_m = re.search(r"\bdo\b", self.source[start:start + 200])
                if not do_m:
                    continue
                body_start = start + do_m.end()
                end_pos = self.matcher.find_block_end(body_start)
                if end_pos <= 0:
                    continue
                body = self.source[start:end_pos]
                branches = len(re.findall(r"\belseif\b", body))
                if branches >= 3:
                    self._extract_handlers_from_text(body, start)

        self.instruction_count = max(self.handlers.keys(), default=-1) + 1

    def _count_branches(self, if_node: ASTNode) -> int:
        return sum(1 for c in if_node.children if c.type == "ElseIf")

    def _extract_handlers_from_dispatcher(self, dispatcher: ASTNode):
        for child in dispatcher.children:
            if child.type == "ElseIf":
                cond = child.children[0] if child.children else None
                if cond and cond.type == "BinOp" and cond.attrs.get("op") == "==":
                    rhs = cond.children[1] if len(cond.children) > 1 else None
                    if rhs and rhs.type == "Number":
                        case_num = int(rhs.attrs["value"])
                        body = child.children[1] if len(child.children) > 1 else None
                        raw_text = self._node_to_text(body) if body else ""
                        handler = VMHandler(case_num, body, raw_text, child.line)
                        self._classify_handler(handler)
                        self.handlers[case_num] = handler

    def _extract_handlers_from_text(self, text: str, global_offset: int):
        s = text
        n = len(s)
        i = 0
        while i < n:
            m = re.search(r"\b(if|elseif)\b", s[i:])
            if not m:
                break
            kw_start = i + m.start()
            kw = m.group(1)
            cond_start = kw_start + len(kw)
            eq_match = re.search(r"==\s*(0x[0-9a-fA-F]+|\d+)", s[cond_start:cond_start + 200])
            if not eq_match:
                i = kw_start + len(kw)
                continue
            try:
                case_num = int(eq_match.group(1), 0)
            except Exception:
                i = kw_start + len(kw)
                continue
            then_m = re.search(r"\bthen\b", s[cond_start:cond_start + 400])
            if not then_m:
                i = kw_start + len(kw)
                continue
            body_start = cond_start + then_m.end()
            end_pos = -1
            depth = 0
            j = body_start
            while j < n:
                c = s[j]
                if c in "\"'":
                    q = c
                    j += 1
                    while j < n:
                        if s[j] == "\\":
                            j += 2
                            continue
                        if s[j] == q:
                            j += 1
                            break
                        if s[j] == "\n":
                            break
                        j += 1
                    continue
                if c == "-" and j + 1 < n and s[j + 1] == "-":
                    while j < n and s[j] != "\n":
                        j += 1
                    continue
                if c.isalpha() or c == "_":
                    ws = j
                    while j < n and (s[j].isalnum() or s[j] == "_"):
                        j += 1
                    w = s[ws:j]
                    if w in ("if", "for", "while", "function", "do", "repeat", "then"):
                        depth += 1
                    elif w in ("end", "until"):
                        if depth == 0:
                            end_pos = ws
                            break
                        depth -= 1
                        if depth == 0:
                            end_pos = ws
                            break
                    continue
                j += 1
            if end_pos < 0:
                i = kw_start + len(kw)
                continue
            handler_body = s[body_start:end_pos].strip()
            prev = self.handlers.get(case_num)
            if prev is None or len(handler_body) > len(prev.raw_text):
                h = VMHandler(case_num, None, handler_body, kw_start)
                h.offset_start = global_offset + body_start
                h.offset_end = global_offset + end_pos
                h.bytes_size = h.offset_end - h.offset_start
                self._classify_handler(h)
                self.handlers[case_num] = h
                self.handler_offsets[case_num] = (h.offset_start, h.offset_end)
            i = end_pos + 3

    def _node_to_text(self, node: Optional[ASTNode]) -> str:
        if node is None:
            return ""
        parts = []
        if node.attrs:
            parts.append(str(node.attrs))
        if node.type == "Name":
            parts.append(str(node.attrs.get("value", "")))
        if node.type == "Number":
            parts.append(str(node.attrs.get("value", "")))
        for c in node.children:
            parts.append(self._node_to_text(c))
        return " ".join(parts)

    def _classify_handler(self, handler: VMHandler):
        text = handler.raw_text
        best_sem: Optional[str] = None
        best_score = 0.0
        best_eff = 0
        for sem, patterns, base_conf, eff in VM_PATTERN_TABLE:
            score = 0.0
            for pat in patterns:
                try:
                    if re.search(pat, text, re.IGNORECASE):
                        score += 1.0
                except re.error:
                    pass
            if score > 0:
                conf = min(base_conf + 0.03 * (score - 1), 0.99)
                if conf > best_score:
                    best_score = conf
                    best_sem = sem
                    best_eff = eff
        if best_sem:
            handler.semantic = best_sem
            handler.confidence = best_score
            handler.stack_effect = best_eff
            self.semantic_map[handler.case_num] = best_sem

        lua_op_map = {
            VMOpcodeSemantics.MOVE: LuaOpcode.OP_MOVE,
            VMOpcodeSemantics.LOADK: LuaOpcode.OP_LOADK,
            VMOpcodeSemantics.LOADBOOL: LuaOpcode.OP_LOADBOOL,
            VMOpcodeSemantics.LOADNIL: LuaOpcode.OP_LOADNIL,
            VMOpcodeSemantics.GETUPVAL: LuaOpcode.OP_GETUPVAL,
            VMOpcodeSemantics.SETUPVAL: LuaOpcode.OP_SETUPVAL,
            VMOpcodeSemantics.GETGLOBAL: LuaOpcode.OP_GETGLOBAL,
            VMOpcodeSemantics.SETGLOBAL: LuaOpcode.OP_SETGLOBAL,
            VMOpcodeSemantics.GETTABLE: LuaOpcode.OP_GETTABLE,
            VMOpcodeSemantics.SETTABLE: LuaOpcode.OP_SETTABLE,
            VMOpcodeSemantics.NEWTABLE: LuaOpcode.OP_NEWTABLE,
            VMOpcodeSemantics.SELF: LuaOpcode.OP_SELF,
            VMOpcodeSemantics.ADD: LuaOpcode.OP_ADD,
            VMOpcodeSemantics.SUB: LuaOpcode.OP_SUB,
            VMOpcodeSemantics.MUL: LuaOpcode.OP_MUL,
            VMOpcodeSemantics.DIV: LuaOpcode.OP_DIV,
            VMOpcodeSemantics.MOD: LuaOpcode.OP_MOD,
            VMOpcodeSemantics.POW: LuaOpcode.OP_POW,
            VMOpcodeSemantics.UNM: LuaOpcode.OP_UNM,
            VMOpcodeSemantics.NOT: LuaOpcode.OP_NOT,
            VMOpcodeSemantics.LEN: LuaOpcode.OP_LEN,
            VMOpcodeSemantics.CONCAT: LuaOpcode.OP_CONCAT,
            VMOpcodeSemantics.JMP: LuaOpcode.OP_JMP,
            VMOpcodeSemantics.EQ: LuaOpcode.OP_EQ,
            VMOpcodeSemantics.LT: LuaOpcode.OP_LT,
            VMOpcodeSemantics.LE: LuaOpcode.OP_LE,
            VMOpcodeSemantics.TEST: LuaOpcode.OP_TEST,
            VMOpcodeSemantics.TESTSET: LuaOpcode.OP_TESTSET,
            VMOpcodeSemantics.CALL: LuaOpcode.OP_CALL,
            VMOpcodeSemantics.TAILCALL: LuaOpcode.OP_TAILCALL,
            VMOpcodeSemantics.RETURN: LuaOpcode.OP_RETURN,
            VMOpcodeSemantics.FORLOOP: LuaOpcode.OP_FORLOOP,
            VMOpcodeSemantics.FORPREP: LuaOpcode.OP_FORPREP,
            VMOpcodeSemantics.TFORLOOP: LuaOpcode.OP_TFORLOOP,
            VMOpcodeSemantics.SETLIST: LuaOpcode.OP_SETLIST,
            VMOpcodeSemantics.CLOSE: LuaOpcode.OP_CLOSE,
            VMOpcodeSemantics.CLOSURE: LuaOpcode.OP_CLOSURE,
            VMOpcodeSemantics.VARARG: LuaOpcode.OP_VARARG,
        }
        if best_sem and best_sem in lua_op_map:
            handler.std_opcode = int(lua_op_map[best_sem])

        self._extract_registers(handler)

    def _extract_registers(self, handler: VMHandler):
        text = handler.raw_text
        writes = re.findall(r"(\w+)\[(\d+|\w+)\]\s*=", text)
        reads = re.findall(r"=\s*\w+\[(\d+|\w+)\]", text)
        for var, idx in writes:
            if idx.isdigit():
                handler.register_writes.append(int(idx))
        for idx in reads:
            if idx.isdigit():
                handler.register_reads.append(int(idx))
        for m in re.finditer(r"\{[^{}]*\}", text):
            inner = m.group(0)
            nums = re.findall(r"\b\d+\b", inner)
            for x in nums[:20]:
                try:
                    handler.const_indices.append(int(x))
                except Exception:
                    pass

    def _analyze_instruction_format(self):
        if self.pc_var:
            pat = re.search(
                rf"{re.escape(self.pc_var)}\s*=\s*{re.escape(self.pc_var)}\s*\+\s*(\d+)",
                self.source,
            )
            if pat:
                pass


class LuraphV11Decoder:
    @staticmethod
    def detect_version(source: str) -> Optional[str]:
        m = re.search(r"Luraph\s*[vV](\d+\.\d+)", source, re.IGNORECASE)
        if m:
            return m.group(1)
        if re.search(r"luraph_v11|LURAPH_V11", source, re.IGNORECASE):
            return "11.x"
        if re.search(r"Luraph\s*11\.(\d+)", source):
            m2 = re.search(r"Luraph\s*11\.(\d+)", source)
            if m2:
                return "11." + m2.group(1)
        return None

    @staticmethod
    def extract_payload_and_key(source: str) -> Optional[Tuple[List[int], List[int]]]:
        payload_pat = None
        for threshold in (200, 150, 100, 80, 60, 40):
            payload_pat = re.search(
                rf"local\s+\w+\s*=\s*\{{((?:\s*\d+\s*,\s*){{{threshold},}}\d+)\}}",
                source, re.DOTALL,
            )
            if payload_pat:
                break
        if not payload_pat:
            for threshold in (200, 100, 50):
                payload_pat = re.search(
                    rf"local\s+\w+\s*=\s*\{{\s*((?:\s*\d+\s*,\s*){{{threshold},}})\s*\}}",
                    source, re.DOTALL,
                )
                if payload_pat:
                    break
        if not payload_pat:
            return None
        payload_raw = payload_pat.group(1)
        payload = [int(x.strip()) for x in re.findall(r"\d+", payload_raw)]

        tail = source[payload_pat.end():payload_pat.end() + 12000]

        inline_key_pat = re.search(
            r"local\s+\w+\s*=\s*\{((?:\s*\d+\s*,\s*){4,64}\d+)\}",
            tail, re.DOTALL,
        )
        if inline_key_pat:
            key = [int(x.strip()) for x in re.findall(r"\d+", inline_key_pat.group(1))]
            if all(0 <= k <= 255 for k in key):
                return payload, key

        b64_key_pat = re.search(r'"([A-Za-z0-9+/]{8,128}={0,2})"', tail)
        if b64_key_pat:
            try:
                key = list(base64.b64decode(b64_key_pat.group(1) + "=" * (-len(b64_key_pat.group(1)) % 4)))
                return payload, key
            except Exception:
                pass

        hex_esc_key = re.search(r'"((?:\\x[0-9a-fA-F]{2}){4,64})"', tail)
        if hex_esc_key:
            try:
                key = [int(x, 16) for x in re.findall(r"\\x([0-9a-fA-F]{2})", hex_esc_key.group(1))]
                return payload, key
            except Exception:
                pass

        raw_str_key = re.search(r'"((?:\\[0-9]{1,3}){8,})"', tail)
        if raw_str_key:
            try:
                key = [int(x) for x in re.findall(r"\\(\d{1,3})", raw_str_key.group(1)) if int(x) <= 255]
                if key:
                    return payload, key
            except Exception:
                pass

        str_char_key = re.search(r"string\.char\(((?:\s*\d+\s*,\s*){4,64}\d+)\)", tail)
        if str_char_key:
            key = [int(x.strip()) for x in str_char_key.group(1).split(",")]
            if all(0 <= k <= 255 for k in key):
                return payload, key

        return payload, []

    @staticmethod
    def _derive_key_variants(payload: List[int]) -> List[List[int]]:
        variants: List[List[int]] = []
        if len(payload) >= 16:
            variants.append([payload[i] & 0xFF for i in range(min(16, len(payload)))])
            variants.append([payload[i] for i in range(0, min(32, len(payload)), 2)])
            variants.append([(payload[i] + payload[i + 1]) & 0xFF for i in range(0, min(32, len(payload)) - 1, 2)])
            variants.append([(payload[i] ^ payload[i + 1]) & 0xFF for i in range(0, min(32, len(payload)) - 1, 2)])
            variants.append([(payload[i] - payload[i + 1]) & 0xFF for i in range(0, min(32, len(payload)) - 1, 2)])
            variants.append([payload[i] for i in range(min(32, len(payload)) - 16, min(32, len(payload)))])
            variants.append([(payload[i] * 31 + 7) & 0xFF for i in range(min(16, len(payload)))])
            variants.append([(payload[i] ^ 0x5A) & 0xFF for i in range(min(16, len(payload)))])
            variants.append([((payload[i] << 1) | (payload[i] >> 7)) & 0xFF for i in range(min(16, len(payload)))])
            variants.append([((payload[i] >> 1) | (payload[i] << 7)) & 0xFF for i in range(min(16, len(payload)))])
        return variants

    @staticmethod
    def _validate(decoded: bytes) -> Optional[str]:
        if not decoded:
            return None
        if decoded[:4] == b"\x1bLua":
            try:
                parser = LuaBytecodeParser(decoded)
                proto = parser.parse()
                if proto and len(proto.instructions) > 0:
                    return LuaCodegen(proto).generate()
            except Exception:
                pass
            return None

        printable = sum(1 for c in decoded[:2048] if 32 <= c < 127 or c in (9, 10, 13))
        ratio = printable / max(min(len(decoded), 2048), 1)
        if ratio > 0.88:
            try:
                text = decoded.decode("utf-8")
                if any(kw in text for kw in ("local ", "function", "return", "if ", "end", "then", "print", "for ", "while")):
                    return text
            except Exception:
                pass
        return None

    @staticmethod
    def decode_v11(source: str) -> str:
        result = LuraphV11Decoder.extract_payload_and_key(source)
        if result is None:
            return source
        payload, key = result

        if key:
            klen = len(key)
            decoded = bytes([(payload[i] ^ key[i % klen]) & 0xFF for i in range(len(payload))])
            out = LuraphV11Decoder._validate(decoded)
            if out:
                return out
            for xk in range(256):
                re_dec = bytes([(b ^ xk) & 0xFF for b in decoded])
                out = LuraphV11Decoder._validate(re_dec)
                if out:
                    return out
            try:
                rc4_dec = RC4.decrypt(bytes(payload), bytes(key))
                out = LuraphV11Decoder._validate(rc4_dec)
                if out:
                    return out
            except Exception:
                pass

        for xk in range(256):
            decoded = bytes([(b ^ xk) & 0xFF for b in payload])
            out = LuraphV11Decoder._validate(decoded)
            if out:
                return out

        for derived in LuraphV11Decoder._derive_key_variants(payload):
            if not derived:
                continue
            klen = len(derived)
            decoded = bytes([(payload[i] ^ derived[i % klen]) & 0xFF for i in range(len(payload))])
            out = LuraphV11Decoder._validate(decoded)
            if out:
                return out

        for start in range(256):
            for step in (1, 3, 5, 7, 13, 17, 31, 63, 127):
                key_c = start
                dec = bytearray(len(payload))
                for i, b in enumerate(payload):
                    dec[i] = b ^ key_c
                    key_c = (key_c + step) & 0xFF
                out = LuraphV11Decoder._validate(bytes(dec))
                if out:
                    return out

        for add in range(256):
            decoded = bytes([(b - add) & 0xFF for b in payload])
            out = LuraphV11Decoder._validate(decoded)
            if out:
                return out
            decoded = bytes([(b + add) & 0xFF for b in payload])
            out = LuraphV11Decoder._validate(decoded)
            if out:
                return out

        if len(payload) > 32:
            for window in (4, 8, 16, 32):
                if len(payload) <= window:
                    continue
                derived = bytes([(payload[i] ^ payload[i + window]) & 0xFF for i in range(window)])
                decoded = bytes([(payload[i] ^ derived[i % window]) & 0xFF for i in range(len(payload))])
                out = LuraphV11Decoder._validate(decoded)
                if out:
                    return out

        if key:
            for mult in (2, 3, 5, 7, 11, 13, 17, 31, 63, 127, 255):
                scaled_key = bytes([(k * mult) & 0xFF for k in key])
                decoded = bytes([(payload[i] ^ scaled_key[i % len(scaled_key)]) & 0xFF for i in range(len(payload))])
                out = LuraphV11Decoder._validate(decoded)
                if out:
                    return out

        if len(payload) > 64:
            for period in (2, 3, 4, 5, 6, 8, 10, 12, 16):
                for base in range(256):
                    derived = bytes([(base + i * period) & 0xFF for i in range(period)])
                    decoded = bytes([(payload[i] ^ derived[i % period]) & 0xFF for i in range(len(payload))])
                    out = LuraphV11Decoder._validate(decoded)
                    if out:
                        return out

        if key:
            for rot in range(1, min(16, len(key))):
                rot_key = bytes(key[rot:] + key[:rot])
                klen = len(rot_key)
                decoded = bytes([(payload[i] ^ rot_key[i % klen]) & 0xFF for i in range(len(payload))])
                out = LuraphV11Decoder._validate(decoded)
                if out:
                    return out

        return source

    @staticmethod
    def strip_vm_wrapper(source: str) -> str:
        source = re.sub(
            r"local\s+\w+\s*=\s*\(\s*function\s*\([^)]{0,80}\)\s*local\s+\w+\s*=\s*\{(?:\d+,?\s*){100,}\}",
            "", source, flags=re.DOTALL,
        )
        source = re.sub(
            r"for\s+\w+\s*=\s*0\s*,\s*#\w+\s*-\s*1\s*do\s*\w+\[\w+\]\s*=\s*\w+\[\w+\+1\]\s*~\s*\w+\[\w+\s*%\s*#\w+\s*\+\s*1\]\s*end",
            "", source, flags=re.DOTALL,
        )
        source = re.sub(
            r"bit\.bxor\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)",
            lambda m: f"({m.group(1)} ~ {m.group(2)})",
            source,
        )
        return source


class LuraphV13Decoder:
    @staticmethod
    def detect_version(source: str) -> Optional[str]:
        m = re.search(r"Luraph\s*[vV](\d+\.\d+)", source, re.IGNORECASE)
        if m:
            return m.group(1)
        if re.search(r"luraph_v13|LURAPH_V13|LuraphV13|Luraph13", source, re.IGNORECASE):
            return "13.x"
        m2 = re.search(r"Luraph\s*13\.(\d+)", source)
        if m2:
            return "13." + m2.group(1)
        return None

    @staticmethod
    def extract_v13_payload(source: str) -> Optional[Tuple[List[int], bytes, str]]:
        payload_pat = None
        for threshold in (300, 200, 150, 100, 60, 40):
            payload_pat = re.search(
                rf"local\s+\w+\s*=\s*\{{((?:\s*\d+\s*,\s*){{{threshold},}}\d+)\}}",
                source, re.DOTALL,
            )
            if payload_pat:
                break
        if not payload_pat:
            for threshold in (300, 200, 100):
                payload_pat = re.search(
                    rf"local\s+\w+\s*=\s*\{{\s*((?:\s*\d+\s*,\s*){{{threshold},}})\s*\}}",
                    source, re.DOTALL,
                )
                if payload_pat:
                    break
        if not payload_pat:
            return None
        payload_raw = payload_pat.group(1)
        payload = [int(x.strip()) for x in re.findall(r"\d+", payload_raw)]

        after = source[payload_pat.end():payload_pat.end() + 14000]

        b64_key = re.search(r'"([A-Za-z0-9+/]{16,}={0,2})"', after)
        if b64_key:
            try:
                key_bytes = base64.b64decode(b64_key.group(1) + "=" * (-len(b64_key.group(1)) % 4))
                if key_bytes:
                    return payload, key_bytes, "base64"
            except Exception:
                pass

        raw_str_key = re.search(r'"((?:\\[0-9]{1,3}){8,})"', after)
        if raw_str_key:
            try:
                raw = raw_str_key.group(1)
                key_bytes = bytes([int(x) for x in re.findall(r"\\(\d+)", raw) if int(x) <= 255])
                if key_bytes:
                    return payload, key_bytes, "rawstr"
            except Exception:
                pass

        inline_key_pat = re.search(
            r"local\s+\w+\s*=\s*\{((?:\s*\d+\s*,\s*){4,64}\d+)\}",
            after, re.DOTALL,
        )
        if inline_key_pat:
            key_list = [int(x.strip()) for x in re.findall(r"\d+", inline_key_pat.group(1))]
            if all(0 <= k <= 255 for k in key_list):
                return payload, bytes(key_list), "inline"

        str_char_key = re.search(r"string\.char\(((?:\s*\d+\s*,\s*){4,128}\d+)\)", after)
        if str_char_key:
            key_list = [int(x.strip()) for x in str_char_key.group(1).split(",")]
            if all(0 <= k <= 255 for k in key_list):
                return payload, bytes(key_list), "string_char"

        return payload, b"", "unknown"

    @staticmethod
    def _validate(decoded: bytes) -> Optional[str]:
        if not decoded:
            return None
        if decoded[:4] == b"\x1bLua":
            try:
                parser = LuaBytecodeParser(decoded)
                proto = parser.parse()
                if proto and len(proto.instructions) > 0:
                    return LuaCodegen(proto).generate()
            except Exception:
                pass
            return None
        printable = sum(1 for c in decoded[:4096] if 32 <= c < 127 or c in (9, 10, 13))
        ratio = printable / max(min(len(decoded), 4096), 1)
        if ratio > 0.88:
            try:
                text = decoded.decode("utf-8")
                if any(kw in text for kw in ("local ", "function", "return", "if ", "end", "then", "print")):
                    return text
            except Exception:
                pass
        return None

    @staticmethod
    def decode_v13(source: str) -> str:
        result = LuraphV13Decoder.extract_v13_payload(source)
        if result is None:
            return source
        payload, key_bytes, key_type = result

        if key_bytes:
            klen = len(key_bytes)
            decoded = bytes([(payload[i] ^ key_bytes[i % klen]) & 0xFF for i in range(len(payload))])
            lifted = LuraphV13Decoder._validate(decoded)
            if lifted:
                return lifted
            try:
                rc4_dec = RC4.decrypt(bytes(payload), key_bytes)
                lifted = LuraphV13Decoder._validate(rc4_dec)
                if lifted:
                    return lifted
            except Exception:
                pass
            try:
                xtea_key = [int.from_bytes(key_bytes[i:i + 4], "little") for i in range(0, min(16, len(key_bytes)) - 3, 4)]
                if len(xtea_key) == 4:
                    xtea_dec = XTEA.decrypt(bytes(payload), xtea_key)
                    lifted = LuraphV13Decoder._validate(xtea_dec)
                    if lifted:
                        return lifted
            except Exception:
                pass
            try:
                tea_key = [int.from_bytes(key_bytes[i:i + 4], "little") for i in range(0, min(16, len(key_bytes)) - 3, 4)]
                if len(tea_key) == 4:
                    tea_dec = TEA.decrypt(bytes(payload), tea_key)
                    lifted = LuraphV13Decoder._validate(tea_dec)
                    if lifted:
                        return lifted
            except Exception:
                pass
            try:
                xxtea_key = [int.from_bytes(key_bytes[i:i + 4], "little") for i in range(0, min(16, len(key_bytes)) - 3, 4)]
                if len(xxtea_key) == 4:
                    xxtea_dec = XXTEA.decrypt(bytes(payload), xxtea_key)
                    lifted = LuraphV13Decoder._validate(xxtea_dec)
                    if lifted:
                        return lifted
            except Exception:
                pass

        for xk in range(256):
            decoded = bytes([(b ^ xk) & 0xFF for b in payload])
            lifted = LuraphV13Decoder._validate(decoded)
            if lifted:
                return lifted

        for start in range(256):
            for step in (1, 3, 5, 7, 11, 13, 17, 31, 63, 127):
                key_c = start
                dec = bytearray(len(payload))
                for i, b in enumerate(payload):
                    dec[i] = b ^ key_c
                    key_c = (key_c + step) & 0xFF
                lifted = LuraphV13Decoder._validate(bytes(dec))
                if lifted:
                    return lifted

        for add in range(256):
            decoded = bytes([(b - add) & 0xFF for b in payload])
            lifted = LuraphV13Decoder._validate(decoded)
            if lifted:
                return lifted
            decoded = bytes([(b + add) & 0xFF for b in payload])
            lifted = LuraphV13Decoder._validate(decoded)
            if lifted:
                return lifted

        if key_bytes:
            for mult in (2, 3, 5, 7, 11, 13, 17, 31, 63, 127, 251):
                scaled_key = bytes([(k * mult) & 0xFF for k in key_bytes])
                klen = len(scaled_key)
                decoded = bytes([(payload[i] ^ scaled_key[i % klen]) & 0xFF for i in range(len(payload))])
                lifted = LuraphV13Decoder._validate(decoded)
                if lifted:
                    return lifted

        if len(payload) > 64:
            for deriv_len in (4, 8, 16, 32, 64):
                if len(payload) <= deriv_len:
                    continue
                derived_key = bytes([(payload[i] ^ payload[i + deriv_len]) & 0xFF for i in range(deriv_len)])
                if any(derived_key):
                    klen = len(derived_key)
                    decoded = bytes([(payload[i] ^ derived_key[i % klen]) & 0xFF for i in range(len(payload))])
                    lifted = LuraphV13Decoder._validate(decoded)
                    if lifted:
                        return lifted

        return source

    @staticmethod
    def strip_vm_wrapper(source: str) -> str:
        source = re.sub(
            r"local\s+\w+\s*=\s*\(\s*function\s*\([^)]{0,100}\)\s*(?:local\s+\w+\s*=\s*\{(?:\d+,?\s*){100,}\}[\s\S]{0,5000}?)end\s*\)\s*\(\s*\)",
            "", source, flags=re.DOTALL,
        )
        return source


class LuraphV14Decoder:
    @staticmethod
    def detect_version(source: str) -> Optional[str]:
        m = re.search(r"Luraph\s*[vV](\d+\.\d+)", source, re.IGNORECASE)
        if m:
            return m.group(1)
        if re.search(r"luraph_v14|LURAPH_V14|LuraphV14|Luraph14", source, re.IGNORECASE):
            return "14.x"
        m2 = re.search(r"Luraph\s*14\.(\d+)", source)
        if m2:
            return "14." + m2.group(1)
        return None

    @staticmethod
    def extract_v14_payload(source: str) -> Optional[Tuple[List[int], bytes, str]]:
        payload_pat = None
        for threshold in (400, 300, 200, 100, 60, 40):
            payload_pat = re.search(
                rf"local\s+\w+\s*=\s*\{{((?:\s*\d+\s*,\s*){{{threshold},}}\d+)\}}",
                source, re.DOTALL,
            )
            if payload_pat:
                break
        if not payload_pat:
            for threshold in (400, 200, 100):
                payload_pat = re.search(
                    rf"local\s+\w+\s*=\s*\{{\s*((?:\s*\d+\s*,\s*){{{threshold},}})\s*\}}",
                    source, re.DOTALL,
                )
                if payload_pat:
                    break
        if not payload_pat:
            return None
        payload_raw = payload_pat.group(1)
        payload = [int(x.strip()) for x in re.findall(r"\d+", payload_raw)]

        after = source[payload_pat.end():payload_pat.end() + 16000]

        b64_key = re.search(r'"([A-Za-z0-9+/]{16,}={0,2})"', after)
        if b64_key:
            try:
                key_bytes = base64.b64decode(b64_key.group(1) + "=" * (-len(b64_key.group(1)) % 4))
                if key_bytes:
                    return payload, key_bytes, "base64"
            except Exception:
                pass

        raw_str_key = re.search(r'"((?:\\[0-9]{1,3}){8,})"', after)
        if raw_str_key:
            try:
                raw = raw_str_key.group(1)
                key_bytes = bytes([int(x) for x in re.findall(r"\\(\d+)", raw) if int(x) <= 255])
                if key_bytes:
                    return payload, key_bytes, "rawstr"
            except Exception:
                pass

        inline_key_pat = re.search(
            r"local\s+\w+\s*=\s*\{((?:\s*\d+\s*,\s*){4,64}\d+)\}",
            after, re.DOTALL,
        )
        if inline_key_pat:
            key_list = [int(x.strip()) for x in re.findall(r"\d+", inline_key_pat.group(1))]
            if all(0 <= k <= 255 for k in key_list):
                return payload, bytes(key_list), "inline"

        hex_str_key = re.search(r'"((?:\\x[0-9a-fA-F]{2}){8,})"', after)
        if hex_str_key:
            try:
                raw = hex_str_key.group(1)
                key_bytes = bytes([int(x, 16) for x in re.findall(r"\\x([0-9a-fA-F]{2})", raw)])
                if key_bytes:
                    return payload, key_bytes, "hex_escape"
            except Exception:
                pass

        str_char_key = re.search(r"string\.char\(((?:\s*\d+\s*,\s*){4,128}\d+)\)", after)
        if str_char_key:
            key_list = [int(x.strip()) for x in str_char_key.group(1).split(",")]
            if all(0 <= k <= 255 for k in key_list):
                return payload, bytes(key_list), "string_char"

        return payload, b"", "unknown"

    @staticmethod
    def _try_decode_with_key(payload: List[int], key: bytes) -> Optional[bytes]:
        if not key:
            return None
        klen = len(key)
        return bytes([(payload[i] ^ key[i % klen]) & 0xFF for i in range(len(payload))])

    @staticmethod
    def _validate(decoded: bytes) -> Optional[str]:
        if not decoded:
            return None
        if decoded[:4] == b"\x1bLua":
            try:
                parser = LuaBytecodeParser(decoded)
                proto = parser.parse()
                if proto and len(proto.instructions) > 0:
                    return LuaCodegen(proto).generate()
            except Exception:
                pass
            return None

        printable = sum(1 for c in decoded[:4096] if 32 <= c < 127 or c in (9, 10, 13))
        ratio = printable / max(min(len(decoded), 4096), 1)
        if ratio > 0.88:
            try:
                text = decoded.decode("utf-8")
                if any(kw in text for kw in ("local ", "function", "return", "if ", "end", "then", "print")):
                    return text
            except Exception:
                pass
        return None

    @staticmethod
    def decode_v14(source: str) -> str:
        result = LuraphV14Decoder.extract_v14_payload(source)
        if result is None:
            return source

        payload, key_bytes, key_type = result

        if key_bytes:
            decoded = LuraphV14Decoder._try_decode_with_key(payload, key_bytes)
            if decoded:
                lifted = LuraphV14Decoder._validate(decoded)
                if lifted:
                    return lifted
            try:
                rc4_dec = RC4.decrypt(bytes(payload), key_bytes)
                lifted = LuraphV14Decoder._validate(rc4_dec)
                if lifted:
                    return lifted
            except Exception:
                pass
            try:
                xtea_key = [int.from_bytes(key_bytes[i:i + 4], "little") for i in range(0, min(16, len(key_bytes)) - 3, 4)]
                if len(xtea_key) == 4:
                    xtea_dec = XTEA.decrypt(bytes(payload), xtea_key)
                    lifted = LuraphV14Decoder._validate(xtea_dec)
                    if lifted:
                        return lifted
            except Exception:
                pass
            try:
                xxtea_key = [int.from_bytes(key_bytes[i:i + 4], "little") for i in range(0, min(16, len(key_bytes)) - 3, 4)]
                if len(xxtea_key) == 4:
                    xxtea_dec = XXTEA.decrypt(bytes(payload), xxtea_key)
                    lifted = LuraphV14Decoder._validate(xxtea_dec)
                    if lifted:
                        return lifted
            except Exception:
                pass

        for xk in range(256):
            decoded = bytes([(b ^ xk) & 0xFF for b in payload])
            lifted = LuraphV14Decoder._validate(decoded)
            if lifted:
                return lifted

        if key_bytes:
            for xk in range(256):
                secondary_key = bytes([(kb ^ xk) & 0xFF for kb in key_bytes])
                decoded = LuraphV14Decoder._try_decode_with_key(payload, secondary_key)
                if decoded:
                    lifted = LuraphV14Decoder._validate(decoded)
                    if lifted:
                        return lifted

        rolling_variants = [
            lambda i, b: (b ^ (i & 0xFF)) & 0xFF,
            lambda i, b: (b ^ ((i * 3 + 7) & 0xFF)) & 0xFF,
            lambda i, b: (b ^ ((i * 5 + 11) & 0xFF)) & 0xFF,
            lambda i, b: (b - i) & 0xFF,
            lambda i, b: (b + i) & 0xFF,
            lambda i, b: (b ^ (0x5A + ((i * 17) & 0xFF))) & 0xFF,
            lambda i, b: (b ^ ((i >> 1) & 0xFF)) & 0xFF,
            lambda i, b: (b ^ (0xA5 + ((i * 13) & 0xFF))) & 0xFF,
            lambda i, b: (b ^ ((i * 7 + 3) & 0xFF)) & 0xFF,
            lambda i, b: (b ^ ((i * 11 + 5) & 0xFF)) & 0xFF,
        ]
        for fn in rolling_variants:
            decoded = bytes([fn(i, payload[i]) for i in range(len(payload))])
            lifted = LuraphV14Decoder._validate(decoded)
            if lifted:
                return lifted

        if len(payload) > 32:
            for deriv_len in (4, 8, 16, 32, 64):
                if len(payload) <= deriv_len:
                    continue
                derived_key = bytes([(payload[i] ^ payload[i + deriv_len]) & 0xFF for i in range(deriv_len)])
                if any(derived_key):
                    decoded = LuraphV14Decoder._try_decode_with_key(payload, derived_key)
                    if decoded:
                        lifted = LuraphV14Decoder._validate(decoded)
                        if lifted:
                            return lifted

        for start in range(256):
            for step in (1, 3, 5, 7, 11, 13, 17, 31, 63, 127):
                key_c = start
                dec = bytearray(len(payload))
                for i, b in enumerate(payload):
                    dec[i] = b ^ key_c
                    key_c = (key_c + step) & 0xFF
                lifted = LuraphV14Decoder._validate(bytes(dec))
                if lifted:
                    return lifted

        for add in range(256):
            decoded = bytes([(b - add) & 0xFF for b in payload])
            lifted = LuraphV14Decoder._validate(decoded)
            if lifted:
                return lifted
            decoded = bytes([(b + add) & 0xFF for b in payload])
            lifted = LuraphV14Decoder._validate(decoded)
            if lifted:
                return lifted

        if key_bytes:
            for mult in (2, 3, 5, 7, 11, 13, 17, 31, 63, 127, 251, 253):
                scaled_key = bytes([(k * mult) & 0xFF for k in key_bytes])
                decoded = LuraphV14Decoder._try_decode_with_key(payload, scaled_key)
                if decoded:
                    lifted = LuraphV14Decoder._validate(decoded)
                    if lifted:
                        return lifted

        if len(payload) > 128:
            key_len = min(64, len(payload) // 4)
            for salt in (0x00, 0x55, 0xAA, 0xFF, 0x5A, 0xA5):
                for base in range(256):
                    candidate_key = bytes([(base + salt * i) & 0xFF for i in range(key_len)])
                    decoded = LuraphV14Decoder._try_decode_with_key(payload, candidate_key)
                    if decoded and decoded[:4] == b"\x1bLua":
                        lifted = LuraphV14Decoder._validate(decoded)
                        if lifted:
                            return lifted

        return source

    @staticmethod
    def strip_vm_wrapper(source: str) -> str:
        source = re.sub(
            r"local\s+\w+\s*=\s*\(\s*function\s*\([^)]{0,100}\)\s*(?:local\s+\w+\s*=\s*\{(?:\d+,?\s*){100,}\}[\s\S]{0,5000}?)end\s*\)\s*\(\s*\)",
            "", source, flags=re.DOTALL,
        )
        source = re.sub(
            r"if\s+\w+\s*~=\s*\w+\s*then\s*(?:error|os\.exit)\s*\(.*?\)\s*end",
            "", source, flags=re.DOTALL,
        )
        source = re.sub(
            r"local\s+\w+\s*=\s*0\s*for\s+\w+\s*=\s*1\s*,\s*#\w+\s*do\s*\w+\s*=\s*\w+\s*\*\s*31\s*\+\s*string\.byte\s*\(\s*\w+\s*,\s*\w+\s*\)\s*end",
            "", source, flags=re.DOTALL,
        )
        return source


class MoonSecV3Decoder:
    @staticmethod
    def detect(source: str) -> bool:
        return bool(re.search(r"moonsec|MoonSec", source, re.IGNORECASE) or
                    re.search(r"local\s+\w+\s*=\s*\{[^\}]{800,}\}", source, re.DOTALL))

    @staticmethod
    def extract_string_pool(source: str) -> Optional[List[int]]:
        best = None
        best_len = 0
        for m in re.finditer(r"local\s+\w+\s*=\s*\{((?:\s*\d+\s*,\s*){80,}\d+)\}", source, re.DOTALL):
            nums = [int(x.strip()) for x in re.findall(r"\d+", m.group(1))]
            if all(0 <= n <= 255 for n in nums) and len(nums) > best_len:
                best = nums
                best_len = len(nums)
        if not best:
            for m in re.finditer(r"\{((?:\s*\d+\s*,\s*){80,}\d+)\}", source, re.DOTALL):
                nums = [int(x.strip()) for x in re.findall(r"\d+", m.group(1))]
                if all(0 <= n <= 255 for n in nums) and len(nums) > best_len:
                    best = nums
                    best_len = len(nums)
        return best

    @staticmethod
    def extract_arithmetic_decoder(source: str) -> Optional[Dict[str, Any]]:
        m = re.search(
            r"for\s+\w+\s*=\s*1\s*,\s*#\w+\s*do\s*\w+\s*\[\s*\w+\s*\]\s*=\s*\(\s*\w+\s*\[\s*\w+\s*\]\s*([+\-*])\s*(\d+)\s*\)\s*%\s*(\d+)",
            source, re.DOTALL,
        )
        if m:
            return {"op": m.group(1), "operand": int(m.group(2)), "modulo": int(m.group(3))}
        m = re.search(
            r"\w+\s*\[\s*\w+\s*\]\s*=\s*\w+\s*\[\s*\w+\s*\]\s*([+\-])\s*(\d+)",
            source,
        )
        if m:
            return {"op": m.group(1), "operand": int(m.group(2)), "modulo": 256}
        return None

    @staticmethod
    def _plausible(text: str) -> bool:
        if not text or len(text) < 4:
            return False
        printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\n\r\t")
        if printable / len(text) < 0.88:
            return False
        return any(kw in text for kw in (
            "local", "function", "return", "end", "then", "if ",
            "print", "for ", "while", "do ", "else", "elseif",
            "game", "script", "Instance", "workspace", "wait",
        ))

    @staticmethod
    def decode_string_pool(payload: List[int], arithmetic: Optional[Dict[str, Any]] = None) -> Optional[str]:
        if arithmetic:
            op = arithmetic.get("op", "+")
            operand = arithmetic.get("operand", 0)
            modulo = arithmetic.get("modulo", 256)
            recovered = []
            for b in payload:
                if op == "+":
                    recovered.append((b - operand) % modulo & 0xFF)
                elif op == "-":
                    recovered.append((b + operand) % modulo & 0xFF)
                elif op == "*":
                    inv = None
                    for i in range(modulo):
                        if (operand * i) % modulo == 1:
                            inv = i
                            break
                    if inv is not None:
                        recovered.append((b * inv) % modulo & 0xFF)
                    else:
                        recovered.append(b & 0xFF)
                else:
                    recovered.append(b & 0xFF)
            try:
                text = bytes(recovered).decode("utf-8")
                if MoonSecV3Decoder._plausible(text):
                    return text
            except Exception:
                pass

        for xk in range(256):
            decoded = bytes([(b ^ xk) & 0xFF for b in payload])
            try:
                text = decoded.decode("utf-8")
                if MoonSecV3Decoder._plausible(text):
                    return text
            except Exception:
                pass

        for roll in range(256):
            decoded = bytes([(payload[i] ^ ((roll + i) & 0xFF)) & 0xFF for i in range(len(payload))])
            try:
                text = decoded.decode("utf-8")
                if MoonSecV3Decoder._plausible(text):
                    return text
            except Exception:
                pass

        for roll in range(256):
            for step in (1, 3, 5, 7, 13, 17, 31):
                key = roll
                dec = bytearray(len(payload))
                for i, b in enumerate(payload):
                    dec[i] = b ^ key
                    key = (key + step) & 0xFF
                try:
                    text = bytes(dec).decode("utf-8")
                    if MoonSecV3Decoder._plausible(text):
                        return text
                except Exception:
                    pass

        for sub in range(256):
            decoded = bytes([(b - sub) & 0xFF for b in payload])
            try:
                text = decoded.decode("utf-8")
                if MoonSecV3Decoder._plausible(text):
                    return text
            except Exception:
                pass

        for add in range(256):
            decoded = bytes([(b + add) & 0xFF for b in payload])
            try:
                text = decoded.decode("utf-8")
                if MoonSecV3Decoder._plausible(text):
                    return text
            except Exception:
                pass

        for key_len in (4, 8, 16, 32):
            if len(payload) <= key_len:
                continue
            derived = bytes([(payload[i] ^ payload[i + key_len]) & 0xFF for i in range(key_len)])
            if any(derived):
                decoded = bytes([(payload[i] ^ derived[i % key_len]) & 0xFF for i in range(len(payload))])
                try:
                    text = decoded.decode("utf-8")
                    if MoonSecV3Decoder._plausible(text):
                        return text
                except Exception:
                    pass

        return None

    @staticmethod
    def decode(source: str) -> str:
        pool = MoonSecV3Decoder.extract_string_pool(source)
        if pool:
            arithmetic = MoonSecV3Decoder.extract_arithmetic_decoder(source)
            decoded = MoonSecV3Decoder.decode_string_pool(pool, arithmetic)
            if decoded:
                return decoded
        return source


class MoonSecV2Decoder:
    @staticmethod
    def detect(source: str) -> bool:
        return bool(re.search(r"MoonSec\s*V2|MoonSecV2", source, re.IGNORECASE))

    @staticmethod
    def decode(source: str) -> str:
        pool = MoonSecV3Decoder.extract_string_pool(source)
        if pool:
            arithmetic = MoonSecV3Decoder.extract_arithmetic_decoder(source)
            decoded = MoonSecV3Decoder.decode_string_pool(pool, arithmetic)
            if decoded:
                return decoded
        return source


class MoonSecV1Decoder:
    @staticmethod
    def detect(source: str) -> bool:
        return bool(re.search(r"MoonSec\s*V1|MoonSecV1", source, re.IGNORECASE))

    @staticmethod
    def decode(source: str) -> str:
        pool = MoonSecV3Decoder.extract_string_pool(source)
        if pool:
            decoded = MoonSecV3Decoder.decode_string_pool(pool)
            if decoded:
                return decoded
        return source


class IronBrew2Decoder:
    @staticmethod
    def detect(source: str) -> bool:
        return bool(re.search(r"IronBrew", source, re.IGNORECASE))

    @staticmethod
    def extract_byte_array(source: str) -> Optional[List[int]]:
        candidates = []
        for m in re.finditer(r"\{((?:\s*\d+\s*,\s*){30,}\d+)\}", source, re.DOTALL):
            nums = [int(x.strip()) for x in re.findall(r"\d+", m.group(1))]
            if all(0 <= n <= 255 for n in nums):
                candidates.append(nums)
        if not candidates:
            return None
        return max(candidates, key=len)

    @staticmethod
    def extract_opcode_table(source: str) -> Optional[List[int]]:
        m = re.search(
            r"local\s+\w+\s*=\s*\{((?:\s*0x[0-9a-fA-F]+\s*,\s*){10,}0x[0-9a-fA-F]+)\}",
            source, re.DOTALL,
        )
        if m:
            vals = [int(x.strip(), 16) for x in re.findall(r"0x[0-9a-fA-F]+", m.group(1))]
            return vals
        m = re.search(
            r"local\s+\w+\s*=\s*\{((?:\s*\d+\s*,\s*){10,}\d+)\}",
            source, re.DOTALL,
        )
        if m:
            vals = [int(x.strip()) for x in re.findall(r"\d+", m.group(1))]
            if len(vals) <= 256:
                return vals
        return None

    @staticmethod
    def extract_stack_size(source: str) -> Optional[int]:
        m = re.search(r"local\s+\w+\s*=\s*(\d+)\s*local\s+\w+\s*=\s*\{[0-9,\s]{50,}\}", source)
        if m:
            return int(m.group(1))
        m = re.search(r"maxstack\s*=\s*(\d+)|MAXSTACK\s*=\s*(\d+)", source, re.IGNORECASE)
        if m:
            return int(m.group(1) or m.group(2))
        return None

    @staticmethod
    def _try_lift(data: bytes) -> Optional[str]:
        if data[:4] != b"\x1bLua":
            return None
        try:
            parser = LuaBytecodeParser(data)
            proto = parser.parse()
            if proto and len(proto.instructions) > 0:
                return LuaCodegen(proto).generate()
        except Exception:
            pass
        return None

    @staticmethod
    def decode(source: str) -> str:
        arr = IronBrew2Decoder.extract_byte_array(source)
        if not arr:
            return source

        for xk in range(256):
            decoded = bytes([(b ^ xk) & 0xFF for b in arr])
            lifted = IronBrew2Decoder._try_lift(decoded)
            if lifted:
                return lifted

        for start in range(256):
            for step in (1, 3, 5, 7, 13, 17, 31, 63, 127):
                key = start
                decoded = bytearray(len(arr))
                for i, b in enumerate(arr):
                    decoded[i] = b ^ key
                    key = (key + step) & 0xFF
                lifted = IronBrew2Decoder._try_lift(bytes(decoded))
                if lifted:
                    return lifted

        for sub in range(256):
            decoded = bytes([(b - sub) & 0xFF for b in arr])
            lifted = IronBrew2Decoder._try_lift(decoded)
            if lifted:
                return lifted
            decoded = bytes([(b + sub) & 0xFF for b in arr])
            lifted = IronBrew2Decoder._try_lift(decoded)
            if lifted:
                return lifted

        if len(arr) >= 16:
            for window in (4, 8, 16):
                derived = bytes([(arr[i] ^ arr[i + window]) & 0xFF for i in range(min(window, len(arr) - window))])
                if any(derived):
                    decoded = bytes([(arr[i] ^ derived[i % len(derived)]) & 0xFF for i in range(len(arr))])
                    lifted = IronBrew2Decoder._try_lift(decoded)
                    if lifted:
                        return lifted

        if len(arr) > 64:
            for period in (4, 8, 16, 32):
                for base in range(256):
                    derived = bytes([(base + i * 7) & 0xFF for i in range(period)])
                    decoded = bytes([(arr[i] ^ derived[i % period]) & 0xFF for i in range(len(arr))])
                    if decoded[:4] == b"\x1bLua":
                        lifted = IronBrew2Decoder._try_lift(decoded)
                        if lifted:
                            return lifted

        return source


class PrometheusDecoder:
    @staticmethod
    def detect(source: str) -> bool:
        return bool(re.search(r"prometheus", source, re.IGNORECASE))

    @staticmethod
    def extract_opcode_map(source: str) -> Optional[Dict[int, int]]:
        m = re.search(
            r"local\s+\w+\s*=\s*\{((?:\s*\{[^}]+\}\s*,\s*){10,})",
            source, re.DOTALL,
        )
        if m:
            entries = re.findall(r"\{([^}]+)\}", m.group(1))
            mapping = {}
            for i, entry in enumerate(entries):
                nums = re.findall(r"\d+", entry)
                if nums:
                    mapping[i] = int(nums[0])
            if mapping:
                return mapping
        return None

    @staticmethod
    def extract_bytecode(source: str) -> Optional[List[int]]:
        best = None
        best_len = 0
        for m in re.finditer(r"local\s+\w+\s*=\s*\{((?:\s*(?:0x[0-9a-fA-F]+|\d+)\s*,\s*){80,})",
                             source, re.DOTALL):
            nums = [int(x.strip(), 0) for x in re.findall(r"0x[0-9a-fA-F]+|\d+", m.group(1))]
            if all(0 <= n <= 255 for n in nums) and len(nums) > best_len:
                best = nums
                best_len = len(nums)
        return best

    @staticmethod
    def _try_lift(data: bytes) -> Optional[str]:
        if data[:4] != b"\x1bLua":
            return None
        try:
            parser = LuaBytecodeParser(data)
            proto = parser.parse()
            if proto and len(proto.instructions) > 0:
                return LuaCodegen(proto).generate()
        except Exception:
            pass
        return None

    @staticmethod
    def decode(source: str) -> str:
        best_arr = PrometheusDecoder.extract_bytecode(source)
        if not best_arr:
            for m in re.finditer(r"local\s+\w+\s*=\s*\{((?:\s*\d+\s*,\s*){80,}\d+)\}", source, re.DOTALL):
                nums = [int(x.strip()) for x in re.findall(r"\d+", m.group(1))]
                if all(0 <= n <= 255 for n in nums) and (not best_arr or len(nums) > len(best_arr)):
                    best_arr = nums
        if not best_arr:
            return source

        for xk in range(256):
            decoded = bytes([(b ^ xk) & 0xFF for b in best_arr])
            lifted = PrometheusDecoder._try_lift(decoded)
            if lifted:
                return lifted

        for start in range(256):
            for step in (1, 3, 5, 7, 13, 17, 31, 63):
                key = start
                dec = bytearray()
                for b in best_arr:
                    dec.append((b ^ key) & 0xFF)
                    key = (key + step) & 0xFF
                lifted = PrometheusDecoder._try_lift(bytes(dec))
                if lifted:
                    return lifted

        for sub in range(256):
            decoded = bytes([(b - sub) & 0xFF for b in best_arr])
            lifted = PrometheusDecoder._try_lift(decoded)
            if lifted:
                return lifted

        if len(best_arr) > 64:
            for window in (4, 8, 16, 32):
                derived = bytes([(best_arr[i] ^ best_arr[i + window]) & 0xFF
                                 for i in range(min(window, len(best_arr) - window))])
                if any(derived):
                    decoded = bytes([(best_arr[i] ^ derived[i % len(derived)]) & 0xFF
                                     for i in range(len(best_arr))])
                    lifted = PrometheusDecoder._try_lift(decoded)
                    if lifted:
                        return lifted

        return source


class MoonveilDecoder:
    @staticmethod
    def detect(source: str) -> bool:
        return bool(re.search(r"moonveil", source, re.IGNORECASE))

    @staticmethod
    def extract_payload(source: str) -> Optional[List[int]]:
        best = None
        best_len = 0
        for m in re.finditer(r"local\s+\w+\s*=\s*\{((?:\s*\d+\s*,\s*){100,}\d+)\}", source, re.DOTALL):
            nums = [int(x.strip()) for x in re.findall(r"\d+", m.group(1))]
            if all(0 <= n <= 255 for n in nums) and len(nums) > best_len:
                best = nums
                best_len = len(nums)
        return best

    @staticmethod
    def extract_rotation_key(source: str) -> Optional[int]:
        m = re.search(r"for\s+\w+\s*=\s*(\d+)\s*,\s*#\w+\s*do", source)
        if m:
            return int(m.group(1))
        return None

    @staticmethod
    def _try_lift(data: bytes) -> Optional[str]:
        if data[:4] != b"\x1bLua":
            return None
        try:
            parser = LuaBytecodeParser(data)
            proto = parser.parse()
            if proto and len(proto.instructions) > 0:
                return LuaCodegen(proto).generate()
        except Exception:
            pass
        return None

    @staticmethod
    def decode(source: str) -> str:
        best_arr = MoonveilDecoder.extract_payload(source)
        if not best_arr:
            return source

        for xk in range(256):
            decoded = bytes([(b ^ xk) & 0xFF for b in best_arr])
            lifted = MoonveilDecoder._try_lift(decoded)
            if lifted:
                return lifted

        for start in range(256):
            for step in (1, 3, 5, 7, 13, 17, 31, 63):
                key = start
                dec = bytearray()
                for b in best_arr:
                    dec.append((b ^ key) & 0xFF)
                    key = (key + step) & 0xFF
                lifted = MoonveilDecoder._try_lift(bytes(dec))
                if lifted:
                    return lifted

        for rot in range(1, 8):
            rotated = best_arr[rot:] + best_arr[:rot]
            for xk in range(256):
                decoded = bytes([(b ^ xk) & 0xFF for b in rotated])
                lifted = MoonveilDecoder._try_lift(decoded)
                if lifted:
                    return lifted

        for sub in range(256):
            decoded = bytes([(b - sub) & 0xFF for b in best_arr])
            lifted = MoonveilDecoder._try_lift(decoded)
            if lifted:
                return lifted
            decoded = bytes([(b + sub) & 0xFF for b in best_arr])
            lifted = MoonveilDecoder._try_lift(decoded)
            if lifted:
                return lifted

        if len(best_arr) > 32:
            for window in (4, 8, 16, 32):
                derived = bytes([(best_arr[i] ^ best_arr[i + window]) & 0xFF
                                 for i in range(min(window, len(best_arr) - window))])
                if any(derived):
                    decoded = bytes([(best_arr[i] ^ derived[i % len(derived)]) & 0xFF
                                     for i in range(len(best_arr))])
                    lifted = MoonveilDecoder._try_lift(decoded)
                    if lifted:
                        return lifted

        return source


class LuaObfuscatorDecoder:
    @staticmethod
    def detect(source: str) -> bool:
        return bool(re.search(r"luaobfuscator|LuaObfuscator", source, re.IGNORECASE))

    @staticmethod
    def decode(source: str) -> str:
        source = LuaObfuscatorDecoder.decode_string_char(source)
        source = LuaObfuscatorDecoder.decode_loadstring(source)
        source = LuaObfuscatorDecoder.decode_table_concat(source)
        source = LuaObfuscatorDecoder.decode_hex_literals(source)
        source = LuaObfuscatorDecoder.decode_gsub_patterns(source)
        source = LuaObfuscatorDecoder.decode_number_obfuscation(source)
        return source

    @staticmethod
    def decode_number_obfuscation(source: str) -> str:
        source = re.sub(
            r"\(((?:0x[0-9a-fA-F]+|\d+)(?:\s*[+*^]\s*(?:0x[0-9a-fA-F]+|\d+))+)\)",
            lambda m: LuaObfuscatorDecoder._eval_number_expr(m.group(1)),
            source,
        )
        return source

    @staticmethod
    def _eval_number_expr(expr: str) -> str:
        try:
            tokens = re.findall(r"0x[0-9a-fA-F]+|\d+|[+*^]", expr)
            if not tokens:
                return expr
            result = int(tokens[0], 0)
            i = 1
            while i < len(tokens) - 1:
                op = tokens[i]
                val = int(tokens[i + 1], 0)
                if op == "+":
                    result += val
                elif op == "*":
                    result *= val
                elif op == "^":
                    result ^= val
                i += 2
            return str(result)
        except Exception:
            return expr

    @staticmethod
    def decode_string_char(source: str) -> str:
        def replacer(m: re.Match) -> str:
            nums_raw = m.group(1)
            nums = [int(x.strip()) for x in re.findall(r"\d+", nums_raw)]
            try:
                decoded = "".join(chr(n) for n in nums if 0 <= n <= 0x10FFFF)
                if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in decoded):
                    return '"' + decoded.replace("\\", "\\\\").replace('"', '\\"') + '"'
            except Exception:
                pass
            for xk in range(1, 256):
                try:
                    decoded = "".join(chr((n ^ xk) & 0xFF) for n in nums if 0 <= n <= 255)
                    if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in decoded) and len(decoded) > 3:
                        return '"' + decoded.replace("\\", "\\\\").replace('"', '\\"') + '"'
                except Exception:
                    pass
            return m.group(0)
        return re.sub(
            r"string\.char\(\s*((?:\d+\s*,\s*)+\d+)\s*\)",
            replacer,
            source,
        )

    @staticmethod
    def decode_loadstring(source: str) -> str:
        def ls_replacer(m: re.Match) -> str:
            inner = m.group(1)
            for _ in range(4):
                try:
                    dec = base64.b64decode(inner + "=" * (-len(inner) % 4))
                    text = dec.decode("utf-8", errors="replace")
                    if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in text) and \
                       any(kw in text for kw in ("local ", "function", "return", "end")):
                        return text
                    inner = text
                except Exception:
                    break
            return m.group(0)
        source = re.sub(
            r'loadstring\s*\(\s*["\']([A-Za-z0-9+/=]{20,})["\']\s*\)',
            ls_replacer,
            source,
        )
        return source

    @staticmethod
    def decode_table_concat(source: str) -> str:
        def concat_replacer(m: re.Match) -> str:
            inner = m.group(1)
            parts = re.findall(r'"([^"]*)"', inner)
            if not parts:
                parts = re.findall(r"'([^']*)'", inner)
            if parts:
                full = "".join(parts)
                try:
                    dec = base64.b64decode(full + "=" * (-len(full) % 4))
                    text = dec.decode("utf-8", errors="replace")
                    if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in text) and len(text) > 3:
                        return '"' + text + '"'
                except Exception:
                    pass
                return '"' + full + '"'
            return m.group(0)
        source = re.sub(
            r'table\.concat\s*\(\s*\{([^}]+)\}\s*,\s*["\']["\']?\s*\)',
            concat_replacer,
            source,
        )
        return source

    @staticmethod
    def decode_hex_literals(source: str) -> str:
        def hex_to_dec(m: re.Match) -> str:
            try:
                return str(int(m.group(0), 16))
            except Exception:
                return m.group(0)
        return re.sub(r"\b0x[0-9a-fA-F]+\b", hex_to_dec, source)

    @staticmethod
    def decode_gsub_patterns(source: str) -> str:
        def gsub_repl(m: re.Match) -> str:
            inner = m.group(1)
            replacements = re.findall(r"\[\s*\"([^\"]+)\"\s*\]\s*=\s*\"([^\"]+)\"", m.group(2))
            if not replacements:
                return m.group(0)
            mapping = dict(replacements)
            result = "".join(mapping.get(ch, ch) for ch in inner)
            return '"' + result + '"'
        return re.sub(
            r'string\.gsub\s*\(\s*"([^"]+)"\s*,\s*\{([^}]+)\}',
            gsub_repl,
            source,
        )


class BoronideDecoder:
    @staticmethod
    def detect(source: str) -> bool:
        return bool(re.search(r"boronide|Boronide|Boron Obfuscator", source, re.IGNORECASE))

    @staticmethod
    def decode(source: str) -> str:
        source = BoronideDecoder.decode_bit32(source)
        source = BoronideDecoder.decode_array(source)
        source = BoronideDecoder.decode_hex_literals(source)
        source = BoronideDecoder.decode_rot_strings(source)
        source = BoronideDecoder.decode_string_char_xor(source)
        return source

    @staticmethod
    def decode_string_char_xor(source: str) -> str:
        def repl(m: re.Match) -> str:
            nums = [int(x.strip()) for x in m.group(1).split(",")]
            for xk in range(256):
                try:
                    text = "".join(chr((n ^ xk) & 0xFF) for n in nums if 0 <= n <= 255)
                    if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in text) and len(text) > 3:
                        if any(kw in text for kw in COMMON_STRINGS):
                            return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
                except Exception:
                    pass
            return m.group(0)
        return re.sub(r"string\.char\(\s*((?:\d+\s*,\s*)+\d+)\s*\)", repl, source)

    @staticmethod
    def decode_bit32(source: str) -> str:
        ops = {
            "bxor": lambda a, b: a ^ b,
            "band": lambda a, b: a & b,
            "bor": lambda a, b: a | b,
            "rshift": lambda a, b: (a >> b) & 0xFFFFFFFF,
            "lshift": lambda a, b: (a << b) & 0xFFFFFFFF,
        }
        for name, op in ops.items():
            def make_replacer(o):
                def repl(m):
                    try:
                        a = int(m.group(1), 0)
                        b = int(m.group(2), 0)
                        return str(o(a, b))
                    except Exception:
                        return m.group(0)
                return repl
            source = re.sub(
                rf"bit32\.{name}\(\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
                make_replacer(op),
                source,
            )

        def bnot_repl(m):
            try:
                a = int(m.group(1), 0)
                return str((~a) & 0xFFFFFFFF)
            except Exception:
                return m.group(0)
        source = re.sub(r"bit32\.bnot\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)", bnot_repl, source)

        def arshift_repl(m):
            try:
                a = int(m.group(1), 0)
                b = int(m.group(2), 0)
                if a >= 0x80000000:
                    a -= 0x100000000
                return str((a >> b) & 0xFFFFFFFF)
            except Exception:
                return m.group(0)
        source = re.sub(
            r"bit32\.arshift\(\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
            arshift_repl, source,
        )

        def lrotate_repl(m):
            try:
                a = int(m.group(1), 0) & 0xFFFFFFFF
                b = int(m.group(2), 0) & 31
                return str(((a << b) | (a >> (32 - b))) & 0xFFFFFFFF if b else a)
            except Exception:
                return m.group(0)
        source = re.sub(
            r"bit32\.lrotate\(\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
            lrotate_repl, source,
        )

        def rrotate_repl(m):
            try:
                a = int(m.group(1), 0) & 0xFFFFFFFF
                b = int(m.group(2), 0) & 31
                return str(((a >> b) | (a << (32 - b))) & 0xFFFFFFFF if b else a)
            except Exception:
                return m.group(0)
        source = re.sub(
            r"bit32\.rrotate\(\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
            rrotate_repl, source,
        )
        return source

    @staticmethod
    def decode_array(source: str) -> str:
        def array_decode(m: re.Match) -> str:
            nums_raw = m.group(1)
            nums = [int(x.strip(), 0) for x in re.findall(r"0x[0-9a-fA-F]+|\d+", nums_raw)]
            if not nums:
                return m.group(0)
            for xk in range(256):
                decoded_bytes = bytes([(b ^ xk) & 0xFF for b in nums])
                try:
                    text = decoded_bytes.decode("utf-8")
                    if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in text) and len(text) > 4:
                        return '"' + text.replace('"', '\\"') + '"'
                except Exception:
                    pass
            for sub in range(256):
                decoded_bytes = bytes([(b - sub) & 0xFF for b in nums])
                try:
                    text = decoded_bytes.decode("utf-8")
                    if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in text) and len(text) > 4:
                        return '"' + text.replace('"', '\\"') + '"'
                except Exception:
                    pass
            return m.group(0)
        source = re.sub(
            r"\{\s*((?:0x[0-9a-fA-F]+|\d+)(?:\s*,\s*(?:0x[0-9a-fA-F]+|\d+)){10,})\s*\}",
            array_decode,
            source,
        )
        return source

    @staticmethod
    def decode_hex_literals(source: str) -> str:
        def hex_to_dec(m: re.Match) -> str:
            try:
                return str(int(m.group(0), 16))
            except Exception:
                return m.group(0)
        return re.sub(r"\b0x[0-9a-fA-F]+\b", hex_to_dec, source)

    @staticmethod
    def decode_rot_strings(source: str) -> str:
        def rot_repl(m: re.Match) -> str:
            inner = m.group(1)
            n = int(m.group(2))
            result = []
            for c in inner:
                if "a" <= c <= "z":
                    result.append(chr((ord(c) - ord("a") + n) % 26 + ord("a")))
                elif "A" <= c <= "Z":
                    result.append(chr((ord(c) - ord("A") + n) % 26 + ord("A")))
                else:
                    result.append(c)
            return '"' + "".join(result) + '"'
        return re.sub(r'string\.rot\s*\(\s*"([^"]+)"\s*,\s*(\d+)\s*\)', rot_repl, source)


class AztupBrewDecoder:
    @staticmethod
    def detect(source: str) -> bool:
        return bool(re.search(r"AztupBrew|aztupbrew|Aztup", source, re.IGNORECASE))

    @staticmethod
    def decode(source: str) -> str:
        result = IronBrew2Decoder.decode(source)
        return result


class XFuscatorDecoder:
    @staticmethod
    def detect(source: str) -> bool:
        return bool(re.search(r"XFuscator|xfuscator", source, re.IGNORECASE))

    @staticmethod
    def decode(source: str) -> str:
        source = re.sub(
            r"local\s+\w+\s*=\s*\{\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)",
            lambda m: "local _ = {" + ", ".join(str(int(m.group(i)) ^ 0x5A) for i in range(1, 5)),
            source,
        )
        return source


class HyperionDecoder:
    @staticmethod
    def detect(source: str) -> bool:
        return bool(re.search(r"Hyperion|hyperion", source, re.IGNORECASE))

    @staticmethod
    def decode(source: str) -> str:
        pool = MoonSecV3Decoder.extract_string_pool(source)
        if pool:
            decoded = MoonSecV3Decoder.decode_string_pool(pool)
            if decoded:
                return decoded
        return source


class PSUDecoder:
    @staticmethod
    def detect(source: str) -> bool:
        return bool(re.search(r"PSU|psu_obf", source, re.IGNORECASE))

    @staticmethod
    def decode(source: str) -> str:
        pool = MoonSecV3Decoder.extract_string_pool(source)
        if pool:
            decoded = MoonSecV3Decoder.decode_string_pool(pool)
            if decoded:
                return decoded
        return source


class WeAreDevsDecoder:
    @staticmethod
    def detect(source: str) -> bool:
        return bool(re.search(r"wearedevs|WeAreDevs|WRD", source, re.IGNORECASE))

    @staticmethod
    def decode(source: str) -> str:
        pool = MoonSecV3Decoder.extract_string_pool(source)
        if pool:
            decoded = MoonSecV3Decoder.decode_string_pool(pool)
            if decoded:
                return decoded
        return source


class StringDecoder:
    @staticmethod
    def try_base64(s: str) -> Optional[str]:
        try:
            padded = s + "=" * (-len(s) % 4)
            decoded = base64.b64decode(padded)
            return decoded.decode("utf-8", errors="replace")
        except Exception:
            return None

    @staticmethod
    def try_base64_bytes(s: str) -> Optional[bytes]:
        try:
            padded = s + "=" * (-len(s) % 4)
            return base64.b64decode(padded)
        except Exception:
            return None

    @staticmethod
    def try_base32(s: str) -> Optional[bytes]:
        try:
            padded = s.upper() + "=" * (-len(s) % 8)
            return base64.b32decode(padded)
        except Exception:
            return None

    @staticmethod
    def try_base85(s: str) -> Optional[bytes]:
        try:
            return base64.b85decode(s)
        except Exception:
            try:
                return base64.a85decode(s)
            except Exception:
                return None

    @staticmethod
    def try_rot13(s: str) -> str:
        result = []
        for c in s:
            if "a" <= c <= "z":
                result.append(chr((ord(c) - ord("a") + 13) % 26 + ord("a")))
            elif "A" <= c <= "Z":
                result.append(chr((ord(c) - ord("A") + 13) % 26 + ord("A")))
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def try_rot_n(s: str, n: int) -> str:
        result = []
        for c in s:
            if "a" <= c <= "z":
                result.append(chr((ord(c) - ord("a") + n) % 26 + ord("a")))
            elif "A" <= c <= "Z":
                result.append(chr((ord(c) - ord("A") + n) % 26 + ord("A")))
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def try_rot47(s: str) -> str:
        result = []
        for c in s:
            o = ord(c)
            if 33 <= o <= 126:
                result.append(chr(33 + ((o - 33 + 47) % 94)))
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def is_mostly_printable(data: bytes, threshold: float = 0.9) -> bool:
        if not data:
            return False
        printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
        return printable / len(data) >= threshold

    @staticmethod
    def decode_ascii_escape(s: str) -> str:
        return re.sub(
            r"\\(\d{1,3})",
            lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0),
            s,
        )

    @staticmethod
    def decode_hex_escape(s: str) -> str:
        return re.sub(
            r"\\x([0-9a-fA-F]{2})",
            lambda m: chr(int(m.group(1), 16)),
            s,
        )

    @staticmethod
    def decode_unicode_escape(s: str) -> str:
        return re.sub(
            r"\\u([0-9a-fA-F]{4})",
            lambda m: chr(int(m.group(1), 16)),
            s,
        )

    @staticmethod
    def decode_string_reversal(source: str) -> str:
        def reverse_replacer(m: re.Match) -> str:
            try:
                inner = m.group(1)
                return '"' + inner[::-1] + '"'
            except Exception:
                return m.group(0)
        source = re.sub(
            r'string\.reverse\s*\(\s*"([^"]+)"\s*\)',
            reverse_replacer,
            source,
        )
        source = re.sub(
            r'string\.sub\s*\(\s*"([^"]+)"\s*,\s*-\s*1\s*,\s*1\s*,\s*-\s*1\s*\)',
            reverse_replacer,
            source,
        )
        return source

    @staticmethod
    def decode_boronide_bit32(source: str) -> str:
        return BoronideDecoder.decode_bit32(source)

    @staticmethod
    def decode_bit_library(source: str) -> str:
        ops = {
            "bxor": lambda a, b: a ^ b,
            "band": lambda a, b: a & b,
            "bor": lambda a, b: a | b,
            "rshift": lambda a, b: (a >> b) & 0xFFFFFFFF,
            "lshift": lambda a, b: (a << b) & 0xFFFFFFFF,
        }
        for name, op in ops.items():
            def make_replacer(o):
                def repl(m):
                    try:
                        a = int(m.group(1), 0)
                        b = int(m.group(2), 0)
                        return str(o(a, b))
                    except Exception:
                        return m.group(0)
                return repl
            source = re.sub(
                rf"bit\.{name}\(\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
                make_replacer(op),
                source,
            )

        def bnot_repl(m):
            try:
                a = int(m.group(1), 0)
                return str((~a) & 0xFFFFFFFF)
            except Exception:
                return m.group(0)
        source = re.sub(r"bit\.bnot\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)", bnot_repl, source)

        def arshift_repl(m):
            try:
                a = int(m.group(1), 0)
                b = int(m.group(2), 0)
                if a >= 0x80000000:
                    a -= 0x100000000
                return str((a >> b) & 0xFFFFFFFF)
            except Exception:
                return m.group(0)
        source = re.sub(
            r"bit\.arshift\(\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
            arshift_repl, source,
        )
        return source

    @staticmethod
    def decode_multi_layer_base64(source: str) -> str:
        def multi_b64(m: re.Match) -> str:
            s = m.group(1)
            original = s
            for _ in range(8):
                try:
                    padded = s + "=" * (-len(s) % 4)
                    decoded_bytes = base64.b64decode(padded)
                    decoded = decoded_bytes.decode("utf-8", errors="replace")
                    if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in decoded) and len(decoded) > 3:
                        s = decoded
                    else:
                        break
                except Exception:
                    break
            if s != original:
                return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
            return m.group(0)
        source = re.sub(r'"([A-Za-z0-9+/]{20,}={0,2})"', multi_b64, source)
        return source

    @staticmethod
    def decode_zlib_payload(source: str) -> str:
        def zlib_replacer(m: re.Match) -> str:
            inner = m.group(1)
            try:
                data = base64.b64decode(inner + "=" * (-len(inner) % 4))
                decompressed = zlib.decompress(data).decode("utf-8", errors="replace")
                if len([c for c in decompressed if 32 <= ord(c) < 127]) / max(len(decompressed), 1) > 0.80:
                    return decompressed
            except Exception:
                pass
            try:
                data = bytes([int(x) for x in re.findall(r"\d+", inner) if int(x) <= 255])
                decompressed = zlib.decompress(data).decode("utf-8", errors="replace")
                if len([c for c in decompressed if 32 <= ord(c) < 127]) / max(len(decompressed), 1) > 0.80:
                    return decompressed
            except Exception:
                pass
            return m.group(0)
        source = re.sub(
            r'(?:zlib\.decompress|inflate)\s*\(\s*(?:base64\.decode\s*\(\s*)?["\']([A-Za-z0-9+/=]+)["\']',
            zlib_replacer,
            source,
        )
        return source

    @staticmethod
    def decode_hex_escape_pair_strings(source: str) -> str:
        def hx(m: re.Match) -> str:
            try:
                raw = m.group(1)
                decoded = bytes([int(x, 16) for x in re.findall(r"\\x([0-9a-fA-F]{2})", raw)])
                text = decoded.decode("utf-8", errors="replace")
                if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in text):
                    return '"' + text.replace('"', '\\"') + '"'
            except Exception:
                pass
            return m.group(0)
        return re.sub(r'"((?:\\x[0-9a-fA-F]{2}){4,})"', hx, source)

    @staticmethod
    def decode_byte_array_to_string(source: str) -> str:
        def arr_repl(m: re.Match) -> str:
            nums = [int(x.strip(), 0) for x in re.findall(r"0x[0-9a-fA-F]+|\d+", m.group(1))]
            if len(nums) < 3 or any(n > 255 for n in nums):
                return m.group(0)
            try:
                txt = bytes(nums).decode("utf-8")
                if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in txt) and len(txt) >= 3:
                    return '"' + txt.replace("\\", "\\\\").replace('"', '\\"') + '"'
            except Exception:
                pass
            for xk in range(256):
                try:
                    dec = bytes([(b ^ xk) & 0xFF for b in nums]).decode("utf-8")
                    if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in dec) and len(dec) >= 3:
                        return '"' + dec.replace("\\", "\\\\").replace('"', '\\"') + '"'
                except Exception:
                    pass
            return m.group(0)
        source = re.sub(
            r"\{\s*((?:0x[0-9a-fA-F]+|\d+)(?:\s*,\s*(?:0x[0-9a-fA-F]+|\d+)){2,})\s*\}",
            arr_repl,
            source,
        )
        return source

    @staticmethod
    def decode_hex_number_literals(source: str) -> str:
        def hex_to_dec(m: re.Match) -> str:
            try:
                return str(int(m.group(0), 16))
            except Exception:
                return m.group(0)
        return re.sub(r"\b0x[0-9a-fA-F]+\b", hex_to_dec, source)

    @staticmethod
    def decode_rot_strings(source: str) -> str:
        return re.sub(
            r'string\.rot(\d+)\s*\(\s*"([^"]+)"\s*\)',
            lambda m: '"' + StringDecoder.try_rot_n(m.group(2), int(m.group(1))) + '"',
            source,
        )

    @staticmethod
    def decode_caesar_strings(source: str) -> str:
        def caesar_repl(m: re.Match) -> str:
            inner = m.group(1)
            for shift in range(1, 26):
                candidate = StringDecoder.try_rot_n(inner, shift)
                if any(kw in candidate for kw in COMMON_STRINGS):
                    return '"' + candidate + '"'
            return m.group(0)
        return re.sub(r'"([a-zA-Z]{5,})"', caesar_repl, source)

    @staticmethod
    def decode_xor_position_strings(source: str) -> str:
        def xor_repl(m: re.Match) -> str:
            try:
                nums = [int(x) for x in re.findall(r"\d+", m.group(1))]
                if not nums:
                    return m.group(0)
                for start in range(256):
                    for step in (1, 3, 5, 7, 11, 13):
                        key = start
                        decoded = ""
                        for b in nums:
                            decoded += chr((b ^ key) & 0xFF)
                            key = (key + step) & 0xFF
                        if all(32 <= ord(c) < 127 for c in decoded) and len(decoded) > 4:
                            if any(kw in decoded for kw in COMMON_STRINGS):
                                return '"' + decoded.replace("\\", "\\\\").replace('"', '\\"') + '"'
            except Exception:
                pass
            return m.group(0)
        return re.sub(r"string\.char\(\s*((?:\d+\s*,\s*)+\d+)\s*\)", xor_repl, source)

    @staticmethod
    def decode_vigenere(source: str, key: str = "SECROVIA") -> str:
        result = []
        ki = 0
        for c in source:
            if "a" <= c <= "z":
                k = ord(key[ki % len(key)].lower()) - ord("a")
                result.append(chr((ord(c) - ord("a") - k) % 26 + ord("a")))
                ki += 1
            elif "A" <= c <= "Z":
                k = ord(key[ki % len(key)].upper()) - ord("A")
                result.append(chr((ord(c) - ord("A") - k) % 26 + ord("A")))
                ki += 1
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def decode_reverse_strings(source: str) -> str:
        def rev_repl(m: re.Match) -> str:
            inner = m.group(1)
            reversed_inner = inner[::-1]
            if any(kw in reversed_inner for kw in COMMON_STRINGS):
                return '"' + reversed_inner + '"'
            return m.group(0)
        return re.sub(r'"([a-zA-Z0-9_\.\:\s]{5,})"', rev_repl, source)

    @staticmethod
    def decode_char_concat_chains(source: str) -> str:
        def chain_repl(m: re.Match) -> str:
            inner = m.group(0)
            chars = re.findall(r'string\.char\((\d+)\)', inner)
            if chars:
                result = "".join(chr(int(c) & 0xFF) for c in chars)
                if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in result):
                    return '"' + result.replace("\\", "\\\\").replace('"', '\\"') + '"'
            return inner
        return re.sub(
            r"(?:string\.char\(\d+\)\s*\.\.\s*)+string\.char\(\d+\)",
            chain_repl,
            source,
        )

    @staticmethod
    def decode_bracket_index_strings(source: str) -> str:
        def repl(m: re.Match) -> str:
            parts = re.findall(r'\["([^"]+)"\]', m.group(0))
            if parts:
                return '"' + "".join(parts) + '"'
            return m.group(0)
        return re.sub(r'(?:\["[^"]+"\]\s*\.\.\s*)*\["[^"]+"\]', repl, source)

    @staticmethod
    def decode_string_char_reverse(source: str) -> str:
        def repl(m: re.Match) -> str:
            nums = [int(x.strip()) for x in m.group(1).split(",") if x.strip()]
            if not nums:
                return m.group(0)
            try:
                text = "".join(chr(n) for n in reversed(nums) if 0 <= n <= 0x10FFFF)
                if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in text) and len(text) > 3:
                    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
            except Exception:
                pass
            return m.group(0)
        return re.sub(r"string\.char\(\s*((?:\d+\s*,\s*)+\d+)\s*\)", repl, source)


class BytecodeExtractor:
    @staticmethod
    def extract_numeric_array(source: str) -> Optional[List[int]]:
        best = None
        best_len = 0
        for m in re.finditer(r"\{((?:\s*\d+\s*,\s*){20,}\d+)\}", source, re.DOTALL):
            nums = re.findall(r"\d+", m.group(1))
            if len(nums) > best_len:
                arr = [int(x) for x in nums if 0 <= int(x) <= 255]
                if len(arr) == len(nums):
                    best = arr
                    best_len = len(arr)
        return best

    @staticmethod
    def extract_hex_array(source: str) -> Optional[List[int]]:
        best = None
        best_len = 0
        for m in re.finditer(r"\{((?:\s*0x[0-9a-fA-F]+\s*,\s*){20,}0x[0-9a-fA-F]+\s*)\}", source, re.DOTALL):
            hexnums = re.findall(r"0x[0-9a-fA-F]+", m.group(1))
            if len(hexnums) > best_len:
                arr = [int(x, 16) for x in hexnums if 0 <= int(x, 16) <= 255]
                if len(arr) == len(hexnums):
                    best = arr
                    best_len = len(arr)
        return best

    @staticmethod
    def extract_string_char_array(source: str) -> Optional[List[int]]:
        best = None
        best_len = 0
        for m in re.finditer(
            r"string\.char\(((?:\s*\d+\s*,\s*)*\d+)\)",
            source, re.DOTALL,
        ):
            nums = [int(x.strip()) for x in m.group(1).split(",")]
            if len(nums) > best_len and all(0 <= n <= 255 for n in nums):
                best = nums
                best_len = len(nums)
        return best

    @staticmethod
    def extract_escaped_string_bytes(source: str) -> Optional[List[int]]:
        best = None
        best_len = 0
        for m in re.finditer(r'"((?:\\[0-9]{1,3}){30,})"', source):
            nums = [int(x) for x in re.findall(r"\\(\d{1,3})", m.group(1)) if int(x) <= 255]
            if len(nums) > best_len:
                best = nums
                best_len = len(nums)
        return best

    @staticmethod
    def extract_boronide_payload(source: str) -> Optional[List[int]]:
        pat = re.search(
            r"local\s+\w+\s*=\s*\{((?:\s*(?:0x[0-9a-fA-F]+|\d+)\s*,\s*){50,}(?:0x[0-9a-fA-F]+|\d+)\s*)\}",
            source, re.DOTALL,
        )
        if pat:
            raw = pat.group(1)
            vals = [int(x.strip(), 0) for x in re.findall(r"0x[0-9a-fA-F]+|\d+", raw)]
            if all(0 <= v <= 255 for v in vals):
                return vals
        return None

    @staticmethod
    def extract_luaobfuscator_payload(source: str) -> Optional[List[int]]:
        concat_pat = re.search(
            r"table\.concat\s*\(\s*\{((?:\s*\"[^\"]*\"\s*,?\s*)+)\}\s*,\s*[\"'][\"']\s*\)",
            source, re.DOTALL,
        )
        if concat_pat:
            parts = re.findall(r'"([^"]*)"', concat_pat.group(1))
            full = "".join(parts)
            try:
                dec = base64.b64decode(full + "=" * (-len(full) % 4))
                return list(dec)
            except Exception:
                pass
        char_chain = re.findall(r"string\.char\(((?:\d+\s*,\s*)*\d+)\)", source)
        if char_chain:
            biggest = max(char_chain, key=lambda x: len(x))
            nums = [int(n.strip()) for n in biggest.split(",")]
            if all(0 <= n <= 255 for n in nums):
                return nums
        return None

    @staticmethod
    def find_decode_key(source: str) -> Optional[Dict[str, Any]]:
        multi_xor_pat = re.search(
            r"for\s+\w+\s*=\s*1\s*,\s*#\w+\s*do\s*\w+\[\w+\]\s*=\s*\w+\[\w+\]\s*~\s*\w+\[(\w+)\s*%\s*#\w+\s*\+\s*1\]",
            source, re.DOTALL,
        )
        if multi_xor_pat:
            key_arr_pat = re.search(
                r"local\s+\w+\s*=\s*\{((?:\s*\d+\s*,\s*){1,64}\d+)\}",
                source,
            )
            if key_arr_pat:
                key_bytes = [int(x.strip()) for x in key_arr_pat.group(1).split(",")]
                return {"type": "multi_xor", "key": bytes(key_bytes)}

        xor_pat = re.search(
            r"for\s+\w+\s*=\s*1\s*,\s*#\w+\s*do\s*\w+\[(\w+)\]\s*=\s*\w+\[(\w+)\]\s*~\s*(\d+|\".*?\"|0x[0-9a-fA-F]+)",
            source, re.DOTALL,
        )
        if xor_pat:
            key_raw = xor_pat.group(3)
            try:
                if key_raw.startswith("0x"):
                    key_val = int(key_raw, 16)
                else:
                    key_val = int(key_raw)
                return {"type": "xor", "key": key_val}
            except ValueError:
                pass

        bit32_xor_pat = re.search(
            r"bit32\.bxor\s*\(\s*\w+\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
            source,
        )
        if bit32_xor_pat:
            try:
                return {"type": "xor", "key": int(bit32_xor_pat.group(1), 0)}
            except ValueError:
                pass

        rolling_pat = re.search(
            r"for\s+\w+\s*=\s*1\s*,\s*#\w+\s*do.*?\w+\s*=\s*\(\s*\w+\s*\+\s*(\d+)\s*\)\s*%\s*256",
            source, re.DOTALL,
        )
        if rolling_pat:
            return {"type": "rolling_xor", "step": int(rolling_pat.group(1))}

        arith_pat = re.search(
            r"\w+\[(\w+)\]\s*=\s*\w+\[(\w+)\]\s*([\+\-\*])\s*(\d+)",
            source,
        )
        if arith_pat:
            return {
                "type": "arith",
                "op": arith_pat.group(3),
                "operand": int(arith_pat.group(4)),
            }

        sub_pat = re.search(r"byte\s*-\s*(\d+)", source)
        if sub_pat:
            return {"type": "sub", "key": int(sub_pat.group(1))}

        return None

    @staticmethod
    def apply_decode(data: List[int], key_info: Optional[Dict]) -> List[int]:
        if key_info is None:
            return data
        t = key_info["type"]
        if t == "xor":
            return [b ^ key_info["key"] for b in data]
        elif t == "rolling_xor":
            result = []
            key = 0
            step = key_info.get("step", 1)
            for b in data:
                result.append(b ^ key)
                key = (key + step) & 0xFF
            return result
        elif t == "multi_xor":
            key = key_info["key"]
            klen = len(key)
            return [data[i] ^ key[i % klen] for i in range(len(data))]
        elif t == "arith":
            op = key_info["op"]
            val = key_info["operand"]
            if op == "+":
                return [(b - val) & 0xFF for b in data]
            elif op == "-":
                return [(b + val) & 0xFF for b in data]
            elif op == "*":
                return [b for b in data]
        elif t == "sub":
            return [(b - key_info["key"]) & 0xFF for b in data]
        return data

    @staticmethod
    def try_brute_xor_keys(data: List[int]) -> Optional[Tuple[int, bytes]]:
        for xk in range(0, 256):
            decoded = bytes([(b ^ xk) & 0xFF for b in data])
            if decoded[:4] == b"\x1bLua":
                return (xk, decoded)
        return None

    @staticmethod
    def try_brute_rolling_xor(data: List[int]) -> Optional[Tuple[Dict, bytes]]:
        for start_key in range(0, 256):
            for step in (1, 3, 5, 7, 11, 13, 17, 31, 63, 127):
                key = start_key
                decoded = []
                for b in data:
                    decoded.append((b ^ key) & 0xFF)
                    key = (key + step) & 0xFF
                decoded_bytes = bytes(decoded)
                if decoded_bytes[:4] == b"\x1bLua":
                    return ({"type": "rolling_xor", "start": start_key, "step": step}, decoded_bytes)
        return None

    @staticmethod
    def try_brute_add_sub(data: List[int]) -> Optional[Tuple[Dict, bytes]]:
        for op in ("add", "sub"):
            for k in range(256):
                if op == "add":
                    dec = bytes([(b + k) & 0xFF for b in data])
                else:
                    dec = bytes([(b - k) & 0xFF for b in data])
                if dec[:4] == b"\x1bLua":
                    return ({"type": op, "key": k}, dec)
        return None

    @staticmethod
    def try_brute_multi_xor(data: List[int]) -> Optional[Tuple[Dict, bytes]]:
        magic = b"\x1bLua"
        for klen in (2, 3, 4, 8, 16):
            if len(data) < klen:
                continue
            key_bytes = bytes([(data[i] ^ magic[i]) & 0xFF for i in range(4)])
            if klen < 4:
                continue
            candidate_key = key_bytes[:klen] if klen <= 4 else key_bytes + bytes(klen - 4)
            decoded = bytes([(data[i] ^ candidate_key[i % klen]) & 0xFF for i in range(len(data))])
            if decoded[:4] == magic:
                return ({"type": "multi_xor", "key": candidate_key}, decoded)
        return None


class DispatcherAnalyzer:
    def __init__(self, ast: ASTNode):
        self.ast = ast
        self.handlers: Dict[int, ASTNode] = {}
        self.dispatch_var: Optional[str] = None

    def find_dispatchers(self) -> List[ASTNode]:
        found: List[ASTNode] = []
        self._walk(self.ast, found)
        return found

    def _walk(self, node: ASTNode, out: List[ASTNode]):
        if node.type == "While":
            for child in node.children:
                if child.type == "Block":
                    for stmt in child.children:
                        if stmt.type == "If" and self._count_elseif(stmt) >= 5:
                            out.append(stmt)
                            break
        for c in node.children:
            self._walk(c, out)

    def _count_elseif(self, node: ASTNode) -> int:
        return sum(1 for c in node.children if c.type == "ElseIf")

    def analyze(self, dispatcher: ASTNode) -> Dict[int, str]:
        result: Dict[int, str] = {}
        for child in dispatcher.children:
            if child.type == "ElseIf":
                cond = child.children[0] if child.children else None
                if cond and cond.type == "BinOp" and cond.attrs.get("op") == "==":
                    rhs = cond.children[1] if len(cond.children) > 1 else None
                    if rhs and rhs.type == "Number":
                        case_num = int(rhs.attrs["value"])
                        body = child.children[1] if len(child.children) > 1 else None
                        if body:
                            text = self._node_to_text(body)
                            result[case_num] = text
        return result

    def _node_to_text(self, node: ASTNode) -> str:
        parts = [node.type]
        if node.attrs:
            parts.append(str(node.attrs))
        for c in node.children:
            parts.append(self._node_to_text(c))
        return " ".join(parts)


class OpcodeMapper:
    def __init__(self):
        self.custom_to_std: Dict[int, int] = {}
        self.custom_to_sem: Dict[int, str] = {}
        self.confidence: Dict[int, float] = {}

    def learn_from_ast(self, ast: ASTNode, dispatcher_node: Optional[ASTNode] = None) -> bool:
        if dispatcher_node is None:
            dispatcher_node = self._find_dispatcher(ast)
        if dispatcher_node is None:
            return False

        branches = self._collect_branches(dispatcher_node)
        for branch in branches:
            op = self._classify_branch(branch)
            if op is not None:
                custom_op, std_op, sem = op
                if custom_op not in self.custom_to_std:
                    self.custom_to_std[custom_op] = std_op
                    self.custom_to_sem[custom_op] = sem
                    self.confidence[custom_op] = 0.85

        return len(self.custom_to_std) > 0

    def learn_from_handlers(self, handlers: Dict[int, Any]) -> int:
        learned = 0
        for case_num, handler in handlers.items():
            text = handler.raw_text if hasattr(handler, "raw_text") else str(handler)
            result = self._classify_handler_text(text)
            if result is not None:
                std, sem = result
                if case_num not in self.custom_to_std:
                    self.custom_to_std[case_num] = std
                    self.custom_to_sem[case_num] = sem
                    self.confidence[case_num] = 0.75
                    learned += 1
        return learned

    def _classify_handler_text(self, text: str) -> Optional[Tuple[int, str]]:
        lua_op_map = {
            VMOpcodeSemantics.ADD: int(LuaOpcode.OP_ADD),
            VMOpcodeSemantics.SUB: int(LuaOpcode.OP_SUB),
            VMOpcodeSemantics.MUL: int(LuaOpcode.OP_MUL),
            VMOpcodeSemantics.DIV: int(LuaOpcode.OP_DIV),
            VMOpcodeSemantics.MOD: int(LuaOpcode.OP_MOD),
            VMOpcodeSemantics.POW: int(LuaOpcode.OP_POW),
            VMOpcodeSemantics.NOT: int(LuaOpcode.OP_NOT),
            VMOpcodeSemantics.LEN: int(LuaOpcode.OP_LEN),
            VMOpcodeSemantics.CONCAT: int(LuaOpcode.OP_CONCAT),
            VMOpcodeSemantics.RETURN: int(LuaOpcode.OP_RETURN),
            VMOpcodeSemantics.CALL: int(LuaOpcode.OP_CALL),
            VMOpcodeSemantics.MOVE: int(LuaOpcode.OP_MOVE),
            VMOpcodeSemantics.LOADK: int(LuaOpcode.OP_LOADK),
            VMOpcodeSemantics.JMP: int(LuaOpcode.OP_JMP),
            VMOpcodeSemantics.GETTABLE: int(LuaOpcode.OP_GETTABLE),
            VMOpcodeSemantics.SETTABLE: int(LuaOpcode.OP_SETTABLE),
        }
        best_sem: Optional[str] = None
        best_score = 0.0
        for sem, patterns, base_conf, eff in VM_PATTERN_TABLE:
            score = 0.0
            for pat in patterns:
                try:
                    if re.search(pat, text, re.IGNORECASE):
                        score += 1.0
                except re.error:
                    pass
            if score > 0:
                conf = min(base_conf + 0.03 * (score - 1), 0.99)
                if conf > best_score:
                    best_score = conf
                    best_sem = sem
        if best_sem and best_sem in lua_op_map:
            return (lua_op_map[best_sem], best_sem)
        return None

    def _find_dispatcher(self, node: ASTNode) -> Optional[ASTNode]:
        if node.type == "While":
            for child in node.children:
                if child.type == "Block":
                    for stmt in child.children:
                        if stmt.type == "If" and self._count_elseif(stmt) > 5:
                            return stmt
        for child in node.children:
            result = self._find_dispatcher(child)
            if result:
                return result
        return None

    def _count_elseif(self, node: ASTNode) -> int:
        return sum(1 for c in node.children if c.type == "ElseIf")

    def _collect_branches(self, if_node: ASTNode) -> List[ASTNode]:
        branches = []
        for child in if_node.children:
            if child.type in ("Block", "ElseIf", "Else"):
                branches.append(child)
        return branches

    def _classify_branch(self, branch: ASTNode) -> Optional[Tuple[int, int, str]]:
        text = self._branch_to_text(branch)

        best_sem: Optional[str] = None
        best_score = 0.0
        for sem, patterns, base_conf, eff in VM_PATTERN_TABLE:
            score = 0.0
            for pat in patterns:
                try:
                    if re.search(pat, text, re.IGNORECASE):
                        score += 1.0
                except re.error:
                    pass
            if score > 0:
                conf = min(base_conf + 0.03 * (score - 1), 0.99)
                if conf > best_score:
                    best_score = conf
                    best_sem = sem

        lua_op_map = {
            VMOpcodeSemantics.MOVE: int(LuaOpcode.OP_MOVE),
            VMOpcodeSemantics.LOADK: int(LuaOpcode.OP_LOADK),
            VMOpcodeSemantics.LOADBOOL: int(LuaOpcode.OP_LOADBOOL),
            VMOpcodeSemantics.LOADNIL: int(LuaOpcode.OP_LOADNIL),
            VMOpcodeSemantics.GETUPVAL: int(LuaOpcode.OP_GETUPVAL),
            VMOpcodeSemantics.SETUPVAL: int(LuaOpcode.OP_SETUPVAL),
            VMOpcodeSemantics.GETGLOBAL: int(LuaOpcode.OP_GETGLOBAL),
            VMOpcodeSemantics.SETGLOBAL: int(LuaOpcode.OP_SETGLOBAL),
            VMOpcodeSemantics.GETTABLE: int(LuaOpcode.OP_GETTABLE),
            VMOpcodeSemantics.SETTABLE: int(LuaOpcode.OP_SETTABLE),
            VMOpcodeSemantics.NEWTABLE: int(LuaOpcode.OP_NEWTABLE),
            VMOpcodeSemantics.SELF: int(LuaOpcode.OP_SELF),
            VMOpcodeSemantics.ADD: int(LuaOpcode.OP_ADD),
            VMOpcodeSemantics.SUB: int(LuaOpcode.OP_SUB),
            VMOpcodeSemantics.MUL: int(LuaOpcode.OP_MUL),
            VMOpcodeSemantics.DIV: int(LuaOpcode.OP_DIV),
            VMOpcodeSemantics.MOD: int(LuaOpcode.OP_MOD),
            VMOpcodeSemantics.POW: int(LuaOpcode.OP_POW),
            VMOpcodeSemantics.UNM: int(LuaOpcode.OP_UNM),
            VMOpcodeSemantics.NOT: int(LuaOpcode.OP_NOT),
            VMOpcodeSemantics.LEN: int(LuaOpcode.OP_LEN),
            VMOpcodeSemantics.CONCAT: int(LuaOpcode.OP_CONCAT),
            VMOpcodeSemantics.JMP: int(LuaOpcode.OP_JMP),
            VMOpcodeSemantics.EQ: int(LuaOpcode.OP_EQ),
            VMOpcodeSemantics.LT: int(LuaOpcode.OP_LT),
            VMOpcodeSemantics.LE: int(LuaOpcode.OP_LE),
            VMOpcodeSemantics.TEST: int(LuaOpcode.OP_TEST),
            VMOpcodeSemantics.TESTSET: int(LuaOpcode.OP_TESTSET),
            VMOpcodeSemantics.CALL: int(LuaOpcode.OP_CALL),
            VMOpcodeSemantics.TAILCALL: int(LuaOpcode.OP_TAILCALL),
            VMOpcodeSemantics.RETURN: int(LuaOpcode.OP_RETURN),
            VMOpcodeSemantics.FORLOOP: int(LuaOpcode.OP_FORLOOP),
            VMOpcodeSemantics.FORPREP: int(LuaOpcode.OP_FORPREP),
            VMOpcodeSemantics.TFORLOOP: int(LuaOpcode.OP_TFORLOOP),
            VMOpcodeSemantics.SETLIST: int(LuaOpcode.OP_SETLIST),
            VMOpcodeSemantics.CLOSE: int(LuaOpcode.OP_CLOSE),
            VMOpcodeSemantics.CLOSURE: int(LuaOpcode.OP_CLOSURE),
            VMOpcodeSemantics.VARARG: int(LuaOpcode.OP_VARARG),
        }
        if best_sem and best_sem in lua_op_map:
            op_num = self._extract_case_number(branch)
            if op_num is not None:
                return (op_num, lua_op_map[best_sem], best_sem)

        if re.search(r"PC\s*=|IP\s*=|pc\s*=|ip\s*=", text) and re.search(r"offset|jump|jmp|sBx", text, re.IGNORECASE):
            op_num = self._extract_case_number(branch)
            if op_num is not None:
                return (op_num, int(LuaOpcode.OP_JMP), VMOpcodeSemantics.JMP)
        if re.search(r"Call|call", text) and re.search(r"\(", text):
            op_num = self._extract_case_number(branch)
            if op_num is not None:
                return (op_num, int(LuaOpcode.OP_CALL), VMOpcodeSemantics.CALL)
        if re.search(r"string\.format|tostring|concat|\.\.", text):
            op_num = self._extract_case_number(branch)
            if op_num is not None:
                return (op_num, int(LuaOpcode.OP_CONCAT), VMOpcodeSemantics.CONCAT)

        return None

    def _extract_case_number(self, branch: ASTNode) -> Optional[int]:
        if branch.type == "ElseIf":
            cond = branch.children[0] if branch.children else None
            if cond and cond.type == "BinOp" and cond.attrs.get("op") == "==":
                rhs = cond.children[1] if len(cond.children) > 1 else None
                if rhs and rhs.type == "Number":
                    return int(rhs.attrs["value"])
        return None

    def _branch_to_text(self, node: ASTNode) -> str:
        parts = []
        if node.attrs:
            parts.append(str(node.attrs))
        for child in node.children:
            parts.append(self._branch_to_text(child))
        return " ".join(parts)

    def translate(self, custom_op: int) -> int:
        return self.custom_to_std.get(custom_op, custom_op)

    def get_semantic(self, custom_op: int) -> Optional[str]:
        return self.custom_to_sem.get(custom_op)

    def get_confidence(self, custom_op: int) -> float:
        return self.confidence.get(custom_op, 0.0)


class ControlFlowSimplifier:
    def __init__(self, source: str):
        self.source = source

    def flatten_dead_code(self) -> str:
        src = self.source
        src = self._remove_never_true_ifs(src)
        src = self._remove_always_true_ifs(src)
        src = self._inline_single_call_functions(src)
        src = self._remove_empty_do_blocks(src)
        src = self._remove_trivial_while_false(src)
        src = self._remove_unused_locals(src)
        src = self._remove_dead_assignments(src)
        src = self._remove_unreachable_code(src)
        src = self._remove_empty_blocks(src)
        src = self._remove_redundant_blocks(src)
        return src

    def _remove_never_true_ifs(self, src: str) -> str:
        for cond in ("false", "nil", r"0\s*==\s*1", r"1\s*==\s*0", r"0", r'""', r"''",
                     r"\(\s*false\s*\)", r"\(\s*nil\s*\)", r"1\s*>\s*2", r"2\s*<\s*1",
                     r"0\s*~=\s*0", r"not\s+true"):
            src = re.sub(rf"if\s+{cond}\s+then.*?end", "", src, flags=re.DOTALL)
        return src

    def _remove_always_true_ifs(self, src: str) -> str:
        for cond in ("true", r"1\s*==\s*1", r"not\s+false", r"not\s+nil", r"not\s+0",
                     r"not\s+\(\s*false\s*\)", r"1\s*<\s*2", r"2\s*>\s*1",
                     r"1\s*~=\s*0", r"not\s+\(\s*nil\s*\)"):
            src = re.sub(rf"if\s+{cond}\s+then\s*(.*?)\s*end", r"\1", src, flags=re.DOTALL)
        return src

    def _inline_single_call_functions(self, src: str) -> str:
        pat = re.compile(
            r"local\s+(\w+)\s*=\s*function\s*\(\s*\)\s*\n\s*return\s+([^\n]+)\n\s*end",
            re.DOTALL,
        )
        for m in list(pat.finditer(src)):
            fname = m.group(1)
            retval = m.group(2).strip()
            if fname in retval:
                continue
            src = src.replace(m.group(0), "")
            src = re.sub(r"\b" + re.escape(fname) + r"\(\)", retval, src)
        return src

    def _remove_empty_do_blocks(self, src: str) -> str:
        return re.sub(r"\bdo\s*end\b", "", src)

    def _remove_trivial_while_false(self, src: str) -> str:
        src = re.sub(r"while\s+false\s+do.*?end", "", src, flags=re.DOTALL)
        src = re.sub(r"while\s+0\s*==\s*1\s+do.*?end", "", src, flags=re.DOTALL)
        src = re.sub(r"while\s+nil\s+do.*?end", "", src, flags=re.DOTALL)
        return src

    def _remove_unused_locals(self, src: str) -> str:
        for _ in range(3):
            decls = list(re.finditer(r"local\s+(\w+)\s*=\s*([^\n;]+)", src))
            for m in decls:
                name = m.group(1)
                rest = src[m.end():]
                uses = len(re.findall(r"\b" + re.escape(name) + r"\b", rest))
                if uses == 0:
                    src = src[:m.start()] + src[m.end():]
        return src

    def _remove_dead_assignments(self, src: str) -> str:
        for _ in range(2):
            assigns = list(re.finditer(r"^\s*(\w+)\s*=\s*([^\n;]+)$", src, re.MULTILINE))
            for m in assigns:
                name = m.group(1)
                rest = src[m.end():]
                next_assign = re.search(r"^\s*" + re.escape(name) + r"\s*=", rest, re.MULTILINE)
                if next_assign:
                    between = rest[:next_assign.start()]
                    if re.search(r"\b" + re.escape(name) + r"\b", between):
                        continue
                    src = src[:m.start()] + src[m.end():]
        return src

    def _remove_unreachable_code(self, src: str) -> str:
        src = re.sub(r"return\s+[^\n]+\n((?:(?!\bend\b|\bfunction\b|\bif\b|\bfor\b|\bwhile\b).*\n)+)",
                     "return\n", src)
        return src

    def _remove_empty_blocks(self, src: str) -> str:
        src = re.sub(r"function\s*\(\s*\)\s*end", "function() end", src)
        return src

    def _remove_redundant_blocks(self, src: str) -> str:
        src = re.sub(r"\bdo\s+(local\s+[^\n]+)\s+end\b", r"\1", src)
        src = re.sub(r"then\s+do\s+end\s*end", "then end", src)
        src = re.sub(r"else\s+do\s+end\b", "else end", src)
        return src

    def unfold_numeric_computations(self) -> str:
        src = self.source
        prev = None
        rounds = 0
        while prev != src and rounds < 12:
            prev = src
            src = re.sub(r"\b(\d+)\s*([\+\-\*\/\%])\s*(\d+)\b",
                         lambda m: self._safe_eval(m), src)
            src = re.sub(r"\(\s*(-?\d+)\s*\)", r"\1", src)
            src = re.sub(r"\b(\d+)\s*\*\s*1\b", r"\1", src)
            src = re.sub(r"\b1\s*\*\s*(\d+)\b", r"\1", src)
            src = re.sub(r"\b(\d+)\s*\+\s*0\b", r"\1", src)
            src = re.sub(r"\b0\s*\+\s*(\d+)\b", r"\1", src)
            src = re.sub(r"\b(\d+)\s*-\s*0\b", r"\1", src)
            src = re.sub(r"\b(\d+)\s*\/\s*1\b", r"\1", src)
            src = re.sub(r"\b(\d+)\s*\^\s*1\b", r"\1", src)
            src = re.sub(r"\b(\d+)\s*\^\s*0\b", "1", src)
            src = re.sub(r"\b(\d+)\s*\/\s*(\d+)\b",
                         lambda m: self._safe_eval(m) if m else m.group(0), src)
            rounds += 1
        return src

    def _safe_eval(self, m: re.Match) -> str:
        try:
            a = int(m.group(1))
            op = m.group(2)
            b = int(m.group(3))
            if op == "+":
                return str(a + b)
            if op == "-":
                return str(a - b)
            if op == "*":
                return str(a * b)
            if op == "/" and b != 0:
                return str(a // b if a % b == 0 else a / b)
            if op == "%" and b != 0:
                return str(a % b)
        except Exception:
            pass
        return m.group(0)

    def remove_redundant_locals(self) -> str:
        src = self.source
        src = re.sub(r"local\s+\w+\s*=\s*nil\s*\n", "\n", src)
        src = re.sub(r"local\s+\w+\s*=\s*0\s*\n(?!\s*\w+\s*[\+\-\*\/]=)", "\n", src)
        src = re.sub(r"local\s+(\w+)\s*=\s*(\w+)\s*\n\s*local\s+\1\s*=", r"local \1 = \2\n", src)
        return src

    def collapse_string_concat(self) -> str:
        src = self.source
        def concat_replacer(m):
            parts = re.findall(r'"([^"]*)"', m.group(0))
            if len(parts) >= 2:
                return '"' + "".join(parts) + '"'
            return m.group(0)
        src = re.sub(r'"[^"]*"\s*\.\.\s*(?:"[^"]*"\s*\.\.\s*)*"[^"]*"', concat_replacer, src)
        src = re.sub(r"'[^']*'\s*\.\.\s*(?:'[^']*'\s*\.\.\s*)*'[^']*'", concat_replacer, src)
        return src

    def normalize_boolean_ops(self) -> str:
        src = self.source
        src = re.sub(r"not\s*\(\s*not\s+(\w+)\s*\)", r"\1", src)
        src = re.sub(r"\(\s*(\w+)\s*and\s*true\s*\)", r"\1", src)
        src = re.sub(r"\(\s*(\w+)\s*or\s*false\s*\)", r"\1", src)
        src = re.sub(r"\(\s*true\s*and\s*(\w+)\s*\)", r"\1", src)
        src = re.sub(r"\(\s*false\s*or\s*(\w+)\s*\)", r"\1", src)
        src = re.sub(r"not\s+nil\b", "true", src)
        src = re.sub(r"not\s+false\b", "true", src)
        src = re.sub(r"\bnot\s+true\b", "false", src)
        return src

    def fold_string_char_calls(self) -> str:
        def repl(m):
            try:
                nums = [int(x.strip()) for x in m.group(1).split(",")]
                return '"' + "".join(chr(n) for n in nums if 0 <= n <= 0x10FFFF).replace("\\", "\\\\").replace('"', '\\"') + '"'
            except Exception:
                return m.group(0)
        return re.sub(r"string\.char\(\s*((?:\d+\s*,\s*)*\d+)\s*\)", repl, self.source)

    def propagate_constants(self) -> str:
        src = self.source
        for _ in range(5):
            const_decls: Dict[str, str] = {}
            for m in re.finditer(r"local\s+(\w+)\s*=\s*(-?\d+(?:\.\d+)?|true|false|nil)\b", src):
                const_decls[m.group(1)] = m.group(2)

            if not const_decls:
                break

            changed = False
            for name, val in list(const_decls.items()):
                pat = re.compile(r"\b" + re.escape(name) + r"\b(?!\s*=\s*)")
                occurrences = list(pat.finditer(src))
                if len(occurrences) <= 1:
                    continue
                for occ in reversed(occurrences[1:]):
                    src = src[:occ.start()] + val + src[occ.end():]
                    changed = True
            if not changed:
                break
        return src

    def simplify_algebraic(self) -> str:
        src = self.source
        src = re.sub(r"\b(\w+)\s*\*\s*1\b", r"\1", src)
        src = re.sub(r"\b1\s*\*\s*(\w+)\b", r"\1", src)
        src = re.sub(r"\b(\w+)\s*\+\s*0\b", r"\1", src)
        src = re.sub(r"\b0\s*\+\s*(\w+)\b", r"\1", src)
        src = re.sub(r"\b(\w+)\s*-\s*0\b", r"\1", src)
        src = re.sub(r"\b(\w+)\s*\/\s*1\b", r"\1", src)
        src = re.sub(r"\b(\w+)\s*\^\s*1\b", r"\1", src)
        src = re.sub(r"\b(\w+)\s*\^\s*0\b", "1", src)
        src = re.sub(r"\b0\s*\*\s*(\w+)\b", "0", src)
        src = re.sub(r"\b(\w+)\s*\*\s*0\b", "0", src)
        src = re.sub(r"\b(\w+)\s*and\s*\1\b", r"\1", src)
        src = re.sub(r"\b(\w+)\s*or\s*\1\b", r"\1", src)
        return src

    def dedupe_identical_locals(self) -> str:
        src = self.source
        pat = re.compile(r"(local\s+(\w+)\s*=\s*([^\n;]+)\s*;?\s*)\n(\s*local\s+\2\s*=\s*\3\s*;?\s*)")
        return pat.sub(r"\1", src)

    def flatten_deep_parens(self) -> str:
        src = self.source
        prev = None
        while prev != src:
            prev = src
            src = re.sub(r"\(\(([^()]+)\)\)", r"(\1)", src)
        return src

    def collapse_loadstring(self) -> str:
        def ls_repl(m):
            try:
                inner = m.group(1)
                for _ in range(5):
                    try:
                        dec = base64.b64decode(inner + "=" * (-len(inner) % 4))
                        text = dec.decode("utf-8", errors="replace")
                        if "local " in text or "function" in text or "return" in text:
                            return text
                        inner = text
                    except Exception:
                        break
                return m.group(0)
            except Exception:
                return m.group(0)
        return re.sub(r'loadstring\s*\(\s*"([A-Za-z0-9+/=]{20,})"\s*\)', ls_repl, self.source)

    def unflatten_state_machine(self) -> str:
        src = self.source
        return src


class AntiTamperBypass:
    def __init__(self, source: str):
        self.source = source

    def strip_integrity_checks(self) -> str:
        src = self.source

        src = re.sub(
            r"if\s+tostring\s*\(\s*\w+\s*\)\s*~=\s*[\"'].*?[\"']\s*then\s*(?:error|os\.exit|return)\s*.*?end",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(
            r"if\s+string\.byte\s*\(.*?\)\s*~=\s*\d+\s*then.*?end",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(
            r"local\s+\w+\s*=\s*require\s*\(\s*[\"']coroutine[\"']\s*\)[\s\S]{0,200}?if\s+\w+\s*~=\s*\w+\s*then",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(
            r"if\s+\w+\s*\(\s*\w+\s*\)\s*~=\s*\w+\s*\(\s*\w+\s*\)\s*then\s*(?:error|return).*?end",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(
            r"pcall\s*\(\s*function\s*\(\s*\)\s*.*?error.*?end\s*\)",
            "pcall(function() end)",
            src, flags=re.DOTALL,
        )
        src = re.sub(r"os\.clock\(\)|os\.time\(\)|tick\(\)", "0", src)
        src = re.sub(r"getfenv\s*\(\s*0\s*\)|getfenv\s*\(\s*1\s*\)", "_ENV", src)
        src = re.sub(
            r"if\s+getmetatable\s*\(.*?\)\s*~=\s*nil\s*then.*?end",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(r"rawset\s*\(\s*_ENV\s*,.*?\)", "", src, flags=re.DOTALL)
        src = re.sub(r"newproxy\s*\(.*?\)", "nil", src, flags=re.DOTALL)
        src = re.sub(
            r"if\s+#\w+\s*~=\s*\d+\s*then\s*(?:error|return|os\.exit).*?end",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(
            r"local\s+\w+\s*=\s*0\s*for\s+\w+\s*=\s*1\s*,\s*#\w+\s*do\s*\w+\s*=\s*\w+\s*\*\s*31\s*\+\s*string\.byte\s*\(\s*\w+\s*,\s*\w+\s*\)\s*end",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(
            r"if\s+\w+\s*~=\s*\d+\s*then\s*(?:error|return|os\.exit)\s*\(.*?\)\s*end",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(
            r"assert\s*\(\s*type\s*\(\s*\w+\s*\)\s*==\s*[\"']\w+[\"']\s*(?:,\s*[\"'][^\"']*[\"'])?\s*\)",
            "", src,
        )
        src = re.sub(
            r"if\s+not\s+pcall\s*\(.*?\)\s*then\s*(?:error|return|os\.exit).*?end",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(
            r"local\s+\w+\s*=\s*select\s*\(\s*[\"']#[\"']\s*,\s*\.\.\.\s*\)\s*if\s+\w+\s*~=\s*\d+\s*then\s*.*?end",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(
            r"if\s+type\s*\(\s*\w+\s*\)\s*~=\s*[\"'](function|table|string|number)[\"']\s*then\s*(?:error|return).*?end",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(
            r"error\s*\(\s*[\"'][^\"']*(?:tamper|corrupt|modif|invalid|integrity)[^\"']*[\"']\s*\)",
            "nil", src, flags=re.IGNORECASE,
        )
        src = re.sub(
            r"if\s+string\.len\s*\(\s*\w+\s*\)\s*~=\s*\d+\s*then\s*(?:error|return|os\.exit).*?end",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(
            r"local\s+\w+\s*=\s*0\s*for\s+\w+\s*=\s*1\s*,\s*#\w+\s*do\s*\w+\s*=\s*\(\w+\s*\+\s*string\.byte\s*\(\w+\s*,\s*\w+\)\s*\*\s*\d+\)\s*%\s*\d+\s*end",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(
            r"local\s+\w+\s*=\s*\{\}\s*for\s+\w+\s*=\s*1\s*,\s*\d+\s*do\s*\w+\s*=\s*\w+\s*\+\s*\w+\s*end",
            "", src, flags=re.DOTALL,
        )
        return src

    def strip_environment_locks(self) -> str:
        src = self.source
        src = re.sub(
            r"local\s+\w+\s*=\s*setmetatable\s*\(\s*\{\s*\}\s*,\s*\{[^\}]*__index\s*=\s*function\b.*?end\s*\}\s*\)",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(r"setfenv\s*\(\s*\d+\s*,\s*\w+\s*\)", "", src)
        src = re.sub(
            r"setmetatable\s*\(\s*\w+\s*,\s*\{\s*__index\s*=\s*function\s*\([^)]*\).*?end\s*\}\s*\)",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(r"rawequal\s*\([^)]+\)", "true", src)
        src = re.sub(
            r"setmetatable\s*\(\s*\w+\s*,\s*\{[^\}]*__metatable\s*=\s*[^\}]*\}\s*\)",
            "", src, flags=re.DOTALL,
        )
        return src

    def strip_debug_checks(self) -> str:
        src = self.source
        src = re.sub(r"debug\.sethook\s*\(.*?\)", "", src, flags=re.DOTALL)
        src = re.sub(r"debug\.getinfo\s*\(.*?\)", "{}", src, flags=re.DOTALL)
        src = re.sub(r"debug\.traceback\s*\(.*?\)", '""', src, flags=re.DOTALL)
        src = re.sub(
            r"if\s+debug\.\w+\s*(?:~=|==)\s*\w+\s*then.*?end",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(r"debug\.setmetatable\s*\([^)]+\)", "", src, flags=re.DOTALL)
        src = re.sub(r"debug\.getregistry\s*\(.*?\)", "{}", src, flags=re.DOTALL)
        src = re.sub(r"debug\.getupvalue\s*\(.*?\)", "nil", src, flags=re.DOTALL)
        src = re.sub(r"debug\.setupvalue\s*\(.*?\)", "", src, flags=re.DOTALL)
        src = re.sub(r"debug\.getlocal\s*\(.*?\)", "nil", src, flags=re.DOTALL)
        return src

    def strip_sandbox_checks(self) -> str:
        src = self.source
        src = re.sub(
            r"if\s+not\s+(?:string|table|math|coroutine)\s+then\s*return\s+end",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(
            r"if\s+_VERSION\s*~=\s*[\"'][^\"']*[\"']\s*then.*?end",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(
            r"local\s+\w+\s*=\s*_ENV\s+if\s+not\s+\w+\s+then.*?end",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(
            r"if\s+not\s+_G\s+then\s*(?:return|error|os\.exit).*?end",
            "", src, flags=re.DOTALL,
        )
        src = re.sub(
            r"if\s+rawget\s*\(\s*_G\s*,\s*[\"'][^\"']*[\"']\s*\)\s*~=\s*nil\s*then.*?end",
            "", src, flags=re.DOTALL,
        )
        return src

    def strip_timing_checks(self) -> str:
        src = self.source
        src = re.sub(r"local\s+\w+\s*=\s*os\.clock\s*\(\)", "", src)
        src = re.sub(r"local\s+\w+\s*=\s*os\.time\s*\(\)", "", src)
        src = re.sub(r"if\s+os\.clock\s*\(\s*\)\s*-\s*\w+\s*>\s*\d+\s*then.*?end", "", src, flags=re.DOTALL)
        src = re.sub(r"if\s+os\.time\s*\(\s*\)\s*-\s*\w+\s*>\s*\d+\s*then.*?end", "", src, flags=re.DOTALL)
        return src


class VariableRenamer:
    def __init__(self, source: str):
        self.source = source
        self.name_map: Dict[str, str] = {}
        self._counter: Dict[str, int] = defaultdict(int)

    OBFUSCATED_PATTERNS = [
        re.compile(r"^[lI]{4,}$"),
        re.compile(r"^[O0]{4,}$"),
        re.compile(r"^_+\d+$"),
        re.compile(r"^__[a-z]{3,6}\d{3,}$", re.IGNORECASE),
        re.compile(r"^[a-z]{1}[0-9]{5,}$"),
        re.compile(r"^[A-Za-z]{8,}$"),
        re.compile(r"^[a-zA-Z][a-zA-Z0-9]{6,}[A-Z][a-z]{2,}$"),
        re.compile(r"^_0x[0-9a-fA-F]{4,}$"),
        re.compile(r"^[_]{2,}[a-zA-Z0-9]{2,}[_]{2,}$"),
        re.compile(r"^[a-zA-Z]{2,3}\d{2,}[a-zA-Z]{1,2}$"),
        re.compile(r"^[lI]{2,}[0-9]{2,}[lI]{2,}$"),
        re.compile(r"^[A-Za-z_][A-Za-z0-9_]*[0-9]{3,}[A-Za-z0-9_]*$"),
        re.compile(r"^[A-Za-z]{1,3}\d{4,}$"),
        re.compile(r"^[Il1|]{6,}$"),
        re.compile(r"^[A-Za-z]{1,4}_[A-Za-z0-9]{6,}$"),
        re.compile(r"^[a-z]{2,4}[A-Z]{2,4}[a-z]{2,4}$"),
    ]

    ROLE_HINTS = {
        re.compile(r"Stack|stk|Stk", re.IGNORECASE): "Stack",
        re.compile(r"Const|const|CONST", re.IGNORECASE): "Const",
        re.compile(r"Instr|instr|opcode|INSTR"): "Instr",
        re.compile(r"Proto|proto|PROTO"): "Proto",
        re.compile(r"Upval|upval|UPVAL"): "Upval",
        re.compile(r"PC|ip\b|IP\b|InstrPtr"): "PC",
        re.compile(r"Env|env|_ENV", re.IGNORECASE): "Env",
        re.compile(r"Closure|closure"): "Closure",
        re.compile(r"Key|key|KEY"): "Key",
        re.compile(r"Table|tbl|Tbl", re.IGNORECASE): "Table",
        re.compile(r"Byte|byte|BYTE"): "Byte",
        re.compile(r"Index|idx|Idx", re.IGNORECASE): "Index",
        re.compile(r"Result|res|Res", re.IGNORECASE): "Result",
        re.compile(r"Count|cnt|Cnt", re.IGNORECASE): "Count",
        re.compile(r"Offset|off|Off", re.IGNORECASE): "Offset",
        re.compile(r"Reg|register|Register", re.IGNORECASE): "Reg",
        re.compile(r"Args|args|Args", re.IGNORECASE): "Args",
        re.compile(r"Cache|cache|Cache", re.IGNORECASE): "Cache",
        re.compile(r"Decoder|decoder|Decode", re.IGNORECASE): "Decoder",
        re.compile(r"Wrap|wrapper|Wrap", re.IGNORECASE): "Wrapper",
        re.compile(r"Temp|tmp", re.IGNORECASE): "Temp",
        re.compile(r"Buf|buffer|Buf", re.IGNORECASE): "Buffer",
        re.compile(r"Handler|handler", re.IGNORECASE): "Handler",
    }

    def is_obfuscated(self, name: str) -> bool:
        for pat in self.OBFUSCATED_PATTERNS:
            if pat.match(name):
                return True
        return False

    def guess_role(self, name: str) -> Optional[str]:
        for pat, role in self.ROLE_HINTS.items():
            if pat.search(name):
                return role
        return None

    def rename(self) -> str:
        tokens = re.findall(r"\b([a-zA-Z_]\w*)\b", self.source)
        unique_names = set(tokens)
        result = self.source
        for name in unique_names:
            if name in LUA_KEYWORDS or name in LUA_BUILTINS:
                continue
            if not self.is_obfuscated(name):
                continue
            if name in self.name_map:
                continue
            role = self.guess_role(name)
            if role:
                self._counter[role] += 1
                new_name = f"{role}_{self._counter[role]}"
            else:
                self._counter["var"] += 1
                new_name = f"var_{self._counter['var']}"
            self.name_map[name] = new_name

        for old, new in sorted(self.name_map.items(), key=lambda x: -len(x[0])):
            result = re.sub(r"\b" + re.escape(old) + r"\b", new, result)
        return result


class LuaCodegen:
    def __init__(self, proto: LuaProto):
        self.proto = proto
        self.indent = 0
        self.output: List[str] = []
        self.register_names: Dict[int, str] = {}
        self._init_registers()

    def _init_registers(self):
        for i, local in enumerate(self.proto.locals):
            if local[0] and local[0] not in ("(for index)", "(for limit)", "(for step)"):
                self.register_names[i] = local[0]

    def _reg(self, r: int) -> str:
        if r in self.register_names:
            return self.register_names[r]
        return f"R{r}"

    def _const(self, k: int) -> str:
        if 0 <= k < len(self.proto.constants):
            c = self.proto.constants[k]
            return str(c)
        return f"K[{k}]"

    def _rk(self, rk: int) -> str:
        if rk >= 256:
            return self._const(rk - 256)
        return self._reg(rk)

    def _write(self, line: str = ""):
        if line:
            self.output.append("  " * self.indent + line)
        else:
            self.output.append("")

    def generate(self) -> str:
        params = [self._reg(i) for i in range(self.proto.num_params)]
        if self.proto.is_vararg:
            params.append("...")

        self._write(f"local function fn_{abs(hash(self.proto.source)) % 10000}({', '.join(params)})")
        self.indent += 1

        i = 0
        instructions = self.proto.instructions
        while i < len(instructions):
            instr = instructions[i]
            op = instr.opcode
            A, B, C, Bx, sBx = instr.A, instr.B, instr.C, instr.Bx, instr.sBx

            if op == LuaOpcode.OP_MOVE:
                self._write(f"{self._reg(A)} = {self._reg(B)}")
            elif op == LuaOpcode.OP_LOADK:
                self._write(f"{self._reg(A)} = {self._const(Bx)}")
            elif op == LuaOpcode.OP_LOADBOOL:
                val = "true" if B else "false"
                self._write(f"{self._reg(A)} = {val}")
                if C:
                    self._write(f"goto label_{i + 2}")
            elif op == LuaOpcode.OP_LOADNIL:
                for r in range(A, B + 1):
                    self._write(f"{self._reg(r)} = nil")
            elif op == LuaOpcode.OP_GETGLOBAL:
                self._write(f"{self._reg(A)} = {self._const(Bx)}")
            elif op == LuaOpcode.OP_SETGLOBAL:
                self._write(f"{self._const(Bx)} = {self._reg(A)}")
            elif op == LuaOpcode.OP_GETTABLE:
                self._write(f"{self._reg(A)} = {self._reg(B)}[{self._rk(C)}]")
            elif op == LuaOpcode.OP_SETTABLE:
                self._write(f"{self._reg(A)}[{self._rk(B)}] = {self._rk(C)}")
            elif op == LuaOpcode.OP_NEWTABLE:
                self._write(f"{self._reg(A)} = {{}}")
            elif op == LuaOpcode.OP_SELF:
                self._write(f"{self._reg(A + 1)} = {self._reg(B)}")
                self._write(f"{self._reg(A)} = {self._reg(B)}[{self._rk(C)}]")
            elif op == LuaOpcode.OP_ADD:
                self._write(f"{self._reg(A)} = {self._rk(B)} + {self._rk(C)}")
            elif op == LuaOpcode.OP_SUB:
                self._write(f"{self._reg(A)} = {self._rk(B)} - {self._rk(C)}")
            elif op == LuaOpcode.OP_MUL:
                self._write(f"{self._reg(A)} = {self._rk(B)} * {self._rk(C)}")
            elif op == LuaOpcode.OP_DIV:
                self._write(f"{self._reg(A)} = {self._rk(B)} / {self._rk(C)}")
            elif op == LuaOpcode.OP_MOD:
                self._write(f"{self._reg(A)} = {self._rk(B)} % {self._rk(C)}")
            elif op == LuaOpcode.OP_POW:
                self._write(f"{self._reg(A)} = {self._rk(B)} ^ {self._rk(C)}")
            elif op == LuaOpcode.OP_UNM:
                self._write(f"{self._reg(A)} = -{self._reg(B)}")
            elif op == LuaOpcode.OP_NOT:
                self._write(f"{self._reg(A)} = not {self._reg(B)}")
            elif op == LuaOpcode.OP_LEN:
                self._write(f"{self._reg(A)} = #{self._reg(B)}")
            elif op == LuaOpcode.OP_CONCAT:
                parts = [self._reg(r) for r in range(B, C + 1)]
                self._write(f"{self._reg(A)} = {' .. '.join(parts)}")
            elif op == LuaOpcode.OP_JMP:
                target = i + 1 + sBx
                self._write(f"goto label_{target}")
            elif op == LuaOpcode.OP_EQ:
                cmp = "==" if A == 0 else "~="
                self._write(f"if {self._rk(B)} {cmp} {self._rk(C)} then")
                self._write(f"  goto label_{i + 2}")
                self._write("end")
            elif op == LuaOpcode.OP_LT:
                cmp = "<" if A == 0 else ">="
                self._write(f"if {self._rk(B)} {cmp} {self._rk(C)} then")
                self._write(f"  goto label_{i + 2}")
                self._write("end")
            elif op == LuaOpcode.OP_LE:
                cmp = "<=" if A == 0 else ">"
                self._write(f"if {self._rk(B)} {cmp} {self._rk(C)} then")
                self._write(f"  goto label_{i + 2}")
                self._write("end")
            elif op == LuaOpcode.OP_TEST:
                cond = "" if C else "not "
                self._write(f"if {cond}{self._reg(A)} then")
                self._write(f"  goto label_{i + 2}")
                self._write("end")
            elif op == LuaOpcode.OP_TESTSET:
                cond = "" if C else "not "
                self._write(f"if {cond}{self._reg(B)} then")
                self._write(f"  {self._reg(A)} = {self._reg(B)}")
                self._write(f"  goto label_{i + 2}")
                self._write("end")
            elif op == LuaOpcode.OP_CALL:
                args_start = A + 1
                num_args = B - 1
                if num_args < 0:
                    args = [self._reg(r) for r in range(args_start, args_start + 4)] + ["..."]
                else:
                    args = [self._reg(r) for r in range(args_start, args_start + num_args)]
                num_rets = C - 1
                if num_rets == 0:
                    self._write(f"{self._reg(A)}({', '.join(args)})")
                elif num_rets == 1:
                    self._write(f"{self._reg(A)} = {self._reg(A)}({', '.join(args)})")
                else:
                    rets = [self._reg(A + r) for r in range(num_rets)]
                    self._write(f"{', '.join(rets)} = {self._reg(A)}({', '.join(args)})")
            elif op == LuaOpcode.OP_TAILCALL:
                args_start = A + 1
                num_args = B - 1
                args = [self._reg(r) for r in range(args_start, args_start + max(num_args, 0))]
                self._write(f"return {self._reg(A)}({', '.join(args)})")
            elif op == LuaOpcode.OP_RETURN:
                if B == 1:
                    self._write("return")
                elif B == 2:
                    self._write(f"return {self._reg(A)}")
                else:
                    num_rets = B - 1
                    rets = [self._reg(A + r) for r in range(num_rets)]
                    self._write(f"return {', '.join(rets)}")
            elif op == LuaOpcode.OP_FORLOOP:
                self._write(f"{self._reg(A)} = {self._reg(A)} + {self._reg(A+2)}")
                self._write(f"if {self._reg(A)} <= {self._reg(A+1)} then goto label_{i + 1 + sBx} end")
            elif op == LuaOpcode.OP_FORPREP:
                self._write(f"{self._reg(A)} = {self._reg(A)} - {self._reg(A+2)}")
                self._write(f"goto label_{i + 1 + sBx}")
            elif op == LuaOpcode.OP_TFORLOOP:
                self._write(f"{self._reg(A+2)} = {self._reg(A+3)}")
                self._write(f"if {self._reg(A+3)} ~= nil then goto label_{i + 1 + sBx} end")
            elif op == LuaOpcode.OP_SETLIST:
                self._write(f"for _i = 1, {B} do {self._reg(A)}[_i] = {self._reg(A+_i)} end")
            elif op == LuaOpcode.OP_CLOSE:
                self._write(f"local _close_{A} = {self._reg(A)}")
            elif op == LuaOpcode.OP_CLOSURE:
                if 0 <= Bx < len(self.proto.protos):
                    self._write(f"{self._reg(A)} = <closure_{Bx}>")
                else:
                    self._write(f"{self._reg(A)} = <closure_{Bx}?>")
            elif op == LuaOpcode.OP_VARARG:
                if B == 0:
                    self._write(f"{self._reg(A)} = ...")
                else:
                    rets = [self._reg(A + r) for r in range(B - 1)]
                    self._write(f"{', '.join(rets)} = ...")
            elif op == LuaOpcode.OP_GETUPVAL:
                upname = self.proto.upvalues[B] if 0 <= B < len(self.proto.upvalues) else f"upval_{B}"
                self._write(f"{self._reg(A)} = {upname}")
            elif op == LuaOpcode.OP_SETUPVAL:
                upname = self.proto.upvalues[B] if 0 <= B < len(self.proto.upvalues) else f"upval_{B}"
                self._write(f"{upname} = {self._reg(A)}")
            else:
                self._write(f"R{A} = R{B}")

            i += 1

        self.indent -= 1
        self._write("end")
        self._write("")
        self._write(f"return fn_{abs(hash(self.proto.source)) % 10000}")
        return "\n".join(self.output)


class LuaBytecodeParser:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.int_size = 4
        self.size_t_size = 4
        self.instr_size = 4
        self.num_size = 8
        self.endian = "little"
        self.version = 0x51
        self.integral = False

    def read(self, n: int) -> bytes:
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            return 0
        return struct.unpack("B", self.read(1))[0]

    def read_int(self) -> int:
        fmt = "<i" if self.endian == "little" else ">i"
        size = self.int_size
        if size == 4:
            return struct.unpack(fmt, self.read(4))[0]
        elif size == 8:
            return struct.unpack(fmt.replace("i", "q"), self.read(8))[0]
        return 0

    def read_size_t(self) -> int:
        if self.size_t_size == 4:
            fmt = "<I" if self.endian == "little" else ">I"
            return struct.unpack(fmt, self.read(4))[0]
        else:
            fmt = "<Q" if self.endian == "little" else ">Q"
            return struct.unpack(fmt, self.read(8))[0]

    def read_double(self) -> float:
        fmt = "<d" if self.endian == "little" else ">d"
        return struct.unpack(fmt, self.read(8))[0]

    def read_float(self) -> float:
        fmt = "<f" if self.endian == "little" else ">f"
        return struct.unpack(fmt, self.read(4))[0]

    def read_string(self) -> str:
        size = self.read_size_t()
        if size == 0:
            return ""
        s = self.read(size)
        if size > 0 and s and s[-1:] == b"\x00":
            s = s[:-1]
        return s.decode("utf-8", errors="replace")

    def parse_header(self) -> bool:
        if len(self.data) < 12:
            return False
        sig = self.read(4)
        if sig != b"\x1bLua":
            return False
        version = self.read_byte()
        if version not in (0x51, 0x52, 0x53, 0x54):
            return False
        self.version = version
        self.read_byte()
        endian_byte = self.read_byte()
        self.endian = "little" if endian_byte == 1 else "big"
        self.int_size = self.read_byte()
        self.size_t_size = self.read_byte()
        self.instr_size = self.read_byte()
        self.num_size = self.read_byte()
        self.integral = bool(self.read_byte())
        if self.version == 0x54:
            self.read_byte()
        return True

    def parse_instruction(self) -> LuaInstruction:
        if self.version == 0x51:
            raw = struct.unpack("<I", self.read(4))[0]
            op = raw & 0x3F
            A = (raw >> 6) & 0xFF
            C = (raw >> 14) & 0x1FF
            B = (raw >> 23) & 0x1FF
            Bx = (raw >> 14) & 0x3FFFF
            sBx = Bx - 131071
            return LuaInstruction(op, A, B, C, Bx, sBx, raw)
        elif self.version in (0x52, 0x53):
            raw = struct.unpack("<I", self.read(4))[0]
            op = raw & 0x3F
            A = (raw >> 6) & 0xFF
            C = (raw >> 14) & 0x1FF
            B = (raw >> 23) & 0x1FF
            Bx = (raw >> 14) & 0x3FFFF
            sBx = Bx - 131071
            return LuaInstruction(op, A, B, C, Bx, sBx, raw)
        else:
            raw = struct.unpack("<I", self.read(4))[0]
            op = raw & 0x7F
            A = (raw >> 7) & 0xFF
            k = (raw >> 15) & 1
            C = (raw >> 16) & 0xFF
            B = (raw >> 24) & 0xFF
            Bx = (raw >> 15) & 0x1FFFF
            sBx = Bx - 65535
            return LuaInstruction(op, A, B, C, Bx, sBx, raw)

    def parse_constant(self) -> LuaConstant:
        t = self.read_byte()
        if t == 0:
            return LuaConstant(0, None)
        elif t == 1:
            b = self.read_byte()
            return LuaConstant(1, bool(b))
        elif t == 3:
            if self.num_size == 8:
                v = self.read_double()
            else:
                v = self.read_float()
            return LuaConstant(3, v)
        elif t == 4:
            s = self.read_string()
            return LuaConstant(4, s)
        elif t == 19:
            if self.int_size == 8:
                v = struct.unpack("<q" if self.endian == "little" else ">q", self.read(8))[0]
            else:
                v = self.read_int()
            return LuaConstant(3, v)
        return LuaConstant(t, None)

    def parse_proto(self) -> LuaProto:
        proto = LuaProto()
        proto.source = self.read_string()
        proto.line_defined = self.read_int()
        proto.last_line_defined = self.read_int()
        proto.num_upvalues = self.read_byte()
        proto.num_params = self.read_byte()
        proto.is_vararg = self.read_byte()
        proto.max_stack_size = self.read_byte()

        n_instrs = self.read_int()
        for _ in range(n_instrs):
            proto.instructions.append(self.parse_instruction())

        n_consts = self.read_int()
        for _ in range(n_consts):
            proto.constants.append(self.parse_constant())

        n_protos = self.read_int()
        for _ in range(n_protos):
            proto.protos.append(self.parse_proto())

        n_lines = self.read_int()
        for _ in range(n_lines):
            proto.lines.append(self.read_int())

        n_locals = self.read_int()
        for _ in range(n_locals):
            name = self.read_string()
            start = self.read_int()
            end = self.read_int()
            proto.locals.append((name, start, end))

        n_upvals = self.read_int()
        for _ in range(n_upvals):
            proto.upvalues.append(self.read_string())

        return proto

    def parse(self) -> Optional[LuaProto]:
        if not self.parse_header():
            return None
        return self.parse_proto()


class Beautifier:
    def __init__(self, source: str):
        self.source = source
        self.indent_size = 2

    def beautify(self) -> str:
        lines = self.source.split("\n")
        result = []
        indent = 0
        in_string = False
        string_char = None

        for line in lines:
            stripped = line.strip()

            if not stripped:
                result.append("")
                continue

            if stripped.startswith("--"):
                result.append("  " * indent + stripped)
                continue

            open_parens = 0
            close_parens = 0
            j = 0
            while j < len(stripped):
                c = stripped[j]
                if in_string:
                    if c == "\\":
                        j += 2
                        continue
                    if c == string_char:
                        in_string = False
                    j += 1
                    continue
                if c == '"' or c == "'":
                    in_string = True
                    string_char = c
                    j += 1
                    continue
                j += 1

            for kw in ("function", "if", "while", "for", "do", "repeat"):
                if re.search(r"\b" + kw + r"\b", stripped):
                    if kw == "do" and re.search(r"\bfor\b|\bwhile\b", stripped):
                        pass
                    elif kw == "if" and re.search(r"\belseif\b", stripped):
                        pass
                    else:
                        open_parens += 1

            for kw in ("end", "until"):
                if re.search(r"\b" + kw + r"\b", stripped):
                    if kw == "end" and re.search(r"\bif\b.*\bthen\b.*\bend\b", stripped):
                        pass
                    else:
                        close_parens += 1

            if re.search(r"\belse\b|\belseif\b", stripped):
                close_parens += 1
                open_parens += 1

            indent = max(0, indent + open_parens - close_parens)

            if re.search(r"\bend\b|\buntil\b|\belse\b|\belseif\b", stripped) and indent > 0:
                result.append("  " * indent + stripped)
            else:
                result.append("  " * indent + stripped)

        return "\n".join(result)

    def normalize_spacing(self) -> str:
        src = self.source
        src = re.sub(r"\s*,\s*", ", ", src)
        src = re.sub(r"\s*=\s*(?!=)", " = ", src)
        src = re.sub(r"\(\s+", "(", src)
        src = re.sub(r"\s+\)", ")", src)
        src = re.sub(r"\{\s+", "{", src)
        src = re.sub(r"\s+\}", "}", src)
        src = re.sub(r"\s*\.\.\s*", " .. ", src)
        src = re.sub(r"\s*:\s*", ": ", src)
        src = re.sub(r"\s*;\s*", "; ", src)
        src = re.sub(r"  +", " ", src)
        return src

    def add_blank_lines(self) -> str:
        src = self.source
        src = re.sub(r"\n(local function|function)\s", r"\n\n\1 ", src)
        src = re.sub(r"\n(return)\s", r"\n\n\1 ", src)
        src = re.sub(r"\n(if)\s", r"\n\n\1 ", src)
        src = re.sub(r"\n(for)\s", r"\n\n\1 ", src)
        src = re.sub(r"\n(while)\s", r"\n\n\1 ", src)
        return src

    def align_equals(self) -> str:
        lines = self.source.split("\n")
        result = []
        for line in lines:
            m = re.match(r"^(\s*local\s+\w+\s*)=\s*(.*)$", line)
            if m:
                result.append(f"{m.group(1)}= {m.group(2)}")
            else:
                result.append(line)
        return "\n".join(result)


class VMSemanticInterpreter:
    def __init__(
        self,
        source: str,
        splitter: VMSplitter,
        extractor: Optional[VMExtractor] = None,
        bytecode: Optional[List[int]] = None,
    ):
        self.source = source
        self.splitter = splitter
        self.extractor = extractor
        self.bytecode = bytecode
        self.instructions: List[VMInstruction] = []
        self.lifted_code: Optional[str] = None
        self.confidence: float = 0.0

    def run(self) -> Optional[str]:
        if not self.splitter.handler_infos:
            return None

        opcode_map: Dict[int, str] = {}
        for case_num, info in self.splitter.handler_infos.items():
            if info.semantic:
                opcode_map[case_num] = info.semantic
        if len(opcode_map) < 4:
            return None

        raw_bytes = self._collect_raw_bytes()
        if not raw_bytes or len(raw_bytes) < 16:
            return None

        layouts = self._candidate_layouts()
        best_code: Optional[str] = None
        best_score = 0.0

        for layout in layouts:
            decoder = VMBytecodeDecoder(opcode_map, **layout)
            for rotation in [0] + list(range(1, 32)):
                try:
                    if rotation:
                        instrs = decoder.decode_with_rotation(raw_bytes, rotation)
                    else:
                        instrs = decoder.decode(raw_bytes)
                except Exception:
                    continue
                if not instrs:
                    continue
                recognized = sum(1 for i in instrs if i.semantic)
                if recognized < 3:
                    continue
                coverage = recognized / len(instrs)
                if coverage < 0.35:
                    continue
                constants = self._collect_constants()
                emulator = VMEmulator(instrs, self.splitter.handler_infos, constants)
                try:
                    output_lines = emulator.execute()
                except Exception:
                    continue
                if not output_lines:
                    continue
                score = coverage * 200.0 + len(output_lines) * 0.5
                if score > best_score:
                    best_score = score
                    best_code = "\n".join(output_lines)

        if best_code and best_score >= 30:
            self.lifted_code = best_code
            self.confidence = min(best_score / 300.0, 1.0)
            return best_code
        return None

    def _candidate_layouts(self) -> List[Dict[str, Any]]:
        base = {
            "word_size": self.splitter.instruction_word_size or 4,
            "endian": self.splitter.instruction_endian or "little",
            "opcode_width": self.splitter.opcode_bit_width or 6,
            "opcode_shift": self.splitter.opcode_shift or 0,
            "a_shift": self.splitter.a_shift or 6,
            "a_width": self.splitter.a_width or 8,
            "b_shift": self.splitter.b_shift or 23,
            "b_width": self.splitter.b_width or 9,
            "c_shift": self.splitter.c_shift or 14,
            "c_width": self.splitter.c_width or 9,
        }
        layouts: List[Dict[str, Any]] = [base]

        standard_variants = [
            {"opcode_width": 6, "opcode_shift": 0, "a_shift": 6, "a_width": 8, "c_shift": 14, "c_width": 9, "b_shift": 23, "b_width": 9},
            {"opcode_width": 6, "opcode_shift": 0, "a_shift": 6, "a_width": 8, "b_shift": 14, "b_width": 9, "c_shift": 23, "c_width": 9},
            {"opcode_width": 5, "opcode_shift": 0, "a_shift": 5, "a_width": 8, "b_shift": 13, "b_width": 9, "c_shift": 22, "c_width": 9},
            {"opcode_width": 8, "opcode_shift": 0, "a_shift": 8, "a_width": 8, "b_shift": 16, "b_width": 8, "c_shift": 24, "c_width": 8},
            {"opcode_width": 7, "opcode_shift": 0, "a_shift": 7, "a_width": 8, "b_shift": 15, "b_width": 8, "c_shift": 23, "c_width": 8},
            {"opcode_width": 6, "opcode_shift": 0, "a_shift": 6, "a_width": 8, "b_shift": 14, "b_width": 8, "c_shift": 22, "c_width": 8},
        ]
        for variant in standard_variants:
            merged = dict(base)
            merged.update(variant)
            if merged not in layouts:
                layouts.append(merged)

        for ws in (4, 8, 2):
            for endian in ("little", "big"):
                for opw in (4, 5, 6, 7, 8):
                    if opw < 4:
                        continue
                    merged = dict(base)
                    merged["word_size"] = ws
                    merged["endian"] = endian
                    merged["opcode_width"] = opw
                    if merged not in layouts:
                        layouts.append(merged)
        return layouts

    def _collect_raw_bytes(self) -> Optional[bytes]:
        if self.bytecode:
            try:
                return bytes([b & 0xFF for b in self.bytecode])
            except Exception:
                pass
        if self.splitter.instruction_array_body:
            raw_nums = re.findall(r"0x[0-9a-fA-F]+|\d+", self.splitter.instruction_array_body)
            if len(raw_nums) >= 16:
                try:
                    return bytes([int(x, 0) & 0xFF for x in raw_nums])
                except Exception:
                    pass
        return None

    def _collect_constants(self) -> List[Any]:
        constants: List[Any] = []
        if not self.splitter.constant_pool:
            return constants
        body = self.splitter.constant_pool
        for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', body):
            try:
                constants.append(bytes(m.group(1), "utf-8").decode("unicode_escape"))
            except Exception:
                constants.append(m.group(1))
        for m in re.finditer(r"'((?:[^'\\]|\\.)*)'", body):
            constants.append(m.group(1))
        for m in re.finditer(r"\b(0x[0-9a-fA-F]+|\d+)\b", body):
            try:
                constants.append(int(m.group(1), 0))
            except Exception:
                pass
        return constants


class DeobfuscationPipeline:
    def __init__(self, source: str, verbose: bool = False):
        self.source = source
        self.verbose = verbose
        self.vm_type = VMFingerprint.UNKNOWN
        self.ast: Optional[ASTNode] = None
        self.mapper = OpcodeMapper()
        self.vm_info: Dict[str, Any] = {}
        self.decoy_detector = DecoyDetector()
        self.utils = Utils()
        self.vm_splitter: Optional[VMSplitter] = None
        self.vm_interpreter: Optional[VMSemanticInterpreter] = None
        self.report: Dict[str, Any] = {
            "vm_type": "unknown",
            "all_detected": [],
            "strings_decoded": 0,
            "anti_tamper_stripped": 0,
            "control_flow_simplified": 0,
            "variables_renamed": 0,
            "bytecode_extracted": False,
            "opcode_map": {},
            "vm_specific_decoded": False,
            "luraph_version": None,
            "sub_decoders_used": [],
            "handlers_extracted": 0,
            "vm_functions": 0,
            "decoys_removed": 0,
            "advanced_cleanup_passes": 0,
            "junk_removed": 0,
            "string_chars_eliminated": 0,
            "vm_components_split": 0,
            "vm_handlers_isolated": 0,
            "vm_dispatchers_found": 0,
            "vm_instruction_arrays": 0,
            "vm_constant_pools": 0,
            "vm_register_flows": 0,
            "vm_jump_edges": 0,
            "vm_opcode_map_size": 0,
            "vm_lifted": False,
            "vm_lift_confidence": 0.0,
            "vm_lift_lines": 0,
            "vm_pc_var": None,
            "vm_stack_var": None,
            "vm_const_var": None,
            "vm_word_size": 0,
        }

    def log(self, msg: str):
        if self.verbose:
            print(f"  [Secrovia V1] {msg}")

    def run(self) -> str:
        self.log("Starting deobfuscation pipeline...")

        self.log("Step 1: Fingerprinting VM...")
        self.vm_type = VMFingerprint.identify(self.source)
        all_detected = VMFingerprint.identify_all(self.source)
        self.report["vm_type"] = self.vm_type
        self.report["all_detected"] = all_detected
        self.log(f"         Detected: {self.vm_type}")
        if len(all_detected) > 1:
            self.log(f"         Also matched: {', '.join(all_detected[:5])}")

        self.log("Step 2: Removing decoy patterns...")
        try:
            cleaned, removed = self.decoy_detector.remove_decoys(self.source)
            total_removed = sum(removed.values())
            if total_removed:
                self.source = cleaned
                self.report["decoys_removed"] = total_removed
                for desc, count in list(removed.items())[:5]:
                    self.log(f"         Removed {count} x {desc}")
        except Exception as e:
            self.log(f"         Decoy removal error: {e}")

        self.log("Step 3: Stripping anti-tamper and debug checks...")
        before = len(self.source)
        atb = AntiTamperBypass(self.source)
        self.source = atb.strip_integrity_checks()
        self.source = atb.strip_environment_locks()
        self.source = atb.strip_debug_checks()
        self.source = atb.strip_sandbox_checks()
        self.source = atb.strip_timing_checks()
        after = len(self.source)
        self.report["anti_tamper_stripped"] = before - after
        self.log(f"         Removed {before - after} chars of anti-tamper")

        self.log("Step 4: VM-specific pre-decode...")
        self.source = self._vm_specific_decode(self.source)
        self.log(f"         VM-specific decode done")

        self.log("Step 5: Eliminating string.char obfuscation...")
        before_sc = len(self.source)
        self.source = StringCharEliminator.eliminate(self.source)
        sc_delta = before_sc - len(self.source)
        self.report["string_chars_eliminated"] = sc_delta
        self.log(f"         Eliminated {sc_delta} chars of string.char obfuscation")

        self.log("Step 6: Decoding strings (multi-layer)...")
        self.source = self._decode_all_strings(self.source)
        self.log(f"         Decoded {self.report['strings_decoded']} strings")

        self.log("Step 7: Applying advanced cleanup pass...")
        self.source = self._advanced_cleanup(self.source)
        self.report["advanced_cleanup_passes"] += 1
        self.log("         Advanced cleanup applied")

        self.log("Step 8: Removing junk code...")
        before_junk = len(self.source)
        jce = JunkCodeEliminator(self.source)
        self.source = jce.eliminate()
        junk_delta = before_junk - len(self.source)
        self.report["junk_removed"] = junk_delta
        self.log(f"         Removed {junk_delta} chars of junk code")

        self.log("Step 9: Parsing AST...")
        try:
            lexer = LuaLexer(self.source)
            tokens = lexer.tokenize()
            parser = LuaParser(tokens)
            self.ast = parser.parse()
            self.log("         AST parsed successfully")
        except Exception as e:
            self.log(f"         AST parse failed: {e} (continuing without)")
            self.ast = None

        self.log("Step 10: Extracting VM dispatch structure...")
        if self.ast:
            extractor = VMExtractor(self.source, self.ast)
            self.vm_info = extractor.extract()
            self.report["handlers_extracted"] = len(self.vm_info.get("handlers", {}))
            self.report["vm_dispatchers_found"] = len(self.vm_info.get("dispatchers", []))
            self.log(f"         Extracted {self.report['handlers_extracted']} handlers")
            self.log(f"         Dispatchers: {self.report['vm_dispatchers_found']}")
            self.log(f"         PC var: {self.vm_info.get('pc_var')}, Stack var: {self.vm_info.get('stack_var')}")

        self.log("Step 11: Splitting VM into components...")
        self.vm_splitter = VMSplitter(self.source)
        vm_components = self.vm_splitter.split()
        self.report["vm_components_split"] = len(vm_components)
        self.report["vm_handlers_isolated"] = len(self.vm_splitter.handlers)
        self.report["vm_dispatchers_found"] = vm_components.get("dispatcher_count", 0)
        self.report["vm_instruction_arrays"] = len(vm_components.get("instruction_arrays", []))
        self.report["vm_constant_pools"] = len(vm_components.get("constant_pools", []))
        self.report["vm_register_flows"] = len(vm_components.get("register_reads", {}))
        edges = sum(len(v) for v in vm_components.get("jump_graph", {}).values())
        self.report["vm_jump_edges"] = edges
        self.report["vm_opcode_map_size"] = len(vm_components.get("opcode_map", {}))
        self.report["vm_pc_var"] = vm_components.get("pc_var")
        self.report["vm_stack_var"] = vm_components.get("stack_var")
        self.report["vm_const_var"] = vm_components.get("const_var")
        self.report["vm_word_size"] = vm_components.get("word_size", 0)
        if vm_components:
            comp_list = [k for k in vm_components.keys() if k not in ("handler_count",)]
            self.log(f"         Split components: {', '.join(comp_list[:12])}")
            self.log(f"         Isolated {len(self.vm_splitter.handlers)} handlers")
            self.log(f"         Dispatchers found: {vm_components.get('dispatcher_count', 0)}")
            self.log(f"         Instruction arrays: {self.report['vm_instruction_arrays']}")
            self.log(f"         Constant pools: {self.report['vm_constant_pools']}")
            self.log(f"         Jump edges: {self.report['vm_jump_edges']}")
            self.log(f"         Register flows: {self.report['vm_register_flows']}")
            if self.vm_splitter.instruction_array_name:
                self.log(f"         Instruction array: {self.vm_splitter.instruction_array_name}")
            if self.vm_splitter.constant_pool_name:
                self.log(f"         Constant pool: {self.vm_splitter.constant_pool_name}")
            if self.vm_splitter.pc_var:
                self.log(f"         PC var: {self.vm_splitter.pc_var}")
            if self.vm_splitter.stack_var:
                self.log(f"         Stack var: {self.vm_splitter.stack_var}")

        self.log("Step 12: Learning opcode map from VM dispatcher...")
        if self.ast:
            success = self.mapper.learn_from_ast(self.ast)
            self.report["opcode_map"] = {
                str(k): (v if isinstance(v, str) else OPCODE_NAMES.get(v, str(v)))
                for k, v in self.mapper.custom_to_sem.items()
            }
            self.log(f"         Mapped {len(self.mapper.custom_to_std)} opcodes")

            if not success:
                analyzer = DispatcherAnalyzer(self.ast)
                dispatchers = analyzer.find_dispatchers()
                for disp in dispatchers:
                    handlers = analyzer.analyze(disp)
                    if handlers:
                        self.log(f"         Dispatcher has {len(handlers)} cases")
                        self._learn_from_dispatcher_handlers(handlers)
                        break

        if self.vm_splitter and self.vm_splitter.handlers:
            learned = self.mapper.learn_from_handlers(
                {k: v for k, v in self.vm_splitter.handler_infos.items()}
            )
            if learned:
                self.log(f"         Learned {learned} opcodes from splitter handlers")
            for case_num, info in self.vm_splitter.handler_infos.items():
                if info.semantic:
                    self.mapper.custom_to_sem[case_num] = info.semantic
            self.report["opcode_map"] = {
                str(k): v
                for k, v in self.mapper.custom_to_sem.items()
            }
        else:
            self.log("         Skipped (no AST)")

        self.log("Step 13: Extracting bytecode payload...")
        bytecode = self._extract_best_bytecode()
        if bytecode:
            key_info = BytecodeExtractor.find_decode_key(self.source)
            decoded_bytecode = BytecodeExtractor.apply_decode(bytecode, key_info)
            self.report["bytecode_extracted"] = True
            self.log(f"         Extracted {len(decoded_bytecode)} bytes of bytecode")

            lua_bin = self._try_parse_lua_binary(bytes(decoded_bytecode))
            if lua_bin:
                self.log("         Parsed as standard Lua bytecode!")
                lifted = LuaCodegen(lua_bin).generate()
                beautified = Beautifier(lifted).beautify()
                return beautified

            brute = BytecodeExtractor.try_brute_xor_keys(decoded_bytecode)
            if brute:
                xor_key, raw_lua = brute
                self.log(f"         Brute-forced XOR key: 0x{xor_key:02X}")
                lua_bin = self._try_parse_lua_binary(raw_lua)
                if lua_bin:
                    lifted = LuaCodegen(lua_bin).generate()
                    beautified = Beautifier(lifted).beautify()
                    return beautified

            rolling_brute = BytecodeExtractor.try_brute_rolling_xor(decoded_bytecode)
            if rolling_brute:
                key_info_r, raw_lua_r = rolling_brute
                self.log(f"         Brute-forced rolling XOR: start={key_info_r['start']}, step={key_info_r['step']}")
                lua_bin = self._try_parse_lua_binary(raw_lua_r)
                if lua_bin:
                    lifted = LuaCodegen(lua_bin).generate()
                    beautified = Beautifier(lifted).beautify()
                    return beautified

            add_sub_brute = BytecodeExtractor.try_brute_add_sub(decoded_bytecode)
            if add_sub_brute:
                key_info_a, raw_lua_a = add_sub_brute
                self.log(f"         Brute-forced {key_info_a['type']} key={key_info_a['key']}")
                lua_bin = self._try_parse_lua_binary(raw_lua_a)
                if lua_bin:
                    lifted = LuaCodegen(lua_bin).generate()
                    beautified = Beautifier(lifted).beautify()
                    return beautified

            multi_brute = BytecodeExtractor.try_brute_multi_xor(decoded_bytecode)
            if multi_brute:
                key_info_m, raw_lua_m = multi_brute
                self.log(f"         Brute-forced multi-byte XOR")
                lua_bin = self._try_parse_lua_binary(raw_lua_m)
                if lua_bin:
                    lifted = LuaCodegen(lua_bin).generate()
                    beautified = Beautifier(lifted).beautify()
                    return beautified
        else:
            self.log("         No bytecode array found")

        self.log("Step 13b: Attempting semantic VM lift (VM -> Lua)...")
        if self.vm_splitter and self.vm_splitter.handler_infos:
            interpreter = VMSemanticInterpreter(
                self.source,
                self.vm_splitter,
                None,
                bytecode,
            )
            lifted_vm = interpreter.run()
            if lifted_vm:
                self.vm_interpreter = interpreter
                self.report["vm_lifted"] = True
                self.report["vm_lift_confidence"] = interpreter.confidence
                self.report["vm_lift_lines"] = len(lifted_vm.splitlines())
                self.log(f"         VM lifted: {self.report['vm_lift_lines']} lines, confidence={interpreter.confidence:.2f}")
                lifted_vm = self._post_lift_refine(lifted_vm)
                beautified_vm = Beautifier(lifted_vm).beautify()
                return beautified_vm
            else:
                self.log("         VM lift failed (insufficient semantic coverage)")
        else:
            self.log("         Skipped (no handler info)")

        self.log("Step 14: Control flow simplification...")
        cfs = ControlFlowSimplifier(self.source)
        self.source = cfs.flatten_dead_code()
        self.source = cfs.unfold_numeric_computations()
        self.source = cfs.propagate_constants()
        self.source = cfs.simplify_algebraic()
        self.source = cfs.remove_redundant_locals()
        self.source = cfs.collapse_string_concat()
        self.source = cfs.normalize_boolean_ops()
        self.source = cfs.fold_string_char_calls()
        self.source = cfs.dedupe_identical_locals()
        self.source = cfs.flatten_deep_parens()
        self.source = cfs.collapse_loadstring()
        self.report["control_flow_simplified"] += 1
        self.log("         Control flow simplified")

        self.log("Step 15: Second-pass junk elimination...")
        jce2 = JunkCodeEliminator(self.source)
        self.source = jce2.eliminate()
        self.source = StringCharEliminator.eliminate(self.source)
        self.log("         Second-pass junk removal done")

        self.log("Step 16: Renaming obfuscated variables...")
        if not self.report.get("skip_rename"):
            renamer = VariableRenamer(self.source)
            self.source = renamer.rename()
            self.report["variables_renamed"] = len(renamer.name_map)
            self.log(f"         Renamed {len(renamer.name_map)} variables")
        else:
            self.log("         Skipped (--no-rename)")

        self.log("Step 17: Beautifying output...")
        beautifier = Beautifier(self.source)
        self.source = beautifier.normalize_spacing()
        self.source = beautifier.beautify()
        self.source = beautifier.add_blank_lines()
        self.source = beautifier.align_equals()
        self.log("         Beautified")

        self.log("Step 18: Final cleanup...")
        self.source = self._final_cleanup(self.source)
        self.log("         Done")

        return self.source

    def _post_lift_refine(self, code: str) -> str:
        code = re.sub(r"\bR(\d+)\b", r"reg_\1", code)
        code = re.sub(r"\b_\s*=\s*_", "", code)
        code = re.sub(r"^[ \t]*$\n", "", code, flags=re.MULTILINE)
        code = re.sub(r"\n{3,}", "\n\n", code)
        code = re.sub(r"\bL(\d+)\b", r"label_\1", code)
        return code.strip()

    def _advanced_cleanup(self, src: str) -> str:
        try:
            src = AdvancedCleanup.fix_duplicate_locals(src)
            src = AdvancedCleanup.fix_table_syntax(src)
            src = AdvancedCleanup.detect_and_fix_syntax_errors(src)
            src = AdvancedCleanup.fix_operator_misuse(src)
            src = AdvancedCleanup.handle_number_obfuscation(src)
            src = AdvancedCleanup.evaluate_arithmetic(src)
            src = AdvancedCleanup.detect_arithmetic_obfuscation(src)
            src = AdvancedCleanup.reconstruct_array_initialization(src)
            src = AdvancedCleanup.resolve_metatable_ops(src)
            src = AdvancedCleanup.simplify_arithmetic_masks(src)
            src = AdvancedCleanup.handle_accumulator_patterns(src)
            src = AdvancedCleanup.track_buffer_permutations(src)
            src = AdvancedCleanup.reverse_array_permutations(src)
            src = AdvancedCleanup.resolve_buffer_indices(src)
            src = AdvancedCleanup.simplify_numeric_operations(src)
            src = AdvancedCleanup.fix_table_declarations(src)
            src = AdvancedCleanup.resolve_library_aliases(src)
            src = AdvancedCleanup.propagate_constants_simple(src)
            src = AdvancedCleanup.remove_invalid_chars(src)
            src = AdvancedCleanup.normalize_loop_structures(src)
            src = AdvancedCleanup.resolve_string_sub_calls(src)
            src = AdvancedCleanup.resolve_array_jumps(src)
            src = AdvancedCleanup.resolve_vm_dispatches(src)
            src = AdvancedCleanup.prune_dead_code(src)
            src = AdvancedCleanup.normalize_string_ops(src)
            src = AdvancedCleanup.collapse_double_brackets(src)
            src = AdvancedCleanup.fold_numeric_constants(src)
            src = AdvancedCleanup.strip_redundant_semicolons(src)
            src = Utils.reverse_string_permutation(src)
            src = self.utils.reconstruct_final_string(src)
        except Exception as e:
            self.log(f"         Advanced cleanup warning: {e}")
        return src

    def _learn_from_dispatcher_handlers(self, handlers: Dict[int, str]):
        patterns = [
            (r"\+", LuaOpcode.OP_ADD),
            (r"Stack\[A\]\s*=\s*Stack\[B\]\s*-\s*Stack\[C\]", LuaOpcode.OP_SUB),
            (r"\*", LuaOpcode.OP_MUL),
            (r"/", LuaOpcode.OP_DIV),
            (r"%", LuaOpcode.OP_MOD),
            (r"\^", LuaOpcode.OP_POW),
        ]
        for case_num, text in handlers.items():
            for pat, op in patterns:
                if re.search(pat, text):
                    if case_num not in self.mapper.custom_to_std:
                        self.mapper.custom_to_std[case_num] = int(op)
                        break

    def _vm_specific_decode(self, src: str) -> str:
        vm = self.vm_type
        all_detected = self.report.get("all_detected", [])

        if vm == VMFingerprint.LURAPH_V11 or VMFingerprint.LURAPH_V11 in all_detected:
            self.log("         Trying Luraph v11.x decoder...")
            ver = LuraphV11Decoder.detect_version(src)
            self.report["luraph_version"] = ver
            decoded = LuraphV11Decoder.decode_v11(src)
            if decoded != src:
                self.report["vm_specific_decoded"] = True
                self.report["sub_decoders_used"].append("luraph_v11")
                self.log(f"         Luraph v11 ({ver}) decoded successfully")
                return LuraphV11Decoder.strip_vm_wrapper(decoded)
            src = LuraphV11Decoder.strip_vm_wrapper(src)

        if vm == VMFingerprint.LURAPH_V13 or VMFingerprint.LURAPH_V13 in all_detected:
            self.log("         Trying Luraph v13.x decoder...")
            ver = LuraphV13Decoder.detect_version(src)
            self.report["luraph_version"] = ver
            decoded = LuraphV13Decoder.decode_v13(src)
            if decoded != src:
                self.report["vm_specific_decoded"] = True
                self.report["sub_decoders_used"].append("luraph_v13")
                self.log(f"         Luraph v13 ({ver}) decoded successfully")
                return LuraphV13Decoder.strip_vm_wrapper(decoded)
            src = LuraphV13Decoder.strip_vm_wrapper(src)

        if vm == VMFingerprint.LURAPH_V14 or VMFingerprint.LURAPH_V14 in all_detected:
            self.log("         Trying Luraph v14.x decoder...")
            ver = LuraphV14Decoder.detect_version(src)
            self.report["luraph_version"] = ver
            decoded = LuraphV14Decoder.decode_v14(src)
            if decoded != src:
                self.report["vm_specific_decoded"] = True
                self.report["sub_decoders_used"].append("luraph_v14")
                self.log(f"         Luraph v14 ({ver}) decoded successfully")
                return LuraphV14Decoder.strip_vm_wrapper(decoded)
            src = LuraphV14Decoder.strip_vm_wrapper(src)

        if vm == VMFingerprint.LURAPH or "luraph" in [d.lower() for d in all_detected]:
            v11_dec = LuraphV11Decoder.decode_v11(src)
            if v11_dec != src:
                self.report["vm_specific_decoded"] = True
                self.report["sub_decoders_used"].append("luraph_v11_fallback")
                return v11_dec
            v13_dec = LuraphV13Decoder.decode_v13(src)
            if v13_dec != src:
                self.report["vm_specific_decoded"] = True
                self.report["sub_decoders_used"].append("luraph_v13_fallback")
                return v13_dec
            v14_dec = LuraphV14Decoder.decode_v14(src)
            if v14_dec != src:
                self.report["vm_specific_decoded"] = True
                self.report["sub_decoders_used"].append("luraph_v14_fallback")
                return v14_dec

        if vm == VMFingerprint.MOONSEC_V3 or VMFingerprint.MOONSEC_V3 in all_detected:
            self.log("         Trying MoonSec v3 decoder...")
            dec = MoonSecV3Decoder.decode(src)
            if dec != src:
                self.report["vm_specific_decoded"] = True
                self.report["sub_decoders_used"].append("moonsec_v3")
                return dec

        if vm == VMFingerprint.MOONSEC_V2 or VMFingerprint.MOONSEC_V2 in all_detected:
            dec = MoonSecV2Decoder.decode(src)
            if dec != src:
                self.report["vm_specific_decoded"] = True
                self.report["sub_decoders_used"].append("moonsec_v2")
                return dec

        if vm == VMFingerprint.MOONSEC_V1 or VMFingerprint.MOONSEC_V1 in all_detected:
            dec = MoonSecV1Decoder.decode(src)
            if dec != src:
                self.report["vm_specific_decoded"] = True
                self.report["sub_decoders_used"].append("moonsec_v1")
                return dec

        if vm == VMFingerprint.IRONBREW2 or VMFingerprint.IRONBREW2 in all_detected:
            self.log("         Trying IronBrew2 decoder...")
            dec = IronBrew2Decoder.decode(src)
            if dec != src:
                self.report["vm_specific_decoded"] = True
                self.report["sub_decoders_used"].append("ironbrew2")
                return dec

        if vm == VMFingerprint.IRONBREW or VMFingerprint.IRONBREW in all_detected:
            dec = IronBrew2Decoder.decode(src)
            if dec != src:
                self.report["vm_specific_decoded"] = True
                self.report["sub_decoders_used"].append("ironbrew")
                return dec

        if vm == VMFingerprint.PROMETHEUS or VMFingerprint.PROMETHEUS in all_detected:
            dec = PrometheusDecoder.decode(src)
            if dec != src:
                self.report["vm_specific_decoded"] = True
                self.report["sub_decoders_used"].append("prometheus")
                return dec

        if vm == VMFingerprint.MOONVEIL or VMFingerprint.MOONVEIL in all_detected:
            dec = MoonveilDecoder.decode(src)
            if dec != src:
                self.report["vm_specific_decoded"] = True
                self.report["sub_decoders_used"].append("moonveil")
                return dec

        if vm == VMFingerprint.LUAOBFUSCATOR or VMFingerprint.LUAOBFUSCATOR in all_detected:
            src = LuaObfuscatorDecoder.decode(src)

        if vm == VMFingerprint.BORONIDE or VMFingerprint.BORONIDE in all_detected:
            src = BoronideDecoder.decode(src)

        if vm == VMFingerprint.AZTUPBREW or VMFingerprint.AZTUPBREW in all_detected:
            src = AztupBrewDecoder.decode(src)

        if vm == VMFingerprint.XFUSCATOR or VMFingerprint.XFUSCATOR in all_detected:
            src = XFuscatorDecoder.decode(src)

        if vm == VMFingerprint.HYPERION or VMFingerprint.HYPERION in all_detected:
            src = HyperionDecoder.decode(src)

        if vm == VMFingerprint.PSU or VMFingerprint.PSU in all_detected:
            src = PSUDecoder.decode(src)

        if vm == VMFingerprint.WEAREDEVS or VMFingerprint.WEAREaredDevs in all_detected:
            src = WeAreDevsDecoder.decode(src)

        src = StringDecoder.decode_string_reversal(src)
        src = StringDecoder.decode_boronide_bit32(src)
        src = StringDecoder.decode_bit_library(src)
        src = StringDecoder.decode_hex_number_literals(src)

        return src

    def _extract_best_bytecode(self) -> Optional[List[int]]:
        vm = self.vm_type

        if vm == VMFingerprint.LURAPH_V11:
            res = LuraphV11Decoder.extract_payload_and_key(self.source)
            if res:
                payload, key = res
                if key:
                    klen = len(key)
                    return [(payload[i] ^ key[i % klen]) & 0xFF for i in range(len(payload))]
                return payload

        if vm == VMFingerprint.LURAPH_V13:
            res = LuraphV13Decoder.extract_v13_payload(self.source)
            if res:
                payload, key_bytes, _ = res
                if key_bytes:
                    klen = len(key_bytes)
                    return [(payload[i] ^ key_bytes[i % klen]) & 0xFF for i in range(len(payload))]
                return payload

        if vm == VMFingerprint.LURAPH_V14:
            res = LuraphV14Decoder.extract_v14_payload(self.source)
            if res:
                payload, key_bytes, _ = res
                if key_bytes:
                    klen = len(key_bytes)
                    return [(payload[i] ^ key_bytes[i % klen]) & 0xFF for i in range(len(payload))]
                return payload

        if vm == VMFingerprint.BORONIDE:
            result = BytecodeExtractor.extract_boronide_payload(self.source)
            if result:
                return result
        if vm == VMFingerprint.LUAOBFUSCATOR:
            result = BytecodeExtractor.extract_luaobfuscator_payload(self.source)
            if result:
                return result

        for extractor in (
            BytecodeExtractor.extract_numeric_array,
            BytecodeExtractor.extract_hex_array,
            BytecodeExtractor.extract_string_char_array,
            BytecodeExtractor.extract_escaped_string_bytes,
        ):
            result = extractor(self.source)
            if result:
                return result
        return None

    def _decode_all_strings(self, src: str) -> str:
        count = 0

        def decode_string_literal(m):
            nonlocal count
            quote = m.group(1)
            content = m.group(2)
            decoded = StringDecoder.decode_ascii_escape(content)
            decoded = StringDecoder.decode_hex_escape(decoded)
            decoded = StringDecoder.decode_unicode_escape(decoded)
            if decoded != content:
                count += 1
                return quote + decoded + quote
            return m.group(0)

        result = re.sub(
            r'(["\'])((?:[^"\'\\]|\\.)*?)\1',
            decode_string_literal,
            src,
        )

        def decode_b64_pattern(m):
            nonlocal count
            b64str = m.group(1)
            dec = StringDecoder.try_base64(b64str)
            if dec and len(dec) > 3 and all(32 <= ord(c) < 127 or c in "\n\r\t" for c in dec):
                count += 1
                return f'"{dec}"'
            return m.group(0)

        result = re.sub(
            r'"([A-Za-z0-9+/]{20,}={0,2})"',
            decode_b64_pattern,
            result,
        )

        result = StringCharEliminator.eliminate(result)
        result = StringDecoder.decode_string_reversal(result)
        result = StringDecoder.decode_boronide_bit32(result)
        result = StringDecoder.decode_bit_library(result)
        result = StringDecoder.decode_multi_layer_base64(result)
        result = StringDecoder.decode_zlib_payload(result)
        result = StringDecoder.decode_hex_escape_pair_strings(result)
        result = StringDecoder.decode_byte_array_to_string(result)
        result = StringDecoder.decode_char_concat_chains(result)
        result = StringDecoder.decode_bracket_index_strings(result)
        result = StringDecoder.decode_caesar_strings(result)
        result = StringDecoder.decode_reverse_strings(result)
        result = StringDecoder.decode_string_char_reverse(result)

        self.report["strings_decoded"] = count
        return result

    def _try_parse_lua_binary(self, data: bytes) -> Optional[LuaProto]:
        if len(data) < 12:
            return None
        if data[:4] == b"\x1bLua":
            try:
                parser = LuaBytecodeParser(data)
                return parser.parse()
            except Exception:
                return None

        for i in range(min(4096, len(data) - 4)):
            if data[i:i + 4] == b"\x1bLua":
                try:
                    parser = LuaBytecodeParser(data[i:])
                    return parser.parse()
                except Exception:
                    pass
        return None

    def _final_cleanup(self, src: str) -> str:
        src = re.sub(r"\n{3,}", "\n\n", src)
        src = re.sub(r"\t", "  ", src)
        src = re.sub(r" {4,}", "  ", src)
        src = re.sub(r"\n +\n", "\n\n", src)
        src = re.sub(r"^\s*\n", "", src, flags=re.MULTILINE)
        return src.strip()

    def get_report(self) -> str:
        lines = [
            "=" * 60,
            " Secrovia V1 — Analysis Report",
            "=" * 60,
            f" VM Type Detected  : {self.report['vm_type']}",
        ]
        all_det = self.report.get("all_detected", [])
        if len(all_det) > 1:
            lines.append(f" All Matched VMs   : {', '.join(all_det[:8])}")
        if self.report.get("luraph_version"):
            lines.append(f" Luraph Version    : {self.report['luraph_version']}")
        sub_decs = self.report.get("sub_decoders_used", [])
        if sub_decs:
            lines.append(f" Sub-Decoders      : {', '.join(sub_decs)}")
        lines += [
            f" Anti-Tamper Chars : {self.report['anti_tamper_stripped']}",
            f" Decoys Removed    : {self.report.get('decoys_removed', 0)}",
            f" StringChars Elim  : {self.report.get('string_chars_eliminated', 0)}",
            f" Junk Code Removed : {self.report.get('junk_removed', 0)}",
            f" Strings Decoded   : {self.report['strings_decoded']}",
            f" Variables Renamed : {self.report.get('variables_renamed', 0)}",
            f" CF Passes         : {self.report['control_flow_simplified']}",
            f" Advanced Cleanups : {self.report.get('advanced_cleanup_passes', 0)}",
            f" Bytecode Found    : {self.report['bytecode_extracted']}",
            f" Opcodes Mapped    : {len(self.report['opcode_map'])}",
            f" Handlers Extracted: {self.report.get('handlers_extracted', 0)}",
            f" VM Dispatchers    : {self.report.get('vm_dispatchers_found', 0)}",
            f" VM Instr Arrays   : {self.report.get('vm_instruction_arrays', 0)}",
            f" VM Const Pools    : {self.report.get('vm_constant_pools', 0)}",
            f" VM Register Flows : {self.report.get('vm_register_flows', 0)}",
            f" VM Jump Edges     : {self.report.get('vm_jump_edges', 0)}",
            f" VM Components     : {self.report.get('vm_components_split', 0)}",
            f" VM Handlers Split : {self.report.get('vm_handlers_isolated', 0)}",
            f" VM Opcode Map Size: {self.report.get('vm_opcode_map_size', 0)}",
            f" VM Specific Decoded: {self.report['vm_specific_decoded']}",
            f" VM Lifted         : {self.report.get('vm_lifted', False)}",
            f" VM Lift Confidence: {self.report.get('vm_lift_confidence', 0.0):.3f}",
            f" VM Lift Lines     : {self.report.get('vm_lift_lines', 0)}",
            f" VM Word Size      : {self.report.get('vm_word_size', 0)}",
        ]
        if self.vm_info:
            if self.vm_info.get("pc_var"):
                lines.append(f" PC Variable       : {self.vm_info['pc_var']}")
            if self.vm_info.get("stack_var"):
                lines.append(f" Stack Variable    : {self.vm_info['stack_var']}")
            if self.vm_info.get("const_var"):
                lines.append(f" Const Variable    : {self.vm_info['const_var']}")
        if self.vm_splitter:
            if self.vm_splitter.instruction_array_name:
                lines.append(f" Instr Array       : {self.vm_splitter.instruction_array_name}")
            if self.vm_splitter.constant_pool_name:
                lines.append(f" Const Pool        : {self.vm_splitter.constant_pool_name}")
            if self.vm_splitter.pc_var:
                lines.append(f" Splitter PC Var   : {self.vm_splitter.pc_var}")
            if self.vm_splitter.stack_var:
                lines.append(f" Splitter Stack Var: {self.vm_splitter.stack_var}")
            if self.vm_splitter.handlers:
                lines.append(f" Handler Cases     : {len(self.vm_splitter.handlers)}")
            if self.vm_splitter.dispatchers:
                lines.append(f" Dispatchers Found : {len(self.vm_splitter.dispatchers)}")
            if self.vm_splitter.instruction_arrays:
                lines.append(f" Instr Arrays      : {len(self.vm_splitter.instruction_arrays)}")
            if self.vm_splitter.constant_pools:
                lines.append(f" Const Pools       : {len(self.vm_splitter.constant_pools)}")
            if self.vm_splitter.decode_loop:
                lines.append(f" Decode Loop Found : yes")
            if self.vm_splitter.handler_infos:
                sem_count = sum(1 for i in self.vm_splitter.handler_infos.values() if i.semantic)
                lines.append(f" Handlers Classified: {sem_count}/{len(self.vm_splitter.handler_infos)}")
        if self.report["opcode_map"]:
            lines.append(" Opcode Map:")
            for custom, std in list(self.report["opcode_map"].items())[:32]:
                try:
                    lines.append(f"   0x{int(custom):02X} -> {std}")
                except Exception:
                    lines.append(f"   {custom} -> {std}")
        lines.append("=" * 60)
        return "\n".join(lines)


class ChunkDeobfuscator:
    def __init__(self, source: str):
        self.source = source

    def detect_encoding(self) -> str:
        if re.search(r"^[A-Za-z0-9+/\n\r]+=*\s*$", self.source.strip()):
            return "base64"
        if re.match(r"^\s*[0-9a-fA-F\s]+\s*$", self.source.strip()):
            return "hex"
        if re.search(r"^[\x00-\x08\x0e-\x1f\x7f-\xff]", self.source):
            return "binary"
        return "lua"

    def preprocess(self) -> str:
        enc = self.detect_encoding()
        if enc == "base64":
            try:
                dec = base64.b64decode(self.source + "=" * (-len(self.source) % 4))
                text = dec.decode("utf-8", errors="replace")
                if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in text):
                    return text
            except Exception:
                pass
        elif enc == "hex":
            try:
                raw = bytes.fromhex(re.sub(r"\s+", "", self.source))
                text = raw.decode("utf-8", errors="replace")
                if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in text):
                    return text
            except Exception:
                pass
        elif enc == "binary":
            try:
                text = self.source.encode("latin-1").decode("utf-8", errors="replace")
                if any(w in text for w in ("local", "function", "return", "end")):
                    return text
            except Exception:
                pass
        return self.source


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description=(
            "Lua VM Deobfuscator — MoonSec v1/v2/v3 / IronBrew / IronBrew2 /\n"
            "                       Prometheus / Moonveil / Luraph / Luraph v11 /\n"
            "                       Luraph v13 / Luraph v14 / LuaObfuscator /\n"
            "                       Boronide / ByteCode Lua / AztupBrew / XFuscator /\n"
            "                       Hyperion / PSU / WeAreDevs / Luacc"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("input", nargs="?", help="Input .lua file to deobfuscate")
    parser.add_argument("-o", "--output", help="Output file (default: <input>_deobf.lua)", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--report", action="store_true", help="Print analysis report after deobfuscation")
    parser.add_argument("--no-rename", action="store_true", help="Skip variable renaming")
    parser.add_argument("--decode-only", action="store_true", help="Only decode strings, skip structural analysis")
    parser.add_argument("--dump-ast", help="Dump AST to a JSON file", default=None)
    parser.add_argument(
        "--force-vm",
        help=(
            "Force a specific VM type:\n"
            "  luaobfuscator, boronide, moonsec_v1, moonsec_v2, moonsec_v3,\n"
            "  ironbrew, ironbrew2, prometheus, moonveil, luraph,\n"
            "  luraph_v11, luraph_v13, luraph_v14, bytecode_lua,\n"
            "  aztupbrew, xfuscator, hyperion, psu, wearedevs, luacc"
        ),
        default=None,
    )
    parser.add_argument("--brute-xor", action="store_true",
                        help="Brute-force XOR keys (0x00-0xFF) on the extracted bytecode payload")
    parser.add_argument("--brute-rolling", action="store_true",
                        help="Brute-force rolling XOR (start_key 0-255, steps 1/3/5/7/13/17/31/63/127)")
    parser.add_argument("--brute-multi", action="store_true",
                        help="Brute-force multi-byte XOR on the extracted bytecode payload")
    parser.add_argument("--decode-hex-literals", action="store_true",
                        help="Convert all 0x hex literals to decimal in the output")
    parser.add_argument("--list-vms", action="store_true", help="List all supported VM types and exit")
    parser.add_argument("--luraph-version",
                        help="Force specific Luraph version (11.8, 11.9, 13.0, 14.0, 14.1 ... 14.8)",
                        default=None)
    parser.add_argument("--vm-only", action="store_true",
                        help="Only perform VM split + VM lift, skip other steps")
    parser.add_argument("--version", action="version", version=f"Secrovia V1 {VERSION}")
    args = parser.parse_args()

    if args.list_vms:
        print("Supported VM types:")
        vms = [
            "moonsec_v1", "moonsec_v2", "moonsec_v3", "ironbrew", "ironbrew2",
            "prometheus", "moonveil", "luraph", "luraph_v11", "luraph_v13",
            "luraph_v14", "luaobfuscator", "boronide", "bytecode_lua",
            "aztupbrew", "xfuscator", "hyperion", "psu", "wearedevs", "luacc",
        ]
        for v in vms:
            print(f"  {v}")
        sys.exit(0)

    if not args.input:
        parser.print_help()
        sys.exit(1)

    if not os.path.isfile(args.input):
        print(f"[!] File not found: {args.input}")
        sys.exit(1)

    with open(args.input, "r", encoding="utf-8", errors="replace") as f:
        source = f.read()

    print(f"[*] Input    : {args.input} ({len(source)} chars)")

    chunk = ChunkDeobfuscator(source)
    source = chunk.preprocess()

    if args.decode_only:
        result = StringCharEliminator.eliminate(source)
        result = StringDecoder.decode_ascii_escape(result)
        result = StringDecoder.decode_hex_escape(result)
        result = StringDecoder.decode_unicode_escape(result)
        result = StringDecoder.decode_string_reversal(result)
        result = StringDecoder.decode_boronide_bit32(result)
        result = StringDecoder.decode_bit_library(result)
        result = StringDecoder.decode_multi_layer_base64(result)
        result = StringDecoder.decode_zlib_payload(result)
        result = StringDecoder.decode_hex_escape_pair_strings(result)
        result = StringDecoder.decode_byte_array_to_string(result)
        result = StringDecoder.decode_char_concat_chains(result)
        result = StringDecoder.decode_bracket_index_strings(result)
        result = StringDecoder.decode_caesar_strings(result)
        result = StringDecoder.decode_reverse_strings(result)
        result = StringDecoder.decode_string_char_reverse(result)
        if getattr(args, "decode_hex_literals", False):
            result = StringDecoder.decode_hex_number_literals(result)
        beautifier = Beautifier(result)
        result = beautifier.normalize_spacing()
        result = beautifier.beautify()
        print(f"[*] Decode-only mode: strings decoded")
    else:
        pipeline = DeobfuscationPipeline(source, verbose=args.verbose)

        if args.no_rename:
            pipeline.report["skip_rename"] = True

        force_vm = getattr(args, "force_vm", None)
        if force_vm:
            pipeline.vm_type = force_vm
            pipeline.report["vm_type"] = force_vm
            print(f"[*] Force VM : {force_vm}")

        luraph_ver = getattr(args, "luraph_version", None)
        if luraph_ver:
            if luraph_ver.startswith("11"):
                pipeline.vm_type = VMFingerprint.LURAPH_V11
            elif luraph_ver.startswith("13"):
                pipeline.vm_type = VMFingerprint.LURAPH_V13
            elif luraph_ver.startswith("14"):
                pipeline.vm_type = VMFingerprint.LURAPH_V14
            pipeline.report["luraph_version"] = luraph_ver
            print(f"[*] Luraph version forced: {luraph_ver}")

        result = pipeline.run()

        if getattr(args, "brute_xor", False):
            print("[*] Brute-XOR mode: scanning all byte arrays for Lua magic...")
            payload = pipeline._extract_best_bytecode()
            if payload:
                brute = BytecodeExtractor.try_brute_xor_keys(payload)
                if brute:
                    xor_key, raw_lua = brute
                    print(f"[*] Brute-force hit: XOR key = 0x{xor_key:02X}")
                    lua_bin = pipeline._try_parse_lua_binary(raw_lua)
                    if lua_bin:
                        lifted = LuaCodegen(lua_bin).generate()
                        beautified = Beautifier(lifted).beautify()
                        result = beautified
                    else:
                        print(f"[!] XOR key 0x{xor_key:02X} found but bytecode parse failed")
                else:
                    print("[!] Brute-XOR: no valid Lua magic found across all 256 keys")
            else:
                print("[!] Brute-XOR: no byte payload extracted")

        if getattr(args, "brute_rolling", False):
            print("[*] Brute-rolling-XOR mode: scanning start_key*step combos...")
            payload = pipeline._extract_best_bytecode()
            if payload:
                rolling_brute = BytecodeExtractor.try_brute_rolling_xor(payload)
                if rolling_brute:
                    key_info_r, raw_lua_r = rolling_brute
                    print(f"[*] Rolling XOR hit: start={key_info_r['start']}, step={key_info_r['step']}")
                    lua_bin = pipeline._try_parse_lua_binary(raw_lua_r)
                    if lua_bin:
                        lifted = LuaCodegen(lua_bin).generate()
                        beautified = Beautifier(lifted).beautify()
                        result = beautified
                    else:
                        print("[!] Rolling XOR match found but parse failed")
                else:
                    print("[!] Brute-rolling: no Lua magic found in any combo")
            else:
                print("[!] Brute-rolling: no byte payload extracted")

        if getattr(args, "brute_multi", False):
            print("[*] Brute-multi-XOR mode: scanning multi-byte key lengths...")
            payload = pipeline._extract_best_bytecode()
            if payload:
                multi_brute = BytecodeExtractor.try_brute_multi_xor(payload)
                if multi_brute:
                    key_info_m, raw_lua_m = multi_brute
                    print(f"[*] Multi-XOR hit")
                    lua_bin = pipeline._try_parse_lua_binary(raw_lua_m)
                    if lua_bin:
                        lifted = LuaCodegen(lua_bin).generate()
                        beautified = Beautifier(lifted).beautify()
                        result = beautified
                    else:
                        print("[!] Multi-XOR match found but parse failed")
                else:
                    print("[!] Brute-multi: no Lua magic found")
            else:
                print("[!] Brute-multi: no byte payload extracted")

        if getattr(args, "decode_hex_literals", False):
            result = StringDecoder.decode_hex_number_literals(result)
            print("[*] Hex literals converted to decimal")

        if args.dump_ast and pipeline.ast:
            def ast_to_dict(node: ASTNode) -> dict:
                return {
                    "type": node.type,
                    "attrs": {k: str(v) for k, v in node.attrs.items()},
                    "line": node.line,
                    "children": [ast_to_dict(c) for c in node.children],
                }
            with open(args.dump_ast, "w") as f:
                json.dump(ast_to_dict(pipeline.ast), f, indent=2)
            print(f"[*] AST dumped to: {args.dump_ast}")

        if args.report:
            print()
            print(pipeline.get_report())

    out_path = args.output
    if out_path is None:
        base, ext = os.path.splitext(args.input)
        out_path = base + "_deobf" + (ext if ext else ".lua")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(result)

    print(f"[*] Output   : {out_path} ({len(result)} chars)")
    print(f"[*] Done.")


if __name__ == "__main__":
    main()
