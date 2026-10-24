'use strict';

const fs = require('fs');
const path = require('path');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

const KEYWORDS = new Set(['and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for', 'function', 'if', 'in', 'local', 'nil', 'not', 'or', 'repeat', 'return', 'then', 'true', 'until', 'while']);
const RESERVED = new Set([...KEYWORDS, 'goto', 'continue', 'export', 'type', 'typeof']);
const FLOOR = '/' + '/';
const EQ = '=' + '=';
const OPS3 = new Set(['...', '..=', FLOOR + '=']);
const OPS2 = new Set([EQ, '~=', '<=', '>=', '..', '::', '+=', '-=', '*=', '/=', '%=', '^=', FLOOR, '<<', '>>']);
const OPS1 = new Set(['+', '-', '*', '/', '%', '^', '#', '&', '~', '|', '<', '>', '=', '(', ')', '{', '}', '[', ']', ';', ':', ',', '.']);
const COMPOUND = new Set(['+=', '-=', '*=', '/=', '%=', '^=', '..=', FLOOR + '=']);
const COMPARE = new Set(['<', '>', '<=', '>=', '~=', EQ]);
const ARITH = new Set(['+', '-', '*', '/', '%', '^', FLOOR]);
const BIN = new Map([
  ['or', [1, 1]], ['and', [2, 2]],
  ['<', [3, 3]], ['>', [3, 3]], ['<=', [3, 3]], ['>=', [3, 3]], ['~=', [3, 3]], [EQ, [3, 3]],
  ['|', [4, 4]], ['~', [5, 5]], ['&', [6, 6]], ['<<', [7, 7]], ['>>', [7, 7]],
  ['..', [9, 8]], ['+', [10, 10]], ['-', [10, 10]],
  ['*', [11, 11]], ['/', [11, 11]], [FLOOR, [11, 11]], ['%', [11, 11]], ['^', [14, 13]],
]);
const NUM_RE = /0[xX][0-9a-fA-F_]*(?:\.[0-9a-fA-F_]*)?(?:[pP][+-]?[0-9]+)?|0[bB][01_]+|(?:[0-9][0-9_]*(?:\.(?!\.)[0-9_]*)?|\.[0-9][0-9_]*)(?:[eE][+-]?[0-9_]+)?/y;
const NAME_RE = /[A-Za-z_\u0080-\uffff][A-Za-z0-9_\u0080-\uffff]*/y;

class LuaError extends Error {
  constructor(message, pos) {
    super(message);
    this.pos = pos;
  }
}

function lineCol(src, pos) {
  let line = 1;
  let last = -1;
  for (let i = src.indexOf('\n'); i !== -1 && i < pos; i = src.indexOf('\n', i + 1)) {
    line += 1;
    last = i;
  }
  return { line, col: pos - last };
}

function bracketLevel(src, i) {
  if (src.charCodeAt(i) !== 91) return -1;
  let j = i + 1;
  while (src.charCodeAt(j) === 61) j += 1;
  return src.charCodeAt(j) === 91 ? j - i - 1 : -1;
}

function closeBracket(src, i, level, errPos) {
  const close = ']' + '='.repeat(level) + ']';
  const idx = src.indexOf(close, i + level + 2);
  if (idx < 0) throw new LuaError('unfinished long bracket', errPos);
  return idx + close.length;
}

function lex(src) {
  const toks = [];
  const n = src.length;
  let i = 0;
  if (src.charCodeAt(0) === 35) {
    while (i < n && src.charCodeAt(i) !== 10) i += 1;
  }
  const push = (t, s, e, k, x, val) => toks.push({ t, s, e, k, x, val, r: null });
  for (;;) {
    while (i < n) {
      const w = src.charCodeAt(i);
      if (w === 32 || (w >= 9 && w <= 13)) i += 1;
      else break;
    }
    if (i >= n) break;
    const s = i;
    const c = src.charCodeAt(i);
    if (c === 45 && src.charCodeAt(i + 1) === 45) {
      i += 2;
      const lv = bracketLevel(src, i);
      if (lv >= 0) {
        i = closeBracket(src, i, lv, s);
      } else {
        while (i < n) {
          const w = src.charCodeAt(i);
          if (w === 10 || w === 13) break;
          i += 1;
        }
      }
      continue;
    }
    if (c === 34 || c === 39 || c === 96) {
      i += 1;
      for (;;) {
        if (i >= n) throw new LuaError('unfinished string', s);
        const d = src.charCodeAt(i);
        if (d === c) {
          i += 1;
          break;
        }
        if (d === 92) {
          i += src.charCodeAt(i + 1) === 13 && src.charCodeAt(i + 2) === 10 ? 3 : 2;
          continue;
        }
        if ((d === 10 || d === 13) && c !== 96) throw new LuaError('unfinished string', s);
        i += 1;
      }
      const raw = src.slice(s + 1, i - 1);
      push('str', s, i, '', src.slice(s, i), raw.indexOf('\\') >= 0 ? null : raw);
      continue;
    }
    if (c === 91) {
      const lv = bracketLevel(src, i);
      if (lv >= 0) {
        i = closeBracket(src, i, lv, s);
        let body = src.slice(s + lv + 2, i - lv - 2);
        if (body.charCodeAt(0) === 13 && body.charCodeAt(1) === 10) body = body.slice(2);
        else if (body.charCodeAt(0) === 10) body = body.slice(1);
        push('str', s, i, '', src.slice(s, i), body);
        continue;
      }
    }
    if ((c >= 48 && c <= 57) || (c === 46 && src.charCodeAt(i + 1) >= 48 && src.charCodeAt(i + 1) <= 57)) {
      NUM_RE.lastIndex = i;
      const m = NUM_RE.exec(src);
      i += m[0].length;
      push('num', s, i, '', m[0], null);
      continue;
    }
    NAME_RE.lastIndex = i;
    const nm = NAME_RE.exec(src);
    if (nm) {
      i += nm[0].length;
      if (KEYWORDS.has(nm[0])) push('kw', s, i, nm[0], nm[0], null);
      else push('name', s, i, '', nm[0], null);
      continue;
    }
    const o3 = src.slice(i, i + 3);
    if (OPS3.has(o3)) {
      i += 3;
      push('op', s, i, o3, o3, null);
      continue;
    }
    const o2 = src.slice(i, i + 2);
    if (OPS2.has(o2)) {
      i += 2;
      push('op', s, i, o2, o2, null);
      continue;
    }
    const o1 = src[i];
    if (OPS1.has(o1)) {
      i += 1;
      push('op', s, i, o1, o1, null);
      continue;
    }
    throw new LuaError("unexpected symbol '" + o1 + "'", s);
  }
  push('eof', n, n, '', '', null);
  return toks;
}

class Parser {
  constructor(src, toks) {
    this.src = src;
    this.toks = toks;
    this.p = 0;
    this.scope = null;
    this.decls = [];
    this.globals = new Map();
  }

  cur() {
    return this.toks[this.p];
  }

  at(k) {
    return this.toks[this.p].k === k;
  }

  accept(k) {
    if (this.toks[this.p].k === k) {
      this.p += 1;
      return true;
    }
    return false;
  }

  expect(k) {
    if (!this.accept(k)) this.fail("'" + k + "' expected");
  }

  fail(message) {
    const t = this.toks[this.p];
    const near = t.t === 'eof' ? '<eof>' : this.src.slice(t.s, Math.min(t.e, t.s + 24));
    throw new LuaError(message + " near '" + near + "'", t.s);
  }

  expectName() {
    if (this.toks[this.p].t !== 'name') this.fail('name expected');
    this.p += 1;
    return this.p - 1;
  }

  openScope() {
    this.scope = { parent: this.scope, vars: new Map(), all: [] };
  }

  closeScope() {
    const s = this.scope;
    const end = this.p - 1;
    for (const d of s.all) d.end = end;
    this.scope = s.parent;
  }

  makeDecl(name, tok, start, kind, extra) {
    const d = {
      id: this.decls.length, name, tok, start, end: -1, kind, refs: [], init: null, initPos: 0,
      assigns: [], use: null, rename: false, final: null, fn: null, index: 0, loopKind: null, pos: 0, iter: null,
    };
    if (extra) Object.assign(d, extra);
    this.scope.vars.set(name, d);
    this.scope.all.push(d);
    this.decls.push(d);
    return d;
  }

  declare(tokIdx, kind, extra) {
    return this.makeDecl(this.toks[tokIdx].x, tokIdx, tokIdx, kind, extra);
  }

  declareImplicit(name) {
    return this.makeDecl(name, -1, this.p, 'self', null);
  }

  resolve(tokIdx) {
    const name = this.toks[tokIdx].x;
    for (let s = this.scope; s; s = s.parent) {
      const d = s.vars.get(name);
      if (d) {
        d.refs.push(tokIdx);
        return d;
      }
    }
    this.globals.set(name, (this.globals.get(name) || 0) + 1);
    return null;
  }

  blockEnd() {
    const t = this.toks[this.p];
    return t.t === 'eof' || t.k === 'end' || t.k === 'else' || t.k === 'elseif' || t.k === 'until';
  }

  parseChunk() {
    this.openScope();
    const body = this.parseStatements();
    if (this.cur().t !== 'eof') this.fail("'<eof>' expected");
    this.closeScope();
    return { type: 'Chunk', body };
  }

  parseStatements() {
    const list = [];
    while (!this.blockEnd()) {
      if (this.at('return')) {
        list.push(this.parseReturn());
        break;
      }
      const st = this.parseStatement();
      if (st) list.push(st);
    }
    return list;
  }

  parseReturn() {
    this.p += 1;
    let values = [];
    if (!this.blockEnd() && !this.at(';')) values = this.parseExprList();
    this.accept(';');
    return { type: 'Return', values };
  }

  parseBlockScoped() {
    this.openScope();
    const body = this.parseStatements();
    this.closeScope();
    return body;
  }

  parseStatement() {
    const t = this.cur();
    if (t.t === 'kw' || t.t === 'op') {
      switch (t.k) {
        case ';':
          this.p += 1;
          return null;
        case 'if':
          return this.parseIf();
        case 'while': {
          this.p += 1;
          const cond = this.parseExpr(0);
          this.expect('do');
          const body = this.parseBlockScoped();
          this.expect('end');
          return { type: 'While', cond, body };
        }
        case 'do': {
          this.p += 1;
          const body = this.parseBlockScoped();
          this.expect('end');
          return { type: 'Do', body };
        }
        case 'for':
          return this.parseFor();
        case 'repeat': {
          this.p += 1;
          this.openScope();
          const body = this.parseStatements();
          this.expect('until');
          const cond = this.parseExpr(0);
          this.closeScope();
          return { type: 'Repeat', body, cond };
        }
        case 'function':
          return this.parseFunctionStat();
        case 'local':
          return this.parseLocal();
        case 'break':
          this.p += 1;
          return { type: 'Break' };
        case '::':
          this.p += 1;
          this.expectName();
          this.expect('::');
          return { type: 'Label' };
        default:
          break;
      }
    } else if (t.t === 'name') {
      const nx = this.toks[this.p + 1];
      const closing = nx.t === 'eof' || nx.k === 'end' || nx.k === 'else' || nx.k === 'elseif' || nx.k === 'until' || nx.k === ';';
      if (t.x === 'continue' && closing) {
        this.p += 1;
        return { type: 'Continue' };
      }
      if (t.x === 'goto' && nx.t === 'name') {
        this.p += 2;
        return { type: 'Goto' };
      }
    }
    return this.parseExprStat();
  }

  parseIf() {
    this.p += 1;
    const clauses = [];
    let els = null;
    let cond = this.parseExpr(0);
    this.expect('then');
    clauses.push({ cond, body: this.parseBlockScoped() });
    for (;;) {
      if (this.accept('elseif')) {
        cond = this.parseExpr(0);
        this.expect('then');
        clauses.push({ cond, body: this.parseBlockScoped() });
      } else if (this.accept('else')) {
        els = this.parseBlockScoped();
        this.expect('end');
        break;
      } else {
        this.expect('end');
        break;
      }
    }
    return { type: 'If', clauses, els };
  }

  parseFor() {
    this.p += 1;
    const first = this.expectName();
    if (this.at('=')) {
      this.p += 1;
      const start = this.parseExpr(0);
      this.expect(',');
      const stop = this.parseExpr(0);
      const step = this.accept(',') ? this.parseExpr(0) : null;
      this.expect('do');
      this.openScope();
      const decl = this.declare(first, 'for', { loopKind: 'num' });
      const body = this.parseStatements();
      this.closeScope();
      this.expect('end');
      return { type: 'NumFor', start, stop, step, body, decl };
    }
    const idxs = [first];
    while (this.accept(',')) idxs.push(this.expectName());
    this.expect('in');
    const exprs = this.parseExprList();
    this.expect('do');
    this.openScope();
    const decls = idxs.map((ix, i) => this.declare(ix, 'for', { loopKind: 'gen', pos: i, iter: exprs }));
    const body = this.parseStatements();
    this.closeScope();
    this.expect('end');
    return { type: 'GenFor', exprs, body, decls };
  }

  parseFunctionStat() {
    this.p += 1;
    const idx = this.expectName();
    const tok = this.toks[idx];
    let target = { type: 'Name', tok: idx, name: tok.x, decl: this.resolve(idx) };
    let isMethod = false;
    while (this.at('.')) {
      this.p += 1;
      const k = this.expectName();
      target = { type: 'Index', obj: target, key: { type: 'String', val: this.toks[k].x }, dot: true };
    }
    if (this.at(':')) {
      this.p += 1;
      const k = this.expectName();
      target = { type: 'Index', obj: target, key: { type: 'String', val: this.toks[k].x }, dot: true };
      isMethod = true;
    }
    const fn = this.parseFuncBody(isMethod);
    return { type: 'FunctionStat', target, fn };
  }

  parseLocal() {
    this.p += 1;
    if (this.accept('function')) {
      const idx = this.expectName();
      const decl = this.declare(idx, 'localfn', null);
      const fn = this.parseFuncBody(false);
      decl.init = fn;
      return { type: 'LocalFunction', decl, fn };
    }
    const idxs = [];
    do {
      idxs.push(this.expectName());
      if (this.at('<')) {
        this.p += 1;
        this.expectName();
        this.expect('>');
      }
    } while (this.accept(','));
    let values = [];
    if (this.accept('=')) values = this.parseExprList();
    const decls = idxs.map((ix) => this.declare(ix, 'local', null));
    const lastValue = values.length ? values[values.length - 1] : null;
    const multi = lastValue && (lastValue.type === 'Call' || lastValue.type === 'MethodCall' || lastValue.type === 'Vararg');
    for (let i = 0; i < decls.length; i += 1) {
      if (i < values.length) {
        decls[i].init = values[i];
      } else if (multi) {
        decls[i].init = lastValue;
        decls[i].initPos = i - (values.length - 1);
      }
    }
    return { type: 'Local', decls, values };
  }

  parseExprStat() {
    const e = this.parseSuffixed();
    if (this.at('=') || this.at(',')) {
      const targets = [e];
      while (this.accept(',')) targets.push(this.parseSuffixed());
      this.expect('=');
      const values = this.parseExprList();
      for (const t of targets) {
        if (t.type !== 'Name' && t.type !== 'Index') this.fail('cannot assign here');
      }
      const lastValue = values[values.length - 1];
      const multi = lastValue.type === 'Call' || lastValue.type === 'MethodCall' || lastValue.type === 'Vararg';
      for (let i = 0; i < targets.length; i += 1) {
        const t = targets[i];
        if (t.type !== 'Name' || !t.decl) continue;
        if (i < values.length) t.decl.assigns.push({ expr: values[i], pos: 0 });
        else if (multi) t.decl.assigns.push({ expr: lastValue, pos: i - (values.length - 1) });
      }
      return { type: 'Assign', targets, values };
    }
    const t = this.cur();
    if (t.t === 'op' && COMPOUND.has(t.k)) {
      this.p += 1;
      const value = this.parseExpr(0);
      return { type: 'Compound', target: e, op: t.k, value };
    }
    if (e.type !== 'Call' && e.type !== 'MethodCall') this.fail('syntax error');
    return { type: 'CallStat', call: e };
  }

  parseFuncBody(isMethod) {
    const fn = { type: 'Function', params: [], vararg: false, body: null, ctx: null, tableKey: null, assignedKey: null };
    this.openScope();
    if (isMethod) this.declareImplicit('self');
    this.expect('(');
    if (!this.at(')')) {
      for (;;) {
        if (this.accept('...')) {
          fn.vararg = true;
          break;
        }
        const idx = this.expectName();
        fn.params.push(this.declare(idx, 'param', { fn, index: fn.params.length }));
        if (!this.accept(',')) break;
      }
    }
    this.expect(')');
    fn.body = this.parseStatements();
    this.expect('end');
    this.closeScope();
    return fn;
  }

  parseExprList() {
    const list = [this.parseExpr(0)];
    while (this.accept(',')) list.push(this.parseExpr(0));
    return list;
  }

  parseExpr(limit) {
    let left;
    const t = this.cur();
    if (t.k === 'not' || t.k === '-' || t.k === '#' || t.k === '~') {
      this.p += 1;
      left = { type: 'Unop', op: t.k, e: this.parseExpr(12) };
    } else {
      left = this.parseSimple();
    }
    for (;;) {
      const op = this.cur().k;
      const prio = BIN.get(op);
      if (!prio || prio[0] <= limit) break;
      this.p += 1;
      const right = this.parseExpr(prio[1]);
      left = { type: 'Binop', op, l: left, r: right };
    }
    return left;
  }

  parseSimple() {
    const t = this.cur();
    switch (t.t) {
      case 'num':
        this.p += 1;
        return { type: 'Number', raw: t.x };
      case 'str':
        this.p += 1;
        return { type: 'String', val: t.val };
      default:
        break;
    }
    switch (t.k) {
      case 'nil':
        this.p += 1;
        return { type: 'Nil' };
      case 'true':
        this.p += 1;
        return { type: 'True' };
      case 'false':
        this.p += 1;
        return { type: 'False' };
      case '...':
        this.p += 1;
        return { type: 'Vararg' };
      case '{':
        return this.parseTable();
      case 'function':
        this.p += 1;
        return this.parseFuncBody(false);
      case 'if': {
        this.p += 1;
        const cond = this.parseExpr(0);
        this.expect('then');
        const a = this.parseExpr(0);
        let b;
        if (this.at('elseif')) {
          this.toks[this.p] = Object.assign({}, this.toks[this.p], { k: 'if' });
          b = this.parseSimple();
        } else {
          this.expect('else');
          b = this.parseExpr(0);
        }
        return { type: 'IfExpr', cond, a, b };
      }
      default:
        return this.parseSuffixed();
    }
  }

  parseTable() {
    this.p += 1;
    const items = [];
    while (!this.at('}')) {
      const t = this.cur();
      if (this.at('[')) {
        this.p += 1;
        const key = this.parseExpr(0);
        this.expect(']');
        this.expect('=');
        items.push({ kind: 'idx', key, value: this.parseExpr(0) });
      } else if (t.t === 'name' && this.toks[this.p + 1].k === '=') {
        this.p += 2;
        items.push({ kind: 'named', name: t.x, value: this.parseExpr(0) });
      } else {
        items.push({ kind: 'pos', value: this.parseExpr(0) });
      }
      if (!this.accept(',') && !this.accept(';')) break;
    }
    this.expect('}');
    return { type: 'Table', items };
  }

  parseCallArgs() {
    const t = this.cur();
    if (t.t === 'str') {
      this.p += 1;
      return [{ type: 'String', val: t.val }];
    }
    if (t.k === '{') return [this.parseTable()];
    this.expect('(');
    const args = this.at(')') ? [] : this.parseExprList();
    this.expect(')');
    return args;
  }

  parseSuffixed() {
    const t = this.cur();
    let node;
    if (t.t === 'name') {
      const idx = this.p;
      this.p += 1;
      node = { type: 'Name', tok: idx, name: t.x, decl: this.resolve(idx) };
    } else if (t.k === '(') {
      this.p += 1;
      const e = this.parseExpr(0);
      this.expect(')');
      node = { type: 'Paren', e };
    } else {
      this.fail('unexpected symbol');
    }
    for (;;) {
      const c = this.cur();
      if (c.k === '.') {
        this.p += 1;
        const k = this.expectName();
        node = { type: 'Index', obj: node, key: { type: 'String', val: this.toks[k].x }, dot: true };
      } else if (c.k === '[') {
        this.p += 1;
        const key = this.parseExpr(0);
        this.expect(']');
        node = { type: 'Index', obj: node, key, dot: false };
      } else if (c.k === ':') {
        this.p += 1;
        const k = this.expectName();
        node = { type: 'MethodCall', obj: node, name: this.toks[k].x, args: this.parseCallArgs() };
      } else if (c.k === '(' || c.k === '{' || c.t === 'str') {
        node = { type: 'Call', fn: node, args: this.parseCallArgs() };
      } else {
        break;
      }
    }
    return node;
  }
}

function pushAll(stack, list) {
  for (let i = 0; i < list.length; i += 1) stack.push(list[i]);
}

function pushKids(n, st) {
  switch (n.type) {
    case 'Chunk':
    case 'Do':
    case 'Function':
      pushAll(st, n.body);
      break;
    case 'Local':
    case 'Return':
      pushAll(st, n.values);
      break;
    case 'LocalFunction':
      st.push(n.fn);
      break;
    case 'Assign':
      pushAll(st, n.targets);
      pushAll(st, n.values);
      break;
    case 'Compound':
      st.push(n.target, n.value);
      break;
    case 'CallStat':
      st.push(n.call);
      break;
    case 'While':
    case 'Repeat':
      st.push(n.cond);
      pushAll(st, n.body);
      break;
    case 'If':
      for (const c of n.clauses) {
        st.push(c.cond);
        pushAll(st, c.body);
      }
      if (n.els) pushAll(st, n.els);
      break;
    case 'NumFor':
      st.push(n.start, n.stop);
      if (n.step) st.push(n.step);
      pushAll(st, n.body);
      break;
    case 'GenFor':
      pushAll(st, n.exprs);
      pushAll(st, n.body);
      break;
    case 'FunctionStat':
      st.push(n.target, n.fn);
      break;
    case 'Index':
      st.push(n.obj);
      if (!n.dot) st.push(n.key);
      break;
    case 'Call':
      st.push(n.fn);
      pushAll(st, n.args);
      break;
    case 'MethodCall':
      st.push(n.obj);
      pushAll(st, n.args);
      break;
    case 'Binop':
      st.push(n.l, n.r);
      break;
    case 'Unop':
    case 'Paren':
      st.push(n.e);
      break;
    case 'Table':
      for (const it of n.items) {
        if (it.kind === 'idx') st.push(it.key);
        st.push(it.value);
      }
      break;
    case 'IfExpr':
      st.push(n.cond, n.a, n.b);
      break;
    default:
      break;
  }
}

const ARG_TYPES = new Map([
  ['pairs', ['tbl']], ['ipairs', ['list']], ['next', ['tbl']], ['unpack', ['list']], ['table.unpack', ['list']],
  ['table.insert', ['list']], ['table.remove', ['list']], ['table.concat', ['list']], ['table.sort', ['list']],
  ['table.find', ['list']], ['table.clear', ['tbl']], ['table.clone', ['tbl']], ['table.freeze', ['tbl']],
  ['setmetatable', ['tbl', 'tbl']], ['getmetatable', ['tbl']], ['rawget', ['tbl']], ['rawset', ['tbl']],
  ['tonumber', ['str']], ['loadstring', ['str']], ['os.date', ['str']],
  ['task.wait', ['num']], ['wait', ['num']], ['task.delay', ['num']], ['delay', ['num']],
]);

const METHOD_OWNER = new Map([
  ['FindFirstChild', 'instance'], ['WaitForChild', 'instance'], ['FindFirstChildOfClass', 'instance'],
  ['FindFirstChildWhichIsA', 'instance'], ['GetChildren', 'instance'], ['GetDescendants', 'instance'],
  ['Destroy', 'instance'], ['Clone', 'instance'], ['IsA', 'instance'], ['IsDescendantOf', 'instance'],
  ['SetAttribute', 'instance'], ['GetAttribute', 'instance'], ['ClearAllChildren', 'instance'],
  ['GetFullName', 'instance'], ['GetPropertyChangedSignal', 'instance'],
  ['Connect', 'signal'], ['Once', 'signal'], ['Wait', 'signal'], ['Disconnect', 'connection'],
  ['FireServer', 'remote'], ['InvokeServer', 'remote'], ['FireClient', 'remote'], ['FireAllClients', 'remote'],
  ['InvokeClient', 'remote'], ['GetService', 'game'], ['HttpGet', 'game'], ['Kick', 'player'],
  ['GetMouse', 'player'], ['LoadCharacter', 'player'], ['GetPlayers', 'players'],
  ['GetPlayerFromCharacter', 'players'], ['LoadAnimation', 'animator'], ['Raycast', 'workspace'],
  ['MoveTo', 'humanoid'], ['TakeDamage', 'humanoid'], ['ChangeState', 'humanoid'], ['GetState', 'humanoid'],
  ['EquipTool', 'humanoid'], ['GetPivot', 'model'], ['PivotTo', 'model'], ['SetPrimaryPartCFrame', 'model'],
  ['Play', 'track'], ['Stop', 'track'], ['AdjustSpeed', 'track'],
]);

const STR_METHODS = new Set(['sub', 'gsub', 'gmatch', 'match', 'find', 'lower', 'upper', 'rep', 'format', 'len', 'byte', 'reverse', 'split', 'trim']);

const FIELD_OWNER = new Map([
  ['Character', 'player'], ['UserId', 'player'], ['Team', 'player'], ['DisplayName', 'player'],
  ['Health', 'humanoid'], ['MaxHealth', 'humanoid'], ['WalkSpeed', 'humanoid'], ['JumpPower', 'humanoid'],
  ['HipHeight', 'humanoid'], ['MoveDirection', 'humanoid'], ['Position', 'part'], ['CFrame', 'part'],
  ['Size', 'part'], ['Anchored', 'part'], ['CanCollide', 'part'], ['Transparency', 'part'], ['Material', 'part'],
  ['Parent', 'instance'], ['Name', 'instance'], ['ClassName', 'instance'], ['Text', 'label'],
  ['TextColor3', 'label'], ['X', 'vector'], ['Y', 'vector'], ['Z', 'vector'], ['Magnitude', 'vector'],
  ['Unit', 'vector'], ['KeyCode', 'input'], ['UserInputType', 'input'], ['UserInputState', 'input'],
  ['Hit', 'mouse'], ['Target', 'mouse'], ['Origin', 'ray'], ['Direction', 'ray'], ['Instance', 'result'],
  ['LookVector', 'cframe'], ['RightVector', 'cframe'], ['UpVector', 'cframe'],
]);

const EVENTS = new Map([
  ['PlayerAdded', ['player']], ['PlayerRemoving', ['player']], ['CharacterAdded', ['character']],
  ['CharacterRemoving', ['character']], ['CharacterAppearanceLoaded', ['character']],
  ['ChildAdded', ['child']], ['ChildRemoved', ['child']], ['DescendantAdded', ['descendant']],
  ['DescendantRemoving', ['descendant']], ['Touched', ['hit']], ['TouchEnded', ['hit']],
  ['InputBegan', ['input', 'gameProcessed']], ['InputEnded', ['input', 'gameProcessed']],
  ['InputChanged', ['input', 'gameProcessed']], ['Heartbeat', ['deltaTime']], ['RenderStepped', ['deltaTime']],
  ['Stepped', ['time', 'deltaTime']], ['PreRender', ['deltaTime']], ['PreSimulation', ['deltaTime']],
  ['PostSimulation', ['deltaTime']], ['PreAnimation', ['deltaTime']], ['Changed', ['property']],
  ['OnServerEvent', ['player']], ['OnClientEvent', []], ['OnServerInvoke', ['player']], ['OnClientInvoke', []],
  ['Chatted', ['message']], ['FocusLost', ['enterPressed', 'inputObject']], ['HealthChanged', ['health']],
  ['Died', []], ['AncestryChanged', ['child', 'parent']], ['Equipped', ['mouse']], ['Unequipped', []],
  ['Activated', []], ['Triggered', ['player']], ['MouseButton1Click', []], ['MouseButton1Down', ['x', 'y']],
  ['MouseButton1Up', ['x', 'y']], ['MouseEnter', ['x', 'y']], ['MouseLeave', ['x', 'y']],
  ['MouseMoved', ['x', 'y']], ['Seated', ['active', 'seat']], ['Jumping', ['active']], ['Running', ['speed']],
  ['StateChanged', ['oldState', 'newState']], ['MessageReceived', ['message']],
  ['ProcessReceipt', ['receiptInfo']], ['PromptProductPurchaseFinished', ['userId', 'productId', 'isPurchased']],
  ['PromptPurchaseFinished', ['player', 'assetId', 'isPurchased']],
]);

const KEY_PARAMS = new Map([
  ['__index', ['self', 'key']], ['__newindex', ['self', 'key', 'value']], ['__call', ['self']],
  ['__tostring', ['self']], ['__len', ['self']], ['__unm', ['self']], ['__namecall', ['self']],
  ['__concat', ['left', 'right']], ['__eq', ['left', 'right']], ['__lt', ['left', 'right']],
  ['__le', ['left', 'right']], ['__add', ['left', 'right']], ['__sub', ['left', 'right']],
  ['__mul', ['left', 'right']], ['__div', ['left', 'right']], ['__mod', ['left', 'right']],
  ['__pow', ['left', 'right']],
]);

const CALL_PARAMS = new Map([
  ['table.sort:1', ['left', 'right']], ['string.gsub:2', ['match']], ['xpcall:1', ['err']],
  ['table.foreach:1', ['key', 'value']], ['table.foreachi:1', ['index', 'value']],
  ['Promise.new:0', ['resolve', 'reject']], ['Promise.defer:0', ['resolve', 'reject']],
  ['hookmetamethod:2', ['self']],
]);

const METHOD_PARAMS = new Map([
  ['andThen:0', ['value']], ['catch:0', ['err']], ['BindToRenderStep:2', ['deltaTime']], ['gsub:1', ['match']],
]);

const CONNECT_METHODS = new Set(['Connect', 'Once', 'ConnectParallel', 'connect', 'on', 'Observe', 'Subscribe']);

const IRREGULAR = new Map([
  ['children', 'child'], ['people', 'person'], ['men', 'man'], ['women', 'woman'], ['mice', 'mouse'],
  ['indices', 'index'], ['vertices', 'vertex'], ['data', 'entry'], ['series', 'entry'],
]);

const CTOR_RE = /^([A-Z][A-Za-z0-9]*)\.(?:new|fromRGB|fromHSV|fromHex|fromAxisAngle|fromEulerAnglesXYZ|Angles|lookAt|fromOrientation|fromScale|fromOffset|fromMatrix|fromNormalId|fromAxis|fromEulerAngles)$/;
const VERBS = new Set(['get', 'find', 'create', 'make', 'build', 'load', 'fetch', 'read', 'parse', 'decode', 'encode', 'to', 'from', 'init', 'calc', 'calculate', 'compute', 'new']);
const BOOL_PREFIX = new Set(['is', 'has', 'can', 'should', 'did', 'will']);
const SEQ = ['i', 'j', 'k', 'm', 'n', 'p', 'q'];

function useOf(d) {
  if (!d.use) {
    d.use = {
      called: 0, methods: new Set(), fields: new Set(), written: new Set(), numIdx: 0, dynIdx: 0,
      concat: 0, arith: 0, cmpStr: 0, cmpNum: 0, len: 0, argTypes: new Map(),
    };
  }
  return d.use;
}

function mark(e, field) {
  if (e.type === 'Name' && e.decl) useOf(e.decl)[field] += 1;
}

function markCompare(a, b) {
  if (a.type !== 'Name' || !a.decl) return;
  if (b.type === 'String') useOf(a.decl).cmpStr += 1;
  else if (b.type === 'Number') useOf(a.decl).cmpNum += 1;
}

function calleeKey(e) {
  if (e.type === 'Name') return e.decl ? null : e.name;
  if (e.type === 'Index' && e.dot) {
    const b = calleeKey(e.obj);
    return b ? b + '.' + e.key.val : null;
  }
  return null;
}

function argTypeOf(key, i) {
  if (!key) return null;
  if (key.startsWith('math.') || key.startsWith('bit32.') || key === 'string.char') return 'num';
  if (key.startsWith('string.')) return i === 0 ? 'str' : null;
  const t = ARG_TYPES.get(key);
  return t ? t[i] || null : null;
}

function keyOfIndex(e) {
  if (e.type === 'Index' && e.key.type === 'String') return e.key.val;
  if (e.type === 'Name') return e.name;
  return null;
}

function visitNode(n) {
  switch (n.type) {
    case 'Call': {
      const key = calleeKey(n.fn);
      for (let i = 0; i < n.args.length; i += 1) {
        const a = n.args[i];
        if (a.type === 'Function') {
          a.ctx = { kind: 'call', key, index: i };
        } else if (a.type === 'Name' && a.decl) {
          const t = argTypeOf(key, i);
          if (t) {
            const m = useOf(a.decl).argTypes;
            m.set(t, (m.get(t) || 0) + 1);
          }
        }
      }
      if (n.fn.type === 'Name' && n.fn.decl) useOf(n.fn.decl).called += 1;
      break;
    }
    case 'MethodCall':
      for (let i = 0; i < n.args.length; i += 1) {
        if (n.args[i].type === 'Function') n.args[i].ctx = { kind: 'method', name: n.name, obj: n.obj, index: i };
      }
      if (n.obj.type === 'Name' && n.obj.decl) useOf(n.obj.decl).methods.add(n.name);
      break;
    case 'Index':
      if (n.obj.type === 'Name' && n.obj.decl) {
        const u = useOf(n.obj.decl);
        if (n.key.type === 'String') u.fields.add(n.key.val);
        else if (n.key.type === 'Number') u.numIdx += 1;
        else u.dynIdx += 1;
      }
      break;
    case 'Binop':
      if (n.op === '..') {
        mark(n.l, 'concat');
        mark(n.r, 'concat');
      } else if (ARITH.has(n.op)) {
        mark(n.l, 'arith');
        mark(n.r, 'arith');
      } else if (COMPARE.has(n.op)) {
        markCompare(n.l, n.r);
        markCompare(n.r, n.l);
      }
      break;
    case 'Unop':
      if (n.op === '#') mark(n.e, 'len');
      else if (n.op === '-') mark(n.e, 'arith');
      break;
    case 'Compound':
      mark(n.target, n.op === '..=' ? 'concat' : 'arith');
      if (n.value.type === 'Function') n.value.assignedKey = keyOfIndex(n.target);
      break;
    case 'Assign':
      for (let i = 0; i < n.targets.length; i += 1) {
        const t = n.targets[i];
        if (t.type === 'Index') {
          if (t.obj.type === 'Name' && t.obj.decl && t.key.type === 'String') useOf(t.obj.decl).written.add(t.key.val);
          if (n.values[i] && n.values[i].type === 'Function') n.values[i].assignedKey = keyOfIndex(t);
        }
      }
      break;
    case 'FunctionStat':
      n.fn.assignedKey = keyOfIndex(n.target);
      break;
    case 'Table':
      for (const it of n.items) {
        if (it.value.type !== 'Function') continue;
        if (it.kind === 'named') it.value.tableKey = it.name;
        else if (it.kind === 'idx' && it.key.type === 'String') it.value.tableKey = it.key.val;
      }
      break;
    default:
      break;
  }
}

function analyze(chunk) {
  const stack = [chunk];
  while (stack.length) {
    const n = stack.pop();
    visitNode(n);
    pushKids(n, stack);
  }
}

function splitWords(text) {
  return String(text).match(/[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+/g) || [];
}

function formatWords(words, style) {
  const low = words.map((w) => w.toLowerCase());
  const cap = (w) => w.charAt(0).toUpperCase() + w.slice(1);
  if (style === 'snake') return low.join('_');
  if (style === 'pascal') return low.map(cap).join('');
  return low[0] + low.slice(1).map(cap).join('');
}

function sanitize(base, style) {
  if (base === '_') return '_';
  let words = splitWords(base);
  if (!words.length) words = ['value'];
  let out = formatWords(words, style);
  while (out.length > 32 && words.length > 1) {
    words = words.slice(0, -1);
    out = formatWords(words, style);
  }
  if (/^[0-9]/.test(out)) out = 'n' + out;
  if (RESERVED.has(out)) out += style === 'snake' ? '_value' : 'Value';
  return out;
}

function singular(base) {
  const words = splitWords(base);
  if (!words.length) return null;
  const last = words[words.length - 1];
  const low = last.toLowerCase();
  let s = null;
  if (IRREGULAR.has(low)) s = IRREGULAR.get(low);
  else if (/ies$/i.test(last) && last.length > 4) s = last.slice(0, -3) + 'y';
  else if (/(ss|us|is)$/i.test(last)) s = null;
  else if (/(ches|shes|xes|sses|zes)$/i.test(last)) s = last.slice(0, -2);
  else if (/s$/i.test(last) && last.length > 3) s = last.slice(0, -1);
  if (s) return words.slice(0, -1).concat(s).join(' ');
  if (/^(list|array|table|map|dict|set|tbl|arr)$/i.test(last)) return words.length > 1 ? words.slice(0, -1).join(' ') : 'item';
  return null;
}

function strName(v) {
  if (v === null || v === undefined) return 'str';
  if (v === '') return 'empty str';
  if (/^https?:/i.test(v)) return 'url';
  if (v.length > 24) return 'text';
  if (/^[0-9]+$/.test(v)) return 'num str';
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(v)) return /^[A-Z]/.test(v) ? v + ' name' : v + ' str';
  return 'str';
}

function tableName(e) {
  if (!e.items.length) return null;
  for (const it of e.items) {
    if (it.kind !== 'pos') return 'tbl';
  }
  return e.items.length === 1 && e.items[0].value.type === 'Vararg' ? 'args' : 'list';
}

const STR_FUNCS = new Set(['tostring', 'string.format', 'string.sub', 'string.rep', 'string.lower', 'string.upper', 'string.reverse', 'string.gsub', 'string.char', 'table.concat', 'utf8.char', 'os.date']);

function verbResult(tail) {
  const words = splitWords(tail);
  if (!words.length) return 'result';
  const head = words[0].toLowerCase();
  if (words.length > 1 && VERBS.has(head)) return words.slice(1).join(' ');
  if (words.length > 1 && BOOL_PREFIX.has(head)) return words.join(' ');
  return words.join(' ') + ' result';
}

function firstString(e) {
  if (e && e.type === 'Name' && e.decl && e.decl.init && e.decl.init.type === 'String' && e.decl.assigns.length === 0) return e.decl.init.val || null;
  return e && e.type === 'String' && e.val ? e.val : null;
}

function callName(e, depth) {
  const key = calleeKey(e.fn);
  const a0 = e.args[0];
  if (key) {
    if (STR_FUNCS.has(key)) return 'str';
    if (key.startsWith('math.')) return key === 'math.random' || key === 'math.randomseed' ? 'rand' : 'num';
    switch (key) {
      case 'require':
        return a0 && (a0.type === 'Index' || a0.type === 'Name') ? exprName(a0, depth + 1) || 'module' : 'module';
      case 'tonumber':
        return 'num';
      case 'type':
      case 'typeof':
        return 'type name';
      case 'select':
        return 'selected';
      case 'setmetatable':
        return a0 && a0.type !== 'Table' ? exprName(a0, depth + 1) || 'obj' : 'obj';
      case 'getmetatable':
      case 'getrawmetatable':
        return 'meta';
      case 'next':
        return 'key';
      case 'unpack':
      case 'table.unpack':
        return 'unpacked';
      case 'table.pack':
        return 'packed';
      case 'table.clone':
      case 'table.freeze':
        return exprName(a0, depth + 1) || 'tbl';
      case 'table.find':
        return 'found index';
      case 'table.remove':
        return 'removed';
      case 'string.find':
        return 'start index';
      case 'string.match':
        return 'match';
      case 'string.gmatch':
        return 'iter';
      case 'string.byte':
        return 'byte value';
      case 'string.len':
        return 'len';
      case 'pcall':
      case 'xpcall':
        return 'ok';
      case 'os.time':
        return 'timestamp';
      case 'os.clock':
        return 'clock';
      case 'tick':
      case 'time':
        return 'now';
      case 'wait':
      case 'task.wait':
        return 'elapsed';
      case 'coroutine.create':
      case 'coroutine.wrap':
      case 'task.spawn':
      case 'task.defer':
      case 'task.delay':
      case 'spawn':
      case 'delay':
        return 'thread';
      case 'loadstring':
        return 'chunk';
      case 'getfenv':
      case 'getgenv':
      case 'getrenv':
      case 'getsenv':
        return 'env';
      case 'newproxy':
        return 'proxy';
      case 'hookfunction':
      case 'hookmetamethod':
        return 'original';
      case 'newcclosure':
      case 'clonefunction':
        return 'func';
      case 'getconnections':
        return 'connections';
      case 'readfile':
        return 'content';
      case 'Instance.new':
        return firstString(a0) || 'instance';
      case 'Drawing.new':
        return firstString(a0) || 'drawing';
      case 'Random.new':
        return 'rng';
      default:
        break;
    }
    const m = CTOR_RE.exec(key);
    if (m) return m[1];
  }
  let tail = null;
  if (e.fn.type === 'Index' && e.fn.key.type === 'String') tail = e.fn.key.val;
  else if (e.fn.type === 'Name') tail = e.fn.decl ? (e.fn.decl.rename ? null : e.fn.decl.name) : e.fn.name;
  if (!tail) return 'result';
  if (tail === 'new' && e.fn.type === 'Index') return exprName(e.fn.obj, depth + 1) || 'obj';
  return verbResult(tail);
}

function methodName(e, depth) {
  const a0 = e.args[0];
  const s0 = firstString(a0);
  switch (e.name) {
    case 'FindFirstChild':
    case 'WaitForChild':
    case 'FindFirstChildOfClass':
    case 'FindFirstChildWhichIsA':
    case 'FindFirstAncestor':
    case 'FindFirstAncestorOfClass':
    case 'FindFirstAncestorWhichIsA':
    case 'FindFirstDescendant':
    case 'GetService':
    case 'GetAttribute':
      return s0 || (e.name === 'GetService' ? 'service' : 'child');
    case 'GetChildren':
      return 'children';
    case 'GetDescendants':
      return 'descendants';
    case 'GetPlayers':
      return 'players';
    case 'GetAttributes':
      return 'attributes';
    case 'GetPlayerFromCharacter':
      return 'player';
    case 'GetMouse':
      return 'mouse';
    case 'Clone':
      return exprName(e.obj, depth + 1) || 'clone';
    case 'Connect':
    case 'Once':
    case 'ConnectParallel':
      return 'connection';
    case 'Wait':
      return 'waited';
    case 'Invoke':
    case 'InvokeServer':
    case 'InvokeClient':
    case 'HttpGet':
    case 'GetAsync':
    case 'PostAsync':
    case 'RequestAsync':
      return 'response';
    case 'JSONDecode':
      return 'data';
    case 'JSONEncode':
      return 'json';
    case 'LoadAnimation':
      return 'animation';
    case 'Raycast':
      return 'raycast result';
    case 'Create': {
      const b = exprName(e.obj, depth + 1);
      return b && /tween/i.test(b) ? 'tween' : 'created';
    }
    case 'sub':
    case 'gsub':
    case 'lower':
    case 'upper':
    case 'format':
    case 'rep':
    case 'reverse':
    case 'trim':
      return 'str';
    case 'find':
      return 'start index';
    case 'match':
      return 'match';
    case 'gmatch':
      return 'iter';
    case 'split':
      return 'parts';
    case 'byte':
      return 'byte value';
    case 'len':
      return 'len';
    case 'new':
      return exprName(e.obj, depth + 1) || 'obj';
    default:
      return verbResult(e.name);
  }
}

function exprName(e, depth) {
  if (!e || depth > 12) return null;
  switch (e.type) {
    case 'Paren':
      return exprName(e.e, depth + 1);
    case 'Name':
      if (e.decl) return e.decl.final && e.decl.final !== '_' ? e.decl.stem || e.decl.final : null;
      return e.name;
    case 'String':
      return strName(e.val);
    case 'Number':
      return 'num';
    case 'True':
    case 'False':
      return 'flag';
    case 'Vararg':
      return 'args';
    case 'Function':
      return 'func';
    case 'Table':
      return tableName(e);
    case 'Index': {
      if (e.key.type === 'String') return e.key.val.length <= 30 ? e.key.val : null;
      const b = exprName(e.obj, depth + 1);
      if (!b) return 'item';
      return singular(b) || b + ' item';
    }
    case 'Call':
      return callName(e, depth);
    case 'MethodCall':
      return methodName(e, depth);
    case 'Binop':
      if (e.op === '..') return 'str';
      if (ARITH.has(e.op)) return 'num';
      if (COMPARE.has(e.op)) return 'flag';
      if (e.op === 'or') return exprName(e.l, depth + 1) || exprName(e.r, depth + 1);
      if (e.op === 'and') return exprName(e.r, depth + 1) || exprName(e.l, depth + 1);
      return 'bits';
    case 'Unop': {
      if (e.op === 'not') return 'flag';
      if (e.op === '#') {
        const b = exprName(e.e, depth + 1);
        return b ? (singular(b) || b) + ' count' : 'len';
      }
      if (e.op === '-') return exprName(e.e, depth + 1) || 'num';
      return 'bits';
    }
    case 'IfExpr':
      return exprName(e.a, depth + 1) || exprName(e.b, depth + 1);
    default:
      return null;
  }
}

function exprNameAt(e, pos) {
  if (pos > 0) {
    if (e.type === 'Vararg') return 'arg' + (pos + 1);
    if (e.type === 'Call') {
      const key = calleeKey(e.fn);
      if (key === 'pcall' || key === 'xpcall') return pos === 1 ? 'result' : 'extra';
      if (key === 'string.find') return pos === 1 ? 'end index' : 'capture';
      if (key === 'string.match') return 'capture';
    }
    return exprName(e, 0) || 'value';
  }
  if (e.type === 'Vararg') return 'arg1';
  return exprName(e, 0);
}

function usageName(d) {
  const u = d.use;
  if (!u) return null;
  if (u.called > 0) return d.kind === 'param' ? 'callback' : 'func';
  let best = null;
  let bestCount = 0;
  for (const [t, c] of u.argTypes) {
    if (c > bestCount) {
      best = t;
      bestCount = c;
    }
  }
  if (best) return best;
  for (const m of u.methods) {
    if (METHOD_OWNER.has(m)) return METHOD_OWNER.get(m);
  }
  for (const m of u.methods) {
    if (STR_METHODS.has(m)) return 'str';
  }
  for (const f of u.fields) {
    if (FIELD_OWNER.has(f)) return FIELD_OWNER.get(f);
  }
  if (u.concat || u.cmpStr) return 'str';
  if (u.arith || u.cmpNum) return 'num';
  if (u.len || u.numIdx) return 'list';
  if (u.fields.size || u.written.size || u.dynIdx) return 'tbl';
  return null;
}

function ctxParams(ctx) {
  if (ctx.kind === 'call') return CALL_PARAMS.get(ctx.key + ':' + ctx.index) || null;
  const specific = METHOD_PARAMS.get(ctx.name + ':' + ctx.index);
  if (specific) return specific;
  if (CONNECT_METHODS.has(ctx.name)) {
    const ev = keyOfIndex(ctx.obj);
    if (ev) return EVENTS.get(ev) || null;
  }
  return null;
}

function paramBase(d) {
  const fn = d.fn;
  let list = null;
  if (fn.ctx) list = ctxParams(fn.ctx);
  if (!list && fn.tableKey) list = KEY_PARAMS.get(fn.tableKey) || EVENTS.get(fn.tableKey) || null;
  if (!list && fn.assignedKey) list = KEY_PARAMS.get(fn.assignedKey) || EVENTS.get(fn.assignedKey) || null;
  if (list && list[d.index]) return list[d.index];
  return usageName(d) || 'arg' + (d.index + 1);
}

function genForBase(d) {
  const it = d.iter;
  const first = it[0];
  let src = null;
  let mode = 'pairs';
  if (first && first.type === 'Call') {
    const key = calleeKey(first.fn);
    if (key === 'pairs' || key === 'next') src = first.args[0] || null;
    else if (key === 'ipairs') {
      src = first.args[0] || null;
      mode = 'ipairs';
    } else if (key === 'string.gmatch') mode = 'gmatch';
    else mode = 'iter';
  } else if (first && first.type === 'MethodCall') {
    mode = first.name === 'gmatch' ? 'gmatch' : 'iter';
  } else if (first && first.type === 'Name' && !first.decl && first.name === 'next' && it.length > 1) {
    src = it[1];
  } else if (first && it.length === 1) {
    src = first;
  }
  const unused = d.refs.length === 0;
  if (d.pos === 0) {
    if (unused) return '_';
    if (mode === 'ipairs') return 'index';
    if (mode === 'gmatch') return 'match';
    return 'key';
  }
  if (unused) return '_';
  if (d.pos === 1) {
    if (mode === 'gmatch') return 'capture';
    const b = src ? exprName(src, 0) : null;
    return (b && singular(b)) || 'value';
  }
  return 'extra';
}

function deriveBase(d) {
  if (d.kind === 'for') {
    if (d.loopKind === 'num') return d.refs.length ? { base: 'i', seq: true } : { base: '_', seq: false };
    return { base: genForBase(d), seq: false };
  }
  if (d.kind === 'param') return { base: paramBase(d), seq: false };
  if (d.kind === 'localfn') return { base: 'func', seq: false };
  let e = d.init;
  let pos = d.initPos;
  if (!e && d.assigns.length) {
    e = d.assigns[0].expr;
    pos = d.assigns[0].pos;
  }
  let base = e ? exprNameAt(e, pos) : null;
  if (!base) base = usageName(d);
  if (!base && e && e.type === 'Function') base = 'func';
  if (!base && e && e.type === 'Table') base = 'tbl';
  return { base: base || 'value', seq: false };
}

function looksGenerated(name) {
  if (name.length === 1) return !'ijkv_n'.includes(name);
  if (/^(?:[A-Za-z]|[A-Za-z]{2}|var|arg|loc|local|tmp|temp|reg|upval|param|unk|unknown)_?[0-9]+(?:_[0-9]+)*_?$/i.test(name)) return true;
  if (/^[lLiI1oO0_|]{2,}$/.test(name)) return true;
  if (/^_*(?:0x)?(?=[0-9a-fA-F]*[0-9])[0-9a-fA-F]{6,}$/.test(name)) return true;
  if (/^[A-Za-z]{1,2}[0-9]+[A-Za-z]{1,2}[0-9]+$/.test(name)) return true;
  if (/^_[A-Za-z0-9]{1,4}_*$/.test(name)) return true;
  return false;
}

function assignNames(parser, opts) {
  const decls = parser.decls.slice().sort((a, b) => a.start - b.start || a.id - b.id);
  const blocked = new Set(RESERVED);
  for (const g of parser.globals.keys()) blocked.add(g);
  const table = new Map();
  const claim = (name, d) => {
    let list = table.get(name);
    if (!list) {
      list = [];
      table.set(name, list);
    }
    list.push(d);
  };
  const clash = (name, d) => {
    const list = table.get(name);
    if (!list) return false;
    for (const x of list) {
      if (x.start <= d.end && d.start <= x.end && (x.refs.length > 0 || d.refs.length > 0)) return true;
    }
    return false;
  };
  const keep = new Set(opts.keep);
  const hints = new Map();
  for (const d of decls) {
    const fixed = d.tok < 0 || keep.has(d.name) || d.name === '_' || d.name === 'self' || d.name === '_ENV';
    d.rename = !fixed && (opts.mode === 'all' || looksGenerated(d.name));
    if (!d.rename) {
      d.final = d.name;
      claim(d.name, d);
    }
  }
  for (const d of decls) {
    if (!d.rename) continue;
    const info = deriveBase(d);
    let name = null;
    d.stem = null;
    if (info.seq) {
      for (const c of SEQ) {
        if (!blocked.has(c) && !clash(c, d)) {
          name = c;
          break;
        }
      }
    }
    if (!name) {
      const base = sanitize(info.base, opts.style);
      const sep = opts.style === 'snake' ? '_' : '';
      d.stem = base;
      let n = Math.max(1, (hints.get(base) || 1) - 8);
      name = n === 1 ? base : base + sep + n;
      while (blocked.has(name) || clash(name, d)) {
        n += 1;
        name = base + sep + n;
      }
      hints.set(base, n);
    }
    d.final = name;
    claim(name, d);
  }
  return decls;
}

function emit(src, toks, decls) {
  for (const d of decls) {
    if (!d.rename || d.final === d.name) continue;
    if (d.tok >= 0) toks[d.tok].r = d.final;
    for (const r of d.refs) toks[r].r = d.final;
  }
  const parts = [];
  let last = 0;
  for (const t of toks) {
    if (t.r === null) continue;
    parts.push(src.slice(last, t.s), t.r);
    last = t.e;
  }
  parts.push(src.slice(last));
  return parts.join('');
}

function bindingSignature(src) {
  const toks = lex(src);
  const parser = new Parser(src, toks);
  parser.parseChunk();
  return {
    tokens: toks.length,
    binds: parser.decls.map((d) => d.start + ':' + d.refs.join(',')).join('|'),
    globals: Array.from(parser.globals.entries()).sort().join('\n'),
  };
}

function verifyBindings(before, after) {
  const a = bindingSignature(before);
  const b = bindingSignature(after);
  return a.tokens === b.tokens && a.binds === b.binds && a.globals === b.globals;
}

function renameLua(src, options) {
  const opts = Object.assign({ mode: 'auto', style: 'camel', keep: [], verify: true }, options);
  const toks = lex(src);
  const parser = new Parser(src, toks);
  const chunk = parser.parseChunk();
  analyze(chunk);
  const decls = assignNames(parser, opts);
  const code = emit(src, toks, decls);
  if (opts.verify && !verifyBindings(src, code)) throw new LuaError('binding verification failed, output discarded', 0);
  const map = [];
  for (const d of decls) {
    if (!d.rename || d.final === d.name) continue;
    const pos = d.tok >= 0 ? toks[d.tok].s : 0;
    map.push({ from: d.name, to: d.final, kind: d.kind, line: lineCol(src, pos).line, refs: d.refs.length });
  }
  const locals = decls.filter((d) => d.tok >= 0).length;
  return { code, map, stats: { locals, renamed: map.length, globals: parser.globals.size } };
}

function usageText() {
  return [
    'usage: node renamer.js <input.lua|-> [options]',
    '  -o <file>   output file (default: <input>.renamed.lua, "-" for stdout)',
    '  -a          rename every local, not only generated looking names',
    '  -c <style>  camel (default), snake, pascal',
    '  -k <list>   comma separated names that must stay untouched',
    '  -m <file>   write the rename map as json',
    '  -x          skip the binding verification pass',
    '  -q          quiet',
  ].join('\n');
}

function parseArgs(argv) {
  const o = { input: null, output: null, mode: 'auto', style: 'camel', keep: [], map: null, verify: true, quiet: false, help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '-o') {
      i += 1;
      o.output = argv[i];
    } else if (a === '-a') o.mode = 'all';
    else if (a === '-c') {
      i += 1;
      o.style = argv[i];
    } else if (a === '-k') {
      i += 1;
      o.keep = String(argv[i] || '').split(',').filter(Boolean);
    } else if (a === '-m') {
      i += 1;
      o.map = argv[i];
    } else if (a === '-x') o.verify = false;
    else if (a === '-q') o.quiet = true;
    else if (a === '-h') o.help = true;
    else if (!o.input) o.input = a;
  }
  if (!['camel', 'snake', 'pascal'].includes(o.style)) o.style = 'camel';
  return o;
}

function main() {
  const o = parseArgs(process.argv.slice(2));
  if (o.help || !o.input) {
    console.error(usageText());
    process.exitCode = o.help ? 0 : 1;
    return;
  }
  const src = fs.readFileSync(o.input === '-' ? 0 : o.input, 'utf8').replace(/^\uFEFF/, '');
  let output = o.output;
  if (!output) {
    if (o.input === '-') output = '-';
    else {
      const ext = path.extname(o.input);
      output = o.input.slice(0, o.input.length - ext.length) + '.renamed' + (ext || '.lua');
    }
  }
  const worker = new Worker(__filename, {
    workerData: { src, opts: { mode: o.mode, style: o.style, keep: o.keep, verify: o.verify } },
    resourceLimits: { stackSizeMb: 256, maxOldGenerationSizeMb: 4096 },
  });
  worker.on('message', (m) => {
    if (!m.ok) {
      const where = m.line ? ' (line ' + m.line + ', col ' + m.col + ')' : '';
      console.error('error: ' + m.message + where);
      process.exitCode = 1;
      return;
    }
    if (output === '-') process.stdout.write(m.code);
    else fs.writeFileSync(output, m.code);
    if (o.map) fs.writeFileSync(o.map, JSON.stringify(m.map, null, 2));
    if (!o.quiet) console.error('renamed ' + m.stats.renamed + ' of ' + m.stats.locals + ' locals, ' + m.stats.globals + ' globals untouched' + (output === '-' ? '' : ' -> ' + output));
  });
  worker.on('error', (e) => {
    console.error('error: ' + e.message);
    process.exitCode = 1;
  });
}

function workerJob() {
  try {
    const r = renameLua(workerData.src, workerData.opts);
    parentPort.postMessage({ ok: true, code: r.code, map: r.map, stats: r.stats });
  } catch (e) {
    const lc = e instanceof LuaError ? lineCol(workerData.src, e.pos) : null;
    parentPort.postMessage({ ok: false, message: e.message, line: lc ? lc.line : 0, col: lc ? lc.col : 0 });
  }
}

if (!isMainThread) {
  workerJob();
} else if (require.main === module) {
  main();
} else {
  module.exports = { renameLua, lex, Parser, LuaError };
}
