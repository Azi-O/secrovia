'use strict';

const fs = require('fs');

const KEYWORDS = new Set([
    'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for', 'function',
    'goto', 'if', 'in', 'local', 'nil', 'not', 'or', 'repeat', 'return', 'then',
    'true', 'until', 'while', 'continue'
]);

const OPS3 = new Set(['...', '..=', '//=']);

const OPS2 = new Set([
    '==', '~=', '<=', '>=', '::', '//', '..', '->',
    '+=', '-=', '*=', '/=', '%=', '^=', '=>', '<<', '>>'
]);

const OPS1 = new Set([
    '+', '-', '*', '/', '%', '^', '#', '&', '~', '|', '<', '>',
    '=', '(', ')', '{', '}', '[', ']', ';', ':', ',', '.', '?'
]);

const BINARY_OPS = new Set([
    '+', '-', '*', '/', '//', '%', '^', '..', '==', '~=',
    '<', '>', '<=', '>=', '&', '|', '<<', '>>',
    '=', '+=', '-=', '*=', '/=', '//=', '%=', '^=', '..=',
    '::', '->'
]);

const VALUE_ENDING_KEYWORDS = new Set(['end', 'true', 'false', 'nil']);
const BLOCK_OPENERS = new Set(['then', 'do', 'repeat', 'else']);
const SPACE_AFTER_KEYWORDS = [
    'local', 'if', 'elseif', 'while', 'for', 'return', 'not', 'and',
    'or', 'in', 'function', 'until', 'then', 'do', 'else', 'goto',
    'continue', 'repeat', 'break'
];

function tokenize(src) {
    const tokens = [];
    let i = 0;
    let nlPending = true;

    function push(type, value, extra) {
        const t = { type: type, value: value, precededByNewline: nlPending };
        if (extra) Object.assign(t, extra);
        tokens.push(t);
        nlPending = false;
    }

    while (i < src.length) {
        const c = src[i];

        if (c === ' ' || c === '\t' || c === '\r' || c === '\u000b' || c === '\f') {
            i++;
            continue;
        }
        if (c === '\n') {
            nlPending = true;
            i++;
            continue;
        }

        if (c === '-' && src[i + 1] === '-') {
            if (src[i + 2] === '[') {
                let eq = 0;
                let j = i + 3;
                while (src[j] === '=') { eq++; j++; }
                if (src[j] === '[') {
                    const close = ']' + '='.repeat(eq) + ']';
                    const endIdx = src.indexOf(close, j + 1);
                    const val = endIdx === -1 ? src.slice(i) : src.slice(i, endIdx + close.length);
                    push('comment', val);
                    i = endIdx === -1 ? src.length : endIdx + close.length;
                    continue;
                }
            }
            let j = i;
            while (j < src.length && src[j] !== '\n') j++;
            push('comment', src.slice(i, j), { isLineComment: true });
            i = j;
            continue;
        }

        if (c === '"' || c === "'") {
            let j = i + 1;
            while (j < src.length) {
                if (src[j] === '\\') { j += 2; continue; }
                if (src[j] === c) { j++; break; }
                if (src[j] === '\n') break;
                j++;
            }
            push('string', src.slice(i, j));
            i = j;
            continue;
        }

        if (c === '`') {
            let j = i + 1;
            let depth = 0;
            while (j < src.length) {
                if (src[j] === '\\') { j += 2; continue; }
                if (src[j] === '`' && depth === 0) { j++; break; }
                if (src[j] === '{') { depth++; j++; continue; }
                if (src[j] === '}' && depth > 0) { depth--; j++; continue; }
                j++;
            }
            push('string', src.slice(i, j));
            i = j;
            continue;
        }

        if (c === '[') {
            let eq = 0;
            let j = i + 1;
            while (src[j] === '=') { eq++; j++; }
            if (src[j] === '[') {
                const close = ']' + '='.repeat(eq) + ']';
                const endIdx = src.indexOf(close, j + 1);
                const val = endIdx === -1 ? src.slice(i) : src.slice(i, endIdx + close.length);
                push('string', val);
                i = endIdx === -1 ? src.length : endIdx + close.length;
                continue;
            }
        }

        if ((c >= '0' && c <= '9') || (c === '.' && src[i + 1] >= '0' && src[i + 1] <= '9')) {
            let j = i;
            if (c === '0' && (src[j + 1] === 'x' || src[j + 1] === 'X')) {
                j += 2;
                while (j < src.length && /[0-9a-fA-F_.]/.test(src[j])) j++;
                if (src[j] === 'p' || src[j] === 'P') {
                    j++;
                    if (src[j] === '+' || src[j] === '-') j++;
                    while (j < src.length && /[0-9]/.test(src[j])) j++;
                }
            } else if (c === '0' && (src[j + 1] === 'b' || src[j + 1] === 'B')) {
                j += 2;
                while (j < src.length && /[01_]/.test(src[j])) j++;
            } else {
                while (j < src.length && /[0-9_]/.test(src[j])) j++;
                if (src[j] === '.') {
                    j++;
                    while (j < src.length && /[0-9_]/.test(src[j])) j++;
                }
                if (src[j] === 'e' || src[j] === 'E') {
                    j++;
                    if (src[j] === '+' || src[j] === '-') j++;
                    while (j < src.length && /[0-9]/.test(src[j])) j++;
                }
            }
            push('number', src.slice(i, j));
            i = j;
            continue;
        }

        if (/[A-Za-z_]/.test(c)) {
            let j = i + 1;
            while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j++;
            const word = src.slice(i, j);
            push(KEYWORDS.has(word) ? 'keyword' : 'ident', word);
            i = j;
            continue;
        }

        const three = src.slice(i, i + 3);
        const two = src.slice(i, i + 2);
        if (OPS3.has(three)) { push('op', three); i += 3; continue; }
        if (OPS2.has(two))   { push('op', two);   i += 2; continue; }
        if (OPS1.has(c))     { push('op', c);     i += 1; continue; }

        i++;
    }

    return tokens;
}

function isUnaryContext(prev) {
    if (!prev) return true;
    if (prev.type === 'ident' || prev.type === 'number' || prev.type === 'string') return false;
    if (prev.type === 'keyword') return !VALUE_ENDING_KEYWORDS.has(prev.value);
    if (prev.type === 'op') return !(prev.value === ')' || prev.value === ']' || prev.value === '}');
    return true;
}

function isValueEnding(tok) {
    if (!tok) return false;
    if (tok.type === 'ident' || tok.type === 'number' || tok.type === 'string') return true;
    if (tok.type === 'keyword' && VALUE_ENDING_KEYWORDS.has(tok.value)) return true;
    if (tok.type === 'op' && (tok.value === ')' || tok.value === ']' || tok.value === '}')) return true;
    return false;
}

function beautify(source, options) {
    options = options || {};
    const indentStr = options.indent !== undefined ? options.indent : '    ';
    const tokens = tokenize(source);

    const nextSig = new Array(tokens.length).fill(null);
    let nxt = null;
    for (let i = tokens.length - 1; i >= 0; i--) {
        nextSig[i] = nxt;
        if (tokens[i].type !== 'comment') nxt = tokens[i];
    }

    let out = '';
    let indent = 0;
    let lineStart = true;
    let parenDepth = 0;
    let braceDepth = 0;
    let bracketDepth = 0;
    const blockStack = [{ baseParen: 0, baseBrace: 0, baseBracket: 0 }];
    let funcParamPending = false;
    let funcParamDepth = null;
    let lastSig = null;
    let lastSigWasUnary = false;

    function getBase() { return blockStack[blockStack.length - 1]; }
    function atStmtLevel() {
        const b = getBase();
        return parenDepth === b.baseParen &&
               braceDepth === b.baseBrace &&
               bracketDepth === b.baseBracket;
    }
    function pushBlock() {
        blockStack.push({
            baseParen: parenDepth,
            baseBrace: braceDepth,
            baseBracket: bracketDepth
        });
    }
    function popBlock() {
        if (blockStack.length > 1) blockStack.pop();
    }

    function ensureIndent() {
        if (lineStart) {
            out += indentStr.repeat(indent);
            lineStart = false;
        }
    }
    function trimEnd() {
        let i = out.length;
        while (i > 0 && (out[i - 1] === ' ' || out[i - 1] === '\t')) i--;
        if (i < out.length) out = out.slice(0, i);
    }
    function newline() {
        if (out.length === 0) { lineStart = true; return; }
        trimEnd();
        if (!out.endsWith('\n')) out += '\n';
        lineStart = true;
    }
    function ensureSpace() {
        if (!lineStart && out.length && !out.endsWith(' ') && !out.endsWith('\n')) {
            out += ' ';
        }
    }
    function emit(s) { ensureIndent(); out += s; }

    function computeSpaceBefore(cur, prev, prevUnary, curUnary) {
        if (!prev) return false;
        const cv = cur.value;
        const pv = prev.value;
        const pOp = prev.type === 'op';
        const cOp = cur.type === 'op';
        const pKw = prev.type === 'keyword';
        const cKw = cur.type === 'keyword';

        if (cOp && (cv === ')' || cv === ']' || cv === '}' ||
                    cv === ',' || cv === ';' || cv === '.' || cv === ':')) return false;

        if (pOp && (pv === '(' || pv === '[' || pv === '{' ||
                    pv === '.' || pv === ':')) return false;

        if (prevUnary) {
            if (cOp && cv === '-' && pv === '-') return true;
            return false;
        }

        if (pOp && pv === '-' && cOp && cv === '-') return true;

        if (cKw && (cv === 'and' || cv === 'or' || cv === 'in')) return true;

        if (cOp && BINARY_OPS.has(cv) && !curUnary) return true;

        if (pOp && BINARY_OPS.has(pv)) return true;

        if (pOp && (pv === ',' || pv === ';')) return true;

        if (pKw && pv === 'function' && cOp && cv === '(') return false;

        if (cKw && (cv === 'then' || cv === 'do' || cv === 'else' ||
                    cv === 'elseif' || cv === 'until' || cv === 'end')) return true;

        if (pKw && SPACE_AFTER_KEYWORDS.indexOf(pv) !== -1) return true;

        if (cur.type === 'string' && prev.type === 'ident') return false;

        if (cur.type === 'string' && pKw &&
            (pv === 'end' || pv === 'true' || pv === 'false' || pv === 'nil')) return false;

        if ((cur.type === 'ident' || cur.type === 'number' || cur.type === 'string') &&
            (prev.type === 'ident' || prev.type === 'number' || prev.type === 'string')) {
            return true;
        }

        return false;
    }

    for (let i = 0; i < tokens.length; i++) {
        const tok = tokens[i];

        if (tok.type === 'comment') {
            if (tok.isLineComment) {
                if (!lineStart) ensureSpace();
                emit(tok.value);
                newline();
            } else {
                if (!lineStart) ensureSpace();
                emit(tok.value);
                if (/[\r\n]\s*$/.test(tok.value)) lineStart = true;
                else if (tok.value.indexOf('\n') !== -1) lineStart = false;
            }
            continue;
        }

        const p = lastSig;
        const n = nextSig[i];
        const v = tok.value;
        const pv = p ? p.value : null;

        const curUnary = tok.type === 'op' &&
            (v === '#' || v === '~' || (v === '-' && isUnaryContext(p)));

        let newlineBefore = false;
        let newlineAfter = false;
        let indentAfter = false;
        let deindentBefore = false;

        if (tok.type === 'keyword') {
            if (v === 'then' || v === 'do') {
                pushBlock();
                indentAfter = true;
                newlineAfter = true;
            } else if (v === 'repeat') {
                newlineBefore = true;
                pushBlock();
                indentAfter = true;
                newlineAfter = true;
            } else if (v === 'else') {
                popBlock();
                deindentBefore = true;
                newlineBefore = true;
                pushBlock();
                indentAfter = true;
                newlineAfter = true;
            } else if (v === 'elseif') {
                popBlock();
                deindentBefore = true;
                newlineBefore = true;
            } else if (v === 'end' || v === 'until') {
                popBlock();
                deindentBefore = true;
                if (!p || !(p.type === 'keyword' && BLOCK_OPENERS.has(pv))) {
                    newlineBefore = true;
                }
            } else if (v === 'local' || v === 'if' || v === 'for' || v === 'while' ||
                       v === 'return' || v === 'break' || v === 'goto' || v === 'continue') {
                newlineBefore = true;
            } else if (v === 'function') {
                if (!p || pv === ';' || pv === 'end' || pv === 'until' ||
                    (p.type === 'keyword' && BLOCK_OPENERS.has(pv))) {
                    newlineBefore = true;
                }
            }
        }

        if (tok.type === 'ident' && atStmtLevel() && isValueEnding(p)) {
            newlineBefore = true;
        }

        if (tok.type === 'op') {
            if (v === ';') {
                if (braceDepth === 0) newlineAfter = true;
            } else if (v === '(') {
                if (funcParamPending) {
                    funcParamPending = false;
                    funcParamDepth = parenDepth;
                }
                parenDepth++;
            } else if (v === ')') {
                parenDepth--;
                if (funcParamDepth !== null && parenDepth === funcParamDepth) {
                    funcParamDepth = null;
                    pushBlock();
                    indentAfter = true;
                    newlineAfter = true;
                }
            } else if (v === '[') {
                bracketDepth++;
            } else if (v === ']') {
                bracketDepth--;
            } else if (v === '{') {
                braceDepth++;
            } else if (v === '}') {
                braceDepth--;
            }
        }

        if (tok.type === 'keyword' && v === 'function') {
            funcParamPending = true;
        }

        const spaceBefore = computeSpaceBefore(tok, p, lastSigWasUnary, curUnary);

        if (deindentBefore) indent = Math.max(0, indent - 1);
        if (newlineBefore) newline();
        else if (spaceBefore) ensureSpace();

        emit(v);

        if (indentAfter) indent++;
        if (newlineAfter) newline();

        lastSig = tok;
        lastSigWasUnary = curUnary;
    }

    trimEnd();
    if (out.length && !out.endsWith('\n')) out += '\n';
    return out;
}

module.exports = beautify;
module.exports.tokenize = tokenize;
module.exports.beautify = beautify;

if (require.main === module) {
    const args = process.argv.slice(2);
    if (args.length === 0) {
        process.stderr.write('Usage: node beautify.js <input.lua> [output.lua] [--indent=N]\n');
        process.exit(1);
    }
    let inputFile = null;
    let outputFile = null;
    let indent = '    ';
    for (let ai = 0; ai < args.length; ai++) {
        const a = args[ai];
        if (a.indexOf('--indent=') === 0) {
            const num = parseInt(a.slice(9), 10);
            if (num > 0) indent = ' '.repeat(num);
        } else if (!inputFile) {
            inputFile = a;
        } else if (!outputFile) {
            outputFile = a;
        }
    }
    if (!inputFile) {
        process.stderr.write('No input file given.\n');
        process.exit(1);
    }
    const src = fs.readFileSync(/* turbopackIgnore: true */ inputFile, 'utf8');
    const result = beautify(src, { indent: indent });
    if (outputFile) {
        fs.writeFileSync(outputFile, result);
    } else {
        process.stdout.write(result);
    }
}
