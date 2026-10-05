#!/usr/bin/env node
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const generate = require("@babel/generator").default;
const t = require("@babel/types");
const fs = require("fs");

function foldConstants(code) {
  const ast = parser.parse(code, { sourceType: "script", errorRecovery: true });

  let changed = true;
  while (changed) {
    changed = false;
    traverse(ast, {
      BinaryExpression(path) {
        const { left, right, operator } = path.node;
        if (t.isNumericLiteral(left) && t.isNumericLiteral(right)) {
          const ops = {
            "+": (a, b) => a + b,
            "-": (a, b) => a - b,
            "*": (a, b) => a * b,
            "/": (a, b) => a / b,
            "%": (a, b) => a % b,
            "|": (a, b) => a | b,
            "&": (a, b) => a & b,
            "^": (a, b) => a ^ b,
            "<<": (a, b) => a << b,
            ">>": (a, b) => a >> b,
            ">>>": (a, b) => a >>> b,
            "==": (a, b) => a == b,
            "===": (a, b) => a === b,
            "!=": (a, b) => a != b,
            "!==": (a, b) => a !== b,
            "<": (a, b) => a < b,
            ">": (a, b) => a > b,
            "<=": (a, b) => a <= b,
            ">=": (a, b) => a >= b,
          };
          if (ops[operator]) {
            const result = ops[operator](left.value, right.value);
            if (typeof result === "boolean") {
              path.replaceWith(t.booleanLiteral(result));
            } else {
              path.replaceWith(t.numericLiteral(result));
            }
            changed = true;
          }
        }
        if (t.isStringLiteral(left) && t.isStringLiteral(right) && operator === "+") {
          path.replaceWith(t.stringLiteral(left.value + right.value));
          changed = true;
        }
      },
      UnaryExpression(path) {
        if (path.node.operator === "-" && t.isNumericLiteral(path.node.argument)) {
          path.replaceWith(t.numericLiteral(-path.node.argument.value));
          changed = true;
        }
        if (path.node.operator === "!" && t.isBooleanLiteral(path.node.argument)) {
          path.replaceWith(t.booleanLiteral(!path.node.argument.value));
          changed = true;
        }
        if (path.node.operator === "~" && t.isNumericLiteral(path.node.argument)) {
          path.replaceWith(t.numericLiteral(~path.node.argument.value));
          changed = true;
        }
      },
      ConditionalExpression(path) {
        if (t.isBooleanLiteral(path.node.test)) {
          path.replaceWith(path.node.test.value ? path.node.consequent : path.node.alternate);
          changed = true;
        }
      },
    });
  }

  return generate(ast, { compact: false, comments: false }).code;
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    console.log("Usage: node constant_folder.js <input> [output]");
    process.exit(1);
  }
  const code = fs.readFileSync(args[0], "utf8");
  const result = foldConstants(code);
  const out = args[1] || args[0].replace(/\.js$/, "_folded.js");
  fs.writeFileSync(out, result);
  console.log(`Written to ${out}`);
}

module.exports = { foldConstants };
