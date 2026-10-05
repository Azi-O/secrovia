#!/usr/bin/env node
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const generate = require("@babel/generator").default;
const t = require("@babel/types");
const fs = require("fs");

function eliminateDeadCode(code) {
  const ast = parser.parse(code, { sourceType: "script", errorRecovery: true });

  traverse(ast, {
    IfStatement(path) {
      const test = path.get("test");
      if (test.isBooleanLiteral()) {
        if (test.node.value === true) {
          path.replaceWith(path.node.consequent);
        } else {
          if (path.node.alternate) {
            path.replaceWith(path.node.alternate);
          } else {
            path.remove();
          }
        }
      }
    },
    ConditionalExpression(path) {
      if (t.isBooleanLiteral(path.node.test)) {
        path.replaceWith(
          path.node.test.value ? path.node.consequent : path.node.alternate
        );
      }
    },
    LogicalExpression(path) {
      if (t.isBooleanLiteral(path.node.left)) {
        if (path.node.operator === "&&") {
          path.replaceWith(path.node.left.value ? path.node.right : t.booleanLiteral(false));
        } else if (path.node.operator === "||") {
          path.replaceWith(path.node.left.value ? t.booleanLiteral(true) : path.node.right);
        }
      }
    },
    FunctionDeclaration(path) {
      const name = path.node.id && path.node.id.name;
      if (name && /^_unused|^dead|^junk|^noop/i.test(name)) {
        path.remove();
      }
    },
    VariableDeclarator(path) {
      const name = path.node.id.name;
      if (name && /^_unused|^dead|^junk/i.test(name)) {
        path.remove();
      }
    },
  });

  const used = new Set();
  traverse(ast, {
    Identifier(path) {
      if (path.isReferencedIdentifier()) {
        used.add(path.node.name);
      }
    },
  });

  traverse(ast, {
    FunctionDeclaration(path) {
      const name = path.node.id && path.node.id.name;
      if (name && !used.has(name) && !["main", "init", "entry"].includes(name)) {
        const binding = path.scope.getBinding(name);
        if (binding && binding.referencePaths.length === 0) {
          path.remove();
        }
      }
    },
  });

  return generate(ast, { compact: false, comments: false }).code;
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    console.log("Usage: node dead_code_elim.js <input> [output]");
    process.exit(1);
  }
  const code = fs.readFileSync(args[0], "utf8");
  const result = eliminateDeadCode(code);
  const out = args[1] || args[0].replace(/\.js$/, "_clean.js");
  fs.writeFileSync(out, result);
  console.log(`Written to ${out}`);
}

module.exports = { eliminateDeadCode };
