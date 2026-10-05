#!/usr/bin/env node
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const generate = require("@babel/generator").default;
const t = require("@babel/types");
const fs = require("fs");

class ASTDeobfuscator {
  constructor(code) {
    this.code = code;
    this.ast = null;
  }

  parse() {
    this.ast = parser.parse(this.code, {
      sourceType: "script",
      plugins: ["optionalChaining", "nullishCoalescingOperator"],
      errorRecovery: true,
    });
    return this.ast;
  }

  eliminateDeadCode() {
    const self = this;
    traverse(this.ast, {
      IfStatement(path) {
        const test = path.node.test;
        if (t.isBooleanLiteral(test)) {
          if (test.value === false) {
            if (path.node.alternate) {
              path.replaceWith(path.node.alternate);
            } else {
              path.remove();
            }
          } else if (test.value === true) {
            path.replaceWith(path.node.consequent);
          }
        }
        if (t.isBinaryExpression(test)) {
          try {
            const left = test.left;
            const right = test.right;
            if (t.isNumericLiteral(left) && t.isNumericLiteral(right)) {
              let result = false;
              switch (test.operator) {
                case "===":
                case "==":
                  result = left.value === right.value;
                  break;
                case "!==":
                case "!=":
                  result = left.value !== right.value;
                  break;
                case ">":
                  result = left.value > right.value;
                  break;
                case "<":
                  result = left.value < right.value;
                  break;
                case ">=":
                  result = left.value >= right.value;
                  break;
                case "<=":
                  result = left.value <= right.value;
                  break;
              }
              if (!result) {
                if (path.node.alternate) {
                  path.replaceWith(path.node.alternate);
                } else {
                  path.remove();
                }
              } else {
                path.replaceWith(path.node.consequent);
              }
            }
          } catch (e) {}
        }
      },
      ConditionalExpression(path) {
        const test = path.node.test;
        if (t.isBooleanLiteral(test)) {
          path.replaceWith(test.value ? path.node.consequent : path.node.alternate);
        }
      },
      LogicalExpression(path) {
        if (t.isBooleanLiteral(path.node.left)) {
          if (path.node.operator === "&&" && path.node.left.value === false) {
            path.replaceWith(t.booleanLiteral(false));
          } else if (path.node.operator === "||" && path.node.left.value === true) {
            path.replaceWith(t.booleanLiteral(true));
          }
        }
      },
    });
  }

  foldConstants() {
    traverse(this.ast, {
      BinaryExpression(path) {
        const { left, right, operator } = path.node;
        if (t.isNumericLiteral(left) && t.isNumericLiteral(right)) {
          let result;
          switch (operator) {
            case "+":
              result = left.value + right.value;
              break;
            case "-":
              result = left.value - right.value;
              break;
            case "*":
              result = left.value * right.value;
              break;
            case "/":
              result = left.value / right.value;
              break;
            case "%":
              result = left.value % right.value;
              break;
            case "|":
              result = left.value | right.value;
              break;
            case "&":
              result = left.value & right.value;
              break;
            case "^":
              result = left.value ^ right.value;
              break;
            case "<<":
              result = left.value << right.value;
              break;
            case ">>":
              result = left.value >> right.value;
              break;
            case ">>>":
              result = left.value >>> right.value;
              break;
            default:
              return;
          }
          path.replaceWith(t.numericLiteral(result));
        }
        if (t.isStringLiteral(left) && t.isStringLiteral(right) && operator === "+") {
          path.replaceWith(t.stringLiteral(left.value + right.value));
        }
      },
      UnaryExpression(path) {
        if (path.node.operator === "-" && t.isNumericLiteral(path.node.argument)) {
          path.replaceWith(t.numericLiteral(-path.node.argument.value));
        }
        if (path.node.operator === "!" && t.isBooleanLiteral(path.node.argument)) {
          path.replaceWith(t.booleanLiteral(!path.node.argument.value));
        }
        if (path.node.operator === "~" && t.isNumericLiteral(path.node.argument)) {
          path.replaceWith(t.numericLiteral(~path.node.argument.value));
        }
      },
    });
  }

  renameVariables() {
    const scopeMap = new Map();
    let counter = 0;
    const meaningful = [
      "value", "result", "temp", "index", "count", "data", "key", "buf",
      "len", "pos", "flag", "state", "ctx", "env", "fn", "cb", "err",
      "str", "num", "obj", "arr", "tbl", "src", "dst", "ptr", "ref",
    ];

    traverse(this.ast, {
      Scope(path) {
        const bindings = path.scope.bindings;
        for (const name of Object.keys(bindings)) {
          if (/^[_vV]\d+$/.test(name) || /^[a-z]$/.test(name) || name.length <= 2) {
            const newName = meaningful[counter % meaningful.length] + (counter >= meaningful.length ? counter : "");
            counter++;
            path.scope.rename(name, newName);
          }
        }
      },
    });
  }

  removeEmptyStatements() {
    traverse(this.ast, {
      EmptyStatement(path) {
        path.remove();
      },
      ExpressionStatement(path) {
        if (t.isLiteral(path.node.expression) || t.isIdentifier(path.node.expression)) {
          if (!path.getFunctionParent()) {
            path.remove();
          }
        }
      },
    });
  }

  simplifySequences() {
    traverse(this.ast, {
      SequenceExpression(path) {
        const exprs = path.node.expressions;
        if (exprs.length === 1) {
          path.replaceWith(exprs[0]);
        }
      },
    });
  }

  deobfuscate() {
    this.parse();
    this.eliminateDeadCode();
    this.foldConstants();
    this.foldConstants();
    this.simplifySequences();
    this.removeEmptyStatements();
    this.renameVariables();
    this.eliminateDeadCode();
    const output = generate(this.ast, {
      compact: false,
      comments: false,
      retainLines: false,
    });
    return output.code;
  }
}

function deobfuscateFile(inputPath, outputPath) {
  const code = fs.readFileSync(inputPath, "utf8");
  const deobf = new ASTDeobfuscator(code);
  const result = deobf.deobfuscate();
  if (outputPath) {
    fs.writeFileSync(outputPath, result, "utf8");
  }
  return result;
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    console.log("Usage: node ast_deobfuscator.js <input.js> [output.js]");
    process.exit(1);
  }
  const out = args[1] || args[0].replace(/\.js$/, "_deobf.js");
  const result = deobfuscateFile(args[0], out);
  console.log(`Deobfuscated written to ${out}`);
}

module.exports = { ASTDeobfuscator, deobfuscateFile };
