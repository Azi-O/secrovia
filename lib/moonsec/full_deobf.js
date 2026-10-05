#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const { ASTDeobfuscator } = require("./ast_deobfuscator");
const EnvironmentBypass = require("./env_bypass");

class FullJSDeobfuscator {
  constructor(strength = "medium") {
    this.strength = strength;
  }

  load(filePath) {
    return fs.readFileSync(filePath, "utf8");
  }

  stripComments(code) {
    code = code.replace(/\/\*[\s\S]*?\*\//g, "");
    code = code.replace(/\/\/[^\n]*/g, "");
    return code;
  }

  extractEmbedded(code) {
    const patterns = [
      /return\s*\(function\s*\(\.\.\.\)\s*([\s\S]*?)\s*end\)\s*\(\.\.\.\)/,
      /loadstring\s*\(\s*["'`]([\s\S]*?)["'`]\s*\)/,
      /Function\s*\(\s*["'`]([\s\S]*?)["'`]\s*\)/,
    ];
    for (const pat of patterns) {
      const m = code.match(pat);
      if (m) return m[1];
    }
    return code;
  }

  deobfuscate(inputPath, outputPath) {
    let code = this.load(inputPath);
    code = this.stripComments(code);

    if (this.strength !== "low") {
      EnvironmentBypass.install();
    }

    code = this.extractEmbedded(code);

    if (this.strength === "low") {
      const simple = code
        .replace(/\s+/g, " ")
        .replace(/;\s*/g, ";\n")
        .replace(/\{\s*/g, "{\n")
        .replace(/\}\s*/g, "}\n");
      if (outputPath) fs.writeFileSync(outputPath, simple);
      return simple;
    }

    const deobf = new ASTDeobfuscator(code);
    let result = deobf.deobfuscate();

    if (this.strength === "high" || this.strength === "extreme") {
      const deobf2 = new ASTDeobfuscator(result);
      result = deobf2.deobfuscate();
    }

    if (this.strength === "extreme") {
      result = this.aggressiveClean(result);
    }

    if (outputPath) {
      fs.writeFileSync(outputPath, result, "utf8");
    }
    return result;
  }

  aggressiveClean(code) {
    code = code.replace(/var\s+(\w+)\s*=\s*\1\s*;/g, "");
    code = code.replace(/let\s+(\w+)\s*=\s*\1\s*;/g, "");
    code = code.replace(/void\s+0/g, "undefined");
    code = code.replace(/!0/g, "true");
    code = code.replace(/!1/g, "false");
    code = code.replace(/!!\[\]/g, "true");
    code = code.replace(/!\[\]/g, "false");
    return code;
  }
}

function main() {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    console.log("Usage: node full_deobf.js <input> [output] [strength]");
    console.log("Strength: low | medium | high | extreme");
    process.exit(1);
  }
  const inp = args[0];
  const out = args[1] || inp.replace(/\.(js|lua)$/, "_deobf.js");
  const strength = args[2] || "medium";
  const deobf = new FullJSDeobfuscator(strength);
  deobf.deobfuscate(inp, out);
  console.log(`Deobfuscated (${strength}) -> ${out}`);
}

if (require.main === module) {
  main();
}

module.exports = { FullJSDeobfuscator };
