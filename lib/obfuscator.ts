import { lex } from './obfuscator-src/lexer/Lexer'
import { parse } from './obfuscator-src/parser/Parser'
import { obfuscate } from './obfuscator-src/obfuscator/Obfuscator'
import { encodeStrings } from './obfuscator-src/obfuscator/StringEncoder'
import { scrambleControlFlow } from './obfuscator-src/obfuscator/ControlFlowScrambler'
import { compile } from './obfuscator-src/vm/Compiler'
import { generateVM, type VMGenLevel } from './obfuscator-src/vm/vm-gen'

export function obfuscateLuau(source: string, level: 'debug' | 'normal' | 'maximum') {
  const { tokens, errors } = lex(source)
  if (errors.length) throw new Error('Invalid Luau source')
  let ast = parse(tokens)
  ast = encodeStrings(ast, { enabled: true })
  ast = scrambleControlFlow(ast, { enabled: true })
  const transformed = obfuscate(ast, { renameLocals: true, preserveGlobals: false })
  const chunk = compile(transformed)
  const vmLevel: VMGenLevel = level === 'debug' ? 'debug' : level === 'maximum' ? 'max' : 'normal'
  return generateVM(chunk, { level: vmLevel, executorGlobals: vmLevel !== 'debug' })
}
