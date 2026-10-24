export const apiServices = {
  obfuscator: { label: 'Obfuscator', path: '/api/v1/obfuscator' },
  chaoticGod: { label: 'Deobfuscator LuaObfuscator Chaotic God', path: '/api/v1/deobfuscator/chaotic-god' },
  prometheus: { label: 'Prometheus Deobfuscator', path: '/api/v1/deobfuscator/prometheus' },
  ironVeil: { label: 'Iron Veil 1 Deobfuscator', path: '/api/v1/deobfuscator/iron-veil' },
  renamer: { label: 'Renamer Tool', path: '/api/v1/tools/renamer' },
  beautifier: { label: 'Beautifier Tool', path: '/api/v1/tools/beautifier' },
} as const

export type ApiServiceKey = keyof typeof apiServices
