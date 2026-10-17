export const apiServices = {
  obfuscator: { label: 'Obfuscator', path: '/api/v1/obfuscator' },
  multiDeobfuscator: { label: 'Multi Deobfuscator', path: '/api/v1/deobfuscator/multi' },
  chaoticGod: { label: 'Deobfuscator LuaObfuscator Chaotic God', path: '/api/v1/deobfuscator/chaotic-god' },
  prometheus: { label: 'Prometheus Deobfuscator', path: '/api/v1/deobfuscator/prometheus' },
} as const

export type ApiServiceKey = keyof typeof apiServices
