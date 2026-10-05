import { NextResponse } from 'next/server'
import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { FullJSDeobfuscator } from '@/lib/moonsec/full_deobf'

export const runtime = 'nodejs'

const strengths = new Set(['low', 'medium', 'high', 'extreme'])

export async function POST(request: Request) {
  try {
    const body = await request.json() as { code?: unknown; strength?: unknown }
    const code = typeof body.code === 'string' ? body.code : ''
    const strength = typeof body.strength === 'string' && strengths.has(body.strength) ? body.strength : 'medium'
    if (!code.trim()) return NextResponse.json({ error: 'Code is required' }, { status: 400 })

    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'moonsec-'))
    const inputPath = path.join(directory, 'input.lua')
    const outputPath = path.join(directory, 'output.lua')
    await fs.writeFile(inputPath, code, 'utf8')
    try {
      const output = new FullJSDeobfuscator(strength).deobfuscate(inputPath, outputPath)
      return NextResponse.json({ code: `--// This file was created by Secrovia https://discord.gg/JqNpxc8QXk\n${output.trimStart()}` })
    } finally {
      await fs.rm(directory, { recursive: true, force: true }).catch(() => undefined)
    }
  } catch (error) {
    console.error('[v0] Moonsec deobfuscation failed', error)
    return NextResponse.json({ error: 'MoonSec deobfuscation failed for this input' }, { status: 422 })
  }
}
