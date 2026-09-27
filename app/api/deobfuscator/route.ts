import { NextResponse } from 'next/server'
import { spawn } from 'node:child_process'
import path from 'node:path'

export const runtime = 'nodejs'

export async function POST(request: Request) {
  const { code } = await request.json() as { code?: string }
  if (!code?.trim()) return NextResponse.json({ error: 'Code is required' }, { status: 400 })
  return new Promise<NextResponse>((resolve) => {
    const script = path.join(process.cwd(), 'lib', 'deobf.py')
    const child = spawn('python3', [script], { stdio: ['pipe', 'pipe', 'pipe'] })
    let output = ''
    let error = ''
    child.stdout.on('data', (chunk) => { output += chunk.toString() })
    child.stderr.on('data', (chunk) => { error += chunk.toString() })
    child.on('error', () => resolve(NextResponse.json({ error: 'Deobfuscator runtime is unavailable' }, { status: 503 })))
    child.on('close', (status) => status === 0 ? resolve(NextResponse.json({ code: output })) : resolve(NextResponse.json({ error: error || 'Deobfuscation failed' }, { status: 422 })))
    child.stdin.end(code)
  })
}
