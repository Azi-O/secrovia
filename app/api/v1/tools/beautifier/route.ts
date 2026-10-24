import { NextResponse } from 'next/server'
import beautify from '@/lib/beautifier'

export async function GET() {
  return new Response('cl cl cl', { headers: { 'Content-Type': 'text/plain; charset=utf-8' } })
}

export async function POST(request: Request) {
  try {
    const body = await request.json() as { code?: unknown; indent?: unknown }
    if (typeof body.code !== 'string' || !body.code.trim()) return NextResponse.json({ error: 'code is required' }, { status: 400 })
    const indent = typeof body.indent === 'string' && body.indent.length <= 16 ? body.indent : '    '
    return NextResponse.json({ code: beautify(body.code, { indent }) })
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : 'Beautifying failed' }, { status: 422 })
  }
}
