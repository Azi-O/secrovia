import { NextResponse } from 'next/server'
import { deobfuscate } from '@/lib/iron-veil'

export async function GET() {
  return new NextResponse('cl cl cl', { headers: { 'Content-Type': 'text/plain; charset=utf-8' } })
}

export async function POST(request: Request) {
  try {
    const body = await request.json() as { code?: unknown }
    if (typeof body.code !== 'string' || !body.code.trim()) {
      return NextResponse.json({ error: 'code is required' }, { status: 400 })
    }
    const code = deobfuscate(body.code)
    return NextResponse.json({ code })
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : 'Iron Veil deobfuscation failed' }, { status: 422 })
  }
}
