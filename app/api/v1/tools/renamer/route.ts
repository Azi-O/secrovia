import { NextResponse } from 'next/server'
import { renameLua } from '@/lib/renamer'

export async function GET() {
  return new Response('cl cl cl', { headers: { 'Content-Type': 'text/plain; charset=utf-8' } })
}

export async function POST(request: Request) {
  try {
    const body = await request.json() as { code?: unknown; mode?: unknown; style?: unknown; keep?: unknown }
    if (typeof body.code !== 'string' || !body.code.trim()) return NextResponse.json({ error: 'code is required' }, { status: 400 })
    const result = renameLua(body.code, { mode: typeof body.mode === 'string' ? body.mode : undefined, style: typeof body.style === 'string' ? body.style : undefined, keep: typeof body.keep === 'string' ? body.keep : undefined })
    return NextResponse.json({ code: result.code, map: result.map, stats: result.stats })
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : 'Renaming failed' }, { status: 422 })
  }
}
