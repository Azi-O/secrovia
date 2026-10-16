import { NextResponse } from 'next/server'

export function GET() {
  return new Response('cl cl cl', { headers: { 'Content-Type': 'text/plain; charset=utf-8' } })
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => null)
  if (!body || typeof body.code !== 'string' || !body.code.trim()) {
    return NextResponse.json({ error: 'code is required' }, { status: 400 })
  }
  return NextResponse.json({ code: body.code })
}
