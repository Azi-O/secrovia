import { NextRequest, NextResponse } from 'next/server'
import { eq } from 'drizzle-orm'
import { db } from '@/lib/db'
import { codeFile } from '@/lib/db/schema'

export async function GET(request: NextRequest, { params }: { params: Promise<{ name: string }> }) {
  const fetchMode = request.headers.get('sec-fetch-mode')
  const accept = request.headers.get('accept') ?? ''
  const userAgent = request.headers.get('user-agent') ?? ''
  const isBrowserNavigation = fetchMode === 'navigate' || accept.includes('text/html')
  const isHttpGetClient = /roblox|robloxstudio|httpget/i.test(userAgent)
  if (isBrowserNavigation && !isHttpGetClient) return protectedResponse()

  const { name } = await params
  const file = await db.select().from(codeFile).where(eq(codeFile.name, decodeURIComponent(name))).limit(1)
  if (!file[0]) return new NextResponse('Not found', { status: 404 })
  await db.update(codeFile).set({ rawAccessCount: file[0].rawAccessCount + 1 }).where(eq(codeFile.id, file[0].id))
  return new NextResponse(file[0].content, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } })
}

export async function HEAD() { return protectedResponse() }
export async function POST() { return protectedResponse() }
export async function PUT() { return protectedResponse() }
export async function PATCH() { return protectedResponse() }
export async function DELETE() { return protectedResponse() }
export async function OPTIONS() { return protectedResponse() }
function protectedResponse() {
  const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Protected file · Secrovia</title>
    <style>
      :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
      * { box-sizing: border-box; }
      body { min-height: 100vh; margin: 0; display: grid; place-items: center; padding: 24px; color: #f4f4f5; background: #09090b; }
      main { width: min(100%, 560px); padding: 42px; border: 1px solid #27272a; border-radius: 24px; background: linear-gradient(145deg, #18181b, #0f0f10); box-shadow: 0 24px 80px rgba(0,0,0,.42); text-align: center; }
      .mark { width: 56px; height: 56px; margin: 0 auto 24px; display: grid; place-items: center; border: 1px solid #3f3f46; border-radius: 16px; color: #d4d4d8; background: #27272a; font-size: 24px; }
      h1 { margin: 0; font-size: clamp(24px, 5vw, 34px); letter-spacing: -.04em; }
      p { margin: 14px 0 0; color: #a1a1aa; line-height: 1.7; }
      a { display: inline-block; margin-top: 28px; padding: 11px 18px; border-radius: 10px; color: #18181b; background: #f4f4f5; font-weight: 700; text-decoration: none; }
      a:hover { background: #d4d4d8; }
      .brand { margin-top: 26px; color: #52525b; font-size: 12px; letter-spacing: .16em; text-transform: uppercase; }
    </style>
  </head>
  <body>
    <main>
      <div class="mark" aria-hidden="true">S</div>
      <h1>This file was protected by Secrovia</h1>
      <p>Raw source is available only through an authorized game HTTP client.</p>
      <a href="https://discord.gg/JqNpxc8QXk" rel="noopener noreferrer">Join Secrovia Discord</a>
      <div class="brand">Secrovia · Protected raw access</div>
    </main>
  </body>
</html>`
  return new NextResponse(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex' } })
}
