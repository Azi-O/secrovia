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
    <meta name="theme-color" content="#080a09" />
    <title>Protected raw · Secrovia</title>
    <style>
      :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
      * { box-sizing: border-box; }
      body { min-height: 100vh; margin: 0; display: grid; place-items: center; overflow: hidden; padding: 24px; color: #f5f7f2; background: #080a09; }
      body::before, body::after { position: fixed; z-index: -1; width: 420px; height: 420px; border-radius: 50%; content: ""; filter: blur(90px); opacity: .16; }
      body::before { top: -180px; left: -120px; background: #a8e650; }
      body::after { right: -160px; bottom: -180px; background: #4d8c72; }
      main { width: min(100%, 620px); padding: 12px; border: 1px solid #29332d; border-radius: 28px; background: rgba(17, 22, 19, .72); box-shadow: 0 30px 100px rgba(0,0,0,.48); backdrop-filter: blur(18px); }
      .card { padding: clamp(28px, 7vw, 64px); border: 1px solid rgba(160, 188, 165, .14); border-radius: 20px; background: linear-gradient(145deg, rgba(31, 42, 35, .92), rgba(13, 17, 15, .94)); text-align: center; }
      .badge { display: inline-flex; align-items: center; gap: 8px; padding: 7px 11px; border: 1px solid #39483b; border-radius: 999px; color: #b9d99d; background: #172019; font-size: 11px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; }
      .badge i { width: 7px; height: 7px; border-radius: 50%; background: #b9e86d; box-shadow: 0 0 14px #b9e86d; }
      .mark { width: 82px; height: 82px; margin: 30px auto 24px; display: grid; place-items: center; overflow: hidden; border: 1px solid #718e59; border-radius: 22px; background: linear-gradient(145deg, #d4f69a, #85b65a); box-shadow: 0 12px 30px rgba(146, 198, 91, .2); } .mark img { width: 100%; height: 100%; object-fit: cover; }
      h1 { max-width: 480px; margin: 0 auto; font-size: clamp(28px, 6vw, 46px); line-height: 1.04; letter-spacing: -.06em; }
      p { max-width: 420px; margin: 18px auto 0; color: #aeb9af; line-height: 1.7; }
      a { display: inline-flex; align-items: center; justify-content: center; margin-top: 28px; padding: 13px 19px; border: 1px solid #d4f69a; border-radius: 11px; color: #11170d; background: #d4f69a; font-size: 14px; font-weight: 800; text-decoration: none; transition: transform .2s ease, background .2s ease; }
      a:hover { transform: translateY(-2px); background: #e1ffb0; }
      .brand { margin-top: 30px; color: #617066; font-size: 11px; font-weight: 700; letter-spacing: .16em; text-transform: uppercase; }
      @media (max-width: 480px) { body { padding: 14px; } main { border-radius: 22px; } .card { padding: 30px 20px; } }
    </style>
  </head>
  <body>
    <main><section class="card">
      <div class="mark"><img src="https://res.cloudinary.com/dtz0urit6/image/upload/f_png,q_auto/cloudinary-tools-uploads/anthu0ohnfyuikenobqi.png" alt="Secrovia logo" /></div>
      <h1>This file was protected by Secrovia</h1>
      <p>https://secrovia.vercel.app</p>
      <a href="https://discord.gg/JqNpxc8QXk" rel="noopener noreferrer">Join the Secrovia Discord</a>
      <div class="brand">Secrovia · Secure code delivery</div>
    </section></main>
  </body>
</html>`
  return new NextResponse(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex' } })
}
