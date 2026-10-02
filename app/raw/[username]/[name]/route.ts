import { and, eq } from 'drizzle-orm'
import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { codeFile, user } from '@/lib/db/schema'

export async function GET(request: NextRequest, { params }: { params: Promise<{ username: string; name: string }> }) {
  const fetchMode = request.headers.get('sec-fetch-mode')
  const accept = request.headers.get('accept') ?? ''
  const userAgent = request.headers.get('user-agent') ?? ''
  const isBrowserNavigation = fetchMode === 'navigate' || accept.toLowerCase().includes('text/html')
  const isGameHttpGet = /roblox|robloxstudio|httpget/i.test(userAgent)
  // Never expose source code to a normal browser navigation, even when the
  // request omits Sec-Fetch headers or arrives through a direct address bar load.
  if (isBrowserNavigation && !isGameHttpGet) return protectedResponse()

  const { username, name } = await params
  const file = await db
    .select({ id: codeFile.id, content: codeFile.content, rawAccessCount: codeFile.rawAccessCount })
    .from(codeFile)
    .innerJoin(user, eq(codeFile.userId, user.id))
    .where(and(eq(user.name, decodeURIComponent(username)), eq(codeFile.name, decodeURIComponent(name))))
    .limit(1)
  if (!file[0]) return new NextResponse('Not found', { status: 404 })

  await db.update(codeFile).set({ rawAccessCount: file[0].rawAccessCount + 1 }).where(eq(codeFile.id, file[0].id))
  return new NextResponse(file[0].content, {
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
  })
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
    <title>Protected file — Secrovia</title>
    <style>
      :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
      * { box-sizing: border-box; }
      body {
        min-height: 100vh; margin: 0; display: grid; place-items: center; padding: 24px;
        color: #f4f4f5; background: #111113;
        background-image: radial-gradient(circle at 50% 0%, rgba(255, 255, 255, .08), transparent 44%), linear-gradient(145deg, #09090b, #27272a);
      }
      main {
        width: min(100%, 520px); padding: 40px 28px; text-align: center;
        border: 1px solid rgba(255, 255, 255, .16); border-radius: 24px;
        background: rgba(24, 24, 27, .9); box-shadow: 0 24px 80px rgba(0, 0, 0, .5);
        backdrop-filter: blur(18px);
      }
      h1 { margin: 0; font-size: clamp(24px, 5vw, 34px); letter-spacing: -.04em; }
      a { display: inline-block; margin-top: 22px; color: #d4d4d8; font-weight: 600; text-decoration: none; }
      a:hover { color: #fff; text-decoration: underline; }
    </style>
  </head>
  <body>
    <main role="status" aria-live="polite">
      <h1>This File Was Protected By Secrovia</h1>
      <a href="https://discord.gg/JqNpxc8QXk" rel="noopener noreferrer">https://discord.gg/JqNpxc8QXk</a>
    </main>
  </body>
</html>`

  return new NextResponse(html, {
    status: 403,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  })
}

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

// URL format: /raw/{username}/{filename}
// The legacy /raw/{filename} endpoint remains available for existing links.
// New links should always use this route.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const _routeContract = '/raw/:username/:name'

void _routeContract
export {}
