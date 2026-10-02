import { and, eq } from 'drizzle-orm'
import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { codeFile, user } from '@/lib/db/schema'

export async function GET(request: NextRequest, { params }: { params: Promise<{ username: string; name: string }> }) {
  const fetchMode = request.headers.get('sec-fetch-mode')
  const accept = request.headers.get('accept') ?? ''
  const userAgent = request.headers.get('user-agent') ?? ''
  const isBrowserNavigation = fetchMode === 'navigate' || accept.includes('text/html')
  const isHttpGetClient = /roblox|robloxstudio|httpget/i.test(userAgent) || (!isBrowserNavigation && !accept.includes('text/html'))
  if (isBrowserNavigation && !isHttpGetClient) return protectedResponse()

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
  return new NextResponse('Protected raw endpoint', {
    status: 403,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
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
