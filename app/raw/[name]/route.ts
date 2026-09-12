import { NextRequest, NextResponse } from 'next/server'
import { eq } from 'drizzle-orm'
import { db } from '@/lib/db'
import { codeFile } from '@/lib/db/schema'

export async function GET(request: NextRequest, { params }: { params: Promise<{ name: string }> }) {
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
function protectedResponse() { return new NextResponse('This file was protected by secrovia https://discord.gg/JqNpxc8QXk', { status: 405, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } }) }
