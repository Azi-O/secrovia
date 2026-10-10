'use server'

import { randomUUID } from 'crypto'
import { and, desc, eq, sql } from 'drizzle-orm'
import { headers } from 'next/headers'
import { revalidatePath } from 'next/cache'
import { auth } from '@/lib/auth'
import { db } from '@/lib/db'
import { codeFile, siteStats, user } from '@/lib/db/schema'

async function getUserId() {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session?.user) throw new Error('Unauthorized')
  return session.user.id
}

export async function listFiles() {
  const userId = await getUserId()
  return db.select().from(codeFile).where(eq(codeFile.userId, userId)).orderBy(desc(codeFile.updatedAt))
}

export async function saveCodeFile(name: string, content: string) {
  const userId = await getUserId()
  const cleanName = name.trim().slice(0, 160)
  if (!cleanName) throw new Error('File name is required')
  const existing = await db.select({ id: codeFile.id }).from(codeFile).where(and(eq(codeFile.userId, userId), eq(codeFile.name, cleanName))).limit(1)
  if (existing[0]) await db.update(codeFile).set({ content, updatedAt: new Date() }).where(and(eq(codeFile.id, existing[0].id), eq(codeFile.userId, userId)))
  else await db.insert(codeFile).values({ id: randomUUID(), userId, name: cleanName, content })
  revalidatePath('/')
}

export async function deleteCodeFile(name: string) {
  const userId = await getUserId()
  await db.delete(codeFile).where(and(eq(codeFile.name, name), eq(codeFile.userId, userId)))
  revalidatePath('/')
}

export async function incrementSiteVisit() {
  await db.update(siteStats).set({ visitCount: sql`${siteStats.visitCount} + 1`, updatedAt: new Date() }).where(eq(siteStats.id, 1))
}

export async function getAdminStats() {
  const userId = await getUserId()
  const currentUser = await db.select({ name: user.name }).from(user).where(eq(user.id, userId)).limit(1)
  if (currentUser[0]?.name !== 'Secrovia') throw new Error('Forbidden')
  const stats = await db.select().from(siteStats).where(eq(siteStats.id, 1)).limit(1)
  const files = await db.select({ id: codeFile.id }).from(codeFile)
  return { visits: stats[0]?.visitCount ?? 0, files: files.length }
}
