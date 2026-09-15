'use server'

import { desc, eq, sql } from 'drizzle-orm'
import { headers } from 'next/headers'
import { auth } from '@/lib/auth'
import { db } from '@/lib/db'
import { codeFile, user } from '@/lib/db/schema'

export async function getStatus() {
  const [accounts, files] = await Promise.all([
    db.select({ id: user.id, name: user.name, fileCount: sql<number>`count(${codeFile.id})` }).from(user).leftJoin(codeFile, eq(codeFile.userId, user.id)).groupBy(user.id).orderBy(user.name),
    db.select({ count: sql<number>`count(*)` }).from(user),
  ])
  return { accountCount: Number(files[0]?.count ?? 0), accounts: accounts.map((account) => ({ name: account.name, fileCount: Number(account.fileCount ?? 0) })) }
}

export async function getLeaderboard() {
  return db.select({ name: user.name, image: user.image, accesses: sql<number>`coalesce(sum(${codeFile.rawAccessCount}), 0)` }).from(user).leftJoin(codeFile, eq(codeFile.userId, user.id)).groupBy(user.id).orderBy(desc(sql`coalesce(sum(${codeFile.rawAccessCount}), 0)`)).limit(25)
}

async function getCurrentUser() {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session?.user) throw new Error('Unauthorized')
  return session.user.id
}

export async function getProfile() {
  const userId = await getCurrentUser()
  const result = await db.select({ name: user.name, image: user.image }).from(user).where(eq(user.id, userId)).limit(1)
  return result[0] ?? { name: '', image: null }
}

export async function getProfileStats() {
  const userId = await getCurrentUser()
  const result = await db.select({ fileCount: sql<number>`count(${codeFile.id})`, mostAccessedName: sql<string | null>`(array_agg(${codeFile.name} order by ${codeFile.rawAccessCount} desc))[1]` }).from(codeFile).where(eq(codeFile.userId, userId)).groupBy(codeFile.userId)
  return { fileCount: Number(result[0]?.fileCount ?? 0), mostAccessedName: result[0]?.mostAccessedName ?? 'None yet' }
}

export async function getAdminStats() {
  const result = await db.select({ fileCount: sql<number>`count(*)`, totalAccesses: sql<number>`coalesce(sum(${codeFile.rawAccessCount}), 0)` }).from(codeFile)
  return { fileCount: Number(result[0]?.fileCount ?? 0), totalAccesses: Number(result[0]?.totalAccesses ?? 0) }
}

export async function updateProfile(name: string, image?: string | null) {
  const userId = await getCurrentUser()
  const nextName = name.trim().slice(0, 80)
  if (!nextName) throw new Error('Name is required')
  const values: { name: string; updatedAt: Date; image?: string | null } = { name: nextName, updatedAt: new Date() }
  if (image !== undefined) values.image = image
  await db.update(user).set(values).where(eq(user.id, userId))
  return { name: nextName, image: image === undefined ? undefined : image ?? null }
}
