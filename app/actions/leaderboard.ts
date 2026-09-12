'use server'

import { desc, eq, sql } from 'drizzle-orm'
import { headers } from 'next/headers'
import { auth } from '@/lib/auth'
import { db } from '@/lib/db'
import { codeFile, user } from '@/lib/db/schema'

export async function getLeaderboard() {
  return db.select({ name: user.name, image: user.image, accesses: sql<number>`coalesce(sum(${codeFile.rawAccessCount}), 0)` }).from(user).leftJoin(codeFile, eq(codeFile.userId, user.id)).groupBy(user.id).orderBy(desc(sql`coalesce(sum(${codeFile.rawAccessCount}), 0)`)).limit(25)
}

export async function updateProfile(name: string, image: string | null) {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session?.user) throw new Error('Unauthorized')
  await db.update(user).set({ name: name.trim().slice(0, 80), image, updatedAt: new Date() }).where(eq(user.id, session.user.id))
}
