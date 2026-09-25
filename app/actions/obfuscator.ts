'use server'

import { headers } from 'next/headers'
import { eq, sql } from 'drizzle-orm'
import { auth } from '@/lib/auth'
import { db } from '@/lib/db'
import { codeFile, user } from '@/lib/db/schema'
import { obfuscateLuau } from '@/lib/obfuscator'

async function getUserId() {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session?.user) throw new Error('Unauthorized')
  return session.user.id
}

export async function getTokenBalance() {
  const userId = await getUserId()
  const [account] = await db.select({ tokenBalance: user.tokenBalance, viewRemainder: user.viewRemainder }).from(user).where(eq(user.id, userId)).limit(1)
  const [views] = await db.select({ total: sql<number>`coalesce(sum(${codeFile.rawAccessCount}), 0)` }).from(codeFile).where(eq(codeFile.userId, userId))
  const totalViews = Number(views?.total ?? 0)
  const earnedTokens = Math.floor(totalViews / 15)
  const remainder = totalViews % 15
  if (earnedTokens > Number(account?.tokenBalance ?? 0) || remainder !== Number(account?.viewRemainder ?? 0)) {
    const [synced] = await db.update(user).set({ tokenBalance: Math.max(Number(account?.tokenBalance ?? 0), earnedTokens), viewRemainder: remainder }).where(eq(user.id, userId)).returning({ tokenBalance: user.tokenBalance })
    return Number(synced?.tokenBalance ?? earnedTokens)
  }
  return Number(account?.tokenBalance ?? 0)
}

export async function obfuscateCode(source: string, level: 'debug' | 'normal' | 'maximum') {
  const userId = await getUserId()
  if (!source.trim()) throw new Error('Code is required')
  const output = obfuscateLuau(source, level)
  if (level === 'maximum') {
    const result = await db.update(user).set({ tokenBalance: sql`coalesce(${user.tokenBalance}, 0) - 1` }).where(sql`${user.id} = ${userId} AND coalesce(${user.tokenBalance}, 0) >= 1`).returning({ tokenBalance: user.tokenBalance })
    if (!result.length) throw new Error('You need 1 token for Maximum obfuscation')
  }
  return output
}
