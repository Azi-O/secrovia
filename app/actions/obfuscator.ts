'use server'

import { headers } from 'next/headers'
import { eq, sql } from 'drizzle-orm'
import { auth } from '@/lib/auth'
import { db } from '@/lib/db'
import { user } from '@/lib/db/schema'
import { obfuscateLuau } from '@/lib/obfuscator'

async function getUserId() {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session?.user) throw new Error('Unauthorized')
  return session.user.id
}

export async function getTokenBalance() {
  const userId = await getUserId()
  const [account] = await db.select({ tokenBalance: user.tokenBalance }).from(user).where(eq(user.id, userId)).limit(1)
  return account?.tokenBalance ?? 0
}

export async function obfuscateCode(source: string, level: 'debug' | 'normal' | 'maximum') {
  const userId = await getUserId()
  if (!source.trim()) throw new Error('Code is required')
  const output = obfuscateLuau(source, level)
  if (level === 'maximum') {
    const result = await db.update(user).set({ tokenBalance: sql`${user.tokenBalance} - 1` }).where(sql`${user.id} = ${userId} AND ${user.tokenBalance} > 0`).returning({ tokenBalance: user.tokenBalance })
    if (!result.length) throw new Error('You need 1 token for Maximum obfuscation')
  }
  return output
}
