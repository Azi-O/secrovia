'use server'

import { randomBytes } from 'crypto'
import { eq } from 'drizzle-orm'
import { headers } from 'next/headers'
import { auth } from '@/lib/auth'
import { db } from '@/lib/db'
import { user } from '@/lib/db/schema'
import type { ApiServiceKey } from '@/lib/api-services'

async function getUserId() {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session?.user) throw new Error('Unauthorized')
  return session.user.id
}

function createToken() { return `Secrovia-${randomBytes(18).toString('base64url')}` }

export async function getApiTokens() {
  const userId = await getUserId()
  const record = await db.select({ apiTokens: user.apiTokens }).from(user).where(eq(user.id, userId)).limit(1)
  try { return JSON.parse(record[0]?.apiTokens ?? '{}') as Record<string, string> } catch { return {} }
}

export async function resetApiToken(service: ApiServiceKey) {
  const userId = await getUserId()
  const record = await db.select({ apiTokens: user.apiTokens }).from(user).where(eq(user.id, userId)).limit(1)
  let tokens: Record<string, string> = {}
  try { tokens = JSON.parse(record[0]?.apiTokens ?? '{}') } catch { tokens = {} }
  tokens[service] = createToken()
  await db.update(user).set({ apiTokens: JSON.stringify(tokens), updatedAt: new Date() }).where(eq(user.id, userId))
  return tokens[service]
}

export async function getApiToken(service: ApiServiceKey) {
  const tokens = await getApiTokens()
  return tokens[service] ?? null
}
