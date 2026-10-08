'use server'

import { randomUUID } from 'crypto'
import { desc, eq } from 'drizzle-orm'
import { headers } from 'next/headers'
import { auth } from '@/lib/auth'
import { db } from '@/lib/db'
import { shareMember, shareMessage, shareSource, user } from '@/lib/db/schema'

async function currentUserId() {
  const session = await auth.api.getSession({ headers: await headers() })
  if (!session?.user) throw new Error('Unauthorized')
  return session.user.id
}

export async function listShareSources() {
  const userId = await currentUserId()
  const owned = await db.select().from(shareSource).where(eq(shareSource.ownerId, userId)).orderBy(desc(shareSource.createdAt))
  const joined = await db.select({ source: shareSource }).from(shareMember).innerJoin(shareSource, eq(shareMember.sourceId, shareSource.id)).where(eq(shareMember.userId, userId)).orderBy(desc(shareSource.createdAt))
  return [...owned, ...joined.map((row) => row.source)].filter((source, index, all) => all.findIndex((item) => item.id === source.id) === index)
}

export async function createShareSource(displayName: string, description: string) {
  const ownerId = await currentUserId()
  const source = { id: randomUUID(), ownerId, displayName: displayName.trim().slice(0, 80), description: description.trim().slice(0, 1000), createdAt: new Date() }
  await db.insert(shareSource).values(source)
  await db.insert(shareMember).values({ id: randomUUID(), sourceId: source.id, userId: ownerId })
  return source
}

export async function joinShareSource(sourceId: string) {
  const userId = await currentUserId()
  const existing = await db.select({ id: shareMember.id }).from(shareMember).where(eq(shareMember.sourceId, sourceId)).limit(1)
  if (!existing[0]) await db.insert(shareMember).values({ id: randomUUID(), sourceId, userId })
  return sourceId
}

export async function listShareMessages(sourceId: string) {
  await currentUserId()
  return db.select({ id: shareMessage.id, content: shareMessage.content, fileName: shareMessage.fileName, fileContent: shareMessage.fileContent, createdAt: shareMessage.createdAt, authorName: user.displayName, authorImage: user.image }).from(shareMessage).innerJoin(user, eq(shareMessage.authorId, user.id)).where(eq(shareMessage.sourceId, sourceId)).orderBy(shareMessage.createdAt)
}

export async function createShareMessage(sourceId: string, content: string, fileName?: string, fileContent?: string) {
  const authorId = await currentUserId()
  const message = { id: randomUUID(), sourceId, authorId, content: content.trim().slice(0, 4000), fileName: fileName?.slice(0, 255) ?? null, fileContent: fileContent ?? null, createdAt: new Date() }
  await db.insert(shareMessage).values(message)
  return message
}
