'use server'

import { randomUUID } from 'crypto'
import { and, desc, eq } from 'drizzle-orm'
import { headers } from 'next/headers'
import { auth } from '@/lib/auth'
import { db } from '@/lib/db'
import { groupChat, groupMember, groupMessage, user } from '@/lib/db/schema'

async function uid() { const session = await auth.api.getSession({ headers: await headers() }); if (!session?.user) throw new Error('Unauthorized'); return session.user.id }
export async function listGroups() { const id = await uid(); const owned = await db.select().from(groupChat).where(eq(groupChat.ownerId, id)).orderBy(desc(groupChat.createdAt)); const joined = await db.select({ group: groupChat }).from(groupMember).innerJoin(groupChat, eq(groupMember.groupId, groupChat.id)).where(eq(groupMember.userId, id)); return [...owned, ...joined.map((x) => x.group)].filter((g, i, a) => a.findIndex((x) => x.id === g.id) === i) }
export async function createGroup(name: string, imageData?: string | null) { const ownerId = await uid(); const safeName = name.trim().slice(0, 80) || 'Untitled group'; const group = { id: randomUUID(), ownerId, name: safeName, imageData: imageData?.startsWith('data:image/') ? imageData.slice(0, 2_000_000) : null, createdAt: new Date() }; await db.insert(groupChat).values(group); await db.insert(groupMember).values({ id: randomUUID(), groupId: group.id, userId: ownerId }); return group }
export async function joinGroup(groupId: string) { const id = await uid(); const rows = await db.select({ id: groupMember.id }).from(groupMember).where(eq(groupMember.groupId, groupId)).limit(1); if (!rows[0]) await db.insert(groupMember).values({ id: randomUUID(), groupId, userId: id }); return groupId }
export async function listGroupMessages(groupId: string) { await uid(); return db.select({ id: groupMessage.id, content: groupMessage.content, fileName: groupMessage.fileName, fileContent: groupMessage.fileContent, authorName: user.displayName, authorImage: user.image }).from(groupMessage).innerJoin(user, eq(groupMessage.authorId, user.id)).where(eq(groupMessage.groupId, groupId)).orderBy(groupMessage.createdAt) }
export async function updateGroup(groupId: string, name: string, imageData?: string | null) { const ownerId = await uid(); await db.update(groupChat).set({ name: name.trim().slice(0, 80), imageData: imageData?.startsWith('data:image/') ? imageData.slice(0, 2_000_000) : imageData ?? null }).where(and(eq(groupChat.id, groupId), eq(groupChat.ownerId, ownerId))) }
export async function deleteGroup(groupId: string) { const ownerId = await uid(); await db.delete(groupMessage).where(eq(groupMessage.groupId, groupId)); await db.delete(groupMember).where(eq(groupMember.groupId, groupId)); await db.delete(groupChat).where(and(eq(groupChat.id, groupId), eq(groupChat.ownerId, ownerId))) }

export async function createGroupMessage(groupId: string, content: string, fileName?: string, fileContent?: string) { const authorId = await uid(); const message = { id: randomUUID(), groupId, authorId, content: content.trim().slice(0, 4000), fileName: fileName?.slice(0, 255) ?? null, fileContent: fileContent ?? null, createdAt: new Date() }; await db.insert(groupMessage).values(message); return message }
