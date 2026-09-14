import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { jwtVerify, SignJWT } from 'jose';
import { config } from './config.js';
import { nowIso, supabase, unwrap } from './db.js';

export type Role = 'admin' | 'reader';
export type Principal = { role: Role; subjectId: string; sessionId: string; tokenVersion: number };
export type AuthenticatedRequest = Request & { principal?: Principal };

const jwtKey = new TextEncoder().encode(config.JWT_SECRET);
const refreshHash = (token: string) => createHash('sha256').update(token).digest('hex');

async function accessToken(principal: Principal) {
  return new SignJWT({ role: principal.role, sid: principal.sessionId, ver: principal.tokenVersion })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(principal.subjectId)
    .setIssuedAt()
    .setExpirationTime('15m')
    .sign(jwtKey);
}

export async function issueSession(role: Role, subjectId: string, tokenVersion = 0, details: Record<string, unknown> = {}) {
  const sessionId = randomUUID();
  const refreshToken = randomBytes(48).toString('base64url');
  const expiresAt = new Date(Date.now() + 30 * 86400000).toISOString();
  unwrap(await supabase.from('auth_sessions').insert({
    id: sessionId,
    subject_type: role,
    subject_id: subjectId,
    refresh_token_hash: refreshHash(refreshToken),
    token_version: tokenVersion,
    expires_at: expiresAt
  }).select('id').single());
  const token = await accessToken({ role, subjectId, sessionId, tokenVersion });
  return { role, token, refreshToken, expiresAt, ...details };
}

export async function rotateSession(refreshToken: string) {
  const row = unwrap<any>(await supabase.from('auth_sessions').select('*')
    .eq('refresh_token_hash', refreshHash(refreshToken)).is('revoked_at', null).gt('expires_at', nowIso()).maybeSingle());
  if (!row) throw Object.assign(new Error('Invalid or expired refresh token.'), { status: 401 });

  if (row.subject_type === 'reader') {
    const reader = unwrap<any>(await supabase.from('readers').select('id,username,full_name,status,device_id,token_version').eq('id', row.subject_id).maybeSingle());
    if (!reader || reader.status !== 'active' || reader.token_version !== row.token_version) throw Object.assign(new Error('Session has been revoked.'), { status: 401 });
    const nextRefresh = randomBytes(48).toString('base64url');
    unwrap(await supabase.from('auth_sessions').update({ refresh_token_hash: refreshHash(nextRefresh), last_used_at: nowIso() }).eq('id', row.id).select('id').single());
    const token = await accessToken({ role: 'reader', subjectId: reader.id, sessionId: row.id, tokenVersion: row.token_version });
    return { role: 'reader' as const, token, refreshToken: nextRefresh, expiresAt: row.expires_at, username: reader.username, fullName: reader.full_name, deviceId: reader.device_id };
  }

  const admin = unwrap<any>(await supabase.from('admin_accounts').select('id,email,status').eq('id', row.subject_id).maybeSingle());
  if (!admin || admin.status !== 'active') throw Object.assign(new Error('Session has been revoked.'), { status: 401 });
  const nextRefresh = randomBytes(48).toString('base64url');
  unwrap(await supabase.from('auth_sessions').update({ refresh_token_hash: refreshHash(nextRefresh), last_used_at: nowIso() }).eq('id', row.id).select('id').single());
  const token = await accessToken({ role: 'admin', subjectId: admin.id, sessionId: row.id, tokenVersion: row.token_version });
  return { role: 'admin' as const, token, refreshToken: nextRefresh, expiresAt: row.expires_at, email: admin.email };
}

export async function authenticate(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  try {
    const raw = req.headers.authorization;
    if (!raw?.startsWith('Bearer ')) throw Object.assign(new Error('Authentication required.'), { status: 401 });
    const { payload } = await jwtVerify(raw.slice(7), jwtKey, { algorithms: ['HS256'] });
    const role = payload.role as Role;
    const sessionId = String(payload.sid ?? '');
    const subjectId = String(payload.sub ?? '');
    const tokenVersion = Number(payload.ver ?? 0);
    if (!['admin', 'reader'].includes(role) || !sessionId || !subjectId) throw new Error('Malformed token.');
    const session = unwrap<any>(await supabase.from('auth_sessions').select('id,revoked_at,expires_at,token_version').eq('id', sessionId).maybeSingle());
    if (!session || session.revoked_at || session.expires_at <= nowIso() || session.token_version !== tokenVersion) {
      throw Object.assign(new Error('Session is no longer valid.'), { status: 401 });
    }
    req.principal = { role, subjectId, sessionId, tokenVersion };
    next();
  } catch (error) {
    next(Object.assign(error instanceof Error ? error : new Error('Invalid token.'), { status: 401 }));
  }
}

export function requireAdmin(req: AuthenticatedRequest, _res: Response, next: NextFunction) {
  if (req.principal?.role !== 'admin') return next(Object.assign(new Error('Administrator access required.'), { status: 403 }));
  next();
}

export async function revokeSession(sessionId: string) {
  unwrap(await supabase.from('auth_sessions').update({ revoked_at: nowIso() }).eq('id', sessionId).select('id').single());
}
