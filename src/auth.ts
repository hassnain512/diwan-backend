import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { compactVerify, decodeJwt, errors as joseErrors, jwtVerify, SignJWT } from 'jose';
import { config } from './config.js';
import { nowIso, supabase, unwrap } from './db.js';

export type Role = 'admin' | 'reader';
export type Principal = { role: Role; subjectId: string; sessionId: string; tokenVersion: number };
export type AuthenticatedRequest = Request & { principal?: Principal };

const jwtKey = new TextEncoder().encode(config.JWT_SECRET);
const refreshHash = (token: string) => createHash('sha256').update(token).digest('hex');

async function accessToken(principal: Principal, expiresAt: string) {
  const expiration = Math.floor(new Date(expiresAt).getTime() / 1000);
  return new SignJWT({ role: principal.role, sid: principal.sessionId, ver: principal.tokenVersion })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(principal.subjectId)
    .setIssuedAt()
    // Keep the JWT lifetime aligned with the session lifetime returned as expiresAt.
    // The mobile app already persists expiresAt, so these two values must describe
    // the same usable authentication lifetime.
    .setExpirationTime(expiration)
    .sign(jwtKey);
}

async function verifyAccessToken(token: string) {
  try {
    return (await jwtVerify(token, jwtKey, { algorithms: ['HS256'] })).payload;
  } catch (error) {
    // Compatibility path for access tokens issued before this fix. Those tokens
    // were signed for 15 minutes even though the API returned the 30-day session
    // expiry in expiresAt. Verify the signature but let the database-backed
    // session expiry below remain authoritative. This can be removed after all
    // pre-fix sessions have naturally expired.
    if (!(error instanceof joseErrors.JWTExpired)) throw error;
    await compactVerify(token, jwtKey, { algorithms: ['HS256'] });
    return decodeJwt(token);
  }
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
  const token = await accessToken({ role, subjectId, sessionId, tokenVersion }, expiresAt);
  return { role, token, refreshToken, expiresAt, ...details };
}


async function touchRefreshSession(sessionId: string, presentedHash: string) {
  const touched = unwrap<any>(await supabase.from('auth_sessions')
    .update({ last_used_at: nowIso() })
    .eq('id', sessionId)
    .eq('refresh_token_hash', presentedHash)
    .is('revoked_at', null)
    .gt('expires_at', nowIso())
    .select('id')
    .maybeSingle());
  if (!touched) {
    throw Object.assign(new Error('Refresh token is no longer valid.'), { status: 401 });
  }
}


export async function rotateSession(refreshToken: string) {
  const presentedHash = refreshHash(refreshToken);
  const row = unwrap<any>(await supabase.from('auth_sessions').select('*')
    .eq('refresh_token_hash', presentedHash).is('revoked_at', null).gt('expires_at', nowIso()).maybeSingle());
  if (!row) throw Object.assign(new Error('Invalid or expired refresh token.'), { status: 401 });

  if (row.subject_type === 'reader') {
    const reader = unwrap<any>(await supabase.from('readers').select('id,username,full_name,status,device_id,token_version').eq('id', row.subject_id).maybeSingle());
    if (!reader || reader.status !== 'active' || reader.token_version !== row.token_version) throw Object.assign(new Error('Session has been revoked.'), { status: 401 });
    // Keep the same refresh token for the lifetime of this session. The previous
    // one-time rotation made concurrent startup refreshes race each other and
    // broke clients that had not persisted the replacement token yet.
    await touchRefreshSession(row.id, presentedHash);
    const token = await accessToken({ role: 'reader', subjectId: reader.id, sessionId: row.id, tokenVersion: row.token_version }, row.expires_at);
    return { role: 'reader' as const, token, refreshToken, expiresAt: row.expires_at, username: reader.username, fullName: reader.full_name, deviceId: reader.device_id };
  }

  const admin = unwrap<any>(await supabase.from('admin_accounts').select('id,email,status').eq('id', row.subject_id).maybeSingle());
  if (!admin || admin.status !== 'active') throw Object.assign(new Error('Session has been revoked.'), { status: 401 });
  await touchRefreshSession(row.id, presentedHash);
  const token = await accessToken({ role: 'admin', subjectId: admin.id, sessionId: row.id, tokenVersion: row.token_version }, row.expires_at);
  return { role: 'admin' as const, token, refreshToken, expiresAt: row.expires_at, email: admin.email };
}

export async function authenticate(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  try {
    const raw = req.headers.authorization;
    if (!raw?.startsWith('Bearer ')) throw Object.assign(new Error('Authentication required.'), { status: 401 });
    const payload = await verifyAccessToken(raw.slice(7));
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
