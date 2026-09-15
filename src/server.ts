import { createHmac, randomInt, randomUUID } from 'node:crypto';
import argon2 from 'argon2';
import cors from 'cors';
import express, { type NextFunction, type Request, type RequestHandler, type Response } from 'express';
import { rateLimit } from 'express-rate-limit';
import * as helmetModule from 'helmet';
import multer from 'multer';
import sanitizeHtml from 'sanitize-html';
import { z } from 'zod';
import { authenticate, issueSession, requireAdmin, revokeSession, rotateSession, type AuthenticatedRequest } from './auth.js';
import { config } from './config.js';
import { assertDatabaseReady, authorToRow, bookToRow, nowIso, supabase, toAuthor, toBook, toReader, toWriting, unwrap, writingToRow } from './db.js';
import { sendOtpEmail } from './mailer.js';

const app = express();
const createHelmetMiddleware = helmetModule.default as unknown as () => RequestHandler;
app.set('trust proxy', config.TRUST_PROXY);
app.disable('x-powered-by');
app.use(createHelmetMiddleware());
app.use(cors({ origin(origin, callback) {
  if (!origin || config.corsAllowAll || config.corsOrigins.includes(origin)) return callback(null, true);
  callback(new Error('Origin is not allowed.'));
}}));
app.use(express.json({ limit: '2mb' }));
app.use((req, res, next) => {
  const supplied = req.get('x-request-id');
  const traceId = supplied && /^[A-Za-z0-9._:-]{1,80}$/.test(supplied) ? supplied : randomUUID();
  req.headers['x-request-id'] = traceId;
  res.setHeader('X-Request-ID', traceId);
  next();
});

const authLimiter = rateLimit({ windowMs: 15 * 60_000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false });
const otpLimiter = rateLimit({ windowMs: 15 * 60_000, limit: 5, standardHeaders: 'draft-8', legacyHeaders: false });
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 6 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, callback) => callback(null, ['image/jpeg', 'image/png', 'image/webp'].includes(file.mimetype))
});

const asyncRoute = (handler: (req: AuthenticatedRequest, res: Response) => Promise<unknown>) =>
  (req: Request, res: Response, next: NextFunction) => Promise.resolve(handler(req as AuthenticatedRequest, res)).catch(next);
const parse = <T>(schema: z.ZodType<T>, value: unknown): T => {
  const result = schema.safeParse(value);
  if (!result.success) throw Object.assign(new Error(z.prettifyError(result.error)), { status: 400, code: 'VALIDATION_ERROR' });
  return result.data;
};
const id = (prefix: string) => `${prefix}_${randomUUID()}`;
const DUMMY_PASSWORD_HASH = '$argon2id$v=19$m=65536,t=3,p=4$2CGTI6Frn64UQUNcSrRuSQ$zLoANs+YV2HubrCKAgutDOyPqZMLO7GJ9Lg/S1EFpQI';
const otpHash = (email: string, code: string) => createHmac('sha256', config.OTP_PEPPER).update(`${email}:${code}`).digest('hex');
const audit = async (req: AuthenticatedRequest, action: string, entityType?: string, entityId?: string, metadata: object = {}) => {
  await supabase.from('audit_logs').insert({ actor_type: req.principal?.role, actor_id: req.principal?.subjectId, action, entity_type: entityType, entity_id: entityId, metadata });
};
const cleanPoetry = (html: string) => sanitizeHtml(html, {
  allowedTags: ['div', 'p', 'br', 'strong', 'b', 'em', 'i', 'u', 'blockquote', 'hr'],
  allowedAttributes: { div: ['dir', 'class'] },
  allowedClasses: { div: ['poetry-container', 'text-center', 'poetry-divider'] }
});

const remoteImageUrl = z.string().max(2048).refine(value => value === '' || /^https?:\/\//i.test(value), 'Image must be an HTTP(S) URL.');
const isoDate = z.string().datetime({ offset: true });

const bookInput = z.object({
  id: z.string().min(1).max(120).optional(), title: z.string().trim().min(1).max(300),
  coverType: z.enum(['generated', 'custom']).optional(), coverUrl: remoteImageUrl.nullish(),
  coverTheme: z.string().max(80).nullish(), coverOrnament: z.string().max(80).nullish(),
  status: z.enum(['draft', 'coming_soon', 'published']), orderIndex: z.number().int().min(0).optional(),
  createdAt: isoDate.optional(), updatedAt: isoDate.optional()
});
const writingInput = z.object({
  id: z.string().min(1).max(120).optional(), bookId: z.string().min(1).max(120).optional(),
  title: z.string().trim().min(1).max(300), content: z.string().max(1_000_000),
  status: z.enum(['draft', 'published']), orderIndex: z.number().int().min(0).optional(),
  createdAt: isoDate.optional(), updatedAt: isoDate.optional()
});
const authorInput = z.object({
  authorName: z.string().trim().min(1).max(160).optional(), authorNameUrdu: z.string().trim().min(1).max(160).optional(),
  penNameUrdu: z.string().trim().min(1).max(160).optional(), email: z.string().email().optional(),
  biography: z.string().max(100_000).optional(), introduction: z.string().max(100_000).optional(),
  profileImage: remoteImageUrl.optional(), updatedAt: isoDate.optional()
});

app.get('/', (_req, res) => {
  res.json({ service: 'diwan-api', status: 'ok', time: nowIso() });
});

app.get('/favicon.ico', (_req, res) => res.status(204).end());

app.get('/health', asyncRoute(async (_req, res) => {
  try {
    unwrap(await supabase.from('author_profile').select('id').limit(1));
    res.json({ ok: true, database: 'connected', time: nowIso() });
  } catch (error) {
    console.error('Health check failed:', error);
    res.status(503).json({ ok: false, database: 'unreachable', time: nowIso() });
  }
}));

app.post('/api/auth/admin/send-otp', otpLimiter, asyncRoute(async (req, res) => {
  const { email } = parse(z.object({ email: z.string().email() }), req.body);
  const normalized = email.toLowerCase();
  const admin = unwrap<any>(await supabase.from('admin_accounts').select('id,status').eq('email', normalized).maybeSingle());
  if (normalized === config.ADMIN_EMAIL && !admin) {
    unwrap(await supabase.from('admin_accounts').insert({ email: normalized }).select('id').single());
  } else if (!admin || admin.status !== 'active') {
    return res.json({ success: true });
  }
  const recent = unwrap<any>(await supabase.from('otp_challenges').select('created_at').eq('email', normalized).order('created_at', { ascending: false }).limit(1).maybeSingle());
  if (recent && Date.now() - new Date(recent.created_at).getTime() < 60_000) return res.json({ success: true });
  const code = String(randomInt(100000, 1_000_000));
  await supabase.from('otp_challenges').delete().eq('email', normalized).is('consumed_at', null);
  const challenge = unwrap<any>(await supabase.from('otp_challenges').insert({
    email: normalized,
    code_hash: otpHash(normalized, code),
    expires_at: new Date(Date.now() + config.OTP_TTL_MINUTES * 60_000).toISOString()
  }).select('id').single());
  try { await sendOtpEmail(normalized, code); }
  catch (error) { await supabase.from('otp_challenges').delete().eq('id', challenge.id); throw error; }
  res.json({ success: true });
}));

app.post('/api/auth/admin/verify-otp', authLimiter, asyncRoute(async (req, res) => {
  const { email, otp } = parse(z.object({ email: z.string().email(), otp: z.string().regex(/^\d{6}$/) }), req.body);
  const normalized = email.toLowerCase();
  const consumed = unwrap<boolean>(await supabase.rpc('consume_admin_otp', { p_email: normalized, p_code_hash: otpHash(normalized, otp) }));
  if (!consumed) throw Object.assign(new Error('The verification code is invalid or expired.'), { status: 401 });
  const admin = unwrap<any>(await supabase.from('admin_accounts').select('id,email,status').eq('email', normalized).single());
  if (admin.status !== 'active') throw Object.assign(new Error('This account is inactive.'), { status: 403 });
  res.json(await issueSession('admin', admin.id, 0, { email: admin.email }));
}));

app.post('/api/auth/reader/login', authLimiter, asyncRoute(async (req, res) => {
  const input = parse(z.object({ username: z.string().trim().min(3).max(64), password: z.string().min(8).max(256), deviceId: z.string().min(8).max(200), deviceName: z.string().max(160) }), req.body);
  const reader = unwrap<any>(await supabase.from('readers').select('*').eq('username', input.username.toLowerCase()).maybeSingle());
  const passwordValid = await argon2.verify(reader?.password_hash ?? DUMMY_PASSWORD_HASH, input.password);
  if (!reader || !passwordValid) throw Object.assign(new Error('Incorrect username or password.'), { status: 401 });
  if (reader.status !== 'active') throw Object.assign(new Error('This reader account is inactive.'), { status: 403 });
  const claimed = await supabase.rpc('claim_reader_device', { p_reader_id: reader.id, p_device_id: input.deviceId, p_device_name: input.deviceName });
  if (claimed.error?.message.includes('DEVICE_LOCKED')) throw Object.assign(new Error('This account is already active on another device.'), { status: 409, code: 'DEVICE_LOCKED' });
  const current = unwrap<any>(claimed as any);
  res.json(await issueSession('reader', reader.id, current.token_version, { username: current.username, fullName: current.full_name, deviceId: current.device_id }));
}));

app.post('/api/auth/refresh', authLimiter, asyncRoute(async (req, res) => {
  const { refreshToken } = parse(z.object({ refreshToken: z.string().min(32) }), req.body);
  res.json(await rotateSession(refreshToken));
}));

app.post('/api/auth/reader/logout', authenticate, asyncRoute(async (req, res) => {
  await revokeSession(req.principal!.sessionId);
  res.json({ success: true });
}));

app.get('/api/author', authenticate, asyncRoute(async (_req, res) => {
  const row = unwrap<any>(await supabase.from('author_profile').select('*').eq('id', 1).maybeSingle());
  if (!row) throw Object.assign(new Error('Author profile is not configured.'), { status: 404 });
  res.json(toAuthor(row));
}));

app.put('/api/author', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  const updates = parse(authorInput, req.body);
  const current = unwrap<any>(await supabase.from('author_profile').select('*').eq('id', 1).single());
  const merged = { ...toAuthor(current), ...updates, updatedAt: nowIso() };
  const row = unwrap<any>(await supabase.from('author_profile').upsert(authorToRow(merged)).select('*').single());
  await audit(req, 'author.update', 'author', '1');
  res.json(toAuthor(row));
}));

app.get('/api/books', authenticate, asyncRoute(async (req, res) => {
  let query = supabase.from('books').select('*').order('order_index');
  if (req.principal!.role === 'reader') query = query.in('status', ['published', 'coming_soon']);
  res.json(unwrap<any[]>(await query).map(toBook));
}));

app.post('/api/books', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  const input = parse(bookInput, req.body);
  const count = unwrap<any[]>(await supabase.from('books').select('id'))?.length ?? 0;
  const stamp = nowIso();
  const row = unwrap<any>(await supabase.from('books').insert(bookToRow({ ...input, id: input.id ?? id('book'), orderIndex: input.orderIndex ?? count, createdAt: stamp, updatedAt: stamp })).select('*').single());
  await audit(req, 'book.create', 'book', row.id);
  res.status(201).json(toBook(row));
}));

app.put('/api/books/:id', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  const input = parse(bookInput.partial(), req.body);
  const current = unwrap<any>(await supabase.from('books').select('*').eq('id', req.params.id).single());
  const row = unwrap<any>(await supabase.from('books').update(bookToRow({ ...toBook(current), ...input, id: current.id, updatedAt: nowIso() })).eq('id', current.id).select('*').single());
  await audit(req, 'book.update', 'book', row.id);
  res.json(toBook(row));
}));

app.delete('/api/books/:id', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  unwrap(await supabase.from('books').delete().eq('id', req.params.id).select('id').single());
  await audit(req, 'book.delete', 'book', String(req.params.id));
  res.status(204).end();
}));

app.get('/api/books/:bookId/writings', authenticate, asyncRoute(async (req, res) => {
  if (req.principal!.role === 'reader') {
    const book = unwrap<any>(await supabase.from('books').select('status').eq('id', req.params.bookId).maybeSingle());
    if (!book || book.status !== 'published') return res.json([]);
  }
  let query = supabase.from('writings').select('*').eq('book_id', req.params.bookId).order('order_index');
  if (req.principal!.role === 'reader') query = query.eq('status', 'published');
  res.json(unwrap<any[]>(await query).map(toWriting));
}));

app.post('/api/books/:bookId/writings', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  const input = parse(writingInput, req.body);
  const existing = unwrap<any[]>(await supabase.from('writings').select('id').eq('book_id', req.params.bookId));
  const stamp = nowIso();
  const row = unwrap<any>(await supabase.from('writings').insert(writingToRow({ ...input, id: input.id ?? id('writing'), bookId: req.params.bookId, content: cleanPoetry(input.content), orderIndex: input.orderIndex ?? existing.length, createdAt: stamp, updatedAt: stamp })).select('*').single());
  await audit(req, 'writing.create', 'writing', row.id);
  res.status(201).json(toWriting(row));
}));

app.put('/api/writings/:id', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  const input = parse(writingInput.partial(), req.body);
  const current = unwrap<any>(await supabase.from('writings').select('*').eq('id', req.params.id).single());
  const merged = { ...toWriting(current), ...input, id: current.id, updatedAt: nowIso() };
  if (input.content !== undefined) merged.content = cleanPoetry(input.content);
  const row = unwrap<any>(await supabase.from('writings').update(writingToRow(merged)).eq('id', current.id).select('*').single());
  await audit(req, 'writing.update', 'writing', row.id);
  res.json(toWriting(row));
}));

app.delete('/api/writings/:id', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  unwrap(await supabase.from('writings').delete().eq('id', req.params.id).select('id').single());
  await audit(req, 'writing.delete', 'writing', String(req.params.id));
  res.status(204).end();
}));

app.put('/api/books/:bookId/reorder-writings', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  const { orderedIds } = parse(z.object({ orderedIds: z.array(z.string().min(1)).max(10_000) }), req.body);
  unwrap(await supabase.rpc('reorder_writings', { p_book_id: req.params.bookId, p_ordered_ids: orderedIds }));
  await audit(req, 'writings.reorder', 'book', String(req.params.bookId));
  res.status(204).end();
}));

app.get('/api/readers', authenticate, requireAdmin, asyncRoute(async (_req, res) => {
  res.json(unwrap<any[]>(await supabase.from('readers').select('*').order('created_at')).map(toReader));
}));

app.post('/api/readers', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  const input = parse(z.object({ fullName: z.string().trim().min(1).max(160), username: z.string().trim().min(3).max(64), password: z.string().min(8).max(256) }), req.body);
  const row = unwrap<any>(await supabase.from('readers').insert({ id: id('reader'), full_name: input.fullName, username: input.username.toLowerCase(), password_hash: await argon2.hash(input.password, { type: argon2.argon2id }), status: 'active' }).select('*').single());
  await audit(req, 'reader.create', 'reader', row.id);
  res.status(201).json(toReader(row));
}));

app.put('/api/readers/:id', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  const input = parse(z.object({ fullName: z.string().trim().min(1).max(160).optional(), username: z.string().trim().min(3).max(64).optional(), password: z.string().min(8).max(256).optional(), status: z.enum(['active', 'inactive']).optional(), deviceId: z.string().max(200).nullable().optional(), deviceName: z.string().max(160).nullable().optional() }), req.body);
  const updates: any = { updated_at: nowIso() };
  if (input.fullName !== undefined) updates.full_name = input.fullName;
  if (input.username !== undefined) updates.username = input.username.toLowerCase();
  if (input.status !== undefined) updates.status = input.status;
  if (input.deviceId !== undefined) updates.device_id = input.deviceId;
  if (input.deviceName !== undefined) updates.device_name = input.deviceName;
  const invalidateSessions = input.password !== undefined || input.status === 'inactive';
  if (input.password !== undefined) updates.password_hash = await argon2.hash(input.password, { type: argon2.argon2id });
  if (invalidateSessions) {
    const current = unwrap<any>(await supabase.from('readers').select('token_version').eq('id', req.params.id).single());
    updates.token_version = current.token_version + 1;
  }
  const row = unwrap<any>(await supabase.from('readers').update(updates).eq('id', req.params.id).select('*').single());
  if (invalidateSessions) await supabase.from('auth_sessions').update({ revoked_at: nowIso() }).eq('subject_type', 'reader').eq('subject_id', req.params.id).is('revoked_at', null);
  await audit(req, 'reader.update', 'reader', row.id);
  res.json(toReader(row));
}));

app.post('/api/readers/:id/reset-device', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  const current = unwrap<any>(await supabase.from('readers').select('token_version').eq('id', req.params.id).single());
  unwrap(await supabase.from('readers').update({ device_id: null, device_name: null, token_version: current.token_version + 1, updated_at: nowIso() }).eq('id', req.params.id).select('id').single());
  await supabase.from('auth_sessions').update({ revoked_at: nowIso() }).eq('subject_type', 'reader').eq('subject_id', req.params.id).is('revoked_at', null);
  await audit(req, 'reader.reset_device', 'reader', String(req.params.id));
  res.status(204).end();
}));

app.delete('/api/readers/:id', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  await supabase.from('auth_sessions').update({ revoked_at: nowIso() }).eq('subject_type', 'reader').eq('subject_id', req.params.id);
  unwrap(await supabase.from('readers').delete().eq('id', req.params.id).select('id').single());
  await audit(req, 'reader.delete', 'reader', String(req.params.id));
  res.status(204).end();
}));

app.post('/api/media/upload', authenticate, requireAdmin, upload.single('file'), asyncRoute(async (req, res) => {
  if (!req.file) throw Object.assign(new Error('A JPEG, PNG, or WebP image is required.'), { status: 400 });
  const kind = req.body.kind === 'profile' ? 'profiles' : 'covers';
  const extension = ({ 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' } as Record<string, string>)[req.file.mimetype];
  const path = `${kind}/${Date.now()}-${randomUUID()}.${extension}`;
  unwrap(await supabase.storage.from(config.SUPABASE_STORAGE_BUCKET).upload(path, req.file.buffer, { contentType: req.file.mimetype, upsert: false }));
  const { data } = supabase.storage.from(config.SUPABASE_STORAGE_BUCKET).getPublicUrl(path);
  res.status(201).json({ path, url: data.publicUrl });
}));

async function applyOutboxOperation(operation: any) {
  const payload = operation.payload ?? {};
  if (operation.entityType === 'author' && operation.operation === 'upsert') {
    const incoming = parse(authorInput, payload);
    const current = unwrap<any>(await supabase.from('author_profile').select('updated_at').eq('id', 1).maybeSingle());
    if (!current || !incoming.updatedAt || current.updated_at <= incoming.updatedAt) unwrap(await supabase.from('author_profile').upsert(authorToRow(incoming)));
  } else if (operation.entityType === 'book') {
    if (operation.operation === 'delete') {
      const current = unwrap<any>(await supabase.from('books').select('updated_at').eq('id', operation.entityId).maybeSingle());
      if (!current || current.updated_at <= operation.updatedAt) unwrap(await supabase.from('books').delete().eq('id', operation.entityId));
    } else {
      const incoming = parse(bookInput.extend({ id: z.string().min(1) }), payload);
      const current = unwrap<any>(await supabase.from('books').select('updated_at').eq('id', incoming.id).maybeSingle());
      if (!current || !incoming.updatedAt || current.updated_at <= incoming.updatedAt) unwrap(await supabase.from('books').upsert(bookToRow(incoming)));
    }
  } else if (operation.entityType === 'writing') {
    if (operation.operation === 'delete') {
      const current = unwrap<any>(await supabase.from('writings').select('updated_at').eq('id', operation.entityId).maybeSingle());
      if (!current || current.updated_at <= operation.updatedAt) unwrap(await supabase.from('writings').delete().eq('id', operation.entityId));
    } else {
      const incoming = parse(writingInput.extend({ id: z.string().min(1), bookId: z.string().min(1) }), payload);
      incoming.content = cleanPoetry(incoming.content);
      const current = unwrap<any>(await supabase.from('writings').select('updated_at').eq('id', incoming.id).maybeSingle());
      if (!current || !incoming.updatedAt || current.updated_at <= incoming.updatedAt) unwrap(await supabase.from('writings').upsert(writingToRow(incoming)));
    }
  } else {
    throw Object.assign(new Error(`Unsupported sync entity: ${operation.entityType}`), { status: 400 });
  }
}

app.post('/api/sync/push', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  const { operations } = parse(z.object({ operations: z.array(z.object({ id: z.number().int().positive(), entityType: z.enum(['author', 'book', 'writing']), entityId: z.string().min(1), operation: z.enum(['upsert', 'delete']), payload: z.unknown(), updatedAt: isoDate })).max(500) }), req.body);
  const acceptedIds: number[] = [];
  for (const operation of operations) { await applyOutboxOperation(operation); acceptedIds.push(operation.id); }
  await audit(req, 'sync.push', undefined, undefined, { count: acceptedIds.length });
  res.json({ acceptedIds });
}));

app.get('/api/sync', authenticate, asyncRoute(async (req, res) => {
  const since = parse(z.coerce.number().int().min(0), req.query.since ?? 0);
  const changes = unwrap<any[]>(await supabase.from('sync_changes').select('*').gt('cursor', since).order('cursor').limit(1000));
  const publishedBooks = req.principal!.role === 'reader'
    ? new Set(unwrap<any[]>(await supabase.from('books').select('id').eq('status', 'published')).map(row => row.id))
    : null;
  const visible = changes.filter(change => {
    if (req.principal!.role === 'admin' || change.operation === 'delete' || change.entity_type === 'author') return true;
    if (change.entity_type === 'book') return ['published', 'coming_soon'].includes(change.payload?.status);
    return change.payload?.status === 'published' && publishedBooks!.has(change.payload?.book_id);
  });
  const mapped = visible.map(change => ({
    cursor: Number(change.cursor), entityType: change.entity_type, entityId: change.entity_id, operation: change.operation,
    payload: change.operation === 'delete' ? null : change.entity_type === 'author' ? toAuthor(change.payload) : change.entity_type === 'book' ? toBook(change.payload) : toWriting(change.payload)
  }));
  res.json({ changes: mapped, cursor: changes.length ? Number(changes[changes.length - 1]!.cursor) : since, hasMore: changes.length === 1000 });
}));

app.get('/api/backup/export', authenticate, requireAdmin, asyncRoute(async (_req, res) => {
  const [author, books, writings, readers] = await Promise.all([
    supabase.from('author_profile').select('*').eq('id', 1).single(), supabase.from('books').select('*').order('order_index'),
    supabase.from('writings').select('*').order('book_id').order('order_index'), supabase.from('readers').select('*').order('created_at')
  ]);
  res.json({ version: '2.0', timestamp: nowIso(), authorProfile: toAuthor(unwrap<any>(author)), books: unwrap<any[]>(books).map(toBook), writings: unwrap<any[]>(writings).map(toWriting), readers: unwrap<any[]>(readers).map(toReader) });
}));

app.post('/api/backup/restore', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  const snapshot = parse(z.object({ authorProfile: authorInput.required(), books: z.array(bookInput.extend({ id: z.string().min(1), createdAt: isoDate, updatedAt: isoDate })).max(10_000), writings: z.array(writingInput.extend({ id: z.string().min(1), bookId: z.string().min(1), createdAt: isoDate, updatedAt: isoDate })).max(100_000) }), req.body);
  const author = authorToRow(snapshot.authorProfile);
  const books = snapshot.books.map(bookToRow);
  const writings = snapshot.writings.map(value => writingToRow({ ...value, content: cleanPoetry(value.content) }));
  unwrap(await supabase.rpc('restore_library_snapshot', { p_author: author, p_books: books, p_writings: writings }));
  await audit(req, 'backup.restore', undefined, undefined, { books: books.length, writings: writings.length });
  res.json({ success: true });
}));

app.use((req, res) => res.status(404).json({ error: 'Route not found.', code: 'NOT_FOUND', requestId: req.get('x-request-id') }));
app.use((error: any, req: Request, res: Response, _next: NextFunction) => {
  const status = Number(error.status) || (error.code === 'LIMIT_FILE_SIZE' ? 413 : 500);
  if (status >= 500) console.error(error);
  res.status(status).json({ error: status >= 500 && config.NODE_ENV === 'production' ? 'Internal server error.' : error.message, code: error.code, requestId: req.get('x-request-id') });
});

export { app };

async function startServer() {
  await assertDatabaseReady();
  const server = app.listen(config.PORT, () => console.info(`Diwan API listening on port ${config.PORT}`));
  server.requestTimeout = 30_000;
  server.headersTimeout = 35_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 100;
  const shutdown = () => server.close(() => process.exit(0));
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

if (!process.env.VERCEL) {
  void startServer().catch((error: Error) => {
    console.error(`Diwan API startup failed: ${error.message}`);
    process.exitCode = 1;
  });
}
