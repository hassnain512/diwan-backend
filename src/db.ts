import { createClient } from '@supabase/supabase-js';
import { config } from './config.js';

export const supabase = createClient(config.SUPABASE_URL, config.SUPABASE_SECRET_KEY, {
  auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false }
});

export async function assertDatabaseReady() {
  unwrap(await supabase.from('admin_accounts').select('id').limit(1));
}

export function unwrap<T>(result: { data: T | null; error: { message: string; code?: string } | null }): T {
  if (result.error) {
    const schemaMissing = result.error.code === 'PGRST205';
    const message = schemaMissing
      ? 'Database schema is not installed. Apply every SQL file in supabase/migrations in filename order, then rerun npm run bootstrap.'
      : result.error.message;
    const error = new Error(message) as Error & { status?: number; code?: string };
    error.status = result.error.code === '23505' ? 409 : schemaMissing ? 503 : 500;
    error.code = result.error.code;
    throw error;
  }
  return result.data as T;
}

export const nowIso = () => new Date().toISOString();

export const toAuthor = (row: any) => ({
  authorName: row.author_name,
  authorNameUrdu: row.author_name_urdu,
  penNameUrdu: row.pen_name_urdu,
  email: row.email,
  biography: row.biography,
  introduction: row.introduction,
  profileImage: row.profile_image,
  updatedAt: row.updated_at
});

export const toBook = (row: any) => ({
  id: row.id,
  title: row.title,
  coverType: row.cover_type,
  coverUrl: row.cover_url ?? undefined,
  coverTheme: row.cover_theme ?? undefined,
  coverOrnament: row.cover_ornament ?? undefined,
  status: row.status,
  orderIndex: row.order_index,
  createdAt: row.created_at,
  updatedAt: row.updated_at
});

export const toWriting = (row: any) => ({
  id: row.id,
  bookId: row.book_id,
  title: row.title,
  content: row.content,
  status: row.status,
  orderIndex: row.order_index,
  createdAt: row.created_at,
  updatedAt: row.updated_at
});

export const toReader = (row: any) => ({
  id: row.id,
  fullName: row.full_name,
  username: row.username,
  status: row.status,
  deviceId: row.device_id,
  deviceName: row.device_name,
  lastLogin: row.last_login_at,
  createdAt: row.created_at,
  updatedAt: row.updated_at
});

export const authorToRow = (value: any) => ({
  id: 1,
  author_name: value.authorName,
  author_name_urdu: value.authorNameUrdu,
  pen_name_urdu: value.penNameUrdu,
  email: value.email,
  biography: value.biography ?? '',
  introduction: value.introduction ?? '',
  profile_image: value.profileImage ?? '',
  updated_at: value.updatedAt ?? nowIso()
});

export const bookToRow = (value: any) => ({
  id: value.id,
  title: value.title,
  cover_type: value.coverType ?? 'generated',
  cover_url: value.coverUrl ?? null,
  cover_theme: value.coverTheme ?? null,
  cover_ornament: value.coverOrnament ?? null,
  status: value.status ?? 'draft',
  order_index: value.orderIndex ?? 0,
  created_at: value.createdAt ?? nowIso(),
  updated_at: value.updatedAt ?? nowIso()
});

export const writingToRow = (value: any) => ({
  id: value.id,
  book_id: value.bookId,
  title: value.title,
  content: value.content ?? '',
  status: value.status ?? 'draft',
  order_index: value.orderIndex ?? 0,
  created_at: value.createdAt ?? nowIso(),
  updated_at: value.updatedAt ?? nowIso()
});



