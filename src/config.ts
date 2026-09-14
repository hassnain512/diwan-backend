import 'dotenv/config';
import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(5003),
  TRUST_PROXY: z.coerce.number().int().min(0).max(10).default(1),
  SUPABASE_URL: z.string().url().refine(value => /^https:\/\//i.test(value), 'SUPABASE_URL must be the HTTPS project API URL, not a PostgreSQL connection string.'),
  SUPABASE_SECRET_KEY: z.string().min(20).refine(value => !/replace|your[-_]/i.test(value), 'Set the real server-side Supabase secret key.'),
  SUPABASE_STORAGE_BUCKET: z.string().min(1).default('diwan-media'),
  JWT_SECRET: z.string().min(32).refine(value => !/replace|your[-_]/i.test(value), 'Generate a real JWT secret.'),
  OTP_PEPPER: z.string().min(32).refine(value => !/replace|your[-_]/i.test(value), 'Generate a real OTP pepper.'),
  ADMIN_EMAIL: z.string().email(),
  OTP_TTL_MINUTES: z.coerce.number().int().min(2).max(30).default(10),
  OTP_DEV_EXPOSE: z.string().default('false').transform(value => value === 'true'),
  CORS_ORIGINS: z.string().default(''),
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().int().default(587),
  SMTP_SECURE: z.string().default('false').transform(value => value === 'true'),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  SMTP_FROM: z.string().default('Diwan <no-reply@example.com>')
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  console.error('Invalid server environment:', z.treeifyError(parsed.error));
  process.exit(1);
}

export const config = {
  ...parsed.data,
  ADMIN_EMAIL: parsed.data.ADMIN_EMAIL.toLowerCase(),
  corsOrigins: parsed.data.CORS_ORIGINS.split(',').map(value => value.trim()).filter(Boolean)
};

