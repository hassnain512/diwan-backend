import 'dotenv/config';
import { createClient } from '@supabase/supabase-js';

const client = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, {
  auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false }
});
const result = await client.from('admin_accounts').select('id,status').limit(1);
console.log({
  tableRequest: result.error ? 'failed' : 'ok',
  status: result.status,
  errorCode: result.error?.code,
  errorMessage: result.error?.message,
  errorDetails: result.error?.details
});
