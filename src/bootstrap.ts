import { config } from './config.js';
import { assertDatabaseReady, supabase, unwrap } from './db.js';

async function bootstrap() {
  await assertDatabaseReady();
  const stamp = new Date().toISOString();

  unwrap(await supabase
    .from('admin_accounts')
    .upsert({ email: config.ADMIN_EMAIL, status: 'active', updated_at: stamp }, { onConflict: 'email' })
    .select('id')
    .single());

  const existing = unwrap<any>(await supabase.from('author_profile').select('id').eq('id', 1).maybeSingle());
  if (!existing) {
    unwrap(await supabase.from('author_profile').insert({
      id: 1,
      author_name: 'Hassnain Raza Maitla',
      author_name_urdu: 'حسنین رضا میتلا',
      pen_name_urdu: 'رضاؔ',
      email: config.ADMIN_EMAIL,
      biography: '',
      introduction: '',
      profile_image: '',
      updated_at: stamp
    }).select('id').single());
  }

  console.info(`Bootstrapped active administrator ${config.ADMIN_EMAIL} and author profile.`);
}

void bootstrap().catch((error: Error) => {
  console.error(`Bootstrap failed: ${error.message}`);
  process.exitCode = 1;
});
