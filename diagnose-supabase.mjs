import 'dotenv/config';

const key = process.env.SUPABASE_SECRET_KEY || '';
console.log({
  urlProtocol: new URL(process.env.SUPABASE_URL).protocol,
  keyLength: key.length,
  keyPrefix: key.startsWith('sb_secret_') ? 'sb_secret' : key.startsWith('eyJ') ? 'jwt' : 'unexpected',
  hasWhitespace: /\s/.test(key),
  hasControl: /[\u0000-\u001f\u007f]/.test(key),
  hasQuotes: /['"]/.test(key)
});

try {
  const response = await fetch(`${process.env.SUPABASE_URL}/rest/v1/`, {
    headers: { apikey: key, Authorization: `Bearer ${key}` }
  });
  console.log({ status: response.status, body: (await response.text()).slice(0, 180) });
} catch (error) {
  console.error({ name: error.name, message: error.message, causeCode: error.cause?.code, causeMessage: error.cause?.message });
  process.exitCode = 1;
}
