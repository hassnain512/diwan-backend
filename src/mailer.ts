import nodemailer from 'nodemailer';
import { config } from './config.js';

const transporter = config.SMTP_HOST
  ? nodemailer.createTransport({
      host: config.SMTP_HOST,
      port: config.SMTP_PORT,
      secure: config.SMTP_SECURE,
      auth: config.SMTP_USER && config.SMTP_PASS ? { user: config.SMTP_USER, pass: config.SMTP_PASS } : undefined
    })
  : null;

const otpEmailHtml = (code: string) => `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Kalam e Raza verification code</title>
  </head>
  <body style="margin:0;padding:0;background:#f3efe5;color:#24251f;font-family:Arial,Helvetica,sans-serif;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f3efe5;padding:32px 14px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:560px;background:#fffdf8;border:1px solid #ded7c7;border-radius:22px;overflow:hidden;box-shadow:0 10px 30px rgba(38,39,31,0.08);">
            <tr>
              <td style="height:7px;background:#666949;font-size:0;line-height:0;">&nbsp;</td>
            </tr>
            <tr>
              <td style="padding:34px 38px 16px;text-align:center;">
                <div style="display:inline-block;min-width:58px;height:58px;line-height:58px;border-radius:18px;background:#f0ede2;color:#666949;font-size:26px;font-weight:700;letter-spacing:1px;">R</div>
                <div style="margin-top:18px;font-size:14px;line-height:20px;letter-spacing:2.4px;text-transform:uppercase;color:#777363;font-weight:700;">Kalam e Raza</div>
                <h1 style="margin:12px 0 0;font-size:28px;line-height:36px;color:#24251f;font-weight:700;">Author verification</h1>
              </td>
            </tr>
            <tr>
              <td style="padding:10px 38px 0;">
                <p style="margin:0;text-align:center;font-size:16px;line-height:25px;color:#6f6b5f;">Use the verification code below to continue to your private author account.</p>
              </td>
            </tr>
            <tr>
              <td style="padding:28px 38px 24px;">
                <div style="border:1px solid #d9d2bf;border-radius:18px;background:#f8f5ec;padding:22px 18px;text-align:center;">
                  <div style="font-size:12px;line-height:18px;letter-spacing:1.8px;text-transform:uppercase;color:#827d6c;font-weight:700;">Verification code</div>
                  <div style="margin-top:10px;font-size:38px;line-height:48px;letter-spacing:10px;color:#55593c;font-weight:700;font-variant-numeric:tabular-nums;">${code}</div>
                  <div style="margin-top:10px;font-size:13px;line-height:20px;color:#8a8578;">Valid for ${config.OTP_TTL_MINUTES} minutes</div>
                </div>
              </td>
            </tr>
            <tr>
              <td style="padding:0 38px 34px;">
                <div style="border-top:1px solid #ebe5d8;padding-top:22px;">
                  <p style="margin:0;font-size:14px;line-height:22px;color:#6f6b5f;"><strong style="color:#3d3e34;">Security notice:</strong> Never share this code with anyone. Kalam e Raza will never ask for your verification code by phone, message, or email.</p>
                  <p style="margin:14px 0 0;font-size:14px;line-height:22px;color:#8a8578;">If you did not request this code, you can safely ignore this email. No changes will be made to your account.</p>
                </div>
              </td>
            </tr>
            <tr>
              <td style="padding:18px 30px;background:#f7f3e9;border-top:1px solid #e8e1d2;text-align:center;font-size:12px;line-height:19px;color:#969081;">Private poetry library · Secure author access</td>
            </tr>
          </table>
          <div style="max-width:560px;padding:18px 20px 0;text-align:center;font-size:11px;line-height:18px;color:#9b9588;">This is an automated security message from Kalam e Raza. Please do not reply.</div>
        </td>
      </tr>
    </table>
  </body>
</html>`;

export async function sendOtpEmail(email: string, code: string) {
  if (!transporter) {
    throw new Error('SMTP is not configured.');
  }
  await transporter.sendMail({
    from: config.SMTP_FROM,
    to: email,
    subject: 'Kalam e Raza · Your author verification code',
    text: [
      'Kalam e Raza — Author verification',
      '',
      `Your verification code is: ${code}`,
      `This code expires in ${config.OTP_TTL_MINUTES} minutes.`,
      '',
      'Never share this code with anyone. Kalam e Raza will never ask for it by phone, message, or email.',
      'If you did not request this code, you can safely ignore this email.'
    ].join('\n'),
    html: otpEmailHtml(code)
  });
}
