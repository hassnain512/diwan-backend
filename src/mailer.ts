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

export async function sendOtpEmail(email: string, code: string) {
  if (!transporter) {
    throw new Error('SMTP is not configured.');
  }
  await transporter.sendMail({
    from: config.SMTP_FROM,
    to: email,
    subject: 'Your Hurriyat verification code',
    text: `Your Hurriyat verification code is ${code}. It expires in ${config.OTP_TTL_MINUTES} minutes.`,
    html: `<p>Your Hurriyat verification code is <strong>${code}</strong>.</p><p>It expires in ${config.OTP_TTL_MINUTES} minutes.</p>`
  });
}
