const nodemailer = require("nodemailer");

// Create reusable transporter using SMTP config from environment
let transporter = null;

function getTransporter() {
  if (transporter) return transporter;

  const host = process.env.SMTP_HOST;
  const port = parseInt(process.env.SMTP_PORT || "587", 10);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host || !user || !pass) {
    console.warn("[email] SMTP not configured. Verification codes will be logged to console only.");
    return null;
  }

  transporter = nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: { user, pass },
  });

  return transporter;
}

/**
 * Send a 6-digit verification code to the user's email.
 * Falls back to console logging if SMTP is not configured.
 */
async function sendVerificationCode(toEmail, code, username) {
  const sender = process.env.SMTP_FROM || process.env.SMTP_USER || "noreply@bloghub.local";

  const htmlBody = `
    <div style="font-family: 'Segoe UI', sans-serif; max-width: 480px; margin: 0 auto; padding: 32px; background: #f8f9fa; border-radius: 12px;">
      <div style="text-align: center; margin-bottom: 24px;">
        <h1 style="color: #1e3a5f; margin: 0 0 8px;">📝 Blog Hub</h1>
        <p style="color: #7f8c8d; margin: 0;">Email Verification</p>
      </div>
      <div style="background: #ffffff; border-radius: 8px; padding: 32px; box-shadow: 0 2px 8px rgba(0,0,0,0.08);">
        <p style="color: #2c3e50; font-size: 1rem; margin: 0 0 16px;">Hi <strong>${username || "there"}</strong>,</p>
        <p style="color: #555; font-size: 0.95rem; margin: 0 0 24px;">Use the code below to verify your email address. This code expires in <strong>15 minutes</strong>.</p>
        <div style="text-align: center; margin: 24px 0;">
          <div style="display: inline-block; background: linear-gradient(135deg, #1e3a5f, #2d5a8c); color: #ffffff; font-size: 2rem; font-weight: 700; letter-spacing: 8px; padding: 16px 32px; border-radius: 8px;">${code}</div>
        </div>
        <p style="color: #999; font-size: 0.85rem; margin: 16px 0 0; text-align: center;">If you didn't create an account on Blog Hub, you can safely ignore this email.</p>
      </div>
    </div>
  `;

  const transport = getTransporter();

  if (!transport) {
    // Fallback: log to console for development
    console.log("═══════════════════════════════════════════");
    console.log(`📧 VERIFICATION CODE for ${toEmail}`);
    console.log(`   Code: ${code}`);
    console.log("═══════════════════════════════════════════");
    return true;
  }

  try {
    await transport.sendMail({
      from: sender,
      to: toEmail,
      subject: `${code} is your Blog Hub verification code`,
      html: htmlBody,
    });
    console.log(`[email] Verification code sent to ${toEmail}`);
    return true;
  } catch (err) {
    console.error("[email] Failed to send verification email:", err.message);
    // Fallback to console so development isn't blocked
    console.log("═══════════════════════════════════════════");
    console.log(`📧 VERIFICATION CODE for ${toEmail} (email send failed)`);
    console.log(`   Code: ${code}`);
    console.log("═══════════════════════════════════════════");
    return false;
  }
}

module.exports = { sendVerificationCode };
