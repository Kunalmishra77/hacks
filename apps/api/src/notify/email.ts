// SMTP email sender, loaded lazily so nodemailer is only needed when email
// alerts are configured. Returns undefined when SMTP_URL isn't set.

export async function createEmailSender(
  smtpUrl: string | undefined,
  from: string | undefined,
): Promise<((to: string, subject: string, text: string) => Promise<void>) | undefined> {
  if (!smtpUrl) return undefined;
  const { createTransport } = await import("nodemailer");
  const transport = createTransport(smtpUrl);
  const sender = from ?? "Aegis ASM <no-reply@aegis.local>";
  return async (to, subject, text) => {
    await transport.sendMail({ from: sender, to, subject, text });
  };
}
