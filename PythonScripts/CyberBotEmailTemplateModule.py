"""CyberBot HTML email templates (stdlib-only; no external images or scripts).
This Module is credited to GPT-6 Astra, I am not a front end guy so I lacked HTML skills!
You are free to redesign the email template as you wished!"""


from __future__ import annotations

from html import escape
from pathlib import Path
from CyberBotRuntimeModule import ROOT_DIR

CYBERBOT_EMAIL_LOGO_PATH = Path(str(ROOT_DIR / "Files" / "Pictures" / "CyberBotEmailLogo.png"))


def getCyberbotEmailLogoBytes() -> bytes:
    """Read the email-optimized CyberBot crest for inline MIME embedding."""
    return CYBERBOT_EMAIL_LOGO_PATH.read_bytes()

def buildCyberbotHTMLEmail(subject: str, user_discord_name: str, logoCID: str = "cyberbot-logo", otp: str="", otp_expiry: int=0) -> str:
    """Build email-safe HTML. Secrets stay TEXT, not part of the logo graphic.

    Args:
        subject: Existing sendEmail() subject string.
        user_discord_name: User discord name.
        logoCID: Content-ID WITHOUT angle brackets; add_related() attaches the PNG.
        otp: The one-time-token if any
        otp_expiry: One-time-token expiry time in seconds.
    """
    heading = subject
    if subject == "Email Verification Code":
        description = "Use this one-time token to verify your CyberBot Admin Account Creation."
        secret = otp
        note = (f"This token code will expire in <strong>{otp_expiry // 60} minutes</strong>.\n"
                f"Next step: Please provide the code with Cyberbot command <strong>/confirm_admin_account_creation</strong>")
        advisory = "If you did not request this code, you can safely ignore this message."
    elif subject == "New Cyberbot Admin Account Created":
        description = "Your CyberBot admin account has been created. Your temporary password is:"
        secret = otp
        note = "To change your password, use <strong>/request_password_reset_token</strong> followed by <strong>/change_password</strong> in Discord."
        advisory = f"For your security, this password will expire in {otp_expiry // 60} minutes. Please change this temporary password as soon as possible. Never share it with anyone."
    elif subject == "Cyberbot Password Reset Token":
        description = "Use this one-time token to set a new password for your Cyberbot admin account."
        secret = otp
        note = (f"This token code will expire in <strong>{otp_expiry // 60} minutes</strong>.\n"
                f"Next step: Please provide the code with Cyberbot command <strong>/change_password</strong>")
        advisory = "If you did not request a password reset, you can safely ignore this message."
    elif subject == "Admin Account Delete Confirmation Token":
        description = "Use this one-time token to verify your CyberBot Admin Account Deletion."
        secret = otp
        note = (f"This token code will expire in <strong>{otp_expiry // 60} minutes</strong>.\n"
                f"Next step: Please provide the code with Cyberbot command <strong>/confirm_delete_admin_account</strong>")
        advisory = "If you did not request a password reset, you can safely ignore this message."
    elif subject == "Admin Account Unregistration Confirmation":
        # CHANGED: Remove the trailing comma so description is a string, not a tuple.
        description = "You have requested an unregistration process of your Cyberbot admin account and your request has been approved!"
        secret = ""
        note = "All data associated with the account are permanently deleted!"
        advisory = ""
    else:
        description = ""
        secret = ""
        note = ""
        advisory = ""

    # Escape all dynamic data to prevent email HTML markup injection.
    safeSubject = escape(subject, quote=True)
    safeHeading = escape(heading, quote=True)
    safeDescription = escape(description, quote=True)
    safeSecret = escape(secret, quote=True)
    safeCID = escape(logoCID.strip("<>"), quote=True)

    if secret:
        credentialBox = f"""
          <tr><td style="padding:4px 30px 22px 30px;">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
              <tr><td align="center" bgcolor="#14263C" style="padding:21px 16px; border:2px solid #F17822; border-radius:13px;">
                <span style="font-family:Consolas,Menlo,Monaco,'Courier New',monospace; color:#FFFFFF; font-size:25px; line-height:35px; letter-spacing:1px; font-weight:700; overflow-wrap:anywhere; word-break:break-all;">{safeSecret}</span>
              </td></tr>
            </table>
          </td></tr>"""
    else:
        credentialBox = ""

    if note:
        # Note contains only controlled template markup, not untrusted input.
        # Split every original note line into a distinct HTML bullet point.
        # Use inline styles for Gmail/Outlook email client compatibility.
        noteItems = "".join(
            f'<li style="margin:0 0 7px 0; padding:0;">{line.strip()}</li>'
            for line in note.splitlines() if line.strip()
        )
        noteBox = f"""
          <tr><td style="padding:0 30px 20px 30px;">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
              <tr><td bgcolor="#FFF1E6" style="padding:16px 20px; color:#5F361E; font-size:14px; line-height:23px; border-radius:10px; border-left:4px solid #F17822;">
                <!-- CHANGED: Remove the stopwatch emoji and render bullet points instead. -->
                <ul style="margin:0; padding:0 0 0 20px; list-style-type:disc;">{noteItems}</ul>
              </td></tr>
            </table>
          </td></tr>"""
    else:
        noteBox = ""

    if advisory:
        advisoryBox = f"""
          <!-- CHANGED: Remove the shield emoji from the advisory box. -->
          <tr><td style="padding:0 30px 34px 30px; font-size:13px; line-height:21px; color:#627187;">
            {escape(advisory, quote=True)}
          </td></tr>"""
    else:
        advisoryBox = ""
    try:
        # Simple table layout + inline styles for common HTML email clients.
        # The logo is a small related MIME image referenced by its Content-ID.
        return f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
            <title>{safeSubject}</title>
    </head>
    <body style="margin:0; padding:0; background-color:#F0F3F7; font-family:Arial,Helvetica,sans-serif; -webkit-text-size-adjust:100%;">
      <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#F0F3F7" style="background-color:#F0F3F7;">
        <tr>
            <td align="center" style="padding:28px 12px;">
                <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="600" style="width:100%; max-width:600px; background-color:#FFFFFF; border:1px solid #DEE5ED; border-radius:14px; overflow:hidden;">
                    <tr>
                        <td align="center" bgcolor="#101D2F" style="background-color:#101D2F; padding:28px 24px 20px 24px; border-bottom:4px solid #F17822;">
                            <img src="cid:{safeCID}" width="158" height="158" alt="CyberBot security crest" style="display:block; border:0; width:158px; height:158px; max-width:100%; object-fit:contain;" />
                            <div style="padding-top:7px; font-size:31px; line-height:37px; font-weight:800; letter-spacing:3px; color:#FFFFFF;">CYBER<span style="color:#FF7A24;">BOT</span></div>
                            <div style="padding-top:8px; color:#C2D0E0; font-size:11px; line-height:17px; font-weight:700; letter-spacing:2px;">DISCORD SECURITY BOT</div>
                        </td>
                    </tr>
                    <tr>
                        <td align="center" style="padding:0 25px 22px 25px; font-size:25px; font-weight:750; color:#14263C; line-height:32px;">{safeHeading}</td>
                    </tr>
                    <tr>
                        <td style="padding:0 30px 12px 30px; font-size:15px; line-height:26px; font-weight:700; color:#1E2D42;">Hello Discord User {user_discord_name},</td>
                    </tr>
                    <tr>
                        <td style="padding:0 30px 23px 30px; font-size:15px; line-height:25px; color:#354358;">{safeDescription}</td>
                    </tr>
                    {credentialBox}
                    {noteBox}
                    {advisoryBox}
                    <tr>
                        <td bgcolor="#101D2F" align="center" style="padding:18px 22px; border-top:3px solid #F17822; background-color:#101D2F; color:#C7D3E0; font-size:12px; line-height:20px;">
                        &copy; 2026 CyberBot &middot; Discord Security Bot &middot; <a href="https://github.com/DavidNguyen1812/Cyberbot" target="_blank" style="color:#FF7A24; text-decoration:underline; font-weight:600;">Project Details</a><br>
                        This is an automated Cyberbot email notification. Do not reply.
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
      </table>
    </body>
    </html>"""
    finally:
        credentialBox = None
