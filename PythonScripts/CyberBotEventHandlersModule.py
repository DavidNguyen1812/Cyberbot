from __future__ import annotations

from CyberBotRuntimeModule import *
from CyberBotScanOrchestrationModule import CyberBotScan
from CyberBotScheduledTasksModule import checking_expired_tokens, checking_member_can_kick_cyberbot, daily_check_for_expired_credential_and_update_llm_usages, reset_current_failed_log_in_attempts
from CyberBotSecurityUtilitiesModule import sendEmail

@Cyberbot.event
async def on_ready():
    await Cyberbot.wait_until_ready()

    print(f"Logged in as {Cyberbot.user} (ID: {Cyberbot.user.id})")
    print("Cyberbot is ONLINE!")

    await Cyberbot.tree.sync()
    SynedCmds = await Cyberbot.tree.fetch_commands()
    for cmd in SynedCmds:
        print(f"Synced command /{cmd.name}")

    print(f"Commands are updated and ready to use!\n\n")

    checking_expired_tokens.start()
    daily_check_for_expired_credential_and_update_llm_usages.start()
    checking_member_can_kick_cyberbot.start()
    reset_current_failed_log_in_attempts.start()


@Cyberbot.event
async def on_member_remove(member):
    adminAccount = CyberBotConfigData["Admins"].get(str(member.id), None)
    if adminAccount:
        if member.guild.id in adminAccount["Accessible Servers"]:
            print(f"Member {member.name} left server {member.guild.name} ID {member.guild.id}\nRemoving member admin access and session from the server...")
            adminAccount["Accessible Servers"].remove(member.guild.id)
            if str(member.guild.id) in adminAccount["Current Admin Session Period"]:
                del adminAccount["Current Admin Session Period"][str(member.guild.id)]
            async with ConfigLock:
                async with aiofiles.open(CYBERBOT_CONFIG, "w") as file:
                    await file.write(json.dumps(CyberBotConfigData, indent=4))
            tryDM = False
            userEmail = adminAccount.get("Notification Email", None)
            if userEmail:
                if await asyncio.to_thread(sendEmail, f"Admin Account Access Revoke:Left Server:{member.guild.name}:{member.guild.id}", userEmail, member.name) != "Email sent successfully!":
                    tryDM = True
                else:
                    print("Admin Access Revoked Notification sent via account email!")
            else:
                tryDM = True
            if tryDM:
                try:
                    await member.send( f"Your admin access to server {member.guild.name} ID {member.guild.id} has been removed.\nThe reason was that you no longer a member of the server!")
                    print("Admin Access Revoked Notification sent via DM channel!")
                except Exception as error:
                    print(f"Error sending DM to user: {error}")


@Cyberbot.tree.command(
    name="manual_malware_scan",
    description="Manually scan the file content you provided with OpenAI, Gemini, and Virus Total"
)
@app_commands.describe(
    file_to_be_scanned="Upload a single file to scan"
)
async def manual_malware_scan(ctx, file_to_be_scanned: discord.Attachment):
    print(f"User {ctx.user.name} initiated Manual Malware Scan for file {file_to_be_scanned.filename}")
    await ctx.response.defer()
    await CyberBotScan(ctx, manualScan=True, manualFileAttachment=file_to_be_scanned)


@Cyberbot.event
async def on_message_edit(before: discord.message.Message, after: discord.message.Message):
    await Cyberbot.process_commands(after)
    if before.content != after.content:
        await CyberBotScan(after, True)


@Cyberbot.event
async def on_message(message: discord.message.Message):
    await Cyberbot.process_commands(message)
    await CyberBotScan(message)
