from __future__ import annotations


from CyberBotRuntimeModule import *
from CyberBotScanOrchestrationModule import CyberBotScan
from CyberBotScheduledTasksModule import checking_expired_tokens, checking_member_can_kick_cyberbot, daily_check_for_expired_credential_and_update_llm_usages

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


@Cyberbot.event
async def on_member_remove(member):
    print(f"Member {member.name} left server {member.guild.name} ID {member.guild.id}\nRemoving member admin access and session from the server...\n\n")
    for admin in CyberBotConfigData["Admins"]:
        if admin["User ID"] == member.id:
            admin["Accessible Servers"].remove(member.guild.id)
            if str(member.guild.id) in admin["Current Admin Session Period"]:
                del admin["Current Admin Session Period"][str(member.guild.id)]
            async with ConfigLock:
                async with aiofiles.open(CYBERBOT_CONFIG, "w") as file:
                    await file.write(json.dumps(CyberBotConfigData, indent=4))
            try:
                await member.send( f"Your admin access to server {member.guild.name} ID {member.guild.id} has been removed.\nThe reason was that you have left the server!")
            except Exception as error:
                print(f"Error sending DM to user: {error}")
            break


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
