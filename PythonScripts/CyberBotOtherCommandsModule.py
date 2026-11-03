from __future__ import annotations

from CyberBotRuntimeModule import *
from CyberBotSecurityUtilitiesModule import LoggingApplicationCommand

@Cyberbot.tree.command(
    name="list_supported_formats",
    description="List all supported file formats that Cyberbot can scan"
)
async def list_supported_formats(ctx):
    print(f"User {ctx.user.name} initiated /list_supported_formats command")
    await ctx.response.defer(ephemeral=True)
    for adminAccount in CyberBotConfigData["Admins"]:
        if ctx.user.id == adminAccount["User ID"]:
            if ctx.guild.id in adminAccount["Accessible Servers"] or ctx.user.id == ctx.guild.owner.id:
                if str(ctx.guild.id) in adminAccount["Current Admin Session Period"]:
                    if time.time() < adminAccount["Current Admin Session Period"][str(ctx.guild.id)]:
                        await ctx.followup.send(f"Cyberbot can scan the following file formats:\n\n"
                                                f"Archive and Disk Image: {SUPPORTED_DISK_IMAGE_AND_ARCHIVE_FILE_FORMATS}\n\n"
                                                f"Executable: {SUPPORTED_EXECUTABLE_FILE_FORMATS}\n\n"
                                                f"Script Files: BASH script, ZShell and all common programming scripts\n\n"
                                                f"Document Files: {SUPPORTED_DOCUMENT_FILE_FORMATS}\n\n"
                                                f"Media Files: {SUPPORTED_PICTURE_FILE_FORMATS + SUPPORTED_AUDIO_FILE_FORMATS + SUPPORTED_VIDEO_FILE_FORMATS}")
                        print(f"The list of Cyberbot supported file formats has been displayed to user!\n\n")
                        await LoggingApplicationCommand(ctx, "/list_supported_formats", "NONE", "Approved/The list of Cyberbot supported file formats has been displayed to user")
                    else:
                        del adminAccount["Current Admin Session Period"][str(ctx.guild.id)]
                        await ctx.followup.send(f"Your admin session with this server has expired! Please log in again.")
                        print(f"User admin session expired!\n\n")
                        async with ConfigLock:
                            async with aiofiles.open(CYBERBOT_CONFIG, "w") as file:
                                await file.write(json.dumps(CyberBotConfigData, indent=4))
                        await LoggingApplicationCommand(ctx, "/list_supported_formats", "NONE", "Denied/User Admin in server session expired")
                else:
                    await ctx.followup.send(f"You need to use /admin_log_in to log in as an admin in this server to execute this command!")
                    print(f"User {ctx.user.name} need to log in as an admin!\n\n")
                    await LoggingApplicationCommand(ctx, "/list_supported_formats", "NONE", "Denied/User need to log in as an admin")
            else:
                await ctx.followup.send(f"You do not have an admin account access to the server, please contact the server owner {ctx.guild.owner.name} to add your admin account access to the server!")
                print(f"User {ctx.user.name} not authorized to execute the command!\n\n")
                await LoggingApplicationCommand(ctx, "/list_supported_formats", "NONE", "Denied/User does not have admin account access to the server!")
            return
    await ctx.followup.send(f"You do not have a Cyberbot admin account yet! Use command /create_admin_account to register a new Cyberbot admin account!")
    print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")
    await LoggingApplicationCommand(ctx, "/list_supported_formats", "NONE", "Denied/User does not have a Cyberbot admin account yet!")


@Cyberbot.tree.command(
    name="get_list_of_accessible_servers",
    description="Getting a list of servers your Cyberbot admin account can access"
)
async def get_list_of_accessible_servers(ctx):
    print(f"User {ctx.user.name} initiated /get_list_of_accessible_servers command")
    await ctx.response.defer(ephemeral=True)
    for admin in CyberBotConfigData["Admins"]:
        if admin["User ID"] == ctx.user.id:
            serverList = ''
            for serverID in admin["Accessible Servers"]:
                guild = Cyberbot.get_guild(serverID)
                serverList += f"Server Name: {guild.name}\tServer ID: {serverID}\tServer Owner: {guild.owner.name}\n"
            await ctx.followup.send(f"Your Cyberbot admin account has access to the following servers:\n{serverList}")
            print(f"Process Finished!\n\n")
            await LoggingApplicationCommand(ctx, "/get_list_of_accessible_servers", "NONE", "Approved/Accessible Servers list sent to user!")
            return
    await ctx.followup.send(f"You do not have a Cyberbot admin account yet! Use command /create_admin_account to register a new Cyberbot admin account!")
    print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")
    await LoggingApplicationCommand(ctx, "/get_list_of_accessible_servers", "NONE", "Denied/User does not have a Cyberbot admin account yet!")


@Cyberbot.tree.command(
    name="checking_file_true_format",
    description="Checking the file true format based on it magic bytes signature"
)
@app_commands.describe(
    file="Upload a single file to check"
)
async def checking_file_true_format(ctx, file: discord.Attachment):
    print(f"User {ctx.user.name} initiated /checking_file_true_format {file.filename}")
    await ctx.response.defer()
    fileExt = await asyncio.to_thread(checkingRealFileExtension, await file.read(), file.filename)
    await ctx.followup.send(f"The file extension is: {fileExt}\n\n")
    await LoggingApplicationCommand(ctx, "/checking_file_true_format", f"file -> {file.name}", f"Approved/File extension is {fileExt}")
    print(f"Command Execution Success!\n\n")


#  Command can run in any channels
@Cyberbot.tree.command(
    name="phishing_email_scan",
    description="Cyberbot will use two of it pre-trained encoder-transformer models to scan the email"
)
@app_commands.describe(
    email_content="Please input the email content",
    keep_output_secret="Select Yes if you want the command (Your input and Cyberbot output) be private!"
)
async def phishing_email_scan(ctx, email_content: str, keep_output_secret: Literal["Yes", "No"]):
    print(f"User {ctx.user.name} initiated phishing_email_scan Scan for email content: {email_content} with keep_output_secret: {keep_output_secret}")
    if keep_output_secret == "Yes":
        await ctx.response.defer(ephemeral=True)
    else:
        await ctx.response.defer()
    BERTPhishingResult, BERTPhishingprobability = await asyncio.to_thread(Prediction, email_content, BERTtokenizer, BERTPhishingClassifier, "Phishing Emails", hardware.lower())
    AllenAIPhishingResult, AllenAIPhishingprobability = await asyncio.to_thread(Prediction, email_content, AllenAItokenizer, AllenAIPhishingClassifier, "Phishing Emails", hardware.lower())
    BERTSpamResult, BERTSpamprobability = await asyncio.to_thread(Prediction, email_content, BERTtokenizer, BERTSpamClassifier, "Spam Emails", hardware.lower())
    AllenAISpamResult, AllenAISpamprobability = await asyncio.to_thread(Prediction, email_content, AllenAItokenizer, ALLENAISpamClassifier, "Spam Emails", hardware.lower())
    result = (f"**BERT-based Encoder-Transformer Phishing Detector Model results**:\n{labels["Phishing"][str(BERTPhishingResult)]}\n**Confidence**: {BERTPhishingprobability * 100:.4f}%\n\n"
        f"**AllenAI-based Encoder-Transformer Phishing Detector results**:\n{labels["Phishing"][str(AllenAIPhishingResult)]}\n**Confidence**: {AllenAIPhishingprobability * 100:.4f}%\n\n"
        f"**BERT-based Encoder-Transformer Spam Detector Model results**:\n{labels["Spam"][str(BERTSpamResult)]}\n**Confidence**: {BERTSpamprobability * 100:.4f}%\n\n"
        f"**AllenAI-based Encoder-Transformer Spam Detector results**:\n{labels["Spam"][str(AllenAISpamResult)]}\n**Confidence**: {AllenAISpamprobability * 100:.4f}%\n\n"
        f"**PLEASE NOTE** that all the pre-trained encoder-transformer models were only trained on emails mostly written in English with a context window of 1500 tokens/words!")
    await ctx.followup.send(result)
    await LoggingApplicationCommand(ctx, "/phishing_email_scan", f"email_content`\n```\n{email_content}\n``", f"Approved`\n\n{result}")
