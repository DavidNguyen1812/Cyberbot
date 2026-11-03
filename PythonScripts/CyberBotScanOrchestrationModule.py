from __future__ import annotations

from CyberBotRuntimeModule import *
from CyberBotAttachmentScanModule import scanOneAttachment
from CyberBotFileUtilitiesModule import SendScanMessage, sendFileScanProgress
from CyberBotHashDatabaseModule import addingHashedData, logScanSession
from CyberBotURLScanModule import scanOneURL

async def CyberBotScan(message: discord.message.Message | discord.interactions.Interaction, isEdit:bool=False,  manualScan:bool=False, manualFileAttachment: discord.Attachment|None=None ) -> None:
    """
    Description: Cyberbot main security scanning pipeline
    :param message: The Discord message object
    :param isEdit: Is the message scan a re-edit message or not
    :param manualScan: Is this a manual scan or not
    :param manualFileAttachment: The file attachment user upload via /manual_malware_scan command
    :return: None
    """
    if manualScan:
        if message.user == Cyberbot.user or str(message.channel) == "Direct Message with Unknown User":
            return
    else:
        if message.author == Cyberbot.user or str(message.channel) == "Direct Message with Unknown User":
            return
    if isEdit:
        print(f"Re-edit Message detected!")

    """Adding new server ID to Configuration file"""
    guildId = str(message.guild.id)
    async with ConfigLock:
        configChanged = False
        for category, defaultValue in (("Non-monitoring-Channels", []), ("Silent-Mode", "False"), ("Automation-Mode", "True")):
            if guildId not in CyberBotConfigData[category]:
                CyberBotConfigData[category][guildId] = defaultValue.copy() if isinstance(defaultValue, list) else defaultValue
                configChanged = True
        if configChanged:
            async with aiofiles.open(CYBERBOT_CONFIG, "w") as file:
                await file.write(json.dumps(CyberBotConfigData, indent=4))

    if not manualScan:
        isSilent = CyberBotConfigData["Silent-Mode"][guildId] == "True"
    else:
        isSilent = True

    sendingMessage = ""
    scan = False
    URLs = []
    if not manualScan:
        if message.content:
            URLs = re.findall(r'https?://(?:(?!https?://)\S)+', message.content.replace(" ", ""))
            URLs = list(dict.fromkeys(URLs))
        if URLs or len(message.attachments) > 0:
            scan = True
    else:
        scan = True

    if not scan:
        return

    if not manualScan:
        logMessage = (
            f"# {time.ctime(time.time())}\n\n---\n\n"
            f"## Discord Message Origin\n"
            f"- **Origin Author:** `{message.author.name}`\n"
            f"- **Author Discord User ID:** `{message.author.id}`\n"
            f"- **Discord Server:** `{message.guild.name}`\n"
            f"- **Discord Server ID:** `{message.guild.id}`\n"
            f"- **Server Channel:** `{message.channel.name}`\n"
            f"- **Channel ID:** `{message.channel.id}`\n\n"
        )
    else:
        logMessage = (
            f"# {time.ctime(time.time())}\n---\n"
            f"## Discord Message Origin\n"
            f"- **Origin Author:** `{message.user.name}`\n"
            f"- **Author Discord User ID:** `{message.user.id}`\n"
            f"- **Discord Server:** `{message.guild.name}`\n"
            f"- **Discord Server ID:** `{message.guild.id}`\n"
            f"- **Server Channel:** `{message.channel.name}`\n"
            f"- **Channel ID:** `{message.channel.id}`\n\n"
        )

    """Checking if the current channel is in the server non monitoring list"""
    if message.channel.id in CyberBotConfigData["Non-monitoring-Channels"][guildId] and not manualScan:
        logMessage += ("## Server Channel Outside Scan Scope\n"
                       "Cyberbot detected the message but the channel is in the exclusion list for this server, so no scan is done!\n\n---\n\n")
        await logScanSession(logMessage)
        return

    fileAttachmentUrls = {}
    if URLs and not manualScan:
        URLs, fileAttachmentUrls, logMessage, continueScan = await processingUrls(URLs, message, logMessage, isSilent, addingHashedData)
        if not continueScan:
            await logScanSession(logMessage)
            return

    if not isEdit:
        if not manualScan:
            if len(message.attachments) > 0:  # Check if the message has at least 1 file attachment and adding the attachment URL to the attachment scan list
                print(f"User {message.author.name} uploads {len(message.attachments)} file attachment(s)!")
                for attachment in message.attachments:
                    fileAttachmentUrls[attachment.url] = attachment.filename
        else:
            if manualFileAttachment is None:
                await message.followup.send("No file attachment was provided.")
                return
            fileAttachmentUrls[manualFileAttachment.url] = manualFileAttachment.filename

    # Announce EACH file using the original progress message BEFORE launching any scanning tasks, so users see the warnings immediately instead of at scan completion.
    if not manualScan and not isSilent and fileAttachmentUrls:
        await asyncio.gather(*(sendFileScanProgress(message, RootFileName, f"Cyberbot is scanning the file {RootFileName} in this message, please do not download until Cyberbot scan is clear of malware.")
            for RootFileName in fileAttachmentUrls.values()
        ))

    if URLs:
        logMessage += "## URL Scan Summary\n"
    scanTasks = [asyncio.create_task(scanOneURL(url)) for url in URLs]
    scanTasks.extend(asyncio.create_task(scanOneAttachment(attachmentUrl, RootFileName, message=message if not manualScan else None, isSilent=isSilent)) for attachmentUrl, RootFileName in fileAttachmentUrls.items())

    messageDeleted = False
    results = []
    fileScanCount = 0
    urlScanCount = 0

    # React to malicious results as soon as *any* task completes.
    # Already-running tasks remain active so their own resources are not destroyed.
    for completedTask in asyncio.as_completed(scanTasks):
        try:
            scanResult = await completedTask
        except Exception as error:
            print("Cyberbot scan task failed")
            logMessage += f"\n# CRITICAL FAILURE\nUnexpected scan task error: `{error}`\n\n"
            sendingMessage += "Cyberbot could not verify one item because a scan task failed.\n"
            continue
        if hasattr(scanResult, "RootFileName"):
            fileScanCount += 1
            if fileScanCount == 1:
                logMessage += "## File Attachment Scan Summary\n"
        elif hasattr(scanResult, "url"):
            urlScanCount += 1
        logMessage += scanResult.logMessage
        results.append(scanResult)
        if scanResult.status == "malicious":
            # Delete original Discord messages at the first malware verdict.
            if not manualScan and not messageDeleted:
                try:
                    await message.delete()
                    messageDeleted = True
                except discord.NotFound:
                    messageDeleted = True
                except discord.Forbidden:
                    print(f"Cyberbot does not have permission to delete message {message.id}")
            if manualScan:
                sendingMessage += scanResult.sendingMessage + "\n"
                await SendScanMessage(message, scanResult.sendingMessage, manualScan=True)
            else:
                await SendScanMessage(message, scanResult.sendingMessage)
        elif not isSilent and not manualScan:
            await SendScanMessage(message, scanResult.sendingMessage)
        elif manualScan:
            if not sendingMessage:
                sendingMessage = "Cyberbot completed the scan, but no conclusive result was returned."
            else:
                sendingMessage += scanResult.sendingMessage + "\n"
                await SendScanMessage(message, sendingMessage, manualScan=True)

    if any(result.status in ("unverified", "error", "too_large", "unsupported") for result in results):
        logMessage += "## SPECIAL NOTE:\nOne or more contents could not be fully verified; do not treat as safe.\n\n---\n\n"
    print(f"Total URL scan: {urlScanCount}")
    print(f"Total file scan: {fileScanCount}")
    await logScanSession(logMessage)
    print("\n\n")