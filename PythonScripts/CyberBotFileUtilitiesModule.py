from __future__ import annotations

from CyberBotRuntimeModule import *

@asynccontextmanager
async def hashedScanLock(RootFileHashed: str):
    """
    Description: Prevent duplicate scan on the same file content
    :param RootFileHashed: The hash of the file currently being scanned
    :return: None
    """
    async with HashScanLocksGuard:
        if RootFileHashed not in HashScanLocks:
            HashScanLocks[RootFileHashed] = [asyncio.Lock(), 0]
        scanLock, _ = HashScanLocks[RootFileHashed]
        HashScanLocks[RootFileHashed][1] += 1
    try:
        async with scanLock:
            yield
    finally:
        async with HashScanLocksGuard:
            HashScanLocks[RootFileHashed][1] -= 1
            if HashScanLocks[RootFileHashed][1] == 0:
                del HashScanLocks[RootFileHashed]


class AttachmentSizeLimitExceeded(Exception):
    def __init__(self, reason, file_size=0):
        self.reason = reason
        self.file_size = file_size


async def hashAttachmentWithoutDownload(attachmentUrl: str) -> tuple[str, int, bytes, bool]:
    """
    Description: Read attachment over HTTPS in bounded chunks without storing content on disk.
    :param attachmentUrl: The URL to GET the attachment content
    :return The file content SHA-256 hash, full content length, full file bytes content currently stored in memory or not and GET content error or not?
    """
    FullContentLength = 0
    RootFileHashed = hashlib.sha256()
    fileBytesChunks = []
    parts = urlsplit(attachmentUrl)
    async with FILE_HASH_SEMAPHORE:
        async with Cyberbot.session.get(attachmentUrl, allow_redirects=False) as response:
            if response.status not in range(200, 399):
                if parts.hostname.lower() in ['cdn.discordapp.com', 'media.discordapp.net'] and parts.port in (None, 443) and parts.username is None and parts.path.startswith('/attachments/'):
                    print("Discord Attachment URL can't be retrieved! Begin refreshing the URL...")
                    Headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
                    Payload = {"attachment_urls": [attachmentUrl]}
                    async with Cyberbot.session.post("https://discord.com/api/v10/attachments/refresh-urls", headers=Headers, json=Payload) as refreshResponse:
                        if refreshResponse.status != 200:
                            print("Shit! Can't refresh Discord URL")
                            return '', 0, b'', True
                        refreshResponseData = await refreshResponse.json()
                    try:
                        downloadURL =  refreshResponseData["refreshed_urls"][0]["refreshed"]
                    except Exception :
                        print("Shit! Can't get the refresh Discord URL")
                        return '', 0, b'', True
                    print("Successfully getting the refreshed Discord attachment URL!")
                else:
                    print("Can't GET URL content")
                    return '', 0, b'', True
            else:
                downloadURL = attachmentUrl
        async with Cyberbot.session.get(downloadURL, allow_redirects=False) as response:
            if response.content_length is not None and response.content_length > MAX_FILE_SCAN_SIZE:
                raise AttachmentSizeLimitExceeded("File attachment exceeding Cyberbot file size limit of 300 MB", response.content_length)
            async for fileBytesContent in response.content.iter_chunked(300000):
                FullContentLength += len(fileBytesContent)
                if FullContentLength > MAX_FILE_SCAN_SIZE:
                    raise AttachmentSizeLimitExceeded("File attachment exceeding Cyberbot file size limit of 300 MB", FullContentLength)
                RootFileHashed.update(fileBytesContent)
                if FullContentLength <= ATTACHMENT_CONTENT_IN_MEMORY_LIMIT:
                    fileBytesChunks.append(fileBytesContent)
    return RootFileHashed.hexdigest(), FullContentLength, b"".join(fileBytesChunks), False


async def checkingFileExtensionFromDisk(filePath: str, RootFileName: str) -> str:
    """Check true file extension without loading a 300 MB file into memory."""
    async with aiofiles.open(filePath, "rb") as file:
        fileBytesContent = await file.read(65536)
        if os.path.getsize(filePath) > 65536:
            await file.seek(-512, os.SEEK_END)
            fileBytesContent += await file.read(512)
    return await asyncio.to_thread(checkingRealFileExtension, fileBytesContent, RootFileName)


async def checkingHashFromDisk(filePath: str) -> str:
    """Obtaining file sha256 small chunk at a time instead of loading full content in RAM"""
    HashedFileData = hashlib.sha256()
    async with aiofiles.open(filePath, "rb") as file:
        while True:
            fileBytesContent = await file.read(65536)
            if not fileBytesContent:
                break
            HashedFileData.update(fileBytesContent)
    return HashedFileData.hexdigest()


async def SendScanMessage(message, sendingMessage: str, manualScan: bool = False) -> None:
    if not sendingMessage:
        return
    sendingMessage = sendingMessage.strip()
    if len(sendingMessage) > 1500:
        buffer = BytesIO(sendingMessage.encode("utf-8"))
        resultFile = discord.File(fp=buffer, filename="ScanResult.md")
        if manualScan:
            await message.followup.send(file=resultFile)
        else:
            try:
                await message.reply(file=resultFile)
            except discord.errors.HTTPException:
                await message.channel.send(file=resultFile)
    else:
        if manualScan:
            await message.followup.send(sendingMessage)
        else:
            try:
                await message.reply(sendingMessage, suppress_embeds=True)
            except discord.errors.HTTPException:
                await message.channel.send(sendingMessage,suppress_embeds=True)

async def sendFileScanProgress(message, RootFileName: str, sendingMessage: str) -> None:
    """Best-effort immediate Discord progress announcement, safe if the source is deleted."""
    try:
        if len(sendingMessage) <= 1900:
            await message.reply(sendingMessage, suppress_embeds=True)
        else:
            await SendScanMessage(message, sendingMessage)
    except discord.NotFound:
        # A different concurrent scan might already have deleted the source message.
        try:
            await SendScanMessage(message, sendingMessage)
        except discord.HTTPException as error:
            print(f"Could not announce progress for {RootFileName}: {error}")
    except (discord.Forbidden, discord.HTTPException) as error:
        print(f"Could not announce progress for {RootFileName}: {error}")


def CyberbotFileScanMessageFormat(reason: str, status: str, fileName: str, fileExt: str, fileSize: str):
    return (f'**File Attachment:** `{fileName}`\n'
            f'**File Extension:** `{fileExt}`\n'
            f'**File Size:** `{fileSize}`\n'
            f'**Scan Status:** `{status}`\n'
            f'**Reason:** `{reason}`')
