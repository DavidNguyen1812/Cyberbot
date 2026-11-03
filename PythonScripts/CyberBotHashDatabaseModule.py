from __future__ import annotations

from CyberBotRuntimeModule import *

async def checkingCleanData(hashedData: str, category: Literal["Archive/Disk File", "Executable/Compiled Files", "Script Files", "Document/PDF Files", "Audio Files", "Image Files", "Video Files", "All Extension", "URLs"]) -> bool:
    """
    Description: Look up the clean hash table for any matching clean Hash
    :param hashedData: SHA256 hash of the file
    :param category: Which file extension category?
    :return: Boolean value of whether the file hash is a hit or not
    """
    async with CleanSignatureLock:
        async with aiofiles.open(CLEAN_SIGNATURES_DB, "r") as file:
            cleanHashedData = json.loads(await file.read())
    if category == "All Extension":
        for cat in cleanHashedData:
            if hashedData in cleanHashedData[cat]:
                return True
    else:
        if hashedData in cleanHashedData[category]:
            return True
    return False


async def checkingFlaggedMaliciousData(hashedData: str, category: Literal["Archive/Disk File", "Executable/Compiled Files", "Script Files", "Document/PDF Files", "Audio Files", "Image Files", "Video Files", "All Extension", "URLs"]) -> bool:
    """
    Description: Look up the malicious hash table for any matching clean Hash
    :param hashedData: SHA256 hash of the file
    :param category: Which file extension category?
    :return: Boolean value of whether the file hash is a hit or not
    """
    async with MaliciousSignatureLock:
        async with aiofiles.open(MALICIOUS_SIGNATURES_DB, "r") as file:
            maliciousHashedData = json.loads(await file.read())
    if category == "All Extension":
        for cat in maliciousHashedData:
            if hashedData in maliciousHashedData[cat]:
                return True
    else:
        if hashedData in maliciousHashedData[category]:
            return True
    return False


async def addingHashedData(hashedData: str, fileExt, malicious: bool, fileCategory='') -> None:
    """
    Description: Adding a new SHA256 hash to the hash table
    :param hashedData: SHA256 hash
    :param fileExt: File extension/URL
    :param malicious: Malicious table or not?
    :param fileCategory: Which file extension category?
    :return: None
    """
    fileExtMap = {"Archive/Disk File": SUPPORTED_DISK_IMAGE_AND_ARCHIVE_FILE_FORMATS,
                  "Executable/Compiled Files": SUPPORTED_EXECUTABLE_FILE_FORMATS,
                  "Script Files": SUPPORTED_SCRIPT_FILE_FORMATS,
                  "Document/PDF Files": SUPPORTED_DOCUMENT_FILE_FORMATS,
                  "Audio Files": SUPPORTED_AUDIO_FILE_FORMATS,
                  "Image Files": SUPPORTED_PICTURE_FILE_FORMATS,
                  "Video Files": SUPPORTED_VIDEO_FILE_FORMATS,
                  "URLs": "URLs"
                  }
    for category in fileExtMap:
        if fileExt in fileExtMap[category]:
            fileCategory = category
            break
    if malicious:
        async with MaliciousSignatureLock:
            async with aiofiles.open(MALICIOUS_SIGNATURES_DB, "r") as file:
                currentMaliciousData = json.loads(await file.read())
            currentMaliciousData.setdefault(fileCategory, [])
            if hashedData not in currentMaliciousData[fileCategory]:
                currentMaliciousData[fileCategory].append(hashedData)
            async with aiofiles.open(MALICIOUS_SIGNATURES_DB, "w") as file:
                await file.write(json.dumps(currentMaliciousData, indent=4))
        print(f"New malicious SHA256 signature was added to category {fileCategory}")
    else:
        async with CleanSignatureLock:
            async with aiofiles.open(CLEAN_SIGNATURES_DB, "r") as file:
                currentCleanData = json.loads(await file.read())
            currentCleanData.setdefault(fileCategory, [])
            if hashedData not in currentCleanData[fileCategory]:
                currentCleanData[fileCategory].append(hashedData)
            async with aiofiles.open(CLEAN_SIGNATURES_DB, "w") as file:
                await file.write(json.dumps(currentCleanData, indent=4))
        print(f"New clean SHA256 signature was added to category {fileCategory}")


async def logScanSession(logData: str) -> None:
    """
    Description: Logging an event of a file/url scan
    :param logData: Scan logs
    :return: None
    """
    async with ScanLogLock:
        async with aiofiles.open(FILE_AND_URL_SCAN_LOG, "a") as logFile:
            await logFile.write(logData)
