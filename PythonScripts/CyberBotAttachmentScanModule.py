from __future__ import annotations


from CyberBotRuntimeModule import *
from CyberBotFileUtilitiesModule import AttachmentSizeLimitExceeded, CyberbotFileScanMessageFormat, checkingFileExtensionFromDisk, checkingHashFromDisk, hashAttachmentWithoutDownload, hashedScanLock, sendFileScanProgress
from CyberBotGhidraIntegrationModule import ghidraDecompile
from CyberBotHashDatabaseModule import addingHashedData, checkingCleanData, checkingFlaggedMaliciousData
from CyberBotLLMScanModule import GeminiSCAT, openAISCAT, partialLLMSCAT
from CyberBotSecurityUtilitiesModule import txtToPDFConversion
from CyberBotVirusTotalModule import virusTotalFileScan

async def scanOneAttachment(attachmentUrl: str, RootFileName: str, message=None, isSilent: bool = True) -> FileScanResult:
    """
    Description: Independently scan one file attachment with a bounded worker.
    :param attachmentUrl: Discord CDN URL to the file attachment
    :param RootFileName: File attachment name from the original message
    :param message: Discord message object
    :param isSilent: Cyberbot silent mode config for the server
    :return: Isolated file analysis results for CyberBotScan
    """
    ScanStartTime = time.perf_counter()
    scanResult = None
    scanFuture = None
    scanOwner = False
    logMessage = f"- **File Attachment Name:** `{RootFileName}`\n"

    print(f"Scanning file {RootFileName}...")

    """Checking ../ attack in file name scheme"""
    NormalizedFileName = RootFileName.replace("\\", "/")
    if "../" in NormalizedFileName or NormalizedFileName.startswith("/") or NormalizedFileName in ("..", "."):
        logMessage += (f"- **Scan Result:** `MALICIOUS`\n"
                       f"- **Reason:** `File name hinted potential directory transversal attack!`\n"
                       f"- **Scan Duration In Second(s):** {time.perf_counter() - ScanStartTime:.2f}s\n\n---\n\n")
        print(f"File {RootFileName} scan duration: {time.perf_counter() - ScanStartTime:.2f}s")
        return FileScanResult(RootFileName, "malicious", CyberbotFileScanMessageFormat(f"File name {RootFileName} hinted potential directory transversal attack!", "MALICIOUS", RootFileName, "DOES NOT CHECK", "DOES NOT CHECK"), logMessage)

    """Retrieving File Attachment Size And Content Via The Attachment URL To RAM"""
    try:
        RootFileHashed, FullContentLength, CachedFileBytesContent, attachmentUrl = await hashAttachmentWithoutDownload(attachmentUrl)

        """Checking file true extension"""
        RootFileTrueExt = await asyncio.to_thread(checkingRealFileExtension,CachedFileBytesContent, RootFileName)
        if message is not None and not isSilent:
            await sendFileScanProgress(message, RootFileName, f"The file {RootFileName} extension is: {RootFileTrueExt}")
        logMessage += (f"- **File Attachment Size:** `{FullContentLength:,} bytes`\n"
                       f"- **File Attachment SHA-256 Hash:** `{RootFileHashed}`\n"
                       f"- **File True Extension:** `{RootFileTrueExt}`\n")
    except asyncio.CancelledError:
        print("File scan process was interrupted and cancelled during attachment fingerprint process!")
        logMessage += (f"- **Scan Result:** `ERROR`\n"
                       f"- **Reason:** `File scan process was interrupted and cancelled during attachment fingerprint process!`\n"
                       f"- **Scan Duration In Second(s):** {time.perf_counter() - ScanStartTime:.2f}s\n\n---\n\n")
        print(f"File {RootFileName} scan duration: {time.perf_counter() - ScanStartTime:.2f}s")
        return FileScanResult(RootFileName, "error", CyberbotFileScanMessageFormat(f"The file could not be verified due to a download error.", "UNVERIFIED", RootFileName, "DOES NOT CHECK", "DOES NOT CHECK"), logMessage)
    except AttachmentSizeLimitExceeded as error:
        logMessage += (f"- **File Attachment Size:** `{error.file_size:,} bytes`\n"
                       f"- **Scan Result:** `UNVERIFIED`\n"
                       f"- **Reason:** `File size too large for Cyberbot to scan!`\n"
                       f"- **Scan Duration In Second(s):** {time.perf_counter() - ScanStartTime:.2f}s\n\n---\n\n")
        print(f"File {RootFileName} scan duration: {time.perf_counter() - ScanStartTime:.2f}s")
        return FileScanResult(RootFileName, "too_large", CyberbotFileScanMessageFormat(f"File size too large for Cyberbot to scan!", "UNVERIFIED", RootFileName, "DOES NOT CHECK", f"{error.file_size:,} bytes"), logMessage)
    except Exception as error:
        print(f"Cyberbot attachment fingerprint failed: {RootFileName}: {error}")
        logMessage += (f"- **Scan Result:** `ERROR`\n"
                       f"- **Reason:** `{error}`\n"
                       f"- **Scan Duration In Second(s):** {time.perf_counter() - ScanStartTime:.2f}s\n\n---\n\n")
        print(f"File {RootFileName} scan duration: {time.perf_counter() - ScanStartTime:.2f}s")
        return FileScanResult(RootFileName, "error", CyberbotFileScanMessageFormat(f"The file could not be verified due to a download error.", "UNVERIFIED", RootFileName, "DOES NOT CHECK", "DOES NOT CHECK"), logMessage)

    # Prevent duplicate scan of the same attachment
    async with HashScanLocksGuard:
        scanFuture = InFlightFileScans.get(RootFileHashed)
        if scanFuture is None:
            scanFuture = asyncio.get_running_loop().create_future()
            InFlightFileScans[RootFileHashed] = scanFuture
            scanOwner = True

    if not scanOwner:
        print(f"File {RootFileName} is currently being scanned by other subroutine!")
        if not isSilent and message is not None:
            await sendFileScanProgress(message, RootFileName, f"Another scan process for the file {RootFileName} is under progressed...")
        sharedResult = await asyncio.shield(scanFuture)
        if sharedResult.status == "malicious":
            status = "MALICIOUS"
        elif not sharedResult.status in ["unverified", "error", "too_large", "unsupported"]:
            status = "CLEAN"
        else:
            status = "UNVERIFIED"
        logMessage += (f"- **Scan Result:** `{status}`\n"
                       f"- **Reason:** `{sharedResult.sendingMessage}`\n"
                       f"- **Scan Duration In Second(s):** {time.perf_counter() - ScanStartTime:.2f}s\n\n---\n\n")
        print(f"File {RootFileName} scan duration: {time.perf_counter() - ScanStartTime:.2f}s")
        return FileScanResult(RootFileName, sharedResult.status, CyberbotFileScanMessageFormat(sharedResult.sendingMessage, status, RootFileName, RootFileTrueExt, f"{FullContentLength:,} bytes"), logMessage, RootFileHashed)

    try:
        if await checkingFlaggedMaliciousData(RootFileHashed, "All Extension"):
            print("File attachment already flagged malicious!")
            logMessage += (f"- **Scan Result:** `MALICIOUS`\n"
                           f"- **Reason:** `File content already flagged Malicious from Cyberbot scan history!`\n")
            scanResult = FileScanResult(RootFileName, "malicious", CyberbotFileScanMessageFormat(f"File {RootFileName} content already flagged Malicious from Cyberbot scan history!", "MALICIOUS", RootFileName, RootFileTrueExt, f"{FullContentLength:,} bytes"), logMessage, RootFileHashed)
        elif await checkingCleanData(RootFileHashed, "All Extension"):
            print("File attachment already passed as clean!")
            logMessage += (f"- **Scan Result:** `CLEAN`\n"
                           f"- **Reason:** `File content already Passed As Clean from Cyberbot scan history!`\n")
            scanResult = FileScanResult(RootFileName, "clean", CyberbotFileScanMessageFormat(f"File {RootFileName} content already passed as Clean from Cyberbot scan history!", "CLEAN", RootFileName, RootFileTrueExt, f"{FullContentLength:,} bytes"), logMessage, RootFileHashed)
        else:
            if CachedFileBytesContent is not None:
                async with FILE_SCAN_SEMAPHORE:
                    os.makedirs(DOWNLOADING_DIR, exist_ok=True)
                    workdir = await asyncio.to_thread( tempfile.mkdtemp, prefix="CyberbotScan_", dir=DOWNLOADING_DIR)
                    filePath = os.path.join(workdir, "attachment.download")
                    tempScanFolder = os.path.join(workdir, "MainMountPoint") + os.sep
                    try:
                        scanResult = await analyzeAttachmentContents(RootFileName, RootFileTrueExt, filePath, tempScanFolder, RootFileHashed=RootFileHashed, CachedFileBytesContent=CachedFileBytesContent, message=message, isSilent=isSilent, logMessage=logMessage)
                    finally:
                        await asyncio.to_thread(shutil.rmtree, workdir, ignore_errors=True)
            else:
                print(f"File attachment content is empty!")
                logMessage += (f"- **Scan Result:** `UNVERIFIED`\n"
                               f"- **Reason:** `File attachment content is empty!`\n")
                scanResult = FileScanResult(RootFileName, "unverified", CyberbotFileScanMessageFormat(f"File attachment content is empty!", "UNVERIFIED", RootFileName, "CAN'T BE DETERMINED!", f"0 bytes"), logMessage, RootFileHashed)
    except asyncio.CancelledError:
        print("File scan was interrupted!")
        logMessage += (f"- **Scan Result:** `ERROR`\n"
                       f"- **Reason:** `File scan was interrupted.`\n")
        scanResult = FileScanResult(RootFileName, "error", CyberbotFileScanMessageFormat(f"File {RootFileName} scan was interrupted.", "UNVERIFIED", RootFileName, RootFileTrueExt, f"{FullContentLength:,} bytes"),logMessage, RootFileHashed)
    except AttachmentSizeLimitExceeded as error:
        logMessage += (f"- **File Attachment Size:** `{error.file_size:,} bytes`\n"
                       f"- **Scan Result:** `UNVERIFIED`\n"
                       f"- **Reason:** `File size too large for Cyberbot to scan!`\n")
        scanResult =  FileScanResult(RootFileName, "too_large", CyberbotFileScanMessageFormat(f"File size too large for Cyberbot to scan!", "UNVERIFIED", RootFileName, RootFileTrueExt, f"{error.file_size:,} bytes"), logMessage)
    except Exception as error:
        print(f"File Scan Error: {error}")
        logMessage += (f"- **Scan Result:** `ERROR`\n"
                       f"- **Reason:** `{error}`\n")
        scanResult = FileScanResult(RootFileName, "error", CyberbotFileScanMessageFormat(f"The file {RootFileName} could not be verified due to a scan error.", "UNVERIFIED", RootFileName, RootFileTrueExt, f"{FullContentLength:,} bytes"), logMessage, RootFileHashed)
    finally:
        if scanResult is None:
            logMessage += (f"- **Scan Result:** `UNVERIFIED`\n"
                           f"- **Reason:** `The file could not be fully verified due an empty scan result report.`\n")
            scanResult = FileScanResult(RootFileName, "error", CyberbotFileScanMessageFormat(f"The file {RootFileName} could not be verified.", "UNVERIFIED", RootFileName, RootFileTrueExt, f"{FullContentLength:,} bytes"), logMessage)
        if not scanFuture.done():
            scanFuture.set_result(scanResult)
        async with HashScanLocksGuard:
            if InFlightFileScans.get(RootFileHashed) is scanFuture:
                del InFlightFileScans[RootFileHashed]
        print(f"File {RootFileName} scan duration: {time.perf_counter() - ScanStartTime:.2f}s")
        scanResult.logMessage += f"- **Scan Duration In Second(s):** {time.perf_counter() - ScanStartTime:.2f}s\n\n---\n\n"
    return scanResult


async def analyzeAttachmentContents(RootFileName: str, RootFileTrueExt: str, filePath: str, tempScanFolder: str, RootFileHashed: str = "", CachedFileBytesContent: bytes= b'', message=None, isSilent: bool = True, logMessage: str= '') -> FileScanResult:
    """Main Discord attachment scan pipeline"""
    sendingMessage = ""
    unverifiedReasons = ""

    """Checking if file size within the supported file size for scan"""
    print("Downloading attachment content...")
    async with aiofiles.open(filePath, "wb") as file:
        await file.write(CachedFileBytesContent)
    FullContentLength = os.path.getsize(filePath)
    print("Attachment file downloaded!")

    if RootFileTrueExt.startswith("."):
        UpdatedFilePath = os.path.join(os.path.dirname(os.path.normpath(tempScanFolder)), f"attachment{RootFileTrueExt}")
        os.replace(filePath, UpdatedFilePath)
        filePath = UpdatedFilePath

    """Checking if there is another subroutine scanning the same file"""
    async with hashedScanLock("file:" + RootFileHashed):

        """Checking if file is encrypted"""
        if RootFileTrueExt.endswith(ENCRYPTED_FILE_FORMATS):
            print(f"File {RootFileName} is encrypted!")
            logMessage += (f"- **Scan Result:** `UNVERIFIED`\n"
                           f"- **Reason:** `File content is encrypted and Cyberbot can not inspect its contents.`\n")
            return FileScanResult(RootFileName, "unverified", CyberbotFileScanMessageFormat(f"The file {RootFileName} is encrypted and Cyberbot can not inspect its contents.", "UNVERIFIED", RootFileName, RootFileTrueExt, f"{FullContentLength:,} bytes"), logMessage, RootFileHashed)

        """Checking if file extension format is in scope"""
        if RootFileTrueExt not in SUPPORTED_FILE_FORMATS:
            print(f"File {RootFileName} extension format is outside of Cyberbot scope of scan!")
            logMessage += (f"- **Scan Result:** `UNVERIFIED`\n"
                           f"- **Reason:** `File extension format is outside of Cyberbot scope of scan!`\n")
            return FileScanResult(RootFileName, "unverified", CyberbotFileScanMessageFormat(f"File extension format is outside of Cyberbot scope of scan!", "UNVERIFIED", RootFileName, RootFileTrueExt, f"{FullContentLength:,} bytes"), logMessage, RootFileHashed)

        os.makedirs(tempScanFolder, exist_ok=True)

        """Start scanning file contents with Virus Total"""
        if message is not None and not isSilent:
            await sendFileScanProgress(message, RootFileName, f"Start scanning {RootFileName} contents with Virus Total...")
        print(f"Start scanning {RootFileName} contents with Virus Total...")
        virusTotalResult = await virusTotalFileScan(filePath)
        if virusTotalResult.startswith("Error"):
            logMessage += f"- **Virus Total Scan Result:** `{virusTotalResult}`\n"
            unverifiedReasons = f"Virus Total Scan Result: An Error Occurred While Scanning File {RootFileName}"
        else:
            try:
                virusTotalResult = virusTotalResult.split(":")
                virusTotalReport = f"{virusTotalResult[0]} Malicious, {virusTotalResult[1]} Suspicious, {virusTotalResult[2]} Harmless, {virusTotalResult[3]} Undetected"
                if not isSilent or int(virusTotalResult[0]) > 0 or int(virusTotalResult[1]) > 0:
                    await sendFileScanProgress(message, RootFileName, f"Virus Total Report: {virusTotalReport}")
                logMessage += f"- **Virus Total Scan Result:** `{virusTotalReport}`\n"
                if int(virusTotalResult[0]) > 0:
                    print(f"One or more scan engine from Virus Total scan flagged the file content as malicious!")
                    await addingHashedData(RootFileHashed, RootFileTrueExt, True)
                    logMessage += (f"- **Scan Result:** `MALICIOUS`\n"
                                   f"- **Reason:** `One or more scan engine from Virus Total scan flagged the file content as malicious!`\n")
                    return FileScanResult(RootFileName, "malicious", CyberbotFileScanMessageFormat(f"One or more scan engine from Virus Total scan flagged the file content as malicious!`\n**Virus Total Scan Report:** `{virusTotalReport}", "MALICIOUS", RootFileName, RootFileTrueExt, f"{FullContentLength:,} bytes"), logMessage, RootFileHashed)
                if int(virusTotalResult[1]) > 0:
                    print(f"One or more scan engine from Virus Total scan flagged the file content as suspicious!")
                    logMessage += f"- **Virus Total Scan Note:** `One or more scan engine from Virus Total scan flagged the file content as suspicious!`\n"
                    unverifiedReasons = f"One or more scan engine from Virus Total scan flagged the file content as suspcious!"
            except (ValueError, IndexError):
                logMessage += f"- **Virus Total Scan Result:** `Return An Invalid Response`\n"
                unverifiedReasons = "VirusTotal returned an invalid response!"

        """Checking archive/disk file content for archive/disk bomb"""
        if RootFileTrueExt.endswith(SUPPORTED_DISK_IMAGE_AND_ARCHIVE_FILE_FORMATS):
            isArchive = True
            print("Attachment is an Archive or Disk Image file, checking for Archive/Disk Image Bomb...")
            archiveReportPath = f"{tempScanFolder}/{uuid.uuid4().hex[:7]}archive_scan_report.json"
            async with ARCHIVE_SEMAPHORE:
                archiveScanResult = await asyncio.to_thread(ArchivesDiskImagesBombAnalysisAndExtraction, [filePath], tempScanFolder, archiveReportPath, RootFileTrueExt)
            ufs = uncompressedFileStructure(archiveReportPath)
            with open(archiveReportPath, "r", encoding="utf-8") as archiveReport:
                scanReport = json.load(archiveReport)
            uncompressedSize = scanReport.get('uncompressedSize', 0)
            totalDuplicatedFile = scanReport.get('totalDuplicatedFile', 0)
            totalDuplicatedArchive = scanReport.get('totalDuplicatedArchive', 0)
            totalFileCount = scanReport.get('totalFileCount', 0)
            notes = scanReport.get('notes', [])
            notes[0] = f"\t+ {notes[0]}"
            notes = f"{"\n\t+ ".join(notes) if len(notes) > 1 else notes[0]}\n"
            logMessage += (
                    f"- **Archive File Uncompressed Content Size:** `{uncompressedSize:,} bytes`\n"
                    f"- **Total Duplicated File(s):** `{totalDuplicatedFile:,}`\n"
                    f"- **Total Duplicated Archive(s):** `{totalDuplicatedArchive:,}`\n"
                    f"- **Total File Count:** `{totalFileCount:,}`\n"
                    f"- **Uncompression Progress NOTES:**\n{notes}"
                    f"- **Uncompressed File Structure:**\n```commandline\n{ufs}\n```\n\n")
            os.remove(archiveReportPath)
            if not archiveScanResult == 'Safe Extraction Complete!':
                if archiveScanResult.startswith(("Large Cumulative Uncompressed Size!", "Path Transversal Attack", "Too Much File Count", "Potential Recursive Archive Bomb Attack!", "Too many duplicated files!", "Too Large Nested Archive Content!", "Matryoshka Archive")):
                    await addingHashedData(RootFileHashed, RootFileTrueExt, True)
                    logMessage += f"- **Scan Result:** `MALICIOUS`\n"
                    reason = ""
                    if archiveScanResult.startswith("Large Cumulative Uncompressed Size!"):
                        uncompressedToCompressedRatio =  archiveScanResult.split(":")[2]
                        reason = f"The archive/disk file {RootFileName} uncompressed content size was unusually large. The uncompressed size is {uncompressedToCompressedRatio} times the compressed size!"
                    if archiveScanResult.startswith("Path Transversal Attack"):
                        reason = f"The archive/disk file {RootFileName} contains a file with a malicious naming scheme. {archiveScanResult.replace('Path Transversal Attack', '')}"
                    if archiveScanResult.startswith("Too Much File Count"):
                        reason = f"The archive/disk file {RootFileName} contains a unusual large amount of files! Potential archive/disk image bomb!"
                    if archiveScanResult.startswith("Potential Recursive Archive Bomb Attack!"):
                        reason = f"The archive/disk file {RootFileName} contains many other embedded archive/disk image! Potential Recursive Archive Bomb Attack"
                    if archiveScanResult.startswith("Too many duplicated files!"):
                        reason = f"The archive/disk file {RootFileName} contains too many duplicated file content! Potential Archive Bomb Attack with useless file content to take up disk and memory space!"
                    if archiveScanResult.startswith("Too Large Nested Archive Content!"):
                        reason = f"The archive/disk file {RootFileName} contains another embedded archive with an usual large compressed size! If the embedded archive was to be extracted, the uncompress size would be too large! Potential Archive Bomb!"
                    if archiveScanResult.startswith("Matryoshka Archive"):
                        reason = f"The archive/disk file {RootFileName} contains many other embedded archives and disk images! A technique known as Matryoshka Doll to attempt to hide malicious payload in many archive layers!"
                    logMessage += f"- **Reason:** `{reason}`\n"
                    return FileScanResult(RootFileName, "malicious", CyberbotFileScanMessageFormat(reason, "MALICIOUS", RootFileName, RootFileTrueExt, f"{FullContentLength:,} bytes"), logMessage, RootFileHashed)
                else:
                    logMessage += f"- **Scan Result:** `UNVERIFIED`\n"
                    reason = ""
                    if archiveScanResult.startswith("Scan Too Long!"):
                        reason = f"The extract and inspect process of the archive/disk file {RootFileName} took too long! Cyberbot can not verify if the content is malicious or not!"
                    if archiveScanResult.startswith("Disk Image Too Large!"):
                        reason = f"The disk image file {RootFileName} too large for Cyberbot to scan! Can not verify if the content is malicious or not!"
                    if archiveScanResult.startswith("Disk Image Error!"):
                        reason = f"The disk image file {RootFileName} cannot be extracted or inspected. Can not verify if the content is malicious or not!"
                    if archiveScanResult.startswith("Encrypted Error"):
                        reason = f"The archive/disk file {RootFileName} is encrypted and its contents cannot be inspected. Can not verify if the content is malicious or not!"
                    if archiveScanResult.startswith("Overlay Disk Image Error!"):
                        reason = archiveScanResult.split(":")[1]
                    if archiveScanResult.startswith("Empty Disk Image Error!"):
                        reason = f"The disk image file {RootFileName} is empty!"
                    if archiveScanResult.startswith("Too Many Snap Shots!"):
                        reason = f"The disk image file {RootFileName} contains too many snapshots, so Cyberbot can not accurately scan the disk image content!"
                    logMessage += f"- **Reason:** `{reason}`\n"
                    return FileScanResult(RootFileName, "unverified", CyberbotFileScanMessageFormat(reason, "UNVERIFIED", RootFileName, RootFileTrueExt, f"{FullContentLength:,} bytes"), logMessage, RootFileHashed)
            else:
                logMessage += f"## Analyzing Uncompressed File Content Within Scope\n"
                sendingMessage += f"The file {RootFileName} uncompressed content is being analyzed.\n"
                if message is not None and not isSilent:
                    await sendFileScanProgress(message, RootFileName, f"# Safe Extraction Analysis Report For {RootFileName}\n\n"
                                                                      f"- **Total Uncompressed Size**: {uncompressedSize:,} bytes\n"
                                                                      f"- **Total File Count**: {totalFileCount:,}\n"
                                                                      f"- **Total Duplicated File**: {totalDuplicatedFile:,}\n"
                                                                      f"- **Total Duplicated Archive/Disk Image**: {totalDuplicatedArchive:,}\n"
                                                                      f"- **Uncompression Progress NOTES:**\n{notes}"
                                                                      f"# Uncompressed File Structure\n"
                                                                      f"```\n"
                                                                      f"{ufs}\n"
                                                                      f"```")
                    await sendFileScanProgress(message, RootFileName, f"The file {RootFileName} uncompressed content is being analyzed. This may take quite some time.")
        else:
            isArchive = False
            shutil.move(filePath, tempScanFolder)


        filePaths = [os.path.join(dirpath, filename) for dirpath, _, filenames in os.walk(tempScanFolder) for filename in filenames]

        CompiledHashedMap = {}

        """Start scanning for the extracted file contents at mountPoint with Virus Total"""
        for filepath in filePaths:
            if os.path.islink(filepath) or os.path.realpath(filepath) != os.path.abspath(filepath):
                await addingHashedData(RootFileHashed, RootFileTrueExt, True)
                logMessage += (f"- **Scan Result:** `MALICIOUS`\n"
                               f"- **Reason:** `The archive/disk image file {RootFileName} contains a file acts as an unsafe symbolic link {filepath}`\n")
                return FileScanResult(RootFileName, "malicious", CyberbotFileScanMessageFormat(f"The archive/disk image file {RootFileName} contains a file acts as an unsafe symbolic link {filepath}", "MALICIOUS", RootFileName, RootFileTrueExt, f"{FullContentLength:,} bytes"), logMessage, RootFileHashed)
            filename = os.path.basename(filepath)
            HashedFileData = await checkingHashFromDisk(filepath)
            fileExt = await checkingFileExtensionFromDisk(filepath, filename)
            if HashedFileData != RootFileHashed:
                logMessage += (f"- **Uncompressed File Name:** `{filename.split("_")[-1]}`\n"
                           f"- **Uncompressed File Size:** `{os.path.getsize(filepath):,} bytes`\n"
                           f"- **Uncompressed File SHA-256 Hash:** `{HashedFileData}`\n"
                           f"- **Uncompressed File True Extension:** `{fileExt}`\n")
                async with hashedScanLock("file:" + HashedFileData):
                    if await checkingFlaggedMaliciousData(HashedFileData, "All Extension"):
                        print(f"File {filename} content already flagged malicious!")
                        await addingHashedData(RootFileHashed, RootFileTrueExt, True)
                        logMessage += (f"- **Scan Result:** `MALICIOUS`\n"
                                       f"- **Reason:** `File content already flagged Malicious from Cyberbot scan history!`\n")
                        return FileScanResult(RootFileName, "malicious", CyberbotFileScanMessageFormat(f"File {RootFileName} contains another file {filename} already flagged Malicious from Cyberbot scan history!", "MALICIOUS", RootFileName, RootFileTrueExt, f"{FullContentLength:,} bytes"), logMessage, RootFileHashed)
                    elif await checkingCleanData(HashedFileData, "All Extension"):
                        print(f"File {filename} content already passed previous scan, skip Virus Total scanning!")
                        logMessage += f"- **Virus Total Scan Result:** `SKIPPED - The file content SHA-256 hash already passed previous scan`\n"
                    else:
                        print(f"Start scanning {filename} contents with Virus Total...")
                        virusTotalResult = await virusTotalFileScan(filepath)
                        if virusTotalResult.startswith("Error"):
                            logMessage += f"- **Virus Total Scan Result:** `{virusTotalResult}`\n"
                            unverifiedReasons += f"`\n- **Virus Total Scan Result For {filename} inside file {RootFileName}:** `An Error Occurred While Scanning File Content`"
                        else:
                            try:
                                virusTotalResult = virusTotalResult.split(":")
                                virusTotalReport = f"{virusTotalResult[0]} Malicious, {virusTotalResult[1]} Suspicious, {virusTotalResult[2]} Harmless, {virusTotalResult[3]} Undetected"
                                if not isSilent or int(virusTotalResult[0]) > 0 or int(virusTotalResult[1]) > 0:
                                    await sendFileScanProgress(message, RootFileName, f"Virus Total Report for {filename} inside file {RootFileName}: {virusTotalReport}")
                                logMessage += f"- **Virus Total Scan Result:** `{virusTotalReport}`\n"
                                if int(virusTotalResult[0]) > 0:
                                    print(f"One or more scan engine from Virus Total scan flagged the file content as malicious!")
                                    await addingHashedData(HashedFileData, fileExt, True)
                                    await addingHashedData(RootFileHashed, RootFileTrueExt, True)
                                    logMessage += (f"- **Scan Result:** `MALICIOUS`\n"
                                                   f"- **Reason:** `One or more scan engine from Virus Total scan flagged the file content as malicious!`\n")
                                    return FileScanResult(RootFileName, "malicious", CyberbotFileScanMessageFormat(f"One or more scan engine from Virus Total scan flagged the file content {filename} inside {RootFileName} as malicious!`\n**Virus Total Scan Report:** `{virusTotalReport}", "MALICIOUS", RootFileName, RootFileTrueExt, f"{FullContentLength:,} bytes"), logMessage, RootFileHashed)
                                if int(virusTotalResult[1]) > 0:
                                    print(f"One or more scan engine from Virus Total scan flagged the file content as suspicious!")
                                    logMessage += f"- **Virus Total Scan Note:** `One or more scan engine from Virus Total scan flagged the file content as suspicious!`\n"
                                    unverifiedReasons += f"\n- **Virus Total Scan Result For {filename} inside file {RootFileName}:** `One or more scan engine from Virus Total scan for {filename} inside file {RootFileName} flagged the file content as suspicious!`"
                                elif fileExt not in SUPPORTED_SCRIPT_FILE_FORMATS and fileExt not in SUPPORTED_EXECUTABLE_FILE_FORMATS:
                                    await addingHashedData(HashedFileData, fileExt, False)
                            except (ValueError, IndexError):
                                logMessage += f"- **Virus Total Scan Result:** `Return An Invalid Response`\n"
                                unverifiedReasons += f"\n- **Virus Total Scan Result For {filename} inside file {RootFileName}:** `VirusTotal returned an invalid response!`"

            LLMScat = False
            if fileExt in SUPPORTED_EXECUTABLE_FILE_FORMATS:
                """Decompiling Binary File"""
                print(f"Found compiled/executable/binary file: {filename} | Type: {fileExt}")
                async with GHIDRA_SEMAPHORE:
                    outputFilePath = await asyncio.to_thread(ghidraDecompile, filepath, tempScanFolder, filename)
                if outputFilePath != "ERROR" and os.path.isfile(outputFilePath):
                    logMessage += (f"- **Ghidra Decompilation Result:** `Successfully decompile binary file {f'{filename} inside file {RootFileName}' if isArchive else filename} for LLM Assisted Static Analysis`\n"
                                   f"- **Decompiled File Name:** `{os.path.basename(outputFilePath)}`\n")
                    HashedDecompiledData = await checkingHashFromDisk(outputFilePath)
                    CompiledHashedMap[HashedFileData] = HashedDecompiledData
                    filepath = outputFilePath
                    LLMScat = True
                else:
                    logMessage += f"- **Ghidra Decompilation Result:** `Error decompiling binary file {f'{filename} inside file {RootFileName}' if isArchive else filename}`\n"
                    unverifiedReasons += f"\n- **Decompilation Error For Binary File {f'{filename} inside file {RootFileName}' if isArchive else filename}:** `Cyberbot can not decompile the binary for further static analysis`"
            elif fileExt in SUPPORTED_SCRIPT_FILE_FORMATS:
                LLMScat = True
            else:
                logMessage += (f"- **Scan Result:** `CLEAN`\n"
                               f"- **Reason:** `File passed all VirusTotal scan engine analysis as clean!`\n")

            if LLMScat:
                filename = os.path.basename(filepath)
                HashedScriptFileData = await checkingHashFromDisk(filepath)
                print(f"Found script file: {filename} | Type: {fileExt}")
                """SCAT Process with OpenAI and Gemini LLMs"""
                pdfPath = os.path.splitext(filepath)[0] + ".pdf"
                async with aiofiles.open(filepath, "rb") as source:
                    fileBytesContent = await source.read(500_000_001)
                if len(fileBytesContent) > 500_000_000:
                    pdfPath = None
                else:
                    print(f"Converting script file {filename} to PDF...")
                    await asyncio.to_thread(txtToPDFConversion, fileBytesContent.decode("utf-8", errors="replace"), pdfPath)
                    if not os.path.isfile(pdfPath):
                        logMessage += f"- **PDF Conversion:** `The file {filename} was converted to PDF file {os.path.basename(pdfPath)}`\n"
                        pdfPath = None

                flaggedMalicious = False
                LLMModel = ""
                LLMResult = ""
                LLMVerified = False

                '''
                print(f"Start OpenAI Model {GPT_MODEL} scan on file {filename} for malware analysis...")
                async with OPENAI_SEMAPHORE:
                    GptScanResult, logMessage = await openAISCAT(pdfPath, logMessage) if pdfPath else "MAXIMUM INPUT TOKEN LIMIT"
                if GptScanResult.startswith(("True", "true")):
                    flaggedMalicious, LLMModel, LLMResult = True, GPT_MODEL, GptScanResult
                elif GptScanResult.startswith(("False", "false")):
                    LLMVerified = True
                elif GptScanResult == "MAXIMUM INPUT TOKEN LIMIT":
                    async with OPENAI_SEMAPHORE:
                        flaggedMalicious, GptScanResult, logMessage = await partialLLMSCAT(filepath, logMessage, "OpenAI")
                    if flaggedMalicious:
                        LLMModel, LLMResult = GPT_MODEL, GptScanResult
                    elif GptScanResult == "Nothing Malicious":
                        LLMVerified = True
                logMessage += "\n---\n\n"
                '''

                if not flaggedMalicious:
                    print(f"Start Gemini Model {GEMINI_MODEL} scan on file {filename} for malware analysis...")
                    async with GEMINI_SEMAPHORE:
                        GeminiScanResult, logMessage = await GeminiSCAT(pdfPath, logMessage) if pdfPath else "MAXIMUM INPUT TOKEN LIMIT"
                    if GeminiScanResult.startswith(("True", "true")):
                        flaggedMalicious, LLMModel, LLMResult = True, GEMINI_MODEL, GeminiScanResult
                    elif GeminiScanResult.startswith(("False", "false")):
                        LLMVerified = True
                    elif GeminiScanResult == "MAXIMUM INPUT TOKEN LIMIT":
                        async with GEMINI_SEMAPHORE:
                            flaggedMalicious, GeminiScanResult, logMessage = await partialLLMSCAT(filepath, logMessage, "Gemini")
                        if flaggedMalicious:
                            LLMModel, LLMResult = GEMINI_MODEL, GeminiScanResult
                        elif GeminiScanResult == "Nothing Malicious":
                            LLMVerified = True

                if flaggedMalicious:
                    logMessage += (f"- **Scan Result:** `MALICIOUS`\n"
                                   f"- **Reason:** `{LLMModel} Static Analysis on file content flagged malicious!`\n")
                    if HashedScriptFileData != RootFileHashed:
                        await addingHashedData(HashedScriptFileData, fileExt, True)
                    await addingHashedData(RootFileHashed, RootFileTrueExt, True)
                    for HashedData, mappedHash in CompiledHashedMap.items():
                        if mappedHash == HashedScriptFileData and HashedData != RootFileHashed:
                            await addingHashedData(HashedData, ".exe", True)
                    return FileScanResult(RootFileName, "malicious", CyberbotFileScanMessageFormat(f"{LLMModel} analyzed {f'decompiled {filename} inside file {RootFileName}' if isArchive else filename} as potential malware!`\n- **LLM SCAT RESULT:**\n{LLMResult}", "MALICIOUS", RootFileName, RootFileTrueExt, f"{FullContentLength:,} bytes"), logMessage, RootFileHashed)


                if LLMVerified:
                    await addingHashedData(HashedScriptFileData, fileExt, False)
                    for HashedData, mappedHash in CompiledHashedMap.items():
                        if mappedHash == HashedScriptFileData and HashedData != RootFileHashed:
                            await addingHashedData(HashedData, ".exe", False)
                    logMessage += (f"- **Scan Result:** `CLEAN`\n"
                                   f"- **Reason:** `File passed VirusTotal and LLM SCAT analysis as clean!`\n")
                else:
                    unverifiedReasons += f"\n- **LLM SCAT Analysis Of {f'Decompiled {filename} inside file {RootFileName}' if isArchive else filename}:** `LLM Static Analysis result as inconclusive`"


            logMessage += "\n---\n\n"

        if unverifiedReasons:
            return FileScanResult(RootFileName, "unverified", CyberbotFileScanMessageFormat(unverifiedReasons, "UNVERIFIED", RootFileName, RootFileTrueExt, f"{FullContentLength:,} bytes"), logMessage, RootFileHashed)
        await addingHashedData(RootFileHashed, RootFileTrueExt, False)
        return FileScanResult(RootFileName, "clean",CyberbotFileScanMessageFormat(f"The file {RootFileName} is safe to download!", "CLEAN", RootFileName, RootFileTrueExt,f"{FullContentLength:,} bytes"), logMessage, RootFileHashed)
