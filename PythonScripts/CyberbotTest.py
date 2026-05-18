import os
import random
import shutil
import subprocess
import zipfile
import tarfile
import gzip
import rarfile  # Need pip install rarfile and brew install unar
import bz2
import lzma  # Need brew install qemu libguestfs
import filetype
import magic
import mimetypes
import hashlib


ARCHIVEFILEFORMATS = (".zip", ".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lzma", ".tgz", ".tbz2", ".txz", ".gz",
                         ".rar", ".bz2", ".xz", ".lzma")

DISKIMAGEANDARCHIVEFORMATS = (".dmg", ".iso", ".img", ".vhd", ".nrg", ".vhdx", ".vmdk", ".qcow", ".qcow2", ".udf",
                                 ".zip", ".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lzma", ".tgz", ".tbz2", ".txz",
                                 ".gz", ".rar", ".bz2", ".xz", ".lzma")
ENCRYPTEDFILEFORMATS = (".enc", ".aes", ".pgp", ".gpg", ".vault")

EXECUTABLEFORMATS = ("Mach-O executable", "ELF executable", ".exe", ".dll", ".dex", ".jar", ".bin")

SCRIPTFILEFORMATS = (".sh", ".zsh", "ASCII document or script files", ".txt", ".c")

DOCUMENTFILEFORMATS = (".pdf",  ".docx", ".doc")

PICTUREFORMATS = (".jpg", ".png", ".jpeg", ".raw", ".bmp", ".webp", ".tiff", ".tif", ".ico", ".icns", ".avif", ".odd",
                  ".heic", ".svg", ".eps", ".gif", ".ps", ".psd")

VIDEOFORMATS = (".mp4", ".mov", ".mkv", ".avi", ".m4v", ".flv", ".mpeg", ".mpg", ".ts", ".wmv", ".3gp",
                ".3g2", ".3gpp", ".cavs", ".dv", ".dvr", ".mod", ".mts", ".m2ts", ".mxf", ".rm", ".rmvb", ".swf",
                ".vob", ".ogv")

AUDIOFORMATS = (".mp3", ".wav", ".oga", ".m4a", ".flac", ".weba", ".aac", ".ac3", ".aif", ".aiff", ".aifc", ".amr",
                ".au", ".caf", ".dss", ".m4a", ".m4b", ".wma", ".opus", ".webm", ".ogg")
DOWNLOADINGDIRPATH = "/Users/davidnguyen/PycharmProjects/TheKnights/Cyberbot/DownloadDirectory/"
CYBERBOTSCOPEOFORMATS = DISKIMAGEANDARCHIVEFORMATS + ENCRYPTEDFILEFORMATS + EXECUTABLEFORMATS + AUDIOFORMATS + SCRIPTFILEFORMATS + DOCUMENTFILEFORMATS + PICTUREFORMATS + VIDEOFORMATS

def ArchivesDiskImagesBombAnalysisAndExtraction(filePath: list, mountPoint: str, archiveLayer=0):
    def checkingFileExtension(fileContent: bytes):
        mime = magic.from_buffer(fileContent, mime=True)
        Ext = mimetypes.guess_extension(mime)
        if Ext:
            if Ext == ".bin":
                if fileContent.startswith(b'PK'):
                    return '.zip'
                elif len(fileContent) > 512:
                    Last512bytes = fileContent[-512:]
                    if b'conectix' in Last512bytes:
                        return '.vhd'
                    elif b'koly' in Last512bytes or Last512bytes.startswith(b'EFI PART') or fileContent.startswith(
                            b'EFI PART'):
                        return '.dmg'
                    else:
                        return ".bin"
            return Ext
        else:
            if fileContent.startswith(b'QFI\xfb'):
                return ".qcow2"
            elif fileContent.startswith(b'vhdxfile'):
                return ".vhdx"
            elif fileContent.startswith(b'KDMV'):
                return ".vmdk"
            elif fileContent[32768:32768 + 5].startswith((b"NSR02", b"NSR03")):
                return '.udf'
            else:
                Ext = filetype.guess(fileContent)
                if Ext:
                    return f".{Ext.extension}"
                else:
                    return "Can't be determined"
    NESTEDARCHIVESIZELIMIT = 1000000000
    UNCOMPRESSEDSIZELIMIT = 32000000000
    CHUNKSIZE = 5000000000  # Read file to RAM content every 5 GB
    DUPLICATEDARCHIVELIMIT = 3
    shutil.copy(filePath[0], mountPoint)
    filePath[0] = f"{mountPoint}{os.path.basename(filePath[0])}"
    with open(filePath[0], 'rb') as rootFile:
        DuplicatedFileDetection = [hashlib.sha256(rootFile.read()).hexdigest()]
    uncompressedSize = os.path.getsize(filePath[0])
    totalDuplicatedFile = 0
    totalDuplicatedArchive = 0
    totalFileCount = 0
    while len(filePath) != 0:
        if archiveLayer == 7:
            print(f"The root archive/disk file has 7 or more nested layers, hinted potential archive bomb!")
            return "Potential Archive Bomb!"
        print(f"Current Archive/Disk paths:\n{filePath}")
        for i in range(len(filePath)):
            if uncompressedSize >= UNCOMPRESSEDSIZELIMIT:
                print(f"The total uncompressed size has reached the limit threshold!")
                return "Potential Archive Bomb!"
            with open(filePath[i], "rb") as ArchiveDiskSource:
                ArchiveDiskContent = ArchiveDiskSource.read()
            fileExt = checkingFileExtension(ArchiveDiskContent)
            if fileExt.endswith((".xz", ".bz2", ".lzma", ".gz")) and os.path.basename(filePath[i]).endswith((".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lzma", ".tgz", ".tbz2", ".txz")):
                fileExt = os.path.basename(filePath[i])
            if fileExt == "Can't be determined" and filePath[i].endswith(".lzma"):
                fileExt = ".lzma"
            if not fileExt.endswith(ARCHIVEFILEFORMATS):
                print(f"Scanning disk image file: {os.path.basename(filePath[i])} at path {filePath[i]}...")
                TempDiskMountPoint = f"{DOWNLOADINGDIRPATH}{os.path.basename(filePath[i]).split('.')[0]}MountPoint{random.randint(1, 100000)}/"
                if fileExt.endswith((".dmg", ".img", ".udf")):
                    print("Disk image in .dmg, .img, and .udf category")
                    print("Checking if disk image is encrypted...")
                    checkEncryptedDiskfile = subprocess.run(["hdiutil", "isencrypted", filePath[i]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    checkEncryptedDiskfile = checkEncryptedDiskfile.stdout + checkEncryptedDiskfile.stderr
                    if "encrypted: YES" in checkEncryptedDiskfile:
                        print(f"Disk image {os.path.basename(filePath[i])} is encrypted!")
                        return "Encrypted Error"
                    else:
                        print("Disk image is not encrypted!")
                        print("Getting mount point using hdiutil...")
                        try:
                            subprocess.run(["hdiutil", "attach", filePath[i], "-mountpoint", TempDiskMountPoint], check=True)
                        except subprocess.CalledProcessError:
                            print(f"Failed to mount disk image {os.path.basename(filePath[i])}")
                            return "Disk Image Error!"
                        print(f"Extracting content in mount point {TempDiskMountPoint} to main scan directory...")
                elif fileExt.endswith((".iso", ".nrg", ".vhd", ".vhdx", ".qcow2", ".vmdk", ".qcow")):
                    if fileExt.endswith((".iso", ".nrg")):
                        print("Disk image in .iso and .nrg category")
                        print("Checking if disk image is encrypted...")
                        checkEncryptedDiskfile = subprocess.run(["7z", "l", filePath[i]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        checkEncryptedDiskfile = checkEncryptedDiskfile.stdout + checkEncryptedDiskfile.stderr
                        if "Enter password" in checkEncryptedDiskfile or "Headers Encrypted" in checkEncryptedDiskfile or "Encrypted = +" in checkEncryptedDiskfile:
                            print(f"Disk image {os.path.basename(filePath[i])} is encrypted!")
                            return "Encrypted Error"
                        else:
                            print("Disk image is not encrypted!")
                    else:
                        print("Disk image in .vhd, .vhdx, .qcow2, .qcow, and .vmdk category")
                        print("Checking if disk image is encrypted...")
                        checkEncryptedDiskfile = subprocess.run(["qemu-img", "info", filePath[i]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        checkEncryptedDiskfile = checkEncryptedDiskfile.stdout + checkEncryptedDiskfile.stderr
                        if "encrypted: yes" in checkEncryptedDiskfile:
                            print(f"Disk image {os.path.basename(filePath[i])} is encrypted!")
                            return "Encrypted Error"
                        else:
                            print("Disk image is not encrypted!")
                            RawFilePath = f"{DOWNLOADINGDIRPATH}{os.path.basename(filePath[i]).split('.')[0]}.img"
                            print(f"Converting disk format to raw .img disk format using qemu-img...")
                            try:
                                subprocess.run(["qemu-img", "convert", "-O", "raw", filePath[i], RawFilePath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                            except subprocess.CalledProcessError:
                                print("Failed to convert disk to raw format using qemu-img")
                                return "Disk Image Error!"
                            print(f"Raw disk format converted, begin extracting content to main scan directory...")
                            os.remove(filePath[i])
                            filePath[i] = RawFilePath
                    os.mkdir(TempDiskMountPoint)
                    print(f"Extracting the disk content using  7z command...")
                    try:
                        subprocess.run(["7z", "x", filePath[i], f"-o{TempDiskMountPoint}", "-y"], stdout=subprocess.DEVNULL, check=True)
                        print(f"Content extracted to temp mount point {TempDiskMountPoint}")
                    except subprocess.CalledProcessError:
                        print(f"Failed to extract content from disk image {filePath[i]}\n")
                        pass
                for dirpath, _, filenames in os.walk(TempDiskMountPoint):
                    for filename in filenames:
                        totalFileCount += 1
                        filepath = os.path.join(dirpath, filename)
                        with open(filepath, "rb") as source:
                            fileData = source.read()
                            hashedData = hashlib.sha256(fileData).hexdigest()
                        if not hashedData in DuplicatedFileDetection:
                            if not filename.startswith("._") and "__MACOSX" not in filepath and not ".DS_Store" in filename:
                                if checkingFileExtension(fileData).endswith(CYBERBOTSCOPEOFORMATS):
                                    shutil.copy(filepath, mountPoint)
                                    print(f"{filename} is written from path {filepath} to path {mountPoint}{filename}!")
                            DuplicatedFileDetection.append(hashedData)
                        else:
                            totalDuplicatedFile += 1
                            if checkingFileExtension(fileData).endswith(DISKIMAGEANDARCHIVEFORMATS):
                                totalDuplicatedArchive += 1
                                print(f"Duplicated archive/disk file at path {filepath}")
                                if totalDuplicatedArchive >= DUPLICATEDARCHIVELIMIT:
                                    return "Potential Recursive Archive Bomb Attack!"
                            else:
                                print(f"Duplicated file at path {filepath}")
                if fileExt.endswith((".dmg", "img", ".udf")):
                    print(f"Unmounting temp mount point {TempDiskMountPoint}...")
                    subprocess.run(['hdiutil', 'detach', TempDiskMountPoint])
                else:
                    print(f"Removing temp mount point {TempDiskMountPoint}...")
                    shutil.rmtree(TempDiskMountPoint)
                if totalFileCount // (totalDuplicatedFile + 1) <= 0.10:
                    return "Too many duplicated files!"
            else:
                print(f"Scanning Archive file: {os.path.basename(filePath[i])} at path {filePath[i]}...")
                if fileExt.endswith(".zip"):
                    print("Archive is a zip file!")
                    with zipfile.ZipFile(filePath[i], 'r') as zipRef:

                        """First Extraction Focusing On Checking Extraction Path and Directory Structure"""
                        for entry in zipRef.infolist():
                            DestinationPath = os.path.abspath(f"{mountPoint}{entry.filename}")
                            if not DestinationPath.startswith(mountPoint):
                                print(f"The uncompressed file name {entry.filename} formed an illegal path {DestinationPath} to cause directory transversal attack!")
                                return "Path Transversal Attack"
                            if "__MACOSX" not in DestinationPath and not os.path.basename(DestinationPath).startswith("._") and not ".DS_Store" in entry.filename:
                                totalFileCount += 1
                                if entry.filename.endswith('/') :
                                    os.makedirs(DestinationPath, exist_ok=True)
                                    print(f"Directory {entry.filename} created at path {DestinationPath}")
                            if totalFileCount // (totalDuplicatedFile + 1) <= 0.10:
                                return "Too many duplicated files!"

                        """Second Extraction Focusing On Extracting All the Compressed Files"""
                        for entry in zipRef.infolist():
                            if entry.filename.endswith('/'):
                                continue
                            DestinationPath = os.path.abspath(f"{mountPoint}{entry.filename}")
                            try:
                                with zipRef.open(entry, 'r') as source:
                                    if source is None:
                                        continue
                                    fileData = b''
                                    while True:
                                        Datachunk = source.read(CHUNKSIZE)
                                        if not Datachunk:
                                            break
                                        fileData += Datachunk
                                        uncompressedSize += len(Datachunk)
                                        if uncompressedSize >= UNCOMPRESSEDSIZELIMIT:
                                            print(f"The total uncompressed size has reached the limit threshold!")
                                            return "Potential Archive Bomb!"
                                if "__MACOSX" not in DestinationPath and not os.path.basename(DestinationPath).startswith("._") and not ".DS_Store" in entry.filename:
                                    hashedData = hashlib.sha256(fileData).hexdigest()
                                    if hashedData not in DuplicatedFileDetection:
                                        if checkingFileExtension(fileData).endswith(CYBERBOTSCOPEOFORMATS):
                                            with open(DestinationPath, 'wb') as f:
                                                f.write(fileData)
                                            print(f"{entry.filename} is written to path {DestinationPath}")
                                        DuplicatedFileDetection.append(hashedData)
                                    else:
                                        totalDuplicatedFile += 1
                                        if checkingFileExtension(fileData).endswith(DISKIMAGEANDARCHIVEFORMATS):
                                            totalDuplicatedArchive += 1
                                            print(f"Duplicated archive/disk file at path {DestinationPath}")
                                            if totalDuplicatedArchive >= DUPLICATEDARCHIVELIMIT:
                                                return "Potential Recursive Archive Bomb Attack!"
                                        else:
                                            print(f"Duplicated file {entry.filename} at path {DestinationPath}")
                                if totalFileCount // (totalDuplicatedFile + 1) <= 0.10:
                                    return "Too many duplicated files!"
                            except zipfile.BadZipFile as error:
                                print(f"Bad Zip File: {error}")
                                pass
                            except RuntimeError as e:
                                if 'password required' in str(e).lower():
                                    print("Zip file is encrypted!")
                                    return "Encrypted Error"
                                else:
                                    print(f"RunTimeError: {e}")
                                    pass
                            except OSError as error:
                                print(f"OSError: {error}")
                                pass
                elif fileExt.endswith((".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lzma", ".tgz", ".tbz2", ".txz")):
                    print("Archive is a tar file!")
                    with tarfile.open(filePath[i], 'r') as tarRef:

                        """First Extraction Focusing On Checking Extraction Path and Directory Structure"""
                        for entry in tarRef.getmembers():
                            DestinationPath = os.path.abspath(f"{mountPoint}{entry.name}")
                            if not DestinationPath.startswith(mountPoint):
                                print(f"The uncompressed file name {entry.name} formed an illegal path {DestinationPath} to cause directory transversal attack!")
                                return "Path Transversal Attack"
                            if "__MACOSX" not in DestinationPath and not os.path.basename( DestinationPath).startswith("._") and not ".DS_Store" in entry.name:
                                totalFileCount += 1
                                if "." not in entry.name:
                                    os.makedirs(DestinationPath, exist_ok=True)
                                    print(f"Directory {entry.name} created at path {DestinationPath}")
                            if totalFileCount // (totalDuplicatedFile + 1) <= 0.10:
                                return "Too many duplicated files!"

                        """Second Extraction Focusing On Extracting All the Compressed Files"""
                        for entry in tarRef.getmembers():
                            if "." not in entry.name:
                                continue
                            DestinationPath = os.path.abspath(f"{mountPoint}{entry.name}")
                            try:
                                with tarRef.extractfile(entry) as source:
                                    if source is None:
                                        continue
                                    fileData = b''
                                    while True:
                                        Datachunk = source.read(CHUNKSIZE)
                                        if not Datachunk:
                                            break
                                        fileData += Datachunk
                                        uncompressedSize += len(Datachunk)
                                        if uncompressedSize >= UNCOMPRESSEDSIZELIMIT:
                                            print(f"The total uncompressed size has reached the limit threshold!")
                                            return "Potential Archive Bomb!"
                                    if "__MACOSX" not in DestinationPath and not os.path.basename( DestinationPath).startswith("._") and not ".DS_Store" in entry.name:
                                        hashedData = hashlib.sha256(fileData).hexdigest()
                                        if hashedData not in DuplicatedFileDetection:
                                            if checkingFileExtension(fileData).endswith(CYBERBOTSCOPEOFORMATS):
                                                with open(DestinationPath, 'wb') as f:
                                                    f.write(fileData)
                                                print(f"{entry.name} is written to path {DestinationPath}")
                                            DuplicatedFileDetection.append(hashedData)
                                        else:
                                            totalDuplicatedFile += 1
                                            if checkingFileExtension(fileData).endswith(DISKIMAGEANDARCHIVEFORMATS):
                                                totalDuplicatedArchive += 1
                                                print(f"Duplicated archive/disk file at path {DestinationPath}")
                                                if totalDuplicatedArchive >= DUPLICATEDARCHIVELIMIT:
                                                    return "Potential Recursive Archive Bomb Attack!"
                                            else:
                                                print(f"Duplicated file at path {DestinationPath}")
                                    if totalFileCount // (totalDuplicatedFile + 1) <= 0.10:
                                        return "Too many duplicated files!"
                            except tarfile.TarError as error:
                                print(f"Tar file error: {error}")
                                pass
                            except OSError as error:
                                print(f"OSError: {error}")
                                pass
                elif fileExt.endswith(".rar"):
                    print("Archive is a rar file!")
                    with rarfile.RarFile(filePath[i], 'r') as rar:
                        if rar.needs_password():
                            print(f"Rar file {filePath[i]} required password!")
                            return "Encrypted Error"

                        """First Extraction Focusing On Checking Extraction Path and Directory Structure"""
                        for entry in rar.infolist():
                            if entry.needs_password():
                                print(f"Compressed file {entry.filename} required password!")
                                return "Encrypted Error"
                            DestinationPath = os.path.abspath(f"{mountPoint}{entry.filename}")
                            if not DestinationPath.startswith(mountPoint):
                                print(f"The uncompressed file name {entry.filename} formed an illegal path {DestinationPath} to cause directory transversal attack!")
                                return "Path Transversal Attack"
                            if "__MACOSX" not in DestinationPath and not os.path.basename(DestinationPath).startswith("._") and not ".DS_Store" in entry.filename:
                                totalFileCount += 1
                                if entry.filename.endswith('/'):
                                    os.makedirs(DestinationPath, exist_ok=True)
                                    print(f"Directory {entry.filename} created at path {DestinationPath}")
                            if totalFileCount // (totalDuplicatedFile + 1) <= 0.10:
                                return "Too many duplicated files!"

                        """Second Extraction Focusing On Extracting All the Compressed Files"""
                        for entry in rar.infolist():
                            DestinationPath = os.path.abspath(f"{mountPoint}{entry.filename}")
                            if entry.filename.endswith('/'):
                                continue
                            try:
                                with rar.open(entry, 'r') as source:
                                    if source is None:
                                        continue
                                    fileData = b''
                                    while True:
                                        Datachunk = source.read(CHUNKSIZE)
                                        if not Datachunk:
                                            break
                                        fileData += Datachunk
                                        uncompressedSize += len(Datachunk)
                                        if uncompressedSize >= UNCOMPRESSEDSIZELIMIT:
                                            print(f"The total uncompressed size has reached the limit threshold!")
                                            return "Potential Archive Bomb!"
                                if "__MACOSX" not in DestinationPath and not os.path.basename(DestinationPath).startswith("._") and not ".DS_Store" in entry.filename:
                                    hashedData = hashlib.sha256(fileData).hexdigest()
                                    if hashedData not in DuplicatedFileDetection:
                                        if checkingFileExtension(fileData).endswith(CYBERBOTSCOPEOFORMATS):
                                            with open(DestinationPath, 'wb') as f:
                                                f.write(fileData)
                                            print(f"{entry.filename} is written to path {DestinationPath}")
                                        DuplicatedFileDetection.append(hashedData)
                                    else:
                                        totalDuplicatedFile += 1
                                        if checkingFileExtension(fileData).endswith(DISKIMAGEANDARCHIVEFORMATS):
                                            totalDuplicatedArchive += 1
                                            print(f"Duplicated archive/disk file at path {DestinationPath}")
                                            if totalDuplicatedArchive >= DUPLICATEDARCHIVELIMIT:
                                                return "Potential Recursive Archive Bomb Attack!"
                                        else:
                                            print(f"Duplicated file {entry.filename} at path {DestinationPath}")
                                if totalFileCount // (totalDuplicatedFile + 1) <= 0.10:
                                    return "Too many duplicated files!"
                            except rarfile.BadRarFile as error:
                                print(f"Bad Rar File Error: {error}")
                                pass
                            except rarfile.NotRarFile as error:
                                print(f"Not Rar File Error: {error}")
                                pass
                            except OSError as error:
                                print(f"OSError: {error}")
                                pass
                elif fileExt.endswith((".gz", ".bz2", ".xz", ".lzma")):
                    totalFileCount += 1
                    try:
                        fileName = os.path.basename(filePath[i]).rsplit(fileExt, 1)[0]
                        DestinationPath = os.path.abspath(f"{mountPoint}{fileName}")
                        if not DestinationPath.startswith(mountPoint):
                            print(f"The uncompressed file name {fileName} formed an illegal path {DestinationPath} to cause directory transversal attack!")
                            return "Path Transversal Attack"
                        fileData = b''
                        if fileExt.endswith(".bz2"):
                            print("Archive is a bz2 file!")
                            with bz2.BZ2File(filePath[i], 'rb') as bz2File:
                                while True:
                                    dataChunk = bz2File.read(CHUNKSIZE)
                                    if not dataChunk or len(fileData) >= UNCOMPRESSEDSIZELIMIT:
                                        break
                                    fileData += dataChunk
                        elif fileExt.endswith(".gz"):
                            print("Archive is a gzip file!")
                            with gzip.open(filePath[i], 'rb') as gzipRef:
                                while True:
                                    dataChunk = gzipRef.read(CHUNKSIZE)
                                    if not dataChunk or len(fileData) >= UNCOMPRESSEDSIZELIMIT:
                                        break
                                    fileData += dataChunk
                        elif fileExt.endswith((".xz", ".lzma")):
                            print("Archive is in xz and lzma category!")
                            with lzma.open(filePath[i], 'rb') as lzFile:
                                while True:
                                    dataChunk = lzFile.read(CHUNKSIZE)
                                    if not dataChunk or len(fileData) >= UNCOMPRESSEDSIZELIMIT:
                                        break
                                    fileData += dataChunk
                        uncompressedSize += len(fileData)
                        if uncompressedSize >= UNCOMPRESSEDSIZELIMIT:
                            print(f"The total uncompressed size has reached the limit threshold!")
                            return "Potential Archive Bomb!"
                        fileExt = checkingFileExtension(fileData)
                        if fileExt == "Can't be determined" and filePath[i].endswith(".lzma"):
                            fileExt = ".lzma"
                        if fileExt.endswith(ARCHIVEFILEFORMATS):
                            DestinationPath += fileExt
                        hashedData = hashlib.sha256(fileData).hexdigest()
                        if hashedData not in DuplicatedFileDetection:
                            if checkingFileExtension(fileData).endswith(CYBERBOTSCOPEOFORMATS):
                                with open(DestinationPath, "wb") as file:
                                    file.write(fileData)
                                print(f"{fileName} is written to path {DestinationPath}")
                            DuplicatedFileDetection.append(hashedData)
                        else:
                            totalDuplicatedFile += 1
                            if checkingFileExtension(fileData).endswith(DISKIMAGEANDARCHIVEFORMATS):
                                totalDuplicatedArchive += 1
                                print(f"Duplicated archive/disk file at path {DestinationPath}")
                                if totalDuplicatedArchive >= DUPLICATEDARCHIVELIMIT:
                                    return "Potential Recursive Archive Bomb Attack!"
                            else:
                                print(f"Duplicated file at path {DestinationPath}")
                        if totalFileCount // (totalDuplicatedFile + 1) <= 0.10:
                            return "Too many duplicated files!"
                    except OSError as error:
                        print(f"OSError: {error}")
                        pass
                    except lzma.LZMAError:
                        print(f"LZMAError: {error}")
                        pass
            os.remove(filePath[i])
            print("\n\n")

        archiveLayer += 1
        filePath.clear()
        for dirpath, _, filenames in os.walk(mountPoint):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                with open(filepath, "rb") as file:
                    fileData = file.read()
                fileExt = checkingFileExtension(fileData)
                if fileExt == "Can't be determined" and filepath.endswith(".lzma"):
                    fileExt = ".lzma"
                if fileExt.endswith(DISKIMAGEANDARCHIVEFORMATS):
                    print(f"Found nested {fileExt} Archive/Image file {filename} at path {filepath}")
                    if os.path.getsize(filepath) >= NESTEDARCHIVESIZELIMIT:
                        print(f"The nested file {filename} size is {os.path.getsize(filepath)}. The number is too large, thus, hinted potential archive bomb!")
                        return "Potential Archive Bomb!"
                    filePath.append(filepath)
    uncompressedSize = str(uncompressedSize)
    betterFormat = ''
    for i in range(len(uncompressedSize)):
        if (i + 1) % 3 == 0:
            betterFormat = f",{uncompressedSize[len(uncompressedSize) - (i + 1)]}{betterFormat}"
        else:
            betterFormat = f"{uncompressedSize[len(uncompressedSize) - (i + 1)]}{betterFormat}"
    if betterFormat.startswith(','):
        betterFormat = betterFormat[1:]
    print(f"Archive and Disk Image content extracted with total uncompressed size of {betterFormat} bytes")
    return f"{betterFormat}|{totalDuplicatedFile}"

# print(ArchivesDiskImagesBombAnalysisAndExtraction(["/Users/davidnguyen/PycharmProjects/TheKnights/TestItems/ExecutableFiles/ActualSafePrograms.zip"], "/Users/davidnguyen/PycharmProjects/TheKnights/Cyberbot/DownloadDirectory/"))
from fpdf import FPDF
filepath = "/Users/davidnguyen/PycharmProjects/TheKnights/TestItems/ScriptFiles/udemy.html"
filename = os.path.basename(filepath)
print(f"Converting script file {filename} to PDF...")
pdf = FPDF()
pdf.add_page()
pdf.set_font("Arial", size=12)
pdfpath = f"{filepath.split(".")[0]}.pdf"
with open(filepath, "r", encoding="utf-8") as SourceCodefile:
    pdf.multi_cell(0, 10, (SourceCodefile.read()).encode("latin-1",errors="replace").decode("latin-1"))
    pdf.output(pdfpath)
    filepath = pdfpath
print(f"Conversion successes!")