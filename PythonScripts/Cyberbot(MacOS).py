import os
import random
import re
import shutil
import smtplib, ssl
import requests
import discord

from discord import app_commands
from discord.ext import commands, tasks
from typing import Literal
from dotenv import load_dotenv
from email.message import EmailMessage
from io import BytesIO
from openai import OpenAI
from google import genai  # Need pip install google-genai
from fpdf import FPDF # Need pip install fpdf
from transformers import BertTokenizer, LongformerTokenizer # Need pip install transformers
from EncoderTransformers import loadClassifierModel, Prediction
# Need brew install qemu-utils

import subprocess
import json
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
import time
import asyncio
import pyhidra # Need pip install pyhidra



"""This version following DAC access control, where each member can have admin account with Cyberbot granted by the Server Owner"""

load_dotenv()

"""----Configuration Constants----"""
ARCHIVEFILEFORMATS = (".zip", ".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lzma", ".tgz", ".tbz2", ".txz", ".gz",
                         ".rar", ".bz2", ".xz", ".lzma")

DISKIMAGEANDARCHIVEFORMATS = (".dmg", ".iso", ".img", ".vhd", ".nrg", ".vhdx", ".vmdk", ".qcow", ".qcow2", ".udf",
                                 ".zip", ".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lzma", ".tgz", ".tbz2", ".txz",
                                 ".gz", ".rar", ".bz2", ".xz", ".lzma")
ENCRYPTEDFILEFORMATS = (".enc", ".aes", ".pgp", ".gpg", ".vault")

EXECUTABLEFORMATS = ("Mach-O executable", "ELF executable", ".exe", ".dll", ".dex", ".jar", ".bin")

SCRIPTFILEFORMATS = (".sh", ".zsh", "ASCII document or script files", ".txt")

DOCUMENTFILEFORMATS = (".pdf",  ".docx", ".doc")

PICTUREFORMATS = (".jpg", ".png", ".jpeg", ".raw", ".bmp", ".webp", ".tiff", ".tif", ".ico", ".icns", ".avif", ".odd",
                  ".heic", ".svg", ".eps", ".gif", ".ps", ".psd")

VIDEOFORMATS = (".mp4", ".mov", ".mkv", ".avi", ".m4v", ".flv", ".mpeg", ".mpg", ".ts", ".wmv", ".3gp",
                ".3g2", ".3gpp", ".cavs", ".dv", ".dvr", ".mod", ".mts", ".m2ts", ".mxf", ".rm", ".rmvb", ".swf",
                ".vob", ".ogv")

AUDIOFORMATS = (".mp3", ".wav", ".oga", ".m4a", ".flac", ".weba", ".aac", ".ac3", ".aif", ".aiff", ".aifc", ".amr",
                ".au", ".caf", ".dss", ".m4a", ".m4b", ".wma", ".opus", ".webm", ".ogg")

labels = {
    "Phishing":
        {
            "0": "Safe Email",
            "1": "Phishing Email"
        },
    "Spam":
        {
            "0": "Spam Email",
            "1": "Work Email",
            "2": "Social Email",
            "3": "Promotion Email",
            "4": "Finance Email"
    }
}

CYBERBOTSCOPEOFORMATS = DISKIMAGEANDARCHIVEFORMATS + ENCRYPTEDFILEFORMATS + EXECUTABLEFORMATS + AUDIOFORMATS + SCRIPTFILEFORMATS + DOCUMENTFILEFORMATS + PICTUREFORMATS + VIDEOFORMATS

LIMITFILESCANPERUSER = 100
CONFIGJSONFILEPATH = os.environ.get("CYBERBOTCONFIGPATH")
DOWNLOADINGDIRPATH = os.environ.get("DOWNLOADPATH")
LOGCOMMANDFILEPATH = os.environ.get("CYBERBOTLOGPATH")
RESETPASSWORDTOKENPATH = os.environ.get("RESETPASSWORDTOKENPATH")
USERFILESCANPROCESSPATH = os.environ.get("USERCURRENTFILESCANPATH")
GHIDRAPROJECTPATH = os.environ.get("GHIDRAPROJECTPATH")
GHIDRAPROJECTNAME = os.environ.get("GHIDRAPROJECTNAME")
CLEANSIGNATURESPATH = os.environ.get("CYBERBOTCLEANSIGNATURES")
MALISCIOUSSIGNATUREPATH = os.environ.get("CYBERBOTMALICIOUSSIGNATURES")
SCATLOGS = os.environ.get("CYBERBOTMLLOGS")
SCANLOG = os.environ.get("CYBERBOTSCANLOGS")
HEADERSFORPARTIALCONTENT = {'User-Agent': 'Mozilla / 5.0(Windows NT 10.0; Win64; x64) AppleWebKit / 537.36(KHTML, likeGecko) Chrome / 142.0.0.0 Safari / 537.36', "Range": "bytes=0-1000000"}
MAINHEADERS = {'User-Agent': 'Mozilla / 5.0(Windows NT 10.0; Win64; x64) AppleWebKit / 537.36(KHTML, likeGecko) Chrome / 142.0.0.0 Safari / 537.36'}
BERTPHISHINGPATH = os.environ.get("BERTPHISHINGPATH")
ALLENAIPHISHINGPATH = os.environ.get("ALLENAIPHISHINGPATH")
BERTPASSWORDPATH = os.environ.get("BERTPASSWORDPATH")
ALLENAIPASSWORDPATH = os.environ.get("ALLENAIPASSWORDPATH")
BERTSPAMPATH = os.environ.get("BERTSPAMPATH")
ALLENAISPAMPATH = os.environ.get("ALLENSPAMPATH")

"""----API Tokens----"""
BOTTOKEN = os.environ.get("CYBERBOTDISCORDAPI")
virusTotalApiKey = os.environ.get("CYBERBOTVTKEY")
KliphyAPI = os.environ.get("CYBERBOTKLIPHYAPI")

"""System Configuration"""
rarfile.UNRAR_TOOL = "unar"
intents = discord.Intents.all()
Cyberbot = commands.Bot(command_prefix='/', intents=intents)
with open(CONFIGJSONFILEPATH, "r") as JSONfile:
    CyberBotConfigData = json.load(JSONfile)
print(f"Cyberbot Configuration Data successfully loaded!")
with open(USERFILESCANPROCESSPATH, "r") as JSONfile:
    users = json.load(JSONfile)
GPTclient = OpenAI(api_key=os.environ.get("CYBERBOTGPTKEY"))
GeminiClient = genai.Client()
GPTMODEL = "gpt-5"
GEMINIMODEL = "gemini-2.5-flash"

"""Loading Pre-Trained Tokenizer Models"""
print(f"Loading Pre-Trained Tokenizer Models...")
BERTtokenizer = BertTokenizer.from_pretrained('bert-base-cased')
print("BERT tokenizer successfully loaded!")
AllenAItokenizer = LongformerTokenizer.from_pretrained('allenai/longformer-base-4096')
print("Allen AI tokenizer successfully loaded!")

"""Loading Pre-trained Encoder Transformer Models"""
print(f"Loading Pre-Trained Encoder-Transformer Models...")
BERTPhishingModel = loadClassifierModel(BERTPHISHINGPATH, "BERT", "Phishing Emails")
AllenAIPhishingModel = loadClassifierModel(ALLENAIPHISHINGPATH, "Allen AI", "Phishing Emails")
BERTPasswordModel = loadClassifierModel(BERTPASSWORDPATH, "BERT", "Password Strength")
AllenAIPasswordModel = loadClassifierModel(ALLENAIPASSWORDPATH, "Allen AI", "Password Strength")
BERTSpamModel = loadClassifierModel(BERTSPAMPATH, "BERT", "Spam Emails")
ALLENAISpamModel = loadClassifierModel(ALLENAISPAMPATH, "Allen AI", "Spam Emails")

@tasks.loop(minutes=1)  # A task every 1 minute
async def checking_expired_tokens():
    print(f"Checking for expired password reset token...")
    with open(RESETPASSWORDTOKENPATH, "r") as file:
        resetTokens = json.load(file)
    delete_tokens = []
    for tokenID in resetTokens:
        if time.time() >= resetTokens[tokenID][1]:
            print(f"Reset token {resetTokens[tokenID][0]} for {tokenID} expired.")
            delete_tokens.append(tokenID)
    for tokenID in delete_tokens:
        print(f"Removing token associated with {tokenID}...")
        del resetTokens[tokenID]
    with open(RESETPASSWORDTOKENPATH, "w") as file:
        json.dump(resetTokens, file, indent=4)
    print(f"Process Finished!\n\n")


@tasks.loop(seconds=15)  # A task every 15 seconds
async def checking_member_can_kick_cyberbot():
    print(f"Checking if member can kick cyberbot...")
    for account in CyberBotConfigData["Admins"]:
        for serverID in account["Accessible Servers"]:
            guild = Cyberbot.get_guild(serverID)
            member = guild.get_member(account["User ID"])
            if guild.me.top_role.position < member.top_role.position and member.id != guild.owner.id:
                await guild.owner.send(f"Member {member.name} from the server {guild.name} ID {serverID} that you owned can kick Cyberbot. Please make sure Cyberbot has a higher role than all the members in the server.")
                print(f"Member {member.name} can kick Cyberbot from server {guild.name} ID {serverID}. Warning was sent to server owner")
    print("Process finished!\n\n")


@tasks.loop(hours=24)  # A task every day
async def checking_expired_passwords():
    print(f"Checking for expired password...")
    for account in CyberBotConfigData["Admins"]:
        if time.time() >= account["Credential Expiration Age"]:
            print(f"Password for {account["User Email"]} expired.")
            sendEmail("Cyberbot admin account password expired",
                         f"Your current admin account password has expired!\n"
                         f"Please use command /request_password_reset_token and /change_password in the DM channel with Cyberbot to update your password!\n",
                         account["User Email"])
    print(f"Process Finished!\n\n")


@tasks.loop(hours=24)  # A task every day
async def clean_dms_with_admins():
    print(f"Cleaning DMs with admins...")
    for Adminaccount in CyberBotConfigData["Admins"]:
        admin = await Cyberbot.fetch_user(Adminaccount["User ID"])
        async for message in admin.history():
            if message.author == Cyberbot.user:
                await message.delete()
        print(f"DMs with admin {admin.name} cleaned successfully!")
    print(f"Process Finished!\n\n")


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
    checking_expired_passwords.start()
    clean_dms_with_admins.start()
    checking_member_can_kick_cyberbot.start()


    for guild in Cyberbot.guilds:
        for member in guild.members:
            users[str(member.id)] = {"Member name": member.name, "Current File Scan Operation": 0}

    with open(USERFILESCANPROCESSPATH, "w") as file:
        json.dump(users, file, indent=4)


@Cyberbot.event
async def on_member_join(member):
    print(f"New member {member.name} joined {member.guild.name}\nAdding new member to user file scan process file...\n\n")
    users[str(member.id)] = {"Member name": member.name,"Current File Scan Operation": 0}
    with open(USERFILESCANPROCESSPATH, "w") as file:
        json.dump(users, file, indent=4)


@Cyberbot.event
async def on_member_remove(member):
    print(f"Member {member.name} left server {member.guild.name} ID {member.guild.id}\nRemoving member admin access and session from the server...\n\n")
    for admin in CyberBotConfigData["Admins"]:
        if admin["User ID"] == member.id:
            admin["Accessible Servers"].remove(member.guild.id)
            if str(member.guild.id) in admin["Current Admin Session Period"]:
                del admin["Current Admin Session Period"][str(member.guild.id)]
            sendEmail("Admin access to Discord Server Removed",
                      f"Your Cyberbot admin access to server {member.guild.name} ID {member.guild.id} has been removed.\nThe reason was that you have left the server!",
                      admin["User Email"])
    with open(CONFIGJSONFILEPATH, "w") as file:
        json.dump(CyberBotConfigData, file, indent=4)
    await member.send(f"Your admin access to server {member.guild.name} ID {member.guild.id} has been removed.\nThe reason was that you have left the server!")


def isKlipyURLValid(gifURL):
    gifSlug = os.path.basename(gifURL)
    response = requests.get(f"https://api.klipy.com/api/v1/{KliphyAPI}/gifs/items?slugs={gifSlug}")
    data = response.json()
    if data["result"]:
        gifURL = data["data"]["data"][0]["file"]["hd"]["gif"]["url"]
        return gifURL
    return "Invalid"


def sendEmail(subject: str, content: str, receiver_email: str):
    # Credit https://www.youtube.com/watch?v=g_j6ILT-X0k
    sender_email = "noreplycyberbot7777@gmail.com"

    # Create a multipart message and set headers
    email = EmailMessage()
    email["From"] = sender_email
    email["To"] = receiver_email
    email["Subject"] = subject

    # Add body to email
    email.set_content(content)
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as server:
            server.login(sender_email, os.environ.get("CYBERBOTEMAILCRED"))
            server.sendmail(sender_email, receiver_email, email.as_string())
    except smtplib.SMTPRecipientsRefused as clientError:
        print(f"Error sending email to {receiver_email}: {clientError}")
        return "Email sent unsuccessfully!"
    except Exception as other_error:
        print(f"Error sending email to {receiver_email}: {other_error}")
        return "Email sent unsuccessfully!"
    return "Email sent successfully!"


def LoggingCommandBeingExecuted(userName: str, command: str):
    with open(LOGCOMMANDFILEPATH, 'a') as logFile:
        logFile.write(f"{time.ctime(time.time())}")
        logFile.write(f"\n{userName} used command {command}\n\n")


def randomPasswordGenerator():
    # Must be 12 length minimum
    # Must have mixed characters and numbers
    # Letters must have mixed case
    # Contains the following special characters !@#$%&*_+=
    char = f"ABCDEFGHIJKLNMOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%&*_+="
    password = ""
    while None in [re.search(r'[a-z]', password), re.search(r'[A-Z]', password), re.search(r'\d', password), re.search(
            r'[!@#$%&*_+=]', password)]:
        password = ""
        for i in range(random.randint(12, 20)):
            password += random.choice(char)
    return password


def GeminiCheckCommonPassword(password: str):
    response = GeminiClient.models.generate_content(
        model="gemini-2.0-flash",
        contents=f"Only say True if {password} seems to be from commonly used passwords, otherwise say False"
    )

    if response.text.startswith(("True", "true")):
        return True
    else:
        return False


def CheckPasswordPwned(password: str):
    sha1Signature = hashlib.sha1(password.encode()).hexdigest().upper()

    prefix = sha1Signature[:5]
    suffix = sha1Signature[5:]

    response = requests.get("https://api.pwnedpasswords.com/range/" + prefix)
    lines = response.text.split("\n")

    for i in range(len(lines)):
        parts = lines[i].split(":")
        if parts[0] == suffix:
            return True  # True if given password has been pwned
    return False  # False if given password not has been pwned


def checkingRealFileExtension(content: str, filename: str, URL=True):
    first1MegaBytes = b''
    if URL:
        print("Getting the first 1M bytes content of the file in http RESPONSE...")
        head = requests.head(content)
        FullContentLength = int(head.headers.get("Content-Length", 0))
        first1MegaBytesResponse = requests.get(content, headers=HEADERSFORPARTIALCONTENT)
        if first1MegaBytesResponse.status_code in (200, 206):
            first1MegaBytes = first1MegaBytesResponse.content
        else:
            return "Invalid Download URL!"
    else:
        print(f"Getting the first 1M bytes content of the file {filename}...")
        FullContentLength = os.path.getsize(content)
        with open(content, "rb") as source:
            first1MegaBytes = source.read(1000000)
    print("Checking file extension with python-magic module...")
    mime = magic.from_buffer(first1MegaBytes, mime=True)
    fileExt = mimetypes.guess_extension(mime)
    if fileExt:
        print(f"python-magic detected extension {fileExt}")
        if fileExt == ".bin":
            if first1MegaBytes.startswith(b'PK'):
                return '.zip'
            elif first1MegaBytes.startswith(b'caff'):
                return '.caf'
            elif FullContentLength > 512:
                last512Bytes = b''
                if URL:
                    last512BytesRange = f"bytes={FullContentLength - 512}-{FullContentLength - 1}"
                    last512BytesResponse = requests.get(content, headers={"Range": last512BytesRange})
                    last512Bytes = last512BytesResponse.content
                else:
                    with open(content, "rb") as source:
                        source.seek(-512, os.SEEK_END)
                        last512Bytes = source.read(512)
                if b'conectix' in last512Bytes:
                    return ".vhd"
                if b'koly' in last512Bytes or last512Bytes.startswith(b'EFI PART') or first1MegaBytes.startswith(b'EFI PART'):
                    return ".dmg"
        if fileExt == ".webm" and filename.endswith(".weba"):
            return ".weba"
        if fileExt == ".webm" and filename.endswith(".wmv"):
            return ".wmv"
        if fileExt == ".wmv" and filename.endswith(".wma"):
            return ".wma"
        if fileExt == ".ogv" and filename.endswith(".ogg"):
            return ".ogg"
        if fileExt == ".asf" and filename.endswith(".wmv"):
            return ".wmv"
        if fileExt == ".asf" and filename.endswith(".wma"):
            return ".wma"
        return fileExt
    else:
        print("python-magic could not determined, manually checking based on pre-defined list...")
        try:
            first1MegaBytesToASCII = first1MegaBytes.decode("ascii")
            if first1MegaBytesToASCII.isascii():
                print(f"ASCII document or script files detected")
                return "ASCII document or script files"
        except UnicodeDecodeError:
            if first1MegaBytes.startswith(
                    (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe',
                     b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca')):
                print("File extension is Mach-O executable!")
                return "Mach-O executable"
            if first1MegaBytes.startswith(b'\x7f\x45\x4c\x46'):
                print("File extension is ELF (Executable and Linkable Format)!")
                return "ELF executable"
            if first1MegaBytes.startswith(b'QFI\xfb'):
                print("File extension is QEMU Copy-On-Write virtual disk!")
                return ".qcow2"
            if first1MegaBytes.startswith(b'vhdxfile'):
                print("File extension is virtual hard disk image!")
                return ".vhdx"
            if first1MegaBytes.startswith(b'KDMV'):
                print("File extension is virtual machine disk image!")
                return ".vmdk"
            if len(first1MegaBytes) >= 32768:  # Sector 16 (2048 * 16)
                if first1MegaBytes[32768:32768 + 5].startswith((b"NSR02", b"NSR03")):
                    print("File extension is an Universal Disk image!")
                    return ".udf"
            print("Checking file extension with filetype module...")
            fileExt = filetype.guess(first1MegaBytes)
            if fileExt:
                print(f"filetype detected extension: {fileExt.extension}")
                return f".{fileExt.extension}"
            else:
                if first1MegaBytes.startswith((b'\x0B\x77', b'\x0bwu\xacT@C')):
                    return ".ac3"
                elif filename.endswith(".lzma"):
                    return ".lzma"
                print(f"File extension can not be determined!")
                return "Can't be determined"


def openAISCAT(filepath: str, instruction: str):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdfPath = f"{filepath.split(".")[0]}.pdf"
    with open(filepath, "r", encoding="utf-8") as SourceCodefile:
        pdf.multi_cell(0, 10, SourceCodefile.read())
        pdf.output(pdfPath)
    with open(pdfPath, "rb") as PDFfile:
        fileResponse = GPTclient.files.create(file=PDFfile, purpose="assistants")
        fileID = fileResponse.id

    response = GPTclient.responses.create(
        model=GPTMODEL,
        input=[
            {"role": "system", "content": "You are a cybersecurity analyst on a file for potential malware detection"},
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": instruction},
                    {"type": "input_file", "file_id": fileID}
                ]
            }
        ]
    )

    GPTclient.files.delete(fileID)

    finalReport = response.output_text
    with open(SCATLOGS, "a") as logfile:
        logfile.write(f"{time.ctime(time.time())}\nFile being scanned: {os.path.basename(filepath)}\nOpenAI Assistant Scan Result: {finalReport}\n\n\n")
    return finalReport


def GeminiSCAT(filepath: str, instruction: str):
    uploadedFile = GeminiClient.files.upload(file=filepath)
    print(f"Uploaded file '{uploadedFile.name}' as: {uploadedFile.uri}")

    promptParts = [
        uploadedFile,
        instruction
    ]

    model = GEMINIMODEL
    # Now, use the uploaded file URI in your content generation request
    response = GeminiClient.models.generate_content(model=model, contents=promptParts)
    with open(SCATLOGS, "a") as logfile:
        logfile.write(f"{time.ctime(time.time())}\nFile being scanned: {os.path.basename(filepath)}\nGemini 1.5 Scan Result: {response.text}\n\n\n")
    return response.text


def virusTotalURLScan(Urls: list):
    HostUrl = "https://www.virustotal.com/api/v3/urls"
    AnalysisUrl = f"https://www.virustotal.com/api/v3/analyses/"
    headers = {
        'x-apikey': virusTotalApiKey,
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded"
    }
    results = {}
    for url in Urls:
            payload = {"url": url}
            response = requests.post(HostUrl, data=payload, headers=headers)
            if response.status_code == 200:
                data = response.json()
                scanID = data["data"]["id"]
                analysisResponse = requests.get(f"{AnalysisUrl}{scanID}",headers=headers, timeout=15)
                analysisData = analysisResponse.json()
                results[url] = f"Malicious counted:{analysisData["data"]["attributes"]["stats"]['malicious']}"
            else:
                results[url] = "URL can't be scanned"
    return results


def virusTotalFileScan(filePath: str):
    HostUrl = "https://www.virustotal.com/api/v3/files"
    headers = {
        'x-apikey': virusTotalApiKey
    }

    with open(filePath, 'rb') as f:
        files = {'file': (filePath, f)}
        response = requests.post(HostUrl, headers=headers, files=files)

    if response.status_code == 200:
        data = response.json()
        analysisId = data["data"]["id"]
        AnalysisUrl = f'https://www.virustotal.com/api/v3/analyses/{analysisId}'
        for attempt in range(10):
            analysisResponse = requests.get(AnalysisUrl, headers=headers)

            if analysisResponse.status_code != 200:
                print("Error getting Analysis Results")
                return "File can't be scanned"

            analysis = analysisResponse.json()
            status = analysis["data"]["attributes"]["status"]

            if status == "completed":
                stats = analysis["data"]["attributes"]["stats"]
                print(
                    f"[+] Scan complete for {filePath}: "
                    f"{stats['malicious']} malicious, {stats['suspicious']} suspicious, "
                    f"{stats['harmless']} harmless, {stats['undetected']} undetected."
                )
                return f"{stats['malicious']}:{stats['suspicious']}:{stats['harmless']}:{stats['undetected']}"

            print(f"[*] Scan not finished yet (status={status}), retrying in {15}s...")
            time.sleep(15)
        return "File can't be scanned"
    else:
        print("Error getting Analysis ID")
        return "File can't be scanned"


def ArchivesDiskImagesBombAnalysisAndExtraction(filePath, mountPoint, archiveLayer=0):
    def checkingFileExtension(fileContent: bytes):
        mime = magic.from_buffer(fileContent, mime=True)
        Ext = mimetypes.guess_extension(mime)
        if Ext:
            if Ext == ".bin":
                if fileContent.startswith(b'PK'):
                    return '.zip'
                elif len(fileContent) > 512:
                    Last512bytes = fileContent[len(fileContent) - 512:len(fileContent) - 1]
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
    shutil.move(filePath[0], mountPoint)
    filePath[0] = f"{mountPoint}{os.path.basename(filePath[0])}"
    with open(filePath[0], 'rb') as rootFile:
        DuplicatedFileDetection = [hashlib.sha256(rootFile.read()).hexdigest()]
    uncompressedSize = os.path.getsize(filePath[0])
    totalDuplicatedFile = 0
    totalDuplicatedArchive = 0
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
                        filepath = os.path.join(dirpath, filename)
                        with open(filepath, "rb") as source:
                            fileData = source.read()
                            hashedData = hashlib.sha256(fileData).hexdigest()
                        if not hashedData in DuplicatedFileDetection:
                            if not filename.startswith("._") and "__MACOSX" not in filepath and not ".DS_Store" in filename:
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
                totalFileCount = 0
                for _, _, files in os.walk(mountPoint):
                    totalFileCount = len(files)
                if totalFileCount // (totalDuplicatedFile + 1) <= 0.10:
                    return "Too many duplicated files!"
            else:
                print(f"Scanning Archive file: {os.path.basename(filePath[i])} at path {filePath[i]}...")
                if fileExt.endswith(".zip"):
                    print("Archive is a zip file!")
                    with zipfile.ZipFile(filePath[i], 'r') as zipRef:
                        for entry in zipRef.infolist():
                            DestinationPath = os.path.abspath(f"{mountPoint}{entry.filename}")
                            if not DestinationPath.startswith(mountPoint):
                                print(f"The uncompressed file name {entry.filename} formed an illegal path {DestinationPath} to cause directory transversal attack!")
                                return "Path Transversal Attack"
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
                                            print(f"Duplicated file at path {DestinationPath}")
                                totalFileCount = 0
                                for _, _, files in os.walk(mountPoint):
                                    totalFileCount = len(files)
                                if totalFileCount // (totalDuplicatedFile + 1) <= 0.10:
                                    return "Too many duplicated files!"
                            except TypeError:
                                print(f"The extracted content of {os.path.basename(filePath[i])} is empty!")
                                pass
                            except zipfile.BadZipFile:
                                pass
                            except RuntimeError as e:
                                if 'password required' in str(e).lower():
                                    print("Zip file is encrypted!")
                                    return "Encrypted Error"
                                else:
                                    pass
                            except OSError:
                                pass
                elif fileExt.endswith((".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lzma", ".tgz", ".tbz2", ".txz")):
                    print("Archive is a tar file!")
                    with tarfile.open(filePath[i], 'r') as tarRef:
                        for entry in tarRef.getmembers():
                            DestinationPath = os.path.abspath(f"{mountPoint}{entry.name}")
                            if not DestinationPath.startswith(mountPoint):
                                print(f"The uncompressed file name {entry.name} formed an illegal path {DestinationPath} to cause directory transversal attack!")
                                return "Path Transversal Attack"
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
                                    totalFileCount = 0
                                    for _, _, files in os.walk(mountPoint):
                                        totalFileCount = len(files)
                                    if totalFileCount // (totalDuplicatedFile + 1) <= 0.10:
                                        return "Too many duplicated files!"
                            except TypeError:
                                print(f"The extracted content of {os.path.basename(filePath[i])} is empty!")
                                pass
                            except (OSError, tarfile.TarError):
                                pass
                elif fileExt.endswith(".rar"):
                    print("Archive is a rar file!")
                    with rarfile.RarFile(filePath[i], 'r') as rar:
                        if rar.needs_password():
                            print(f"Rar file {filePath[i]} required password!")
                            return "Encrypted Error"
                        for entry in rar.infolist():
                            if entry.needs_password():
                                print(f"Rar file {entry.filename} required password!")
                                return "Encrypted Error"
                            DestinationPath = os.path.abspath(f"{mountPoint}{entry.filename}")
                            if not DestinationPath.startswith(mountPoint):
                                print(f"The uncompressed file name {entry.filename} formed an illegal path {DestinationPath} to cause directory transversal attack!")
                                return "Path Transversal Attack"
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
                                            print(f"Duplicated file at path {DestinationPath}")
                                totalFileCount = 0
                                for _, _, files in os.walk(mountPoint):
                                    totalFileCount = len(files)
                                if totalFileCount // (totalDuplicatedFile + 1) <= 0.10:
                                    return "Too many duplicated files!"
                            except TypeError:
                                print(f"The extracted content of {os.path.basename(filePath[i])} is empty!")
                                pass
                            except (rarfile.BadRarFile, OSError, rarfile.NotRarFile):
                                pass
                elif fileExt.endswith((".gz", ".bz2", ".xz", ".lzma")):
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
                        totalFileCount = 0
                        for _, _, files in os.walk(mountPoint):
                            totalFileCount = len(files)
                        if totalFileCount // (totalDuplicatedFile + 1) <= 0.10:
                            return "Too many duplicated files!"
                    except (OSError, lzma.LZMAError, OSError):
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
                    print(f"Found nested Archive/Image file {filename} at path {filepath}")
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


def checkingCleanData(hashedData: str, category: Literal["Archive/Disk File", "Executable/Compiled Files", "Script Files", "Document/PDF Files", "Audio Files", "Image Files", "Video Files", "All Extension", "URLs"]):
    with open(CLEANSIGNATURESPATH, "r") as file:
        cleanHashedData = json.load(file)
    if category == "All Extension":
        for cat in cleanHashedData:
            if hashedData in cleanHashedData[cat]:
                return True
    else:
        if hashedData in cleanHashedData[category]:
            return True
    return False


def checkingFlaggedMaliciousData(hashedData: str, category: Literal["Archive/Disk File", "Executable/Compiled Files", "Script Files", "Document/PDF Files", "Audio Files", "Image Files", "Video Files", "All Extension", "URLs"]):
    with open(MALISCIOUSSIGNATUREPATH, "r") as file:
        maliciousHashedData = json.load(file)
    if category == "All Extension":
        for cat in maliciousHashedData:
            if hashedData in maliciousHashedData[cat]:
                return True
    else:
        if hashedData in maliciousHashedData[category]:
            return True
    return False


def addingHashedData(hashedData: str, fileExt, malicious: bool, fileCategory=''):
    fileExtMap = {"Archive/Disk File": DISKIMAGEANDARCHIVEFORMATS,
                  "Executable/Compiled Files": EXECUTABLEFORMATS,
                  "Script Files": SCRIPTFILEFORMATS,
                  "Document/PDF Files": DOCUMENTFILEFORMATS,
                  "Audio Files": AUDIOFORMATS,
                  "Image Files": PICTUREFORMATS,
                  "Video Files": VIDEOFORMATS,
                  "URLs": "URLs"
                }
    for category in fileExtMap:
        if fileExt in fileExtMap[category]:
            fileCategory = category
            break
    if malicious:
        with open(MALISCIOUSSIGNATUREPATH, "r") as file:
            currentMaliciousData = json.load(file)
        currentMaliciousData[fileCategory].append(hashedData)
        with open(MALISCIOUSSIGNATUREPATH, "w") as file:
            json.dump(currentMaliciousData, file, indent=4)
        print(f"New malicious SHA256 signature was added to category {fileCategory}")
    else:
        with open(CLEANSIGNATURESPATH, "r") as file:
            currentCleanData = json.load(file)
        currentCleanData[fileCategory].append(hashedData)
        with open(CLEANSIGNATURESPATH, "w") as file:
            json.dump(currentCleanData, file, indent=4)
        print(f"New clean SHA256 signature was added to category {fileCategory}")


def logScanSession(logData: str):
    with open(SCANLOG, "a") as logFile:
        logFile.write(logData)


@Cyberbot.tree.command(
    name="checking_cyberbot_configuration",
    description="Checking Cyberbot current configuration in the server"
)
async def checking_cyberbot_configuration(ctx):
    print(f"User {ctx.user.name} initiated /checking_cyberbot_configuration command")
    await ctx.response.defer(ephemeral=True)
    accountExist = False
    for account in CyberBotConfigData["Admins"]:
        if account["User ID"] == ctx.user.id and ctx.guild.id in account["Accessible Servers"]:
            if str(ctx.guild.id) not in CyberBotConfigData["Automation-Mode"]:
                CyberBotConfigData["Automation-Mode"][str(ctx.guild.id)] = "True"
            if str(ctx.guild.id) not in CyberBotConfigData["Silent-Mode"]:
                CyberBotConfigData["Silent-Mode"][str(ctx.guild.id)] = "True"
            if str(ctx.guild.id) not in CyberBotConfigData["Non-monitoring-Channels"]:
                CyberBotConfigData["Non-monitoring-Channels"][str(ctx.guild.id)] = []
            with open(CONFIGJSONFILEPATH, "w") as file:
                json.dump(CyberBotConfigData, file, indent=4)
            nonMonitoringChannels = "Non monitoring channels in this server are:\n"
            for nonMonitoringChannelID in CyberBotConfigData["Non-monitoring-Channels"][str(ctx.guild.id)]:
                nonMonitoringChannel = Cyberbot.get_channel(nonMonitoringChannelID)
                if nonMonitoringChannel:
                    nonMonitoringChannels += f"Channel ID: {nonMonitoringChannel.id}\tChannel name: {nonMonitoringChannel.name}\n"
                else:
                    CyberBotConfigData["Non-monitoring-Channels"][str(ctx.guild.id)].remove(nonMonitoringChannelID)
                    with open(CONFIGJSONFILEPATH, "w") as file:
                        json.dump(CyberBotConfigData, file, indent=4)
            await ctx.followup.send(f"Automation scan mode for this server is {CyberBotConfigData["Automation-Mode"][str(ctx.guild.id)]}!\n"
                                    f"Silent scan mode for this server is {CyberBotConfigData["Silent-Mode"][str(ctx.guild.id)]}!\n{nonMonitoringChannels}")
            LoggingCommandBeingExecuted(ctx.user.name, f"/checking_cyberbot_status\nCommand Status: Approved")
            accountExist = True
            break
    if not accountExist:
        LoggingCommandBeingExecuted(ctx.user.name, f"/checking_cyberbot_status\nCommand Status: Denied/User does not have admin account access to the server!")
        await ctx.followup.send(f"Your admin account is not permitted to access in this server, please contact the server owner {ctx.guild.owner.name} to give you admin account access to the server!")
        print(f"User {ctx.user.name} does not have admin account access to the server!\n\n")


@Cyberbot.tree.command(
    name="list_supported_formats",
    description="List all supported file formats that Cyberbot can scan"
)
async def list_supported_formats(ctx):
    await ctx.response.send_message("Cyberbot can scan the following file formats:\n\n"
                              "Archive and Disk Image: .dmg, .iso, .img, .vhd, .nrg, .vhdx, .vmdk, .qcow, .qcow2, .udf,"
                              " .zip, .tar, .tar.gz, .tar.bz2, .tar.xz, .tar.lzma, .tgz, .tbz2, .txz, .gz, .rar, .bz2, .xz, .lzma\n\n"
                              "Executable: Mach-O executable (All architecture), ELF executable, Windows exe and dll, .dex, .jar\n\n"
                              "Script Files: BASH script, ZShell and all common programming scripts\n\n"
                              "Document Files: .txt, .pdf, .docx\n\n"
                              "Media Files: .jpg, .png, .jpeg, .raw, .bmp, .webp, .tiff, .tif, .ico, .icns, .avif, .odd, .heic, "
                              ".svg, .eps, .gif, .ps, .psd, .mp4, .mov, .mkv, .avi, .m4v, .flv, .mpeg, .mpg, .ts, .wmv, .3gp, .3g2,"
                              ".3gpp, .cavs, .dv, .dvr, .mod, .mts, .m2ts, .mxf, .rm, .rmvb, .swf, .vob, .ogv, .mp3, .wav, .oga, .m4a,"
                              " .flac, .weba, .aac, .ac3, .aif, .aiff, .aifc, .amr, .au, .caf, .dss, .m4a, .m4b, .wma, .opus, .webm, .ogg"
                              )

@Cyberbot.tree.command(
    name="get_list_of_accessible_servers",
    description="Getting a list of servers your Cyberbot admin account can access"
)
async def get_list_of_accessible_servers(ctx):
    print(f"User {ctx.user.name} initiated /get_list_of_accessible_servers command")
    await ctx.response.defer(ephemeral=True)
    accountExist = False
    for admin in CyberBotConfigData["Admins"]:
        if admin["User ID"] == ctx.user.id:
            accountExist = True
            serverList = ''
            for serverID in admin["Accessible Servers"]:
                guild = Cyberbot.get_guild(serverID)
                serverList += f"Server Name: {guild.name}\tServer ID: {serverID}\tServer Owner: {guild.owner.name}\n"
            LoggingCommandBeingExecuted(ctx.user.name,f"/get_list_of_accessible_servers\nCommand Status: Approved/Accessible Servers list sent to user!")
            await ctx.followup.send(f"Your Cyberbot admin account has access to the following servers:\n{serverList}")
            print(f"Process Finished!\n\n")
            break
    if not accountExist:
        LoggingCommandBeingExecuted(ctx.user.name, f"/get_list_of_accessible_servers\nCommand Status: Denied/User does not have a Cyberbot admin account yet!")
        await ctx.followup.send(f"{ctx.user.name} does not have a Cyberbot admin account yet!")
        print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")


@Cyberbot.tree.command(
    name="create_admin_account",
    description="Create a Cyberbot admin account"
)
@app_commands.describe(
    user_email="Please provide an email address to register your Cyberbot admin account!"
)
async def create_admin_account(ctx, user_email: str):
    print(f"User {ctx.user.name} initiated /create_admin_account command")
    await ctx.response.defer(ephemeral=True)
    accountExist = False
    emailTaken = False
    for admin in CyberBotConfigData["Admins"]:
        if admin["User ID"] == ctx.user.id:
            accountExist = True
            LoggingCommandBeingExecuted(ctx.user.name, f"/create_admin_account\nCommand Status: Denied/User already has an admin account!")
            await ctx.followup.send(f"You already have a Cyberbot admin account associated with email address {admin['User Email']}\nIf you want to change your password, use command /request_password_reset_token and /change_password with Cyberbot!")
            print("User already has an admin account!\n\n")
            break
        if admin["User Email"] == user_email:
            emailTaken = True
            LoggingCommandBeingExecuted(ctx.user.name, f"/create_admin_account\nCommand Status: Denied/Email address already taken by other admin account!")
            await ctx.followup.send(f"The email address already associated with a different admin account!")
            print("Email address already associated with a different admin account!\n\n")
            break
    if not accountExist and not emailTaken:
        defaultPassword = randomPasswordGenerator()
        if sendEmail("New Cyberbot Admin Account Created",
                     f"A new Cyberbot admin account was created with a default password:\n{defaultPassword}\nIf you want to change your password, use command /request_password_reset_token and /change_password with Cyberbot!",
                     user_email) == "Email sent successfully!":
            CyberBotConfigData["Admins"].append(
                {"User ID": ctx.user.id,
                 "User Email": user_email,
                 "User Credential": hashlib.sha512(f"{defaultPassword}{ctx.user.id}".encode()).hexdigest(),
                 "Credential Minimum Age": 0,
                 "Credential Expiration Age": time.time() + 15552000,
                 "Previous Credentials Used": [hashlib.sha512(f"{defaultPassword}{ctx.user.id}".encode()).hexdigest()],
                 "Current Admin Session Period": {},
                 "Last Time Logged In": "",
                 "Current Account Locked Out Period": 0,
                 "Failed Log In Attempts": 0,
                 "Locked Out History": [],
                 "Total Locked Out": 0,
                 "Accessible Servers": [],
                 "Account Creation Date": time.ctime(time.time())
                 }
            )
            with open(CONFIGJSONFILEPATH, "w") as file:
                json.dump(CyberBotConfigData, file, indent=4)
            LoggingCommandBeingExecuted(ctx.user.name, f"/create_admin_account\nCommand Status: Approved/New admin account registered for user {ctx.user.name}")
            await ctx.followup.send(f"A new admin account has been created for you! Please check the email you used to registered the account for more details!")
            print(f"New Admin account created for user {ctx.user.name}\n\n")
        else:
            LoggingCommandBeingExecuted(ctx.user.name, f"/create_admin_account\nCommand Status: Denied/Error sending email!")
            await ctx.followup.send(f"Cyberbot can't register a new admin account with the email address: {user_email}")
            print(f"Error sending email!\n\n")


@Cyberbot.tree.command(
    name="adding_admins",
    description="Granting member their admin account access to the server!"
)
@app_commands.describe(
    member="Please mention a member in the server to grant their admin account access!"
)
# Command for server owner ONLY!
async def adding_admins(ctx, member: discord.Member):
    print(f"User {ctx.user.name} initiated /adding_admins command")
    await ctx.response.defer(ephemeral=True)
    if ctx.user.id == ctx.guild.owner.id:
        if ctx.guild.me.top_role.position < member.top_role.position and member.id != ctx.guild.owner.id:
            LoggingCommandBeingExecuted(ctx.user.name, f"/adding_admins {member}\nCommand Status: Denied/Member {member.name} can kick Cyberbot out of the server {ctx.guild.name}")
            await ctx.followup.send(f"{member.name} can kick Cyberbot out of the server! Therefore their admin account will not be allowed to work in the server! The reason is if their discord account is compromised, the attacker can kick Cyberbot out and does not need to be an admin to disable Cyberbot scan protection! Please ensure that Cyberbot always has the highest role than all the members in the server!")
            print(f"{member.name}  can kick Cyberbot out of the server {ctx.guild.name}\n\n")
        else:
            accountExist = False
            for admin in CyberBotConfigData["Admins"]:
                if admin["User ID"] == member.id:
                    accountExist = True
                    if ctx.guild.id not in admin["Accessible Servers"]:
                        if sendEmail("New Accessible Server Added",
                                     f"The owner {ctx.user.name} of server {ctx.guild.name} with server ID {ctx.guild.id} has granted your Cyberbot Admin Account access to the server",
                                     admin["User Email"]) == "Email sent successfully!":
                            admin["Accessible Servers"].append(ctx.guild.id)
                            with open(CONFIGJSONFILEPATH, "w") as file:
                                json.dump(CyberBotConfigData, file, indent=4)
                            LoggingCommandBeingExecuted(ctx.user.name, f"/adding_admins {member}\nCommand Status: Approved/Access to the server {ctx.guild.name} ID {ctx.guild.id} for Admin User Account {admin['User ID']} added!")
                            await member.send(f"You have been authorized to have a Cyberbot admin account access on server {ctx.guild.name} by the server owner {ctx.user.name}\nPlease check your email {admin["User Email"]} for more details!")
                            await ctx.followup.send(f"{member.name} admin account can now be used in server {ctx.guild.name}")
                            print(f"{member.name} admin access to server {ctx.guild.name} added!\n\n")
                        else:
                            LoggingCommandBeingExecuted(ctx.user.name,f"/adding_admins {member}\nCommand Status: Denied/Error sending email!")
                            await ctx.followup.send(f"Cyberbot can't register {member.name} admin account!")
                            print(f"Error sending email\n\n")
                    else:
                        LoggingCommandBeingExecuted(ctx.user.name, f"/adding_admins {member}\nCommand Status: Denied/Admin account already has access to server {ctx.guild.name} ID {ctx.guild.id}")
                        await ctx.followup.send(f"{member.name} admin account already has access to the server!")
                        print(f"{member.name} admin account already has access to the server!\n\n")
                    break
            if not accountExist:
                LoggingCommandBeingExecuted(ctx.user.name, f"/adding_admins {member}\nCommand Status: Denied/Mentioned member does not have a Cyberbot admin account yet!")
                await ctx.followup.send(f"{member.name} does not have a Cyberbot admin account yet!")
                print(f"{member.name} does not have a Cyberbot admin account!\n\n")
    else:
        LoggingCommandBeingExecuted(ctx.user.name, f"adding_admins {member}\nCommand Status: Denied/Unauthorized User")
        await ctx.followup.send("You're not the server's owner, the command /adding_admins is restricted to server owner ONLY!")
        print(f"User {ctx.user.name} not authorized to execute the command!\n\n")


@Cyberbot.tree.command(
    name="removing_admins",
    description="Removing a member admin account access to the server!"
)
@app_commands.describe(
    member="Please mention a member in the server to remove their admin account access!"
)
# Command for server owner ONLY!
async def removing_admins(ctx, member: discord.Member):
    print(f"User {ctx.user.name} initiated /removing_admins command")
    await ctx.response.defer(ephemeral=True)
    if ctx.user.id == ctx.guild.owner.id:
        accountExist = False
        for admin in CyberBotConfigData["Admins"]:
            if admin["User ID"] == member.id:
                accountExist = True
                if ctx.guild.id not in admin["Accessible Servers"]:
                    LoggingCommandBeingExecuted(ctx.user.name, f"/removing_admins {member}\nCommand Status: Denied/Admin account already has no access to server {ctx.guild.name} ID {ctx.guild.id}")
                    await ctx.followup.send(f"{member.name} admin account already has no access to the server!")
                    print(f"{member.name} admin account already has no access to the server!\n\n")
                else:
                    if sendEmail("New Accessible Server Removed",
                                 f"The owner {ctx.user.name} of server {ctx.guild.name} with server ID {ctx.guild.id} has removed your Cyberbot Admin Account access from the server",
                                 admin["User Email"]) == "Email sent successfully!":
                        admin["Accessible Servers"].remove(ctx.guild.id)
                        with open(CONFIGJSONFILEPATH, "w") as file:
                            json.dump(CyberBotConfigData, file, indent=4)
                        LoggingCommandBeingExecuted(ctx.user.name,f"/removing_admins {member}\nCommand Status: Approved/Access to the server {ctx.guild.name} ID {ctx.guild.id} for Admin User Account {admin['User ID']} removed!")
                        await member.send(f"Your admin account access on server {ctx.guild.name} ID {ctx.guild.id} has been removed by the server owner {ctx.user.name}\nPlease check your email {admin["User Email"]} for more details!")
                        await ctx.followup.send(f"{member.name} admin account access removed from the server!")
                        print(f"{member.name} admin access to server {ctx.guild.name} removed!\n\n")
                    else:
                        LoggingCommandBeingExecuted(ctx.user.name, f"/removing_admins {member}\nCommand Status: Denied/Error sending email!")
                        await ctx.followup.send(f"Cyberbot can't register {member.name} admin account!")
                        print(f"Error sending email\n\n")
                break
        if not accountExist:
            LoggingCommandBeingExecuted(ctx.user.name, f"/removing_admins {member}\nCommand Status: Denied/Mentioned member does not have a Cyberbot admin account yet!")
            await ctx.followup.send(f"{member.name} does not have a Cyberbot admin account yet!")
            print(f"{member.name} does not have a Cyberbot admin account!\n\n")
    else:
        LoggingCommandBeingExecuted(ctx.user.name, f"/removing_admins {member}\nCommand Status: Denied/Unauthorized User")
        await ctx.followup.send("You're not the server's owner, the command /removing_admins is restricted to server owner ONLY!")
        print(f"User {ctx.user.name} not authorized to execute the command!\n\n")


@Cyberbot.tree.command(
    name="request_password_reset_token",
    description="Request a new password reset token"
)
async def request_password_reset_token(ctx):
    print(f"User {ctx.user.name} initiated /request_password_reset_token command")
    await ctx.response.defer(ephemeral=True)
    accountExist = False
    for adminAccount in CyberBotConfigData["Admins"]:
        if ctx.user.id == adminAccount["User ID"]:
            accountExist = True
            if time.time() > adminAccount["Current Account Locked Out Period"]:
                if time.time() >= adminAccount["Credential Minimum Age"]:
                    with open(RESETPASSWORDTOKENPATH, "r") as file:
                        resetTokens = json.load(file)
                    token = ""
                    for i in range(7):
                        token += random.choice(f"ABCDEFGHIJKLNMOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%&*_+=")
                    resetTokens[adminAccount["User Email"]] = [token, time.time() + 180]
                    with open(RESETPASSWORDTOKENPATH, "w") as file:
                        json.dump(resetTokens, file, indent=4)
                    sendEmail("Cyberbot Password Reset Token",
                              f"Your password reset token is {token}, it will expired in 3 minutes!",
                              adminAccount["User Email"])
                    LoggingCommandBeingExecuted(ctx.user.name, f"/request_password_reset_token\nCommand Status: Approved/A reset token has been sent to user email!")
                    await ctx.followup.send(f"Please check your email {adminAccount["User Email"]}!")
                    print(f"A new reset token has been sent to user {ctx.user.name} via email {adminAccount['User Email']}!\n\n")
                else:
                    LoggingCommandBeingExecuted(ctx.user.name, f"/request_password_reset_token\nCommand Status: Denied/User password age not above 3 hours yet")
                    await ctx.followup.send(f"You just changed your password. Your password must have a minimum age of 3 hours in order to be able to be changed again!")
                    print(f"User {ctx.user.name} just changed the admin account password!\n\n")
            else:
                LoggingCommandBeingExecuted(ctx.user.name, f"/request_password_reset_token\nCommand Status: Denied/Admin account locked!")
                hours_remaining = (adminAccount["Current Account Locked Out Period"] - time.time()) / 3600
                minutes_remaining = round(float(f".{str(hours_remaining).split('.')[1]}") * 60)
                await ctx.followup.send(f"Your admin account is currently being locked out for {round(hours_remaining // 1)} hour(s) and {minutes_remaining} minute(s)")
                print(f"User {ctx.user.name} admin account is currently being locked out!\n\n")
            break
    if not accountExist:
        LoggingCommandBeingExecuted(ctx.user.name, f"/request_password_reset_token\nCommand Status: Denied/User does not have a Cyberbot admin account yet!")
        await ctx.followup.send(f"You do not have a Cyberbot admin account yet! Use command /create_admin_account to register a new Cyberbot admin account!")
        print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")


@Cyberbot.tree.command(
    name="change_password",
    description="Update your admin account password! ONLY work in DM channel with Cyberbot!"
)
@app_commands.describe(
    passwordresettoken="Please provide the temporary password reset token sent to your email",
    accountemail="Please provide a valid email address associated with your admin account",
    custompassword="Select True if you want to create your own password, else Cyberbot will create and email the password to you!",
    newpassword="Please provide a new password for your account"
)
async def change_password(ctx, passwordresettoken: str, accountemail: str, custompassword: Literal["False", "True"], newpassword: str = "Default"):
    print(f"User {ctx.user.name} initiated /change_password command")
    await ctx.response.defer(ephemeral=True)
    accountExist = False
    for adminAccount in CyberBotConfigData["Admins"]:
        if ctx.user.id == adminAccount["User ID"]:
            accountExist = True
            if time.time() > adminAccount["Current Account Locked Out Period"]:
                if accountemail == adminAccount["User Email"]:
                    with open(RESETPASSWORDTOKENPATH, "r") as file:
                        resetTokens = json.load(file)
                    if accountemail in resetTokens and resetTokens[accountemail][0] == passwordresettoken and time.time() < resetTokens[accountemail][1]:
                        if time.time() >= adminAccount["Credential Minimum Age"]:
                            update = True
                            if custompassword == "True":
                                hashednewpassword = hashlib.sha512(f"{newpassword}{ctx.user.id}".encode()).hexdigest()
                                if len(newpassword) > 30:
                                    LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/Password too long")
                                    await ctx.followup.send("Your new password is too long!")
                                    print(f"User {ctx.user.name} new password too long!\n\n")
                                    update = False
                                elif hashednewpassword == adminAccount["User Credential"]:
                                    LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/Password is the same as the old one")
                                    await ctx.followup.send("Your new password is the same as your old password!")
                                    print(f"User {ctx.user.name} reused password!\n\n")
                                    update = False
                                elif hashednewpassword in adminAccount["Previous Credentials Used"]:
                                    LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/Password already been used from the past!")
                                    await ctx.followup.send("You have used this password before, please set a new password!")
                                    print(f"User {ctx.user.name} reused password!\n\n")
                                    update = False
                                elif None in [re.search(r'[a-z]', newpassword), re.search(r'[A-Z]', newpassword),
                                              re.search(r'\d', newpassword), re.search(r'[!@#$%&*_+=]', newpassword)] \
                                        or len(newpassword) < 12:
                                    LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/Password does not match the criteria")
                                    await ctx.followup.send("Your new password password must be:\n"
                                                            "At least 12 characters\n"
                                                            "Have mixed case ASCII letters and numbers\n"
                                                            "Contains any of the following special characters !@#$%&*_+=\n"
                                                            "Please provide a different password")
                                    print(f"User {ctx.user.name} new password not match the password policy!\n\n")
                                    update = False
                                elif CheckPasswordPwned(newpassword):
                                    LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/New Password existed in a data breach database")
                                    await ctx.followup.send("The new password that you want to set was detected to already existed in a data breach database, please choose a different password!")
                                    print(f"User {ctx.user.name} new password existed in data breach database!\n\n")
                                    update = False
                                else:
                                    passwordStrength, probability = Prediction(newpassword, BERTtokenizer, BERTPasswordModel, "Password Strength")
                                    if passwordStrength < 3 and probability > 0.5:
                                        LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/BERT model detected password strength at level {passwordStrength} out of 5 levels ranking system with probability value of {f"{probability}"}")
                                        await ctx.followup.send("Your new password contains patterns that Cyberbot pre-trained weak password classifier BERT encoder-transformer flagged as weak password!\nPlease provide a different password")
                                        print(f"User {ctx.user.name} new password flagged weak by BERT model!\n\n")
                                        update = False
                                    else:
                                        passwordStrength, probability = Prediction(newpassword, AllenAItokenizer, AllenAIPasswordModel,"Password Strength")
                                        if passwordStrength < 3 and probability > 0.5:
                                            LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/Allen AI model detected password strength at level {passwordStrength} out of 5 levels ranking system with probability value of {f"{probability}"}")
                                            await ctx.followup.send("Your new password contains patterns that Cyberbot pre-trained weak password classifier Allen AI encoder-transformer flagged as weak password!\nPlease provide a different password")
                                            print(f"User {ctx.user.name} new password flagged weak by Allen AI model!\n\n")
                                            update = False
                                        elif GeminiCheckCommonPassword(newpassword):
                                            LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/Password too common and easy to guess")
                                            await ctx.followup.send("Your new password contains keywords easy to guess or already in a common used password list!\nPlease provide a different password")
                                            print(f"User {ctx.user.name} new password too common and easy to guess!\n\n")
                                            update = False
                            else:
                                newpassword = randomPasswordGenerator()
                                while hashlib.sha512(f"{newpassword}{ctx.user.id}".encode()).hexdigest() == adminAccount["User Credential"] or hashlib.sha512(f"{newpassword}{ctx.user.id}".encode()).hexdigest() in adminAccount["Previous Credentials Used"]:
                                    newpassword = randomPasswordGenerator()
                                hashednewpassword = hashlib.sha512(f"{newpassword}{ctx.user.id}".encode()).hexdigest()
                            if update:
                                adminAccount["User Credential"] = hashednewpassword
                                adminAccount["Credential Minimum Age"] = time.time() + 10800
                                adminAccount["Credential Expiration Age"] = time.time() + 15552000
                                adminAccount["Previous Credentials Used"].append(adminAccount["User Credential"])
                                with open(CONFIGJSONFILEPATH, "w") as file:
                                    json.dump(CyberBotConfigData, file, indent=4)
                                if custompassword == "False":
                                    sendEmail("Cyberbot Admin Account Password Updated",
                                              f"Your admin account password has been changed to {newpassword}\n"
                                              f"Please delete this email once you have acknowledged your new password change!",
                                              accountemail)
                                LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Approved/Admin account password updated")
                                await ctx.followup.send(f"Your password has been updated to {newpassword}")
                                print(f"User {ctx.user.name} admin account updated successfully!\n\n")
                        else:
                            LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/User password age not above 3 hours yet")
                            await ctx.followup.send(f"You just changed your password. Your password must have a minimum age of 3 hours in order to be able to be changed again!")
                            print(f"User {ctx.user.name} just changed the admin account password!\n\n")
                    else:
                        LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/Expired or Invalid Password Reset Token")
                        await ctx.followup.send(f"The reset token provided is invalid or expired. Please request a new one again!")
                        print(f"User {ctx.user.name} password reset token Expired/Invalid!\n\n")
                else:
                    LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/Wrong Email Address")
                    await ctx.followup.send("Your email address is wrong!")
                    print(f"User {ctx.user.name} provided wrong email address!\n\n")
            else:
                LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/Admin account locked!")
                hours_remaining = (adminAccount["Current Account Locked Out Period"] - time.time()) / 3600
                minutes_remaining = round(float(f".{str(hours_remaining).split('.')[1]}") * 60)
                await ctx.followup.send( f"Your admin account is currently being locked out for {round(hours_remaining // 1)} hour(s) and {minutes_remaining} minute(s)")
                print(f"User {ctx.user.name} admin account is currently being locked out!\n\n")
            break
    if not accountExist:
        LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/User does not have a Cyberbot admin account yet!")
        await ctx.followup.send(f"You do not have a Cyberbot admin account yet! Use command /create_admin_account to register a new Cyberbot admin account!")
        print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")


@Cyberbot.tree.command(
    name="admin_log_in",
    description="Logging in with your Cyberbot admin account in the server"
)
@app_commands.describe(
    accountemail="Please provide a valid email address associated with your admin account",
    accountpassword="Please provide the password associated with your account"
)
async def admin_log_in(ctx, accountemail: str, accountpassword: str):
    print(f"User {ctx.user.name} initiated /admin_log_in command")
    await ctx.response.defer(ephemeral=True)
    accountExist = False
    for adminAccount in CyberBotConfigData["Admins"]:
        if adminAccount["User ID"] == ctx.user.id:
            accountExist = True
            logIn = False
            if time.time() > adminAccount["Current Account Locked Out Period"]:
                if str(ctx.guild.id) in adminAccount["Current Admin Session Period"]:
                    if time.time() < adminAccount["Current Admin Session Period"][str(ctx.guild.id)]:
                        logIn = True
                        LoggingCommandBeingExecuted(ctx.user.name,f"/admin_log_in\nCommand Status: Denied/User already logged in")
                        await ctx.followup.send("You already logged in! If you want to log out, please use the command /admin_log_out")
                        print(f"User {ctx.user.name} already logged in as an admin in the server!\n\n")

                if not logIn:
                    if adminAccount["User Email"] == accountemail and adminAccount["User Credential"] == hashlib.sha512(f"{accountpassword}{ctx.user.id}".encode()).hexdigest():
                        if time.time() < adminAccount["Credential Expiration Age"]:
                            if ctx.guild.id in adminAccount["Accessible Servers"]:
                                adminAccount["Failed Log In Attempts"] = 0
                                adminAccount["Current Admin Session Period"][str(ctx.guild.id)] = time.time() + 3600
                                adminAccount["Last Time Logged In"] = time.ctime(time.time())
                                LoggingCommandBeingExecuted(ctx.user.name,f"/admin_log_in\nCommand Status: Approved/New 1 hour admin session with admin account {adminAccount['User ID']} in server {ctx.guild.name} ID {ctx.user.id} created")
                                await ctx.followup.send("Cyberbot will now recognize you as an admin for 1 hour in this server before requiring you to log in again!")
                                print(f"User {ctx.user.name} logged in as an admin in the server!\n\n")
                            else:
                                LoggingCommandBeingExecuted(ctx.user.name,f"/admin_log_in\nCommand Status: Denied/User does not have admin account access to the server!")
                                await ctx.followup.send(f"Your admin account is not permitted to access in this server, please contact the server owner {ctx.guild.owner.name} to give you admin account access to the server!")
                                print(f"User {ctx.user.name} does not have admin account access to the server!\n\n")
                        else:
                            LoggingCommandBeingExecuted(ctx.user.name,f"/admin_log_in\nCommand Status: Denied/Expired Password")
                            await ctx.followup.send("Your password has expired. Please use /request_password_reset_token and /change_password to update your password!")
                            print(f"User {ctx.user.name} password expired!\n\n")
                    else:
                        adminAccount["Failed Log In Attempts"] += 1
                        if adminAccount["Failed Log In Attempts"] != 7:
                            LoggingCommandBeingExecuted(ctx.user.name,f"/admin_log_in\nCommand Status: Denied/Bad Credentials")
                            await ctx.followup.send(f"Invalid user email or password!!!\nYou have {7 - adminAccount["Failed Log In Attempts"]} attempts left to log in!")
                            print(f"User {ctx.user.name} input invalid credentials!\n\n")
                        else:
                            adminAccount["Locked Out History"].append(time.ctime(time.time()))
                            adminAccount["Current Account Locked Out Period"] = time.time() + 10800
                            adminAccount["Total Locked Out"] = len(adminAccount["Locked Out History"])
                            adminAccount["Failed Log In Attempts"] = 0
                            sendEmail("Admin Account Locked Out", f"Dear user {ctx.user.name},\n\n"
                                                                  f"You received this email from Cyberbot to notify that your admin account has been locked for 3 hours due too many invalid login attempts.\n"
                                                                  f"The current total lock out times associated with your account is: {len(adminAccount['Locked Out History'])}.",
                                      adminAccount["User Email"])
                            LoggingCommandBeingExecuted(ctx.user.name,f"/admin_log_in\nCommand Status: Denied/Bad Credentials and account has been locked!")
                            await ctx.followup.send("Too many failed login attempts! Your admin account has been locked for 3 hours!")
                            print(f"User {ctx.user.name} input too many invalid log in attempts, initiating admin account lock out!\n\n")
                    with open(CONFIGJSONFILEPATH, "w") as file:
                        json.dump(CyberBotConfigData, file, indent=4)
            else:
                LoggingCommandBeingExecuted(ctx.user.name,f"/admin_log_in\nCommand Status: Denied/Admin account locked!")
                hours_remaining = (adminAccount["Current Account Locked Out Period"] - time.time()) / 3600
                minutes_remaining = round(float(f".{str(hours_remaining).split('.')[1]}") * 60)
                await ctx.followup.send(f"Your admin account is currently being locked out for {round(hours_remaining // 1)} hour(s) and {minutes_remaining} minute(s)")
                print(f"User {ctx.user.name} admin account is currently being locked out!\n\n")
            break
    if not accountExist:
        LoggingCommandBeingExecuted(ctx.user.name, f"/admin_log_in\nCommand Status: Denied/User does not have a Cyberbot admin account yet!")
        await ctx.followup.send(f"You do not have a Cyberbot admin account yet! Use command /create_admin_account to register a new Cyberbot admin account!")
        print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")


@Cyberbot.tree.command(
    name="admin_log_out",
    description="Logging out of your current Cyberbot admin account session in the server"
)
async def admin_log_out(ctx):
    print(f"User {ctx.user.name} initiated /admin_log_out command")
    await ctx.response.defer(ephemeral=True)
    adminAccountExist = False
    for adminAccount in CyberBotConfigData["Admins"]:
        if ctx.user.id == adminAccount["User ID"]:
            adminAccountExist = True
            if str(ctx.guild.id) in adminAccount["Current Admin Session Period"]:
                del adminAccount["Current Admin Session Period"][str(ctx.guild.id)]
                with open(CONFIGJSONFILEPATH, "w") as file:
                    json.dump(CyberBotConfigData, file, indent=4)
                await ctx.followup.send("You have been logged out of your Cyberbot admin session with this server!")
                LoggingCommandBeingExecuted(ctx.user.name, f"/admin_log_out\nCommand Status: Approved")
                print(f"User {ctx.user.name} admin account logged out successfully!\n\n")
            else:
                await ctx.followup.send("You do not have any admin account session in this server!")
                LoggingCommandBeingExecuted(ctx.user.name, f"/admin_log_out\nCommand Status: Denied/User not logged in")
                print(f"User {ctx.user.name} not currently logged in as an admin in server!\n\n")
            break
    if not adminAccountExist:
        LoggingCommandBeingExecuted(ctx.user.name, f"/admin_log_out\nCommand Status: Denied/User does not have a Cyberbot admin account yet!")
        await ctx.followup.send("You do not have a Cyberbot admin account yet! Use command /create_admin_account to register a new Cyberbot admin account!")
        print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")


# Command for Admins and in non-DM with Cyberbot ONLY!
@Cyberbot.tree.command(
    name="cyberbot_config",
    description="Modifying Cyberbot configuration in the server"
)
@app_commands.describe(
    configuration="Please select a configuration mode to enable/disable",
    action="Please select enable/disable"
)
async def cyberbot_config(ctx, configuration: Literal["Automation-Mode", "Silent-Mode"], action: Literal["ENABLE", "DISABLE"]):
    print(f"User {ctx.user.name} initiated /cyberbot_config command")
    await ctx.response.defer(ephemeral=True)
    if str(ctx.channel.type).startswith("private"):
        await ctx.followup.send("/cyberbot_config can only be used in server channels!")
        LoggingCommandBeingExecuted(ctx.user.name, f"/cyberbot_config {configuration} {action}\nCommand Status: Denied/Command runs in DM channel")
        print(f"Command forbidden to execute in DM channel!\n\n")
    else:
        adminAccountExist = False
        for adminAccount in CyberBotConfigData["Admins"]:
            if ctx.user.id == adminAccount["User ID"]:
                adminAccountExist = True
                if ctx.guild.id in adminAccount["Accessible Servers"]:
                    if str(ctx.guild.id) in adminAccount["Current Admin Session Period"]:
                        if time.time() < adminAccount["Current Admin Session Period"][str(ctx.guild.id)]:
                            if action == "ENABLE":
                                CyberBotConfigData[configuration][str(ctx.guild.id)] = "True"
                            else:
                                CyberBotConfigData[configuration][str(ctx.guild.id)] = "False"
                            await ctx.followup.send("DONE")
                            await ctx.followup.send(f"{configuration} for this server has been {'enabled' if (CyberBotConfigData[configuration][str(ctx.guild.id)] == "True") else 'disabled'} by user {ctx.user.mention}!")
                            LoggingCommandBeingExecuted(ctx.user.name, f"/cyberbot_config {configuration} {action}\nCommand Status: Approved/{configuration} {action} in server {ctx.guild.name} - ID {ctx.guild.id}")
                            print(f"{configuration} been reconfigured!\n\n")
                        else:
                            del adminAccount["Current Admin Session Period"][str(ctx.guild.id)]
                            LoggingCommandBeingExecuted(ctx.user.name,f"/cyberbot_config {configuration} {action}\nCommand Status: Denied/Admin session expired")
                            await ctx.followup.send(f"Your admin session with this server has expired! Please logging in again.")
                            print(f"User admin session expired!\n\n")
                        with open(CONFIGJSONFILEPATH, "w") as file:
                            json.dump(CyberBotConfigData, file, indent=4)
                    else:
                        LoggingCommandBeingExecuted(ctx.user.name, f"/cyberbot_config {configuration} {action}\nCommand Status: Denied/User need to log in as an admin")
                        await ctx.followup.send(f"You need to use /admin_log_in to log in as an admin in this server to execute this command!")
                        print(f"User {ctx.user.name} need to log in as an admin!\n\n")
                else:
                    LoggingCommandBeingExecuted(ctx.user.name, f"/cyberbot_config {configuration} {action}\nCommand Status: Denied/User does not have admin account access to the server!")
                    await ctx.followup.send(f"You do not have an admin account access to the server, please contact the server owner {ctx.guild.owner.name} to create an admin account for you!")
                    print(f"User {ctx.user.name} not authorized to execute the command!\n\n")
        if not adminAccountExist:
            LoggingCommandBeingExecuted(ctx.user.name, f"/cyberbot_config {configuration} {action}\nCommand Status: Denied/User does not have a Cyberbot admin account yet!")
            await ctx.followup.send("You do not have a Cyberbot admin account yet! Use command /create_admin_account to register a new Cyberbot admin account!")
            print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")


# Command for Admins and in non-DM with Cyberbot ONLY!
@Cyberbot.tree.command(
    name="non_monitoring_channel",
    description="Adding or Removing the channel in the server that Cyberbot will not scan"
)
@app_commands.describe(
    action="Please select ADD/REMOVE"
)
async def non_monitoring_channel(ctx, action: Literal["ADD", "REMOVE"]):
    print(f"User {ctx.user.name} initiated /non_monitoring_channel command")
    await ctx.response.defer(ephemeral=True)
    if str(ctx.channel.type).startswith("private"):
        await ctx.followup.send("/non_monitoring_channel can only be used in server channels!")
        LoggingCommandBeingExecuted(ctx.user.name, f"/non_monitoring_channel {action}\nCommand Status: Denied/Command runs in DM channel")
        print(f"Command forbidden to execute in DM channel!\n\n")
    else:
        adminAccountExist = False
        for adminAccount in CyberBotConfigData["Admins"]:
            if ctx.user.id == adminAccount["User ID"]:
                adminAccountExist = True
                if ctx.guild.id in adminAccount["Accessible Servers"]:
                    if str(ctx.guild.id) in adminAccount["Current Admin Session Period"]:
                        if time.time() < adminAccount["Current Admin Session Period"][str(ctx.guild.id)]:
                            if not str(ctx.guild.id) in CyberBotConfigData["Non-monitoring-Channels"]:
                                CyberBotConfigData["Non-monitoring-Channels"][str(ctx.guild.id)] = []
                            if action == "ADD":
                                if ctx.channel.id not in CyberBotConfigData["Non-monitoring-Channels"][str(ctx.guild.id)]:
                                    CyberBotConfigData["Non-monitoring-Channels"][str(ctx.guild.id)].append(ctx.channel.id)
                                    await ctx.followup.send(f"Channel '{ctx.channel.name}' - ID {ctx.channel.id} has been added to the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                                    await ctx.followup.send(f"Channel '{ctx.channel.name}' - ID {ctx.channel.id} has been added to the server non monitoring channel list by user {ctx.user.mention}!")
                                    LoggingCommandBeingExecuted(ctx.user.name,f"/non_monitoring_channel {action}\nCommand Status: Approved/Channel '{ctx.channel.name}' - ID {ctx.channel.id} has been added to the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                                else:
                                    await ctx.followup.send(f"Channel '{ctx.channel.name}' - ID {ctx.channel.id} already been added to the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                                    LoggingCommandBeingExecuted(ctx.user.name,f"/non_monitoring_channel {action}\nCommand Status: Denied/Channel '{ctx.channel.name}' - ID {ctx.channel.id} already been added to the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                            else:
                                if ctx.channel.id in CyberBotConfigData["Non-monitoring-Channels"][str(ctx.guild.id)]:
                                    CyberBotConfigData["Non-monitoring-Channels"][str(ctx.guild.id)].remove(ctx.channel.id)
                                    await ctx.followup.send(f"Channel '{ctx.channel.name}' - ID {ctx.channel.id} has been removed from the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                                    await ctx.followup.send(f"Channel '{ctx.channel.name}' - ID {ctx.channel.id} has been removed from the server non monitoring channel list by user {ctx.user.mention}!")
                                    LoggingCommandBeingExecuted(ctx.user.name,f"/non_monitoring_channel {action}\nCommand Status: Approved/Channel '{ctx.channel.name}' - ID {ctx.channel.id} has been removed from the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                                else:
                                    await ctx.followup.send(f"Channel '{ctx.channel.name}' - ID {ctx.channel.id} already been removed from the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                                    LoggingCommandBeingExecuted(ctx.user.name,f"/non_monitoring_channel {action}\nCommand Status: Denied/Channel '{ctx.channel.name}' - ID {ctx.channel.id} already been removed from the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                        else:
                            del adminAccount["Current Admin Session Period"][str(ctx.guild.id)]
                            LoggingCommandBeingExecuted(ctx.user.name, f"/non_monitoring_channel {action}\nCommand Status: Denied/Admin session expired")
                            await ctx.followup.send(f"Your admin session with this server has expired! Please logging in again.")
                            print(f"User admin session expired!\n\n")
                        with open(CONFIGJSONFILEPATH, "w") as file:
                            json.dump(CyberBotConfigData, file, indent=4)
                    else:
                        LoggingCommandBeingExecuted(ctx.user.name,f"/non_monitoring_channel {action}\nCommand Status: Denied/User need to log in as an admin")
                        await ctx.followup.send(f"You need to use /admin_log_in to log in as an admin in this server to execute this command!")
                        print(f"User {ctx.user.name} need to log in as an admin!\n\n")
                else:
                    LoggingCommandBeingExecuted(ctx.user.name,f"/non_monitoring_channel {action}\nCommand Status: Denied/User does not have admin account access to the server!")
                    await ctx.followup.send(f"You do not have an admin account access to the server, please contact the server owner {ctx.guild.owner.name} to create an admin account for you!")
                    print(f"User {ctx.user.name} not authorized to execute the command!\n\n")
        if not adminAccountExist:
            LoggingCommandBeingExecuted(ctx.user.name, f"/non_monitoring_channel {action}\nCommand Status: Denied/User does not have a Cyberbot admin account yet!")
            await ctx.followup.send("You do not have a Cyberbot admin account yet! Use command /create_admin_account to register a new Cyberbot admin account!")
            print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")


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
    fileExt = checkingRealFileExtension(file.url, file.filename)
    await ctx.followup.send(f"The file extension is: {fileExt}\n\n")
    LoggingCommandBeingExecuted(ctx.user.name, f"/checking_file_true_format file temporary URL: {file.url}\n"
                                f"Command Status: Approved")


@Cyberbot.tree.command(
    name="semgrep_vulnerability_scan",
    description="Perform a static vulnerability scan with Semgrep"
)
@app_commands.describe(
    file="Upload a single file to scan",
    semgrep_rule="Please select any non-premium semgrep rules from https://semgrep.dev/p/default"
)
async def semgrep_vulnerability_scan(ctx, file: discord.Attachment, semgrep_rule: str):
    print(f"User {ctx.user.name} initiated Semgrep Vulnerability Scan for file {file.filename}")
    await ctx.response.defer()
    if "../" in file.filename:
        await ctx.followup.sent("Vulnerability scan not performed for this file due to potential ../ attack in the file name scheme!")
        LoggingCommandBeingExecuted(ctx.user.name, f"/semgrep_vulnerability_scan file temporary URL: {file.url} Rule: {semgrep_rule}\n"
                                                   f"Command Status: Denied/File name hinted potential ../ attack!")
        print(f"Potential ../ attack! Reject scan process!\n\n")
    else:
        LoggingCommandBeingExecuted(ctx.user.name,f"/semgrep_vulnerability_scan file temporary URL: {file.url} Rule: {semgrep_rule}\n"
                                    f"Command Status: Approved")
        print("Downloading file content...")
        filePath = f"{DOWNLOADINGDIRPATH}{os.path.basename(file.url).split('?')[0]}"
        with requests.get(file.url, headers=MAINHEADERS, stream=True) as r:
            if r.status_code == 200:
                with open(filePath, "wb") as data:
                    for chunk in r.iter_content(chunk_size=8192):
                        data.write(chunk)
        print("Downloading Success!!!")
        try:
            result = subprocess.run(
                ["semgrep", "--config", f"{semgrep_rule}", "--json", filePath],
                capture_output=True,
                text=True
            )
            semgrep_raw_data = json.loads(result.stdout)
            semgrep_raw_data.pop("paths", None)
            for finding in semgrep_raw_data["results"]:
                finding.pop("path", None)
            semGrepJSONResult = json.dumps(semgrep_raw_data, indent=2)
            buffer = BytesIO()
            buffer.write(semGrepJSONResult .encode('utf-8'))
            buffer.seek(0)
            resultFile = discord.File(fp=buffer, filename="SemgrepJSONResult.json")
            await ctx.followup.send("Here is the Semgrep vulnerability scan result!",
                                      file=resultFile)
            os.remove(filePath)
            print(f"Scan Successful!\n\n")
        except Exception as e:
            print(f"Error running semgrep: {e}")
            os.remove(filePath)
            await ctx.followup.send(f"Error running semgrep: {e}")


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
    LoggingCommandBeingExecuted(ctx.user.name,f"/phishing_email_scan on email Content: {email_content} with keep_output_secret: {keep_output_secret}\nCommand Status: Approved")
    BERTPhishingResult, BERTPhishingprobability = Prediction(email_content, BERTtokenizer, BERTPhishingModel, "Phishing Emails")
    AllenAIPhishingResult, AllenAIPhishingprobability = Prediction(email_content, AllenAItokenizer, AllenAIPhishingModel, "Phishing Emails")
    BERTSpamResult, BERTSpamprobability = Prediction(email_content, BERTtokenizer, BERTSpamModel, "Spam Emails")
    AllenAISpamResult, AllenAISpamprobability = Prediction(email_content, AllenAItokenizer, ALLENAISpamModel, "Spam Emails")

    await ctx.followup.send(f"BERT-based Encoder-Transformer Phishing Detector Model results:\n{labels["Phishing"][str(BERTPhishingResult)]}\nConfidence: {BERTPhishingprobability * 100:.4f}%\n\n"
                            f"AllenAI-based Encoder-Transformer Phishing Detector  results:\n{labels["Phishing"][str(AllenAIPhishingResult)]}\nConfidence: {AllenAIPhishingprobability * 100:.4f}%\n\n"
                            f"BERT-based Encoder-Transformer Spam Detector Model results:\n{labels["Spam"][str(BERTSpamResult)]}\nConfidence: {BERTSpamprobability * 100:.4f}%\n\n"
                            f"AllenAI-based Encoder-Transformer Spam Detector  results:\n{labels["Spam"][str(AllenAISpamResult)]}\nConfidence: {AllenAISpamprobability * 100:.4f}%\n\n"
                            f"PLEASE NOTE that all the pre-trained encoder-transformer models were only trained on emails mostly written in English only with maximum of 1500 tokens/words!")


'''
#  Command can run in any channels
@Cyberbot.tree.command(
    name="manual_malware_scan_mode",
    description="Manually scan the file content you provided with GPT, Gemini, Virus Total, ClamAV, and CAPEv2"
)
@app_commands.describe(
    file="Upload a single file to scan"
)
async def manual_malware_scan_mode(ctx, file: discord.Attachment):
    print(f"User {ctx.user.name} initiated Manual Malware Scan for file {file.filename}")
    await ctx.response.defer()
    if "../" in file.filename:
        await ctx.followup.sent("Vulnerability scan not performed for this file due to potential ../ attack in the file name scheme!")
        LoggingCommandBeingExecuted(ctx.user.name,
                                    f"/manual_malware_scan_mode file temporary URL: {file.url}\nCommand Status: Denied/File name hinted potential ../ attack!")
        print(f"Potential ../ attack! Reject scan process!\n\n")
    else:
        LoggingCommandBeingExecuted(ctx.user.name,
                                    f"/manual_malware_scan_mode file temporary URL: {file.url}\nCommand Status: Approved")
        if file.filename.endswith((".enc", ".aes", ".pgp", ".gpg", ".vault")):
            print("File is encrypted, can not open without the key!")
            print("Scan Process Finish!\n\n")
            await ctx.followup.send(f"The file {file.filename} appears to be an encrypted file that may"
                                    f" contain confidential or malware information, it is encrypted,"
                                    f" so Cyberbot can not scan for the content. If you're intend to share the "
                                    f"encrypted file for sharing legitimate information with someone, please do "
                                    f"it via DM with the wanted party. If you received the file from someone that"
                                    f" you do not know, I advice not to download the file and decrypt it! If you have the"
                                    f" key, you can decrypt the file but do not open it and send again for Cyberbot to "
                                    f"scan!")
            LoggingCommandBeingExecuted(ctx.user.name,  f"/manual_malware_scan_mode file temporary URL: {file.url}\nCommand Status: File is encrypted!")
            return

        filePath = f"{DOWNLOADINGDIRPATH}{os.path.basename(file.url).split('?')[0]}"
        print("Downloading file content...")
        with requests.get(file.url, stream=True) as r:
            if r.status_code == 200:
                with open(filePath, "wb") as data:
                    for chunk in r.iter_content(chunk_size=8192):
                        data.write(chunk)
        print("Downloading Success!!!")
'''


@Cyberbot.event
async def on_message_edit(before, after):
    if after.author == Cyberbot.user:
        return

    if not str(after.guild.id) in CyberBotConfigData["Non-monitoring-Channels"]:
        CyberBotConfigData["Non-monitoring-Channels"][str(after.guild.id)] = []

    if after.channel.id in CyberBotConfigData["Non-monitoring-Channels"][str(after.guild.id)]:
        return

    if before.content != after.content:
        await Cyberbot.process_commands(after)
        if str(after.guild.id) not in CyberBotConfigData["Automation-Mode"] or str(after.guild.id) not in CyberBotConfigData["Silent-Mode"]:
            if str(after.guild.id) not in CyberBotConfigData["Automation-Mode"]:
                CyberBotConfigData["Automation-Mode"][str(after.guild.id)] = "True"
            if str(after.guild.id) not in CyberBotConfigData["Silent-Mode"]:
                CyberBotConfigData["Silent-Mode"][str(after.guild.id)] = "True"
            with open(CONFIGJSONFILEPATH, "w") as file:
                json.dump(CyberBotConfigData, file, indent=4)
        if CyberBotConfigData["Automation-Mode"][str(after.guild.id)] == "True":
            URLs = re.findall(r'https?://(?:(?!https?://)\S)+', after.content)
            if URLs:
                print("Detecting URLs in Re-edited text content...")
                if not CyberBotConfigData["Silent-Mode"][str(after.guild.id)] == "True":
                    await after.reply("Cyberbot detected URL(s) in text content. Begin scanning the URL(s) with Virus Total.")
                hashedUrl = ""
                for url in URLs:
                    print(f"Found URL: {url}")
                    hashedUrl = hashlib.sha256(url.encode('utf-8')).hexdigest()
                    if checkingCleanData(hashedUrl, "URLs"):
                        logScanSession(f"{time.ctime(time.time())}\nUser {after.author.name} re-edited message with url {url} already been scanned as safe to visit\n\n")
                        print(f"URL: {url} has been checked in Cyberbot scan history and recorded in the safe to visit")
                        if not CyberBotConfigData["Silent-Mode"][str(after.guild.id)] == "True":
                            await after.reply(f"URL: {url} has been checked in Cyberbot scan history and recorded in the safe to visit", suppress_embeds=True)
                        URLs.remove(url)
                    elif checkingFlaggedMaliciousData(hashedUrl, "URLs"):
                        logScanSession(f"{time.ctime(time.time())}\nUser {after.author.name} re-edited message with url {url} already been scanned as not safe to visit\n\n")
                        print(f"URL: {url} has been checked in Cyberbot scan history and recorded in the not safe to visit\n\n")
                        await after.reply(f"URL: {url} has been checked in Cyberbot scan history and recorded in the not safe to visit", suppress_embeds=True)
                        await after.delete()
                        return
                    else:
                        if url.startswith("https://klipy.com/gifs/"):
                            print(f"URL {url} is a Klipy gif, getting the real gif URL...")
                            klipyUrl = isKlipyURLValid(url)
                            if klipyUrl != "Invalid":
                                print(f"Klipy URL is valid!")
                                URLs.append(klipyUrl)
                                URLs.remove(url)
                            else:
                                print(f"Klipy URL is invalid!")
                                logScanSession(f"{time.ctime(time.time())}\nUser {after.author.name} sent Kliphy URL {url} that Cyberbot can not find the correct gif URL to access\n\n")
                                await after.reply(f"Cyberbot cannot access URL {url}")
                                URLs.remove(url)
                        else:
                            try:
                                testValidURLresponse = requests.get(url=url, headers=MAINHEADERS)
                                if testValidURLresponse.status_code in range(400, 500):
                                    logScanSession(f"{time.ctime(time.time())}\nUser {after.author.name} re-edited message with URL {url} with status code: {testValidURLresponse.status_code}\n\n")
                                    print(f"Can not access URL {url}\nStatus Code: {testValidURLresponse.status_code}")
                                    await after.reply(f"Cyberbot can not access URL {url} with status code: {testValidURLresponse.status_code}",suppress_embeds=True)
                                    URLs.remove(url)
                            except Exception as error:
                                print(f"Can not access URL {url}\nError: {error}")
                                logScanSession(f"{time.ctime(time.time())}\nUser {after.author.name} re-edited message with URL {url} with Error:\n{error}\n\n")
                                await after.reply(f"Cyberbot can not scan URL {url}", suppress_embeds=True)
                                URLs.remove(url)
                if URLs:
                    UrlScanResults = virusTotalURLScan(URLs)
                    for url in UrlScanResults:
                        if UrlScanResults[url] == "URL can't be scanned":
                            logScanSession(f"{time.ctime(time.time())}\nUser {after.author.name} re-edited message with URL {url} that can't be scanned by Virus Total\n\n")
                            print(f"URL {url} can't be scanned by Virus Total")
                            await after.reply(f"URL {url} can't be scanned by Virus Total", suppress_embeds=True)
                        elif int(UrlScanResults[url].split(":")[1]) > 0:
                            logScanSession(f"{time.ctime(time.time())}\nUser {after.author.name} re-edited message with URL {url} that flagged malicious by Virus Total\n\n")
                            print(f"URL {url} flagged malicious by Virus Total")
                            addingHashedData(hashedUrl, "URLs", True)
                            await after.channel.send(f"URL {url} is flagged malicious by Virus Total", suppress_embeds=True)
                            await after.delete()
                            print("Scan Process Finish!\n\n")
                            return
                        else:
                            logScanSession(f"{time.ctime(time.time())}\nUser {after.author.name} re-edited message with URL {url} that passed as safe to visit\n\n")
                            print(f"URL {url} passed Virus Total scan as Safe to visit!")
                            addingHashedData(hashedUrl, "URLs", False)
                            if not CyberBotConfigData["Silent-Mode"][str(after.guild.id)] == "True":
                                await after.reply(f"URL {url} is safe to visit", suppress_embeds=True)
                    print(f"URL scan finished!\n\n")



@Cyberbot.event
async def on_message(message):
    await Cyberbot.process_commands(message)
    if message.author == Cyberbot.user:
        return

    if not str(message.guild.id) in CyberBotConfigData["Non-monitoring-Channels"]:
        CyberBotConfigData["Non-monitoring-Channels"][str(message.guild.id)] = []

    if message.channel.id in CyberBotConfigData["Non-monitoring-Channels"][str(message.guild.id)]:
        return

    if str(message.guild.id) not in CyberBotConfigData["Automation-Mode"] or str(message.guild.id) not in CyberBotConfigData["Silent-Mode"]:
        if str(message.guild.id) not in CyberBotConfigData["Automation-Mode"]:
            CyberBotConfigData["Automation-Mode"][str(message.guild.id)] = "True"
        if str(message.guild.id) not in CyberBotConfigData["Silent-Mode"]:
            CyberBotConfigData["Silent-Mode"][str(message.guild.id)] = "True"
        with open(CONFIGJSONFILEPATH, "w") as file:
            json.dump(CyberBotConfigData, file, indent=4)

    if CyberBotConfigData["Automation-Mode"][str(message.guild.id)] == "True":
        if message.content:  # Check if the message text has at least 1 URL and Automation Mode is Enable!
            URLs = re.findall(r'https?://(?:(?!https?://)\S)+', message.content)
            if URLs:
                print("Detecting URLs in text content...")
                if not CyberBotConfigData["Silent-Mode"][str(message.guild.id)] == "True":
                    await message.reply("Cyberbot detected URL(s) in text content. Begin scanning the URL(s) with Virus Total.")
                hashedUrl = ""
                for url in URLs:
                    print(f"Found URL: {url}")
                    hashedUrl = hashlib.sha256(url.encode('utf-8')).hexdigest()
                    if checkingCleanData(hashedUrl, "URLs"):
                        logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} sent url {url} already been scanned as safe to visit\n\n")
                        print(f"URL: {url} has been checked in Cyberbot scan history and recorded in the safe to visit")
                        if not CyberBotConfigData["Silent-Mode"][str(message.guild.id)] == "True":
                            await message.reply(f"URL: {url} has been checked in Cyberbot scan history and recorded in the safe to visit", suppress_embeds=True)
                        URLs.remove(url)
                    elif checkingFlaggedMaliciousData(hashedUrl, "URLs"):
                        logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} sent url {url} already been scanned as not safe to visit\n\n")
                        print(f"URL: {url} has been checked in Cyberbot scan history and recorded in the not safe to visit\n\n")
                        await message.reply(f"URL: {url} has been checked in Cyberbot scan history and recorded in the not safe to visit", suppress_embeds=True)
                        await message.delete()
                        return
                    else:
                        if url.startswith("https://klipy.com/gifs/"):
                            print(f"URL {url} is a Klipy gif, getting the real gif URL...")
                            klipyUrl = isKlipyURLValid(url)
                            if klipyUrl != "Invalid":
                                print(f"Klipy URL is valid!")
                                URLs.append(klipyUrl)
                                URLs.remove(url)
                            else:
                                print(f"Klipy URL is invalid!")
                                logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} sent Kliphy URL {url} that Cyberbot can not find the correct gif URL to access\n\n")
                                await message.reply(f"Cyberbot cannot access URL {url}")
                                URLs.remove(url)
                        else:
                            try:
                                testValidURLresponse = requests.get(url=url, headers=MAINHEADERS)
                                if testValidURLresponse.status_code in range(400, 500):
                                    print(f"Can not access URL {url}\nStatus Code: {testValidURLresponse.status_code}")
                                    logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} sent URL {url} with status code: {testValidURLresponse.status_code}\n\n")
                                    print(f"URL {url} status code: {testValidURLresponse.status_code}")
                                    await message.reply(f"Cyberbot cannot access URL {url} with status code: {testValidURLresponse.status_code}", suppress_embeds=True)
                                    URLs.remove(url)
                            except Exception as error:
                                print(f"Can not access URL {url}\nError: {error}")
                                logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} sent URL {url} with Error:\n{error}\n\n")
                                await message.reply(f"Cyberbot can not scan URL {url}", suppress_embeds=True)
                                URLs.remove(url)
                if URLs:
                    UrlScanResults = virusTotalURLScan(URLs)
                    for url in UrlScanResults:
                        if UrlScanResults[url] == "URL can't be scanned":
                            logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} sent URL {url} that can't be scanned by Virus Total\n\n")
                            print(f"URL {url} can't be scanned by Virus Total")
                            await message.reply(f"URL {url} can't be scanned by Virus Total", suppress_embeds=True)
                        elif int(UrlScanResults[url].split(":")[1]) > 0:
                            logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} sent URL {url} that flagged malicious by Virus Total\n\n")
                            print(f"URL {url} flagged malicious by Virus Total")
                            addingHashedData(hashedUrl, "URLs", True)
                            await message.channel.send(f"URL {url} is flagged malicious by Virus Total", suppress_embeds=True)
                            await message.delete()
                            print("Scan Process Finish!\n\n")
                            return
                        else:
                            logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} sent URL {url} that passed as safe to visit\n\n")
                            print(f"URL {url} passed Virus Total scan as Safe to visit!")
                            addingHashedData(hashedUrl, "URLs", False)
                            if not CyberBotConfigData["Silent-Mode"][str(message.guild.id)] == "True":
                                await message.reply(f"URL {url} is safe to visit", suppress_embeds=True)
                    print(f"URL scan finished!\n\n")

        if len(message.attachments) > 0:  # Check if the message has at least 1 file attachment and Automation Mode is Enable!
            print(f"User {message.author.name} upload {len(message.attachments)} file attachment(s)!")

            """Checking if the current total file scan operation associated with the user exceeding the limit to prevent DOS attacks"""
            if str(message.author.id) not in users:
                users[str(message.author.id)] = {"Member name": message.author.name, "Current File Scan Operation": 0}
                with open(USERFILESCANPROCESSPATH, "w") as file:
                    json.dump(users, file, indent=4)

            if users[str(message.author.id)]["Current File Scan Operation"] + len(message.attachments) <= LIMITFILESCANPERUSER:
                users[str(message.author.id)]["Current File Scan Operation"] += len(message.attachments)
                currentScanProcesses = len(message.attachments)
                with open(USERFILESCANPROCESSPATH, 'w') as file:
                    json.dump(users, file, indent=4)

                for attachment in message.attachments:
                    if not CyberBotConfigData["Silent-Mode"][str(message.guild.id)] == "True":
                        await message.reply(f"Cyberbot is scanning the file {attachment.filename} in this message, please do not download until Cyberbot scan is clear of malware.")

                    """Checking ../ attack in file name scheme"""
                    if "../" in attachment.filename:
                        logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} uploaded a file attachment {attachment.filename} flagged ../ attack!\n\n")
                        print(f"File name {attachment.filename} hinted potential directory transversal attack!")
                        await message.reply(f"The file {attachment.filename} name hinted potential directory transversal attack, also known as ../ attack!")
                        await message.delete()
                        print("Scan Process Finish!\n\n")
                        users[str(message.author.id)]["Current File Scan Operation"] -= currentScanProcesses
                        with open(USERFILESCANPROCESSPATH, 'w') as file:
                            json.dump(users, file, indent=4)
                        return

                    """Checking file true extension"""
                    RootFileTrueExt = checkingRealFileExtension(attachment.url, attachment.filename)
                    if not CyberBotConfigData["Silent-Mode"][str(message.guild.id)] == "True":
                        await message.reply(f"The file {attachment.filename} extension is: {RootFileTrueExt}")

                    """Checking if file is encrypted"""
                    if RootFileTrueExt in CYBERBOTSCOPEOFORMATS:
                        if RootFileTrueExt.endswith(ENCRYPTEDFILEFORMATS):
                            logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} uploaded an encrypted file attachment {attachment.filename}!\n\n")
                            print("File is encrypted, can not open without the key!")
                            await message.reply(f"The file {attachment.filename} is an encrypted file that may"
                                                       f" contain confidential or malware information, it is encrypted,"
                                                       f" so Cyberbot can not scan for the content. If you're intend to share the "
                                                       f"encrypted file for sharing legitimate information with someone, please do "
                                                       f"it via DM with the wanted party. If you received the file from someone"
                                                       f" that you do not know, I advice not to download the file and decrypt it!"
                                                       f" If you have the key, you can decrypt the file but do not open it and send"
                                                       f" again for Cyberbot to scan!")
                            print("Scan Process Finish!\n\n")
                            users[str(message.author.id)]["Current File Scan Operation"] -= currentScanProcesses
                            with open(USERFILESCANPROCESSPATH, 'w') as file:
                                json.dump(users, file, indent=4)
                            return


                        scanOperation = False
                        filePath = f"{DOWNLOADINGDIRPATH}{attachment.filename}"

                        """Checking if file size within the supported file size for scan"""
                        head = requests.head(attachment.url)
                        FullContentLength = int(head.headers.get("Content-Length", 0))
                        if FullContentLength > 300000000:
                            logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} uploaded a file attachment {attachment.filename} with total size exceeding 300 MB\n\n")
                            await message.reply(f"The file {attachment.filename} has a size {FullContentLength} bytes, which"
                                                f" exceeding the file size limit that Cyberbot can support! The content won't be"
                                                f" scanned!")
                            currentScanProcesses -= 1
                            users[str(message.author.id)]["Current File Scan Operation"] -= 1
                            with open(USERFILESCANPROCESSPATH, 'w') as file:
                                json.dump(users, file, indent=4)
                        else:
                            with requests.get(attachment.url, headers=MAINHEADERS) as r:
                                if r.status_code == 200:
                                    RootFileHashed = hashlib.sha256(r.content).hexdigest()
                                    """Checking if file hashed signature already in clean or malicious data set"""
                                    if checkingCleanData(RootFileHashed, "All Extension"):
                                        logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} uploaded a file attachment {attachment.filename} already been scanned as safe to download\n\n")
                                        print(f"File {attachment.filename} has already been checked and recorded in the clean data set!\n\n")
                                        if not CyberBotConfigData["Silent-Mode"][str(message.guild.id)] == "True":
                                            await message.reply(f"File {attachment.filename} has been checked in Cyberbot scan history and recorded in the safe to download dataset!")
                                        currentScanProcesses -= 1
                                        users[str(message.author.id)]["Current File Scan Operation"] -= 1
                                        with open(USERFILESCANPROCESSPATH, 'w') as file:
                                            json.dump(users, file, indent=4)
                                    elif checkingFlaggedMaliciousData(RootFileHashed, "All Extension"):
                                        logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} uploaded a file attachment {attachment.filename} already been scanned as malicious\n\n")
                                        print(f"File {attachment.filename} has already been checked and recorded in the malicious file set!\n\n")
                                        await message.reply(f"File {attachment.filename} has been checked in Cyberbot scan history and recorded in the Malicious dataset! The content is deleted!")
                                        await message.delete()
                                        users[str(message.author.id)]["Current File Scan Operation"] -= currentScanProcesses
                                        with open(USERFILESCANPROCESSPATH, 'w') as file:
                                            json.dump(users, file, indent=4)
                                    else:
                                        scanOperation = True
                                        print("Downloading attachment content...")
                                        with open(filePath, "wb") as file:
                                            for chunk in r.iter_content(chunk_size=8192):
                                                file.write(chunk)
                                        print("Attachment file downloaded!")
                                else:
                                    logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} uploaded a file attachment {attachment.filename} unable to be downloaded\n\n")
                                    print("Cyberbot can not retrieve the attachment for scan!")
                                    await message.reply(f"Cyberbot can not retrieve {attachment.filename}!")
                                    await message.delete()
                                    users[str(message.author.id)]["Current File Scan Operation"] -= currentScanProcesses
                                    with open(USERFILESCANPROCESSPATH, 'w') as file:
                                        json.dump(users, file, indent=4)

                        if scanOperation:
                            if RootFileTrueExt.endswith(DISKIMAGEANDARCHIVEFORMATS):
                                mountPoint = f"{DOWNLOADINGDIRPATH}{attachment.filename.split('.')[0]}MainMountPoint/"
                                os.mkdir(mountPoint)
                                print("Attachment is an Archive or Disk Image file, checking for Archive/Disk Image Bomb...")
                                FileUncompressedSize = ArchivesDiskImagesBombAnalysisAndExtraction([filePath], mountPoint)
                                if FileUncompressedSize.startswith(("Encrypted Error", "Path Transversal Attack", "Potential Archive Bomb!", "Disk Image Error!", "Potential Recursive Archive Bomb Attack!", "Too many duplicated files!")):
                                    if FileUncompressedSize.startswith("Encrypted Error"):
                                        logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} uploaded an encrypted archive/disk file attachment {attachment.filename}\n\n")
                                        print(f"Archive/Disk file encrypted!")
                                        await message.reply(
                                            f"The archive/disk file {attachment.filename} contains an encrypted file"
                                            f" that may contain confidential or malware, it is encrypted, so Cyberbot can not scan"
                                            f" for the content. If you're intend to share the encrypted file for sharing legitimate"
                                            f" information with someone, please do it via DM with the wanted party. If you received"
                                            f" the file from someone that you do not know, I advice not to download the file and"
                                            f" decrypt it!"
                                        )
                                    elif FileUncompressedSize.startswith("Path Transversal Attack"):
                                        logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} uploaded an archive/disk file attachment {attachment.filename} with ../ attack\n\n")
                                        print(f"Archive/Disk file detected potential path transversal attack!")
                                        await message.reply(
                                            f"The file {attachment.filename} contains a file content with file name that"
                                            f" can cause a path transversal attack! The archive file will be deleted!"
                                        )
                                    elif FileUncompressedSize.startswith("Potential Archive Bomb!"):
                                        logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} uploaded an archive/disk file attachment {attachment.filename} flagged as potential archive/disk bomb\n\n")
                                        print(f"Archive/Disk file uncompressed size exceeding 32 GB!")
                                        await message.reply(
                                            f"The file {attachment.filename} has an uncompressed size exceeding 32 GB,"
                                            f" potential archive/diskImage bomb detected!"
                                        )
                                    elif FileUncompressedSize.startswith("Disk Image Error!"):
                                        logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} uploaded a corrupted archive/disk file attachment {attachment.filename}\n\n")
                                        print(f"Archive/Disk file has corrupted disk image")
                                        await message.reply(
                                            f"The file {attachment.filename} has a corrupted disk image!"
                                        )
                                    elif FileUncompressedSize.startswith("Potential Recursive Archive Bomb Attack!"):
                                        logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} uploaded an archive/disk file attachment {attachment.filename} flagged as potential archive/disk bomb\n\n")
                                        print(f"Archive/Disk file has more than 3 duplicated archive/disk files")
                                        await message.reply(
                                            f"The file {attachment.filename} has more than 3 duplicated archive/disk files within it "
                                            f"compressed content! This is a hint for a potential Recursive Archive/Disk Bomb Attack!"
                                        )
                                    else:
                                        logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} uploaded an archive/disk file attachment {attachment.filename} flagged as potential archive/disk bomb\n\n")
                                        print(f"Archive/Disk file has too many duplicated contents")
                                        await message.reply(
                                            f"The file {attachment.filename} has too many duplicated files within it "
                                            f"compressed content! This is a hint for a potential Archive/Disk Bomb Attack Method that"
                                            f" extract many duplicated content to fill up storage space!"
                                        )
                                    if not FileUncompressedSize.startswith("Encrypted Error"):
                                        await message.delete()
                                    print("Cleaning up process...")
                                    shutil.rmtree(mountPoint)
                                    addingHashedData(RootFileHashed, RootFileTrueExt, True)
                                    print(f"Scan Process Finish!\n\n")
                                    users[str(message.author.id)]["Current File Scan Operation"] -= currentScanProcesses
                                    with open(USERFILESCANPROCESSPATH, 'w') as file:
                                        json.dump(users, file, indent=4)
                                    return

                                if not CyberBotConfigData["Silent-Mode"][str(message.guild.id)] == "True":
                                    await message.reply(f"The file {attachment.filename} has an uncompressed size of"
                                                        f" {FileUncompressedSize.split('|')[0]} bytes, which below the standard "
                                                        f"threshold uncompressed size of 32 GB to be flagged as archive/diskImage "
                                                        f"bomb!\nBegin the scanning process on the uncompressed content"
                                                        f", which may take quite some time. There are {FileUncompressedSize.split('|')[1]}"
                                                        f" duplicated content to be aware of!")
                                    files = ""
                                    for _, _, filenames in os.walk(mountPoint):
                                        for filename in filenames:
                                            files += f"{filename}\n"
                                    await message.reply(f"File contents in {attachment.filename} are:\n{files}")

                                print(f"Start scanning for the extracted file contents at {mountPoint} with Virus Total...")
                                for dirpath, _, filenames in os.walk(mountPoint):
                                    for filename in filenames:
                                        filepath = os.path.join(dirpath, filename)
                                        fileSize = os.path.getsize(filepath)
                                        fileExt = checkingRealFileExtension(filepath, filename, False)
                                        with open(filepath, 'rb') as source:
                                            HashedFileData = hashlib.sha256(source.read()).hexdigest()
                                        print(f"Found file: {filename} | Type: {fileExt} | Size: {fileSize} bytes | From path {filepath}")
                                        if checkingCleanData(HashedFileData, "All Extension"):
                                            print(f"File {filename} has already been checked and recorded in the clean data set!")
                                            if not CyberBotConfigData["Silent-Mode"][str(message.guild.id)] == "True":
                                                await message.reply(f"File {filename} inside archive/disk image {attachment.filename} has been checked in Cyberbot scan history and recorded in the safe to download dataset!")
                                            os.remove(filepath)
                                        elif checkingFlaggedMaliciousData(HashedFileData, "All Extension"):
                                            logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} uploaded a file attachment {filename} inside the archive/disk attachment {attachment.filename} already flagged as malicious\n\n")
                                            print(f"File {filename} has already been checked and recorded in the malicious file set!")
                                            await message.reply(f"File {filename} inside {attachment.filename} has been checked in Cyberbot scan history and recorded in the Malicious dataset! The content is deleted!")
                                            await message.delete()
                                            addingHashedData(RootFileHashed, RootFileTrueExt, True)
                                            users[str(message.author.id)]["Current File Scan Operation"] -= currentScanProcesses
                                            with open(USERFILESCANPROCESSPATH, 'w') as file:
                                                json.dump(users, file, indent=4)
                                            print("Cleaning up process...")
                                            shutil.rmtree(mountPoint)
                                            print(f"Scan Process Finish!\n\n")
                                            return
                                        else:
                                            print("Start Virus Total Scan...")
                                            virusTotalResult = virusTotalFileScan(filePath).split(":")
                                            virusTotalReport = f"{virusTotalResult[0]} Malicious, {virusTotalResult[1]} Suspicious, {virusTotalResult[2]} Harmless, {virusTotalResult[3]} Undetected"
                                            if int(virusTotalResult[0]) > 0:
                                                logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} uploaded a file attachment {filename} inside the archive/disk attachment {attachment.filename} flagged as malicious by Virus Total\nReport:{virusTotalReport}\n\n")
                                                print(f"Virus Total analyzed file {filename} as malicious!")
                                                await message.reply(f"File {filename} inside archive/disk image {attachment.filename} was flagged malicious by Virus Total!\n{virusTotalReport}")
                                                await message.delete()
                                                addingHashedData(HashedFileData, fileExt, True)
                                                addingHashedData(RootFileHashed, RootFileTrueExt, True)
                                                users[str(message.author.id)]["Current File Scan Operation"] -= currentScanProcesses
                                                with open(USERFILESCANPROCESSPATH, 'w') as file:
                                                    json.dump(users, file, indent=4)
                                                print("Cleaning up process...")
                                                shutil.rmtree(mountPoint)
                                                print(f"Scan Process Finish!\n\n")
                                                return
                            else:  # All other single file format
                                print("Start Virus Total Scan...")
                                virusTotalResult = virusTotalFileScan(filePath).split(":")
                                virusTotalReport = f"{virusTotalResult[0]} Malicious, {virusTotalResult[1]} Suspicious, {virusTotalResult[2]} Harmless, {virusTotalResult[3]} Undetected"
                                if int(virusTotalResult[0]) > 0:
                                    logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} uploaded a file attachment {attachment.filename} flagged as malicious by Virus Total\nReport:{virusTotalReport}\n\n")
                                    print(f"Virus Total analyzed file {attachment.filename} as malicious!")
                                    await message.reply(f"File {attachment.filename} was flagged malicious by Virus Total!\n{virusTotalReport}")
                                    await message.delete()
                                    addingHashedData(RootFileHashed, RootFileTrueExt, True)
                                    users[str(message.author.id)]["Current File Scan Operation"] -= currentScanProcesses
                                    with open(USERFILESCANPROCESSPATH, 'w') as file:
                                        json.dump(users, file, indent=4)
                                    print("Cleaning up process...")
                                    os.remove(filePath)
                                    print(f"Scan Process Finish!\n\n")
                                    return
                                mountPoint = f"{DOWNLOADINGDIRPATH}{attachment.filename.split('.')[0]}MountPoint/"
                                os.mkdir(mountPoint)
                                shutil.move(filePath, mountPoint)
                                print(f"Content has been moved to main scan directory {mountPoint}")


                            CompiledHashedMap = {}
                            print(f"Start scanning for COMPILED file contents ONLY at {mountPoint}...")
                            for dirpath, _, filenames in os.walk(mountPoint):
                                for filename in filenames:
                                    filepath = os.path.join(dirpath, filename)
                                    fileSize = os.path.getsize(filepath)
                                    fileExt = checkingRealFileExtension(filepath, filename, False)
                                    with open(filepath, 'rb') as source:
                                        HashedCompiledFileData = hashlib.sha256(source.read()).hexdigest()
                                    if fileExt in EXECUTABLEFORMATS:
                                        print(f"Found compiled file: {filename} | Type: {fileExt} | Size: {fileSize} bytes | From path {filepath}")
                                        try:
                                            with pyhidra.open_program(
                                                    filepath,
                                                    project_name=GHIDRAPROJECTNAME,
                                                    project_location=GHIDRAPROJECTPATH,
                                                    analyze=True  # Run auto-analysis
                                            ) as flat_api:
                                                print(
                                                    f"Successfully opened program: {flat_api.getCurrentProgram().getName()}")

                                                # Get Ghidra API objects from the flat_api
                                                currentProgram = flat_api.getCurrentProgram()
                                                from ghidra.util.task import TaskMonitor

                                                monitor = TaskMonitor.DUMMY

                                                # Initialize the decompiler
                                                from ghidra.app.decompiler import DecompInterface
                                                decompiler = DecompInterface()
                                                decompiler.openProgram(currentProgram)

                                                outputFilePath = os.path.join(mountPoint, f"{currentProgram.getName()}_decompiled.c")
                                                print(f"Exporting decompiled code to: {outputFilePath}")

                                                with open(outputFilePath, "w") as f:
                                                    f.write("// Decompiled by Ghidra (via Pyhidra)\n")
                                                    f.write(f"// Program: {currentProgram.getName()}\n\n")

                                                    function_manager = currentProgram.getFunctionManager()
                                                    functions = function_manager.getFunctions(True)  # True for ordered functions

                                                    for function in functions:
                                                        res = decompiler.decompileFunction(function, 0, monitor)
                                                        if res.decompileCompleted():
                                                            f.write(f"\n// Function: {function.getName()}\n")
                                                            f.write(str(res.getDecompiledFunction().getC()))

                                                print(f"Decompilation and export complete. Cleaning up compiled file {filename}")
                                                os.remove(filepath)

                                        except Exception as e:
                                            print(f"An error occurred: {e}")
                                            os.remove(filepath)
                                        with open(outputFilePath, "rb") as file:
                                            HashedDecompiledData = hashlib.sha256(file.read()).hexdigest()

                                        CompiledHashedMap[HashedCompiledFileData] = HashedDecompiledData

                            print(f"Start scanning for SCRIPT file contents ONLY at {mountPoint}...")
                            for dirpath, _, filenames in os.walk(mountPoint):
                                for filename in filenames:
                                    filepath = os.path.join(dirpath, filename)
                                    fileSize = os.path.getsize(filepath)
                                    fileExt = checkingRealFileExtension(filepath, filename, False)
                                    with open(filepath, 'rb') as source:
                                        HashedScriptFileData = hashlib.sha256(source.read()).hexdigest()
                                    if fileExt in SCRIPTFILEFORMATS:
                                        print(f"Found script file: {filename} | Type: {fileExt} | Size: {fileSize} bytes | From path {filepath}")

                                        flaggedMalicious = False

                                        if not flaggedMalicious:
                                            print(f"Start {GPTMODEL} scan on file {filename} for malware analysis...")
                                            GptScanResult = openAISCAT(filepath, "Reads"
                                                                               " the source/script file contents and decides if it is malware"
                                                                               " exhibit any malicious pattern. if you suspect it is malware,"
                                                                               " start the response with True or False and explain why. Do not bold or highlight any characters in the response!")
                                            if GptScanResult.startswith(("True", "true")):
                                                flaggedMalicious = True
                                                print(f"{GPTMODEL} analyzed the content of being a potential malware!")
                                                if len(GptScanResult) > 1500:
                                                    print(
                                                        f"Scan result exceeding 1500 words, creating a txt file to send the report...")
                                                    buffer = BytesIO()
                                                    buffer.write(GptScanResult.encode('utf-8'))
                                                    buffer.seek(0)
                                                    resultFile = discord.File(fp=buffer, filename="GPTScanResult.txt")
                                                    await message.reply(
                                                        f"The {GPTMODEL} scan result for file {attachment.filename} suggested"
                                                        f" a potential malicious file, therefore it will be deleted!",
                                                        file=resultFile)
                                                else:
                                                    await message.reply(
                                                        f"{GPTMODEL} scan result: {GptScanResult}\n\nThe file"
                                                        f" {attachment.filename} was detected of being a"
                                                        f" potential malicious file, therefore it will be"
                                                        f" deleted!")

                                        if not flaggedMalicious:
                                            print(f"Start Gemini Model {GEMINIMODEL} scan on file {filename} for malware analysis...")
                                            GeminiScanResult = GeminiSCAT(filepath,
                                                                          "You are a security engineer bot that reads"
                                                                          " the source/script file contents and decides if it is malware"
                                                                          " exhibit any malicious pattern. if you suspect it is malware,"
                                                                          " start the response with True or False and explain why. Do not bold or highlight any characters in the response!")

                                            if GeminiScanResult.startswith(("True", "true")):
                                                flaggedMalicious = True
                                                print(f"Gemini analyzed the content of being a potential malware!")
                                                if len(GeminiScanResult) > 1500:
                                                    print(f"Scan result exceeding 1500 words, creating a txt file to send the report...")
                                                    buffer = BytesIO()
                                                    buffer.write(GeminiScanResult.encode('utf-8'))
                                                    buffer.seek(0)
                                                    resultFile = discord.File(fp=buffer, filename="GeminiScanResult.txt")
                                                    await message.reply(
                                                        f"The {GEMINIMODEL} scan result for file {attachment.filename} suggested"
                                                        f" a potential malicious file, therefore it will be deleted!",
                                                        file=resultFile)
                                                else:
                                                    await message.reply(
                                                        f"{GEMINIMODEL} scan result: {GeminiScanResult}\n\nThe file"
                                                        f" {attachment.filename} was detected of being a"
                                                        f" potential malicious file, therefore it will be"
                                                        f" deleted!")

                                        if flaggedMalicious:
                                            logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} uploaded a script file attachment {filename} flagged as malicious\n\n")
                                            if HashedScriptFileData == RootFileHashed:
                                                addingHashedData(RootFileHashed, RootFileTrueExt, True)
                                            else:
                                                addingHashedData(HashedScriptFileData, fileExt, True)
                                                addingHashedData(RootFileHashed, RootFileTrueExt, True)
                                                for HashedData in CompiledHashedMap:
                                                    if CompiledHashedMap[
                                                        HashedData] == HashedScriptFileData and HashedData != RootFileHashed:
                                                        addingHashedData(HashedData, ".exe", True)
                                                        break
                                            await message.delete()
                                            print("Cleaning up process...")
                                            shutil.rmtree(mountPoint)
                                            print(f"Scan Process Finish!\n\n")
                                            users[str(message.author.id)][
                                                "Current File Scan Operation"] -= currentScanProcesses
                                            with open(USERFILESCANPROCESSPATH, 'w') as file:
                                                json.dump(users, file, indent=4)
                                            return
                                        else:
                                            addingHashedData(HashedScriptFileData, fileExt, False)
                                            for HashedData in CompiledHashedMap:
                                                if CompiledHashedMap[
                                                    HashedData] == HashedScriptFileData and HashedData != RootFileHashed:
                                                    addingHashedData(HashedData, ".exe", False)
                                                    break

                            print("Cleaning up process...")
                            shutil.rmtree(mountPoint)
                            addingHashedData(RootFileHashed, RootFileTrueExt, False)
                            logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} uploaded file attachment {attachment.filename} passed the scan as safe to download\n\n")
                            if not CyberBotConfigData["Silent-Mode"][str(message.guild.id)] == "True":
                                await message.reply(f"The file {attachment.filename} is safe to download!")
                            currentScanProcesses -= 1
                            users[str(message.author.id)]["Current File Scan Operation"] -= 1
                            with open(USERFILESCANPROCESSPATH, 'w') as file:
                                json.dump(users, file, indent=4)
                            print(f"Scan Process Finish!\n\n")
                    else:
                        logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} uploaded file attachment {attachment.filename} with format outside of Cyberbot scope of supported formats\n\n")
                        await message.reply(f"The file {attachment.filename} extension is outside of Cyberbot scope of file "
                                            f"formats for malware analysis!")
                        currentScanProcesses -= 1
                        users[str(message.author.id)]["Current File Scan Operation"] -= 1
                        with open(USERFILESCANPROCESSPATH, 'w') as file:
                            json.dump(users, file, indent=4)

            else:
                logScanSession(f"{time.ctime(time.time())}\nUser {message.author.name} reached file scan rate limit!\n\n")
                try:
                    await message.author.send(f"The limit of how many file scan processes per user is {LIMITFILESCANPERUSER}!\n"
                                              f"There is currently {users[str(message.author.id)]["Current File Scan Operation"]} file scan operations associated with the files originated from you!\n"
                                              f"You can upload {LIMITFILESCANPERUSER - users[str(message.author.id)]["Current File Scan Operation"]} to scan or wait until all of your total file scan to be below {LIMITFILESCANPERUSER} to upload the next file(s)!")
                except discord.Forbidden:
                    await message.reply(f"The limit of how many file scan processes per user is {LIMITFILESCANPERUSER}!\n"
                                        f"There is currently {users[str(message.author.id)]["Current File Scan Operation"]} file scan operations associated with the files originated from you!\n"
                                        f"You can upload {LIMITFILESCANPERUSER - users[str(message.author.id)]["Current File Scan Operation"]} to scan or wait until all of your total file scan to be below {LIMITFILESCANPERUSER} to upload the next file(s)!")
                    await asyncio.sleep(7)
                    await message.delete()
Cyberbot.run(BOTTOKEN)
