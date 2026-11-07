"""Cyberbot authentication is following DAC access control, where each member that have admin account with Cyberbot MUST BE granted by the Server Owner to alter the configuration of Cyberbot for the server"""
from __future__ import annotations


"""In this version, Cyberbot will store the admin user registered email as a SHA512 hash. This would make the email notification feature be disabled."""
import os
import subprocess
from dotenv import load_dotenv

load_dotenv()


"""Operating System Configuration"""
OperatingSystem = "MacOS" # Set this to the OS that the bot is running on (Support MacOS and Linux)

print("Checking Essential System Binaries")
systembinaries = ["7zz", "qemu-img", "java", "unar"]
for systembinary in systembinaries:
    result = subprocess.run(["which", systembinary], capture_output=True, text=True)
    if f"{result.stderr}{result.stdout}":
        if "not found" in f"{result.stderr}{result.stdout}":
            raise ModuleNotFoundError(f"System binary {systembinary} NOT FOUND. Please install the system binary via brew or apt or compiled from source code for Cyberbot to function")
        else:
            print(f"System binary {systembinary} FOUND.")
    else:
        raise ModuleNotFoundError(f"System binary {systembinary} NOT FOUND. Please install the system binary via brew or apt or compiled from source code for Cyberbot to function")


"""Python Dependencies Check"""
print("Checking Python Dependencies")
dependencies = ["discord-py", "python-dotenv", "filetype", "openai", "python-magic", "rarfile", "aiofiles", "aiocsv", "numpy", "pandas", "matplotlib", "fpdf", "google-genai", "transformers", "torch", "jep", "email-validator", "bcrypt"]
for dependency in dependencies:
    result = subprocess.run(["pip", "show", dependency], capture_output=True, text=True)
    if "not found" in f"{result.stderr}{result.stdout}":
        raise ModuleNotFoundError(f"Python dependency {dependency} NOT FOUND. Please install the dependency via pip in order for Cyberbot to function")
    else:
        print(f"Python dependency {dependency} FOUND.")


"""Ghidra Configuration"""
GHIDRA_INSTALL_DIR = os.environ.get("GHIDRA_INSTALL_DIR")


"""Checking Ghidra and GhidraThon Installed Properly"""
print("Checking Ghidra and Ghidrathon installation")
if os.path.exists(GHIDRA_INSTALL_DIR):
    print(f"Ghidra FOUND.")
    if os.path.exists(os.path.join(GHIDRA_INSTALL_DIR, "Ghidra", "Extensions", "Ghidrathon")):
        print(f"Ghidrathon extension FOUND.")
    else:
        raise ModuleNotFoundError(f"Ghidrathon extension NOT FOUND. Please install Ghidrathon extension following the instruction in the README.md!")
else:
    raise ModuleNotFoundError(f"Ghidra NOT FOUND. Please install Ghidra following the instruction in the README.md!")

from CyberBotArchiveDiskImageScanModule import *
from CyberBotURLPreprocessingModule import *
from CyberBotEncoderTransformersModule import loadClassifierModel, Prediction

import shutil
import smtplib, ssl
import datetime

from discord import app_commands
from discord.ext import tasks
from typing import Literal
from email.message import EmailMessage
from io import BytesIO
from openai import AsyncOpenAI
from google import genai
from fpdf import FPDF
from transformers import BertTokenizer, LongformerTokenizer
from aiocsv import AsyncWriter
from zoneinfo import ZoneInfo
from email_validator import validate_email, EmailNotValidError
from google.genai import types
from google.genai.types import HttpOptions
from google.genai.errors import APIError
from httpx import ConnectTimeout
from contextlib import asynccontextmanager

import pathlib
import openai
import aiofiles
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
import bcrypt


"""Getting Important File Paths"""
ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent

# Configuration Files
CYBERBOT_CONFIG = str(ROOT_DIR / "Files" / "Configurations" / "CyberBotConfig.json")
ONE_TIME_TOKEN_PATH = str(ROOT_DIR / "Files" / "Configurations" / "OneTimeToken.json")
DOWNLOADING_DIR = str(ROOT_DIR / "DownloadDirectory/")

# Application Logs
CYBERBOT_APPLICATION_COMMAND_LOG = str(ROOT_DIR / "Files" / "Logs" / "CyberBotDiscordCommandsLog.md")
FILE_AND_URL_SCAN_LOG = str(ROOT_DIR / "Files" / "Logs" / "CyberbotURLAndFileScanLog.md")
CRON_TASK_LOG = str(ROOT_DIR / "Files" / "Logs" / "CyberBotCronTasksLog.md")
LLM_USAGE_LOG = str(ROOT_DIR / "Files" / "LLM Usages") + "/"

# Local hash JSON databases
CLEAN_SIGNATURES_DB = str(ROOT_DIR / "Files" / "HashedSignatures" / "CleanSHA256Signatures.json")
MALICIOUS_SIGNATURES_DB = str(ROOT_DIR / "Files" / "HashedSignatures" / "MaliciousSHA256Signatures.json")

# Local Pre-train LLM PyTorch Files
if OperatingSystem == "MacOS":
    hardware = "MPS"
else:
    hardware = "CPU"
BERT_PHISHING_CLASSIFIER = str(ROOT_DIR / "Files" / "MLModels" / hardware / f"BERTBasedEncoderPhishingDetector{hardware}.pth")
ALLEN_AI_PHISHING_CLASSIFIER = str(ROOT_DIR / "Files" / "MLModels" / hardware / f"AllenAIBasedPhishingDetector{hardware}.pth")
BERT_PASSWORD_STRENGTH_CLASSIFIER = str(ROOT_DIR / "Files" / "MLModels" / hardware / f"BERTBasedEncoderPasswordClassifier{hardware}.pth")
ALLEN_AI_PASSWORD_STRENGTH_CLASSIFIER = str(ROOT_DIR / "Files" / "MLModels" / hardware / f"AllenAIBasedEncoderPasswordClassifier{hardware}.pth")
BERT_SPAM_CLASSIFIER = str(ROOT_DIR / "Files" / "MLModels" / hardware / f"BERTBasedEncoderSpamClassifier{hardware}.pth")
ALLEN_AI_SPAM_CLASSIFIER = str(ROOT_DIR / "Files" / "MLModels" / hardware / f"AllenAIBasedEncoderSpamClassifier{hardware}.pth")


"""----API Tokens----"""
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_API_KEY")
virusTotalApiKey = os.environ.get("VT_API_KEY")

"""System Configuration"""
rarfile.UNRAR_TOOL = "unar"
intents = discord.Intents.all()
with open(CYBERBOT_CONFIG, "r") as JSONfile:
    CyberBotConfigData = json.load(JSONfile)
print(f"Cyberbot Configuration Data successfully loaded!")

"""LLM Configuration"""
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

GPTclient = AsyncOpenAI(timeout=300, max_retries=0) # We will handle retry manually
GeminiClient = genai.Client(http_options=HttpOptions(timeout=300000))
GPT_MODEL = "gpt-5.3-codex"
GEMINI_MODEL = "gemini-3.8-flash"
LLM_MODEL_INFORMATION = {
    GEMINI_MODEL:
        {
            "Maximum Input Tokens": 1048576,
            "Cost": {"Input Token": [0.75, 0.75], "Output Token": [3.75, 3.75], "Cached Read": [0.075, 0.075], "Cached Writes": [0.5, 0.5]},
            "TPM": 2000000
        },
    GPT_MODEL:
        {
            "Maximum Input Tokens": 400000,
            "Cost": {"Input Token": [1.75, 1.75], "Output Token": [14, 14], "Cached Read": [0.175, 0.175]},
            "TPM": 500000
        }
}

"""Loading Pre-Trained Tokenizer Models"""
print(f"Loading Pre-Trained Tokenizer Models...")
BERTtokenizer = BertTokenizer.from_pretrained('bert-base-cased')
print("BERT tokenizer successfully loaded!")
AllenAItokenizer = LongformerTokenizer.from_pretrained('allenai/longformer-base-4096')
print("Allen AI tokenizer successfully loaded!")

"""Loading Pre-trained Encoder Transformer Classifiers"""
print(f"Loading Pre-Trained Encoder-Transformer Models...")
BERTPhishingClassifier = loadClassifierModel(BERT_PHISHING_CLASSIFIER, "BERT", "Phishing Emails", hardware.lower())
AllenAIPhishingClassifier = loadClassifierModel(ALLEN_AI_PHISHING_CLASSIFIER, "Allen AI", "Phishing Emails", hardware.lower())
BERTPasswordClassifier = loadClassifierModel(BERT_PASSWORD_STRENGTH_CLASSIFIER, "BERT", "Password Strength", hardware.lower())
AllenAIPasswordClassifier = loadClassifierModel(ALLEN_AI_PASSWORD_STRENGTH_CLASSIFIER, "Allen AI", "Password Strength", hardware.lower())
BERTSpamClassifier = loadClassifierModel(BERT_SPAM_CLASSIFIER, "BERT", "Spam Emails", hardware.lower())
ALLENAISpamClassifier = loadClassifierModel(ALLEN_AI_SPAM_CLASSIFIER, "Allen AI", "Spam Emails", hardware.lower())


"""Initializing asyncio locks for Thread-Safe File I/O to prevent race conditions"""
ConfigLock = asyncio.Lock()
ScanLogLock = asyncio.Lock()
CommandLogLock = asyncio.Lock()
OneTimeTokenLock = asyncio.Lock()
CleanSignatureLock = asyncio.Lock()
MaliciousSignatureLock = asyncio.Lock()
MonthlyCSVLock = asyncio.Lock()
YearlyCSVLock = asyncio.Lock()
CronTaskLock = asyncio.Lock()
HashScanLocksGuard = asyncio.Lock()
HashScanLocks = {} # Share an in-flight file scan result by SHA-256; duplicate attachments never create a second disk copy.
InFlightFileScans = {} # Bound disk-free fingerprint downloads separately from expensive full malware scans.
FILE_HASH_SEMAPHORE = asyncio.Semaphore(8) # Maximum 8 file content hash operation
ATTACHMENT_CONTENT_IN_MEMORY_LIMIT = 8_000_000_000 # Maximum 8 Gig of RAM storage is allowed to allocate temporary attachment file content
VIRUSTOTAL_SEMAPHORE = asyncio.Semaphore(2) # Maximum 2 concurrent Virus Total API call at any given time (Depending on your tier, free tier are heavily rate limited)
FILE_SCAN_SEMAPHORE = asyncio.Semaphore(7) # Maximum 7 concurrent full file scan at any given time
URL_SCAN_SEMAPHORE = asyncio.Semaphore(7)  # Maximum 7 concurrent full URL scan at any given time
ARCHIVE_SEMAPHORE = asyncio.Semaphore(3) # Maximum 2 archive file scan at any given time
GHIDRA_SEMAPHORE = asyncio.Semaphore(1) # Maximum 1 ghidra decompilation process at any given time, ghidra is very compute expensive
GEMINI_SEMAPHORE = asyncio.Semaphore(10) # Maximum 10 concurrent Gemini API call at any given time
OPENAI_SEMAPHORE = asyncio.Semaphore(10) # Maximum 10 concurrent OpenAI API call at any given time

"""Getting Current Time Value"""
ct = time.ctime(time.time()).split()
previousMonth = ct[1]
previousDate = ct[2]
previousYear = ct[4]
if not os.path.exists(f"{LLM_USAGE_LOG}{previousYear}"):
    os.mkdir(f"{LLM_USAGE_LOG}{previousYear}")
if not os.path.exists(f"{LLM_USAGE_LOG}{previousYear}/{previousMonth}"):
    os.mkdir(f"{LLM_USAGE_LOG}{previousYear}/{previousMonth}")

"""Ghidra Configuration"""
GHIDRA_TEMP_PROJECTS = str(ROOT_DIR / "CyberbotGhidraProject/")
GHIDRA_HEADLESS_EXECUTABLE = f"{GHIDRA_INSTALL_DIR}/support/analyzeHeadless"
GHIDRA_DECOMPILE_SCRIPT = str(ROOT_DIR / "PythonScripts" / "CyberBotGhidraDecompileModule.py")
JEPLIB_PATH = os.environ.get("JEPLIBPATH")


"""Scan Result dataclass"""
@dataclass
class FileScanResult:
    def __init__(self, RootFileName: str, status: str, sendingMessage: str, logMessage: str, RootFileHashed: str = ""):
        self.RootFileName = RootFileName
        self.status = status
        self.sendingMessage = sendingMessage
        self.logMessage = logMessage
        self.RootFileHashed = RootFileHashed

@dataclass
class URLScanResult:
    def __init__(self, url: str, status: str, sendingMessage: str, logMessage: str):
        self.url = url
        self.status = status
        self.sendingMessage = sendingMessage
        self.logMessage = logMessage

