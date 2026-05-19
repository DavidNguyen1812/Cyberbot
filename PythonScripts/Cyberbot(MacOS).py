import os
import random
import re
import shutil
import smtplib, ssl
import discord
import datetime

from discord import app_commands
from discord.ext import commands, tasks
from typing import Literal
from dotenv import load_dotenv
from email.message import EmailMessage
from io import BytesIO
from openai import AsyncOpenAI
from google import genai  # Need pip install google-genai
from fpdf import FPDF # Need pip install fpdf
from transformers import BertTokenizer, LongformerTokenizer # Need pip install transformers
from EncoderTransformers import loadClassifierModel, Prediction
from aiocsv import AsyncWriter
from zoneinfo import ZoneInfo
from urllib.parse import unquote
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
import aiohttp
import aiofiles
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np



"""This version following DAC access control, where each member can have admin account with Cyberbot granted by the Server Owner"""

load_dotenv()

"""Define all file extensions Cyberbot will scan"""
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

CYBERBOTSCOPEOFORMATS = DISKIMAGEANDARCHIVEFORMATS + ENCRYPTEDFILEFORMATS + EXECUTABLEFORMATS + AUDIOFORMATS + SCRIPTFILEFORMATS + DOCUMENTFILEFORMATS + PICTUREFORMATS + VIDEOFORMATS

"""Getting Important File Paths"""
CYBERBOTCONFIG = os.environ.get("CYBERBOTCONFIGPATH")
DOWNLOADINGDIRPATH = os.environ.get("CYBERBOTROOTFILEDOWNLOADPATH")
CYBERBOTCOMMANDLOG = os.environ.get("CYBERBOTCOMMANDLOGPATH")
RESETPASSWORDTOKENPATH = os.environ.get("RESETPASSWORDTOKENPATH")
CLEANSIGNATURESPATH = os.environ.get("CYBERBOTCLEANSIGNATURES")
MALISCIOUSSIGNATUREPATH = os.environ.get("CYBERBOTMALICIOUSSIGNATURES")
SCATLOG = os.environ.get("CYBERBOTSCATLOGS")
SCANLOG = os.environ.get("CYBERBOTSCANLOGS")
CRONTASKLOG = os.environ.get("CYBERBOTCRONTASKLOG")
MAINHEADERS = {'User-Agent': 'Mozilla / 5.0(Windows NT 10.0; Win64; x64) AppleWebKit / 537.36(KHTML, likeGecko) Chrome / 142.0.0.0 Safari / 537.36'}
BERTPHISHINGPATH = os.environ.get("BERTPHISHINGPATH")
ALLENAIPHISHINGPATH = os.environ.get("ALLENAIPHISHINGPATH")
BERTPASSWORDPATH = os.environ.get("BERTPASSWORDPATH")
ALLENAIPASSWORDPATH = os.environ.get("ALLENAIPASSWORDPATH")
BERTSPAMPATH = os.environ.get("BERTSPAMPATH")
ALLENAISPAMPATH = os.environ.get("ALLENSPAMPATH")
LLMUSAGELOGDIR = os.environ.get("LLMUSAGELOGDIR")
FILEDOWNLOADCOUNTER = 1
CURRENTSCANOPERATION = {}

"""----API Tokens----"""
BOTTOKEN = os.environ.get("CYBERBOTDISCORDAPI")
virusTotalApiKey = os.environ.get("CYBERBOTVTKEY")
KliphyAPI = os.environ.get("CYBERBOTKLIPHYAPI")
TENORAPI = os.environ.get("CYBERBOTTENORAPI")

"""System Configuration"""
rarfile.UNRAR_TOOL = "unar"
intents = discord.Intents.all()
with open(CYBERBOTCONFIG, "r") as JSONfile:
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

GPTclient = AsyncOpenAI(api_key=os.environ.get("CYBERBOTGPTKEY"))
GeminiClient = genai.Client()
GPTMODEL = "gpt-5.3-codex"
GEMINIMODEL = "gemini-3.1-pro-preview"
LLMMODELINFORMATION = {
                        GEMINIMODEL:
                            {
                                "Maximum Input Tokens": 1048576,
                                "Cost": {"Input Token": [2, 4], "Output Token": [12, 18]},
                                "TPM": 2000000
                            },
                        GPTMODEL:
                            {
                                "Maximum Input Tokens": 400000,
                                "Cost": {"Input Token": [1.75, 1.75], "Output Token": [14, 14]},
                                "TPM": 500000
                            }
                      }
LLMModels = [GPTMODEL, GEMINIMODEL]

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

"""Initialize aiohttp.ClientSession in setUpHook"""
class CyberBot(commands.Bot):
    async def setup_hook(self):
        self.session = aiohttp.ClientSession()
        print("aiohttp ClientSession initialized.")

    async def close(self):
        await super().close()
        await self.session.close()
Cyberbot = CyberBot(command_prefix='/', intents=intents)

"""Initializing asyncio locks for Thread-Safe File I/O to prevent race conditions"""
ConfigLock = asyncio.Lock()
ScanLogLock = asyncio.Lock()
CommandLogLock = asyncio.Lock()
ResetTokenLock = asyncio.Lock()
CleanSignatureLock = asyncio.Lock()
MaliciousSignatureLock = asyncio.Lock()
ScatLogLock = asyncio.Lock()
MonthlyCSVLock = asyncio.Lock()
YearlyCSVLock = asyncio.Lock()
CronTaskLock = asyncio.Lock()

"""Getting Current Time Value"""
ct = time.ctime(time.time()).split()
previousMonth = ct[1]
previousDate = ct[2]
previousYear = ct[4]
if not os.path.exists(f"{LLMUSAGELOGDIR}{previousYear}"):
    os.mkdir(f"{LLMUSAGELOGDIR}{previousYear}")
if not os.path.exists(f"{LLMUSAGELOGDIR}{previousYear}/{previousMonth}"):
    os.mkdir(f"{LLMUSAGELOGDIR}{previousYear}/{previousMonth}")

"""Ghidra Configuration"""
GHIDRAPROJECTPATH = os.environ.get("GHIDRAPROJECTPATH")
GHIDRAPROJECTNAME = os.environ.get("GHIDRAPROJECTNAME")
GHIDRA_INSTALL_DIR = os.environ.get("GHIDRA_INSTALL_DIR")
GHIDRAHEADLESS = f"{GHIDRA_INSTALL_DIR}/support/analyzeHeadless"
GHIDRASCRIPTPATH = os.environ.get("GHIDRASCRIPTPATH")
JEPLIBPATH = os.environ.get("JEPLIBPATH")

def plotBarCharts(datasets: list[dict], xLabels: list[str], suptitle: str, savePath: str) -> None:
    """
    Description: Plotting three bar charts representing Total Input Tokens, Total Output Tokens and Total Costs
    :param datasets: The list of all y values for each bar chart
    :param xLabels: The x label for each bar chart
    :param suptitle: The Main Title for all the bar charts
    :param savePath: The path to save the bar charts
    :return: None, the bar charts will be saved in the savePath
    """
    x = np.arange(len(xLabels))
    barWidth = 0.55
    fig, axes = plt.subplots(3, 1, figsize=(13, 13))
    fig.patch.set_facecolor("#F7F8FA")
    fig.suptitle(suptitle, fontsize=17, fontweight="bold", color="#1E2A3A", y=0.98)
    for ax, ds in zip(axes, datasets):
        values = ds["values"]
        color = ds["color"]
        max_v = max(values) if any(v > 0 for v in values) else 1
        bars = ax.bar(x, values, width=barWidth, color=color, alpha=0.88, edgecolor="white", linewidth=0.8, zorder=3)
        ax.set_facecolor("#F7F8FA")
        ax.set_title(ds["title"], fontsize=13, fontweight="bold", color="#1E2A3A", pad=8, loc="left")
        ax.set_xticks(x)
        ax.set_xticklabels(xLabels, fontsize=10, color="#444")
        ax.tick_params(axis="y", labelsize=9, colors="#666")
        ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{v:,.0f}"))
        ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
        ax.spines[["top", "right", "left"]].set_visible(False)
        ax.spines["bottom"].set_color("#DDD")
        ax.yaxis.grid(True, color="#E0E0E0", linewidth=0.7, zorder=0)
        ax.set_axisbelow(True)
        ax.tick_params(axis="x", length=0)
        for bar, val in zip(bars, values):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max_v * 0.015, f"{val:,}", ha="center", va="bottom", fontsize=7.5, color="#333", fontweight="500")
        for i, val in enumerate(values):
            if val == 0:
                ax.axvspan(i - barWidth / 2, i + barWidth / 2, color="#E8E8E8", alpha=0.5, zorder=1)
    plt.savefig(savePath, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)


def plotModelCalls(LLMModelUses: list[int], savePath: str):
    """
    Description: Plotting a single bar chart showing the total calls per LLM models each month
    :param LLMModelUses: The usage value of each LLM models
    :param savePath: The path to save the bar chart
    :return: None, the bar chart will be saved in the savePath
    """

    x = np.arange(len(LLMModels))
    max_val = max(LLMModelUses) if any(LLMModelUses) else 2

    fig, ax = plt.subplots(figsize=(10, 7))
    fig.patch.set_facecolor("#F7F8FA")

    bars = ax.bar(LLMModels, LLMModelUses, width=0.55, color="Purple", alpha=0.88, edgecolor="white", linewidth=0.8, zorder=3)
    ax.set_facecolor("#F7F8FA")
    ax.set_title("LLM Model Calls", fontsize=13, fontweight="bold", color="#1E2A3A", pad=8, loc="left")
    ax.set_xticks(x)
    ax.set_xticklabels(LLMModels, fontsize=10, color="#444", rotation=40, ha="right")
    ax.tick_params(axis="y", labelsize=9, colors="#666")
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{v:,.0f}"))
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.spines["bottom"].set_color("#DDD")
    ax.yaxis.grid(True, color="#E0E0E0", linewidth=0.7, zorder=0)
    ax.set_axisbelow(True)
    ax.tick_params(axis="x", length=0)
    for bar, val in zip(bars, LLMModelUses):
        if val > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max_val * 0.015,f"{val:,}", ha="center", va="bottom", fontsize=7.5, color="#333", fontweight="500")

    for i, val in enumerate(LLMModelUses):
        if val == 0:
            ax.axvspan(i - 0.55 / 2, i + 0.55 / 2, color="#E8E8E8", alpha=0.5, zorder=1)
    ax.set_ylim(0, max_val * 1.35)
    plt.savefig(savePath, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)


async def writingLLMUsageCsv(csvPath: str, mode: Literal['w', 'a'], data: list, ObjectLock: asyncio.locks.Lock) -> None:
    """
    Description: Executing read and write only operation on the csv files related to logging Samson LLM Usage
    :param csvPath: The path to the csv file
    :param mode: Must be 'w' or 'a'
    :param data: The data to write
    :param ObjectLock: Object lock on write operation to prevent race condition
    :return: None
    """
    async with ObjectLock:
        async with aiofiles.open(csvPath, mode) as f:
            csvWriter = AsyncWriter(f)
            await csvWriter.writerow(data)


def calculateUsageCost(model: str, totalInputTokens: int, totalOutputTokens: int) -> float:
   """
   Description: Calculate the usage cost of the LLM model based on the total input tokens and output tokens.
   :param model: LLM Model
   :param totalInputTokens: The total input tokens of a prompt
   :param totalOutputTokens: The total output tokens of a prompt
   :return: The final calculated usage cost
   """
   totalCost = (totalInputTokens / 1000000) * LLMMODELINFORMATION[model]["Cost"]["Input Token"][0] + (totalOutputTokens / 1000000) * LLMMODELINFORMATION[model]["Cost"]["Output Token"][0]
   return round(totalCost, 5)


async def CronTaskLog(logData: str):
    async with CronTaskLock:
        async with aiofiles.open(CRONTASKLOG, "a") as logFile:
            await logFile.write(logData)


@tasks.loop(minutes=1)  # A task every 1 minute
async def checking_expired_tokens():
    # print(f"Checking for expired password reset token...")
    async with ResetTokenLock:
        async with aiofiles.open(RESETPASSWORDTOKENPATH, "r") as file:
            resetTokens = json.loads(await file.read())
    delete_tokens = []
    for tokenID in resetTokens:
        if time.time() >= resetTokens[tokenID][1]:
            print(f"Reset token {resetTokens[tokenID][0]} for {tokenID} expired.")
            delete_tokens.append(tokenID)
    for tokenID in delete_tokens:
        print(f"Removing token associated with {tokenID}...")
        del resetTokens[tokenID]
    async with ResetTokenLock:
        async with aiofiles.open(RESETPASSWORDTOKENPATH, "w") as file:
            await file.write(json.dumps(resetTokens, indent=4))
    # print(f"Process Finished!\n\n")


@tasks.loop(seconds=15)  # A task every 15 seconds
async def checking_member_can_kick_cyberbot():
    # print(f"Checking if member can kick cyberbot...")
    for account in CyberBotConfigData["Admins"]:
        for serverID in account["Accessible Servers"]:
            guild = Cyberbot.get_guild(serverID)
            member = guild.get_member(account["User ID"])
            if guild.me.top_role.position < member.top_role.position and member.id != guild.owner.id:
                await guild.owner.send(f"Member {member.name} from the server {guild.name} ID {serverID} that you owned can kick Cyberbot. Please make sure Cyberbot has a higher role than all the members in the server.")
                print(f"Member {member.name} can kick Cyberbot from server {guild.name} ID {serverID}. Warning was sent to server owner")
    # print("Process finished!\n\n")


@tasks.loop(time=datetime.time(hour=0, minute=0, tzinfo=ZoneInfo("America/New_York")))  # A task every new day
async def checking_expired_passwords_clear_dms_with_admins_update_llm_usages():

    global previousYear, previousMonth, previousDate

    try:
        await CronTaskLog(f"{time.ctime(time.time())}\n")
        print(f"Checking for expired password...")
        await CronTaskLog("Cron Task: DAILY CHECKING FOR EXPIRED PASSWORDS\n")
        for account in CyberBotConfigData["Admins"]:
            if time.time() >= account["Credential Expiration Age"]:
                print(f"Password for {account["User Email"]} expired.")
                if await asyncio.to_thread(sendEmail, "Cyberbot admin account password expired",
                             f"Your current admin account password has expired!\n"
                             f"Please use command /request_password_reset_token and /change_password in the DM channel with Cyberbot to update your password!\n",
                             account["User Email"]) == "Email sent successfully!":
                    await CronTaskLog(f"Password for {account["User Email"]} expired. Notification Email successfully sent!\n")
                else:
                    await CronTaskLog(f"Password for {account["User Email"]} expired. Notification Email sent FAILURE!\n")
        print(f"Process Finished!\n\n")
        await CronTaskLog("Status: Success\n\n")
    except Exception as e:
        await CronTaskLog(f"Error: {e}\n\n")

    try:
        await CronTaskLog(f"{time.ctime(time.time())}\n")
        print(f"Cleaning DMs with admins...")
        await CronTaskLog("Cron Task: DAILY CLEANING DM CHATS WITH USERS THAT HAS ADMIN ACCOUNT\n")
        for AdminAccount in CyberBotConfigData["Admins"]:
            admin = await Cyberbot.fetch_user(AdminAccount["User ID"])
            async for message in admin.history():
                if message.author == Cyberbot.user:
                    await message.delete()
            print(f"DMs with admin {admin.name} cleaned successfully!")
            await CronTaskLog(f"DMs with admin {admin.name} cleaned successfully!\n")
        print(f"Process Finished!\n\n")
        await CronTaskLog("Status: Success\n\n")
    except Exception as e:
        await CronTaskLog(f"Error: {e}\n\n")

    currentTime = time.ctime(time.time()).split()

    # Checking new date
    if currentTime[2] != previousDate:
        await CronTaskLog(f"{time.ctime(time.time())}\n")
        print(f"New Day of the Month Change: {previousMonth} {previousDate} -> {currentTime[1]} {currentTime[2]}")
        try:
            print(f"Updating LLMMonthlyUsageReport.png...")
            await CronTaskLog("Cron Task: DAILY UPDATING LLMMonthlyUsageReport.png\n")
            async with MonthlyCSVLock:
                monthlyData = await asyncio.to_thread(pd.read_csv, f"{LLMUSAGELOGDIR}LLMMonthlyUsage.csv")
            monthlyTotalInputToken = []
            monthlyTotalOutputToken = []
            monthlyTotalCost = []
            for day in range(1, int(currentTime[2]) + 1):
                dailyTotalInputToken = 0
                dailyTotalOutputToken = 0
                dailyTotalCost = 0
                for _, row in monthlyData.iterrows():
                    if int(row["Date"].split(" ")[1]) == day:
                        dailyTotalInputToken += row["Total Input Tokens"]
                        dailyTotalOutputToken += row["Total Output Tokens"]
                        dailyTotalCost += row["Total Cost"]
                monthlyTotalInputToken.append(dailyTotalInputToken)
                monthlyTotalOutputToken.append(dailyTotalOutputToken)
                monthlyTotalCost.append(dailyTotalCost)
            datasets = [
                {"values": monthlyTotalInputToken, "title": "Total Input Tokens", "color": "Blue"},
                {"values": monthlyTotalOutputToken, "title": "Total Output Tokens", "color": "Green"},
                {"values": monthlyTotalCost, "title": "Total Cost ($)", "color": "Orange"},
            ]
            dates = [str(date) for date in range(1, int(currentTime[2]) + 1)]
            plotBarCharts(datasets, dates, "LLM Usage - Monthly Overview",f"{LLMUSAGELOGDIR}{previousYear}/{previousMonth}/LLMMonthlyUsageReport.png")
            print(f"Successfully Updating LLMMonthlyUsageReport.png!")
            await CronTaskLog("Status: Success\n\n")

            try:
                print(f"Updating LLMModelsUsed.png...")
                await CronTaskLog("Cron Task: DAILY UPDATING LLMModelsUsed.png\n")
                LLMModelUses = [0 for _ in range(len(LLMModels))]
                for _, row in monthlyData.iterrows():
                    LLMModelUses[LLMModels.index(row["LLM Models"])] += 1
                plotModelCalls(LLMModelUses, f"{LLMUSAGELOGDIR}{previousYear}/{previousMonth}/LLMModelsUsed.png")
                print(f"Successfully Updating LLMModelsUsed.png!")
                await CronTaskLog("Status: Success\n\n")
            except Exception as error:
                print(f"An error occurs while updating LLMModelsUsed.png\n{error}")
                await CronTaskLog(f"Error: {error}\n\n")

        except Exception as error:
            print(f"An error occurs while updating LLMMonthlyUsageReport.png\n{error}")
            await CronTaskLog(f"Error: {error}\n\n")

        previousDate = currentTime[2]

    # Checking new year
    if currentTime[4] != previousYear:
        await CronTaskLog(f"{time.ctime(time.time())}\n")
        print(f"New Year Change: {previousYear} -> {currentTime[4]}")
        try:
            print(f"Generating LLM Usage Yearly Report...")
            await CronTaskLog("Cron Task: GENERATING LLM USAGE YEARLY REPORT\n")
            async with YearlyCSVLock:
                yearlyData = await asyncio.to_thread(pd.read_csv, f"{LLMUSAGELOGDIR}LLMYearlyUsage.csv")
            months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
            monthlyTotalInputTokens = []
            monthlyTotalOutputTokens = []
            monthlyTotalCosts = []
            for month in months:
                monthlyTotalInputToken = 0
                monthlyTotalOutputToken = 0
                monthlyTotalCost = 0
                for _, row in yearlyData.iterrows():
                    if row["Date"].split(' ')[0] == month:
                        monthlyTotalInputToken += row["Total Input Tokens"]
                        monthlyTotalOutputToken += row["Total Output Tokens"]
                        monthlyTotalCost += row["Total Cost"]
                monthlyTotalInputTokens.append(monthlyTotalInputToken)
                monthlyTotalOutputTokens.append(monthlyTotalOutputToken)
                monthlyTotalCosts.append(monthlyTotalCost)
            datasets = [
                {"values": monthlyTotalInputTokens, "title": "Total Input Tokens", "color": "Blue"},
                {"values": monthlyTotalOutputTokens, "title": "Total Output Tokens", "color": "Green"},
                {"values": monthlyTotalCosts, "title": "Total Cost ($)", "color": "Orange"},
            ]
            plotBarCharts(datasets, months, "LLM Usage - End of Year Overview",f"{LLMUSAGELOGDIR}{previousYear}/FullYearUsageReport.png")
            print(f"Successfully Generating LLM Usage Yearly Report!")
            await CronTaskLog("Status: Success\n\n")

            try:
                print(f"Resetting LLMYearlyUsage.csv...")
                await CronTaskLog("Cron Task: RESETTING LLMYearlyUsage.csv\n")
                await writingLLMUsageCsv(f"{LLMUSAGELOGDIR}LLMYearlyUsage.csv", "w",["Date", "Total Input Tokens", "Total Output Tokens", "LLM Models", "Total Cost"], YearlyCSVLock)
                print(f"Successfully resetting LLMYearlyUsage.csv!")
                await CronTaskLog("Status: Success\n\n")

                try:
                    print(f"Creating a new year folder...")
                    await CronTaskLog("Cron Task: CREATING A NEW YEAR FOLDER\n")
                    os.mkdir(f"{LLMUSAGELOGDIR}{currentTime[4]}")
                    print(f"Successfully create a new year folder!")
                    await CronTaskLog("Status: Success\n\n")

                except Exception as error:
                    print(f"An error occurs while creating a new year folder\n{error}")
                    await CronTaskLog(f"Error: {error}\n\n")

            except Exception as error:
                print(f"An error occurs while resetting LLMYearlyUsage.csv\n{error}")
                await CronTaskLog(f"Error: {error}\n\n")

        except Exception as error:
            print(f"An error occurs while generating LLM Usage Yearly Report\n{error}")
            await CronTaskLog(f"Error: {error}\n\n")

        previousYear = currentTime[4]

    # Checking new month
    if currentTime[1] != previousMonth:
        await CronTaskLog(f"{time.ctime(time.time())}\n")
        print(f"New Month Change: {previousMonth} -> {currentTime[1]}")
        try:
            print(f"Resetting LLMMonthlyUsage.csv...")
            await CronTaskLog("Cron Task: RESETTING LLMMonthlyUsage.csv\n")
            await writingLLMUsageCsv(f"{LLMUSAGELOGDIR}LLMMonthlyUsage.csv", "w",["Date", "Total Input Tokens", "Total Output Tokens", "LLM Models", "Total Cost"], MonthlyCSVLock)
            print(f"Successfully resetting LLMMonthlyUsage.csv!")
            await CronTaskLog("Status: Success\n\n")
            try:
                print(f"Creating a new month folder...")
                await CronTaskLog("Cron Task: CREATING A NEW MONTH FOLDER\n")
                os.mkdir(f"{LLMUSAGELOGDIR}{currentTime[4]}/{currentTime[1]}")
                print(f"Successfully create a new month folder!")
                await CronTaskLog("Status: Success\n\n")

            except Exception as error:
                print(f"An error occurs while creating a new month folder\n{error}")
                await CronTaskLog(f"Error: {error}\n\n")

        except Exception as error:
            print(f"An error occurs while resetting LLMMonthlyUsage.csv\n{error}")
            await CronTaskLog(f"Error: {error}\n\n")
        previousMonth = currentTime[1]


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
    checking_expired_passwords_clear_dms_with_admins_update_llm_usages.start()
    checking_member_can_kick_cyberbot.start()


@Cyberbot.event
async def on_member_join(member):
    print(f"New member {member.name} joined {member.guild.name}\nAdding new member to user file scan process file...\n\n")


@Cyberbot.event
async def on_member_remove(member):
    print(f"Member {member.name} left server {member.guild.name} ID {member.guild.id}\nRemoving member admin access and session from the server...\n\n")
    for admin in CyberBotConfigData["Admins"]:
        if admin["User ID"] == member.id:
            admin["Accessible Servers"].remove(member.guild.id)
            if str(member.guild.id) in admin["Current Admin Session Period"]:
                del admin["Current Admin Session Period"][str(member.guild.id)]
            await asyncio.to_thread(sendEmail,"Admin access to Discord Server Removed",
                      f"Your Cyberbot admin access to server {member.guild.name} ID {member.guild.id} has been removed.\nThe reason was that you have left the server!",
                      admin["User Email"])
    async with ConfigLock:
        async with aiofiles.open(CYBERBOTCONFIG, "w") as file:
            await file.write(json.dumps(CyberBotConfigData, indent=4))
    await member.send(f"Your admin access to server {member.guild.name} ID {member.guild.id} has been removed.\nThe reason was that you have left the server!")


async def isKlipyURLValid(gifURL):
    try:
        gifSlug = os.path.basename(gifURL)
        gifURL = f"https://api.klipy.com/api/v1/{KliphyAPI}/gifs/items?slugs={gifSlug}"
        async with Cyberbot.session.get(gifURL) as response:
            if response.status == 200:
                data = await response.json()
                if data["result"]:
                    gifURL = data["data"]["data"][0]["file"]["hd"]["gif"]["url"]
                    return gifURL
        return "Invalid"
    except Exception as error:
        print(f"Klipy URL error: {error}")
        return "Invalid"


async def isTenorURLValid(gifURL: str) -> str:
    """
    Description: Tenor URL validation
    :param gifURL: Tenor URL
    :return: The correct tenor URL or Invalid if URL is not a tenor URL
    """
    try:
        gifID = gifURL.split('/')[4].split('-')[len(gifURL.split('/')[4].split('-')) - 1]
        gifURL = f"https://tenor.googleapis.com/v2/posts?ids={gifID}&key={TENORAPI}"
        async with Cyberbot.session.get(gifURL) as response:
            if response.status == 200:
                data = await response.json()
                if data["results"]:
                    gifUrl = data["results"][0]["media_formats"]["gif"]["url"]
                    return gifUrl
            return "Invalid"
    except Exception as error:
        print(f"Tenor URL error: {error}")
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


async def LoggingCommandBeingExecuted(userName: str, command: str):
    async with CommandLogLock:
        async with aiofiles.open(CYBERBOTCOMMANDLOG, "a") as logFile:
            await logFile.write(f"{time.ctime(time.time())}")
            await logFile.write(f"\n{userName} used command {command}\n\n")


async def randomPasswordGenerator():
    # Must be 12 length minimum
    # Must have mixed characters and numbers
    # Letters must have mixed case
    # Contains the following special characters !@#$%&*_+=
    char = f"ABCDEFGHIJKLNMOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%&*_+="
    password = ""
    while None in [re.search(r'[a-z]', password), re.search(r'[A-Z]', password), re.search(r'\d', password), re.search(r'[!@#$%&*_+=]', password)]:
        password = ""
        for i in range(random.randint(12, 20)):
            password += random.choice(char)
    return password


async def GeminiCheckCommonPassword(password: str):
    response = await GeminiClient.aio.models.generate_content(
        model="gemini-3.1-pro-preview",
        contents=f"Only say True if {password} seems to be from commonly used passwords, otherwise say False"
    )

    inputPromptTokenCount = response.usage_metadata.prompt_token_count
    outputPromptTokenCount = response.usage_metadata.total_token_count - inputPromptTokenCount
    cMonth = time.ctime(time.time()).split()[1]
    cDay = time.ctime(time.time()).split()[2]
    totalCost = calculateUsageCost(GEMINIMODEL, inputPromptTokenCount, outputPromptTokenCount)
    await writingLLMUsageCsv(f"{LLMUSAGELOGDIR}LLMMonthlyUsage.csv", "a",[f"{cMonth} {cDay}", inputPromptTokenCount, outputPromptTokenCount, GEMINIMODEL, totalCost], MonthlyCSVLock)
    await writingLLMUsageCsv(f"{LLMUSAGELOGDIR}LLMYearlyUsage.csv", "a", [f"{cMonth} {cDay}", inputPromptTokenCount, outputPromptTokenCount, GEMINIMODEL, totalCost], YearlyCSVLock)

    if response.text.startswith(("True", "true")):
        return True
    else:
        return False


async def CheckPasswordPwned(password: str):
    # Reference: https://haveibeenpwned.com/API/v3

    sha1Signature = hashlib.sha1(password.encode()).hexdigest().upper()
    firstFiveChars = sha1Signature[:5]
    everyCharsAFterTheFirstFive = sha1Signature[5:]

    async with Cyberbot.session.get(f"https://api.pwnedpasswords.com/range/{firstFiveChars}") as response:
        pwnedPasswords = (await response.text()).split("\n")

    for password in pwnedPasswords:
        parts = password.split(":")
        if parts[0] == everyCharsAFterTheFirstFive:
            return True
    return False


async def checkingRealFileExtension(BytesContent: bytes, filename: str) -> str:
    print("Checking file extension with Python-Magic module...")
    mime = magic.from_buffer(BytesContent, mime=True)
    fileExt = mimetypes.guess_extension(mime)
    FullContentLength = len(BytesContent)
    if fileExt:
        if fileExt == ".bin":
            if BytesContent.startswith(b'PK'):
                print(f"Detected file extension .zip")
                return '.zip'
            elif BytesContent.startswith(b'caff'):
                print(f"Detected file extension .caf")
                return '.caf'
            elif FullContentLength > 512:
                last512Bytes = BytesContent[-512:]
                if b'conectix' in last512Bytes:
                    print(f"Detected file extension .vhd")
                    return ".vhd"
                if b'koly' in last512Bytes or last512Bytes.startswith(b'EFI PART') or BytesContent.startswith(b'EFI PART'):
                    print(f"Detected file extension .dmg")
                    return ".dmg"
        if fileExt == ".webm" and filename.endswith(".weba"):
            print(f"Detected file extension .weba")
            return ".weba"
        if fileExt == ".webm" and filename.endswith(".wmv"):
            print(f"Detected file extension .wmv")
            return ".wmv"
        if fileExt == ".wmv" and filename.endswith(".wma"):
            print(f"Detected file extension .wma")
            return ".wma"
        if fileExt == ".ogv" and filename.endswith(".ogg"):
            print(f"Detected file extension .ogg")
            return ".ogg"
        if fileExt == ".asf" and filename.endswith(".wmv"):
            print(f"Detected file extension .wmv")
            return ".wmv"
        if fileExt == ".asf" and filename.endswith(".wma"):
            print(f"Detected file extension .wma")
            return ".wma"
        print(f"Detected file extension {fileExt}")
        return fileExt
    else:
        print("python-magic could not determined, manually checking based on pre-defined list...")
        try:
            if BytesContent.decode("ascii").isascii():
                print(f"ASCII document or script files detected")
                return "ASCII document or script files"
        except UnicodeDecodeError:
            if BytesContent.startswith(
                    (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe',
                     b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca')):
                print("File extension is Mach-O executable!")
                return "Mach-O executable"
            if BytesContent.startswith(b'\x7f\x45\x4c\x46'):
                print("File extension is ELF (Executable and Linkable Format)!")
                return "ELF executable"
            if BytesContent.startswith(b'QFI\xfb'):
                print("File extension is QEMU Copy-On-Write virtual disk!")
                return ".qcow2"
            if BytesContent.startswith(b'vhdxfile'):
                print("File extension is virtual hard disk image!")
                return ".vhdx"
            if BytesContent.startswith(b'KDMV'):
                print("File extension is virtual machine disk image!")
                return ".vmdk"
            if len(BytesContent) >= 32768:  # Sector 16 (2048 * 16)
                if BytesContent[32768:32768 + 5].startswith((b"NSR02", b"NSR03")):
                    print("File extension is an Universal Disk image!")
                    return ".udf"
            print("Checking file extension with filetype module...")
            fileExt = filetype.guess(BytesContent)
            if fileExt:
                print(f"filetype detected extension: {fileExt.extension}")
                return f".{fileExt.extension}"
            else:
                if BytesContent.startswith((b'\x0B\x77', b'\x0bwu\xacT@C')):
                    print(f"Detected file extension .ac3")
                    return ".ac3"
                elif filename.endswith(".lzma"):
                    print(f"Detected file extension .lzma")
                    return ".lzma"
    print(f"File extension can not be determined!")
    return "Can't be determined"


async def openAISCAT(filepath: str, prompt: str):
    async with aiofiles.open(filepath, "rb") as PDFfile:
        fileResponse = await GPTclient.files.create(file=(f"{FILEDOWNLOADCOUNTER}.pdf", await PDFfile.read()), purpose="assistants")
        fileID = fileResponse.id

    inputPromptTokenCount = (await GPTclient.responses.input_tokens.count(model=GPTMODEL, instructions="You are a cybersecurity analyst on a file for potential malware detection", input=[{"role": "user", "content": [{"type": "input_text", "text": prompt}, {"type": "input_file", "file_id": fileID}]}])).input_tokens
    print(f"Total Input Tokens: {inputPromptTokenCount}")
    if inputPromptTokenCount > LLMMODELINFORMATION[GPTMODEL]["Maximum Input Tokens"] or inputPromptTokenCount > LLMMODELINFORMATION[GPTMODEL]["TPM"]:
        print(f"MAXIMUM TOKEN LIMIT!!")
        await GPTclient.files.delete(fileID)
        async with ScatLogLock:
            async with aiofiles.open(SCATLOG, "a") as logfile:
                await logfile.write(f"{time.ctime(time.time())}\nFile being scanned: {os.path.basename(filepath)}\nTotal Input Tokens: {inputPromptTokenCount}\nOpenAI Assistant {GPTMODEL} Scan Result: MAXIMUM TOKEN LIMIT!\n\n\n")
        return "MAXIMUM TOKEN LIMIT"
    else:
        response = await GPTclient.responses.create(model=GPTMODEL, instructions="You are a cybersecurity analyst on a file for potential malware detection", input=[{"role": "user", "content": [{"type": "input_text", "text": prompt}, {"type": "input_file", "file_id": fileID}]}])
        await GPTclient.files.delete(fileID)
        outputPromptTokenCount = response.usage.total_tokens - inputPromptTokenCount
        print(f"Total Output Tokens: {outputPromptTokenCount}")
        cMonth = time.ctime(time.time()).split()[1]
        cDay = time.ctime(time.time()).split()[2]
        totalCost = calculateUsageCost(GPTMODEL, inputPromptTokenCount, outputPromptTokenCount)
        await writingLLMUsageCsv(f"{LLMUSAGELOGDIR}LLMMonthlyUsage.csv", "a",[f"{cMonth} {cDay}", inputPromptTokenCount, outputPromptTokenCount, GPTMODEL, totalCost], MonthlyCSVLock)
        await writingLLMUsageCsv(f"{LLMUSAGELOGDIR}LLMYearlyUsage.csv", "a",[f"{cMonth} {cDay}", inputPromptTokenCount, outputPromptTokenCount, GPTMODEL, totalCost], YearlyCSVLock)
        async with ScatLogLock:
            async with aiofiles.open(SCATLOG, "a") as logfile:
                await logfile.write(f"{time.ctime(time.time())}\nFile being scanned: {os.path.basename(filepath)}\nTotal Input Tokens: {inputPromptTokenCount}\nOpenAI Assistant {GPTMODEL} Scan Result: {response.output_text}\nTotal Output Tokens: {outputPromptTokenCount}\n\n\n")
        return response.output_text


async def GeminiSCAT(filepath: str, prompt: str):
    uploadedFile = await GeminiClient.aio.files.upload(file=filepath)
    print(f"Uploaded file '{uploadedFile.name}' as: {uploadedFile.uri}")
    prompts = [uploadedFile, prompt]
    try:
        totalInputTokenCount = (await GeminiClient.aio.models.count_tokens(model=GEMINIMODEL, contents=prompts)).total_tokens
    except Exception as error:
        print(f"Received error: {error}\nAttempting upload original source file")
        uploadedFile = await GeminiClient.aio.files.upload(file=filepath.replace(".pdf", ".txt"))
        print(f"Uploaded file '{uploadedFile.name}' as: {uploadedFile.uri}")
        prompts = [uploadedFile, prompt]
        totalInputTokenCount = (await GeminiClient.aio.models.count_tokens(model=GEMINIMODEL, contents=prompts)).total_tokens
    print(f"Total Input Tokens: {totalInputTokenCount}")
    if totalInputTokenCount > LLMMODELINFORMATION[GEMINIMODEL]["Maximum Input Tokens"] or totalInputTokenCount > LLMMODELINFORMATION[GEMINIMODEL]["TPM"]:
        print(f"MAXIMUM TOKEN LIMIT!!")
        async with ScatLogLock:
            async with aiofiles.open(SCATLOG, "a") as logfile:
                await logfile.write(f"{time.ctime(time.time())}\nFile being scanned: {os.path.basename(filepath)}\nTotal Input Tokens: {totalInputTokenCount}\nGemini {GEMINIMODEL} Scan Result: MAXIMUM TOKEN LIMIT!\n\n\n")
        return "MAXIMUM TOKEN LIMIT"
    else:
        response = await GeminiClient.aio.models.generate_content(model=GEMINIMODEL, contents=prompts)
        totalOutputTokenCount = response.usage_metadata.total_token_count - totalInputTokenCount
        print(f"Total Output Tokens: {totalInputTokenCount}")
        cMonth = time.ctime(time.time()).split()[1]
        cDay = time.ctime(time.time()).split()[2]
        totalCost = calculateUsageCost(GEMINIMODEL, totalInputTokenCount, totalOutputTokenCount)
        await writingLLMUsageCsv(f"{LLMUSAGELOGDIR}LLMMonthlyUsage.csv", "a",[f"{cMonth} {cDay}", totalInputTokenCount, totalOutputTokenCount, GEMINIMODEL, totalCost], MonthlyCSVLock)
        await writingLLMUsageCsv(f"{LLMUSAGELOGDIR}LLMYearlyUsage.csv", "a",[f"{cMonth} {cDay}", totalInputTokenCount, totalOutputTokenCount, GEMINIMODEL, totalCost], YearlyCSVLock)
        async with ScatLogLock:
            async with aiofiles.open(SCATLOG, "a") as logfile:
                await logfile.write(f"{time.ctime(time.time())}\nFile being scanned: {os.path.basename(filepath)}\nTotal Input Tokens: {totalInputTokenCount}\nGemini {GEMINIMODEL} Scan Result: {response.text}\nTotal Output Tokens: {totalOutputTokenCount}\n\n\n")
        return response.text


async def virusTotalURLScan(url: str) -> str:
    HostUrl = "https://www.virustotal.com/api/v3/urls"
    headers = {
        'x-apikey': virusTotalApiKey,
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded"
    }
    async with Cyberbot.session.post(HostUrl, data={"url": url}, headers=headers) as response:
        if response.status == 200:
            data = await response.json()
            scanID = data["data"]["id"]
            AnalysisUrl = f'https://www.virustotal.com/api/v3/analyses/{scanID}'
            for attempt in range(10):
                async with Cyberbot.session.get(AnalysisUrl,headers=headers, timeout=15) as analysisResponse:
                    if analysisResponse.status != 200:
                        print("Error getting Analysis Results")
                        return "URL can't be scanned"
                    analysis = await analysisResponse.json()
                    status = analysis["data"]["attributes"]["status"]

                    if status == "completed":
                        return f"Malicious counted:{analysis["data"]["attributes"]["stats"]['malicious']}"

                print(f"[*] Scan for {url} not finished yet (status={status}), retrying in {15}s...")
                await asyncio.sleep(15)
            else:
                return "URL can't be scanned"
        else:
            print("Error getting Analysis ID")
            return "URL can't be scanned"


async def virusTotalFileScan(filePath: str):
    HostUrl = "https://www.virustotal.com/api/v3/files"
    headers = {
        'x-apikey': virusTotalApiKey
    }

    async with aiofiles.open(filePath, "rb") as f:
        file = aiohttp.FormData()
        file.add_field('file', await f.read(), filename=os.path.basename(filePath))

    async with Cyberbot.session.post(HostUrl, headers=headers, data=file) as response:
        if response.status == 200:
            data = await response.json()
            analysisId = data["data"]["id"]
            AnalysisUrl = f'https://www.virustotal.com/api/v3/analyses/{analysisId}'
            for attempt in range(10):
                async with Cyberbot.session.get(AnalysisUrl, headers=headers, timeout=15) as analysisResponse:
                    if analysisResponse.status != 200:
                        print("Error getting Analysis Results")
                        return "File can't be scanned"
                    analysis = await analysisResponse.json()
                    status = analysis["data"]["attributes"]["status"]

                    if status == "completed":
                        stats = analysis["data"]["attributes"]["stats"]
                        print(
                            f"[+] Scan complete for {filePath}: "
                            f"{stats['malicious']} malicious, {stats['suspicious']} suspicious, "
                            f"{stats['harmless']} harmless, {stats['undetected']} undetected."
                        )
                        return f"{stats['malicious']}:{stats['suspicious']}:{stats['harmless']}:{stats['undetected']}"

                print(f"[*] Scan for file {os.path.basename(filePath)} not finished yet (status={status}), retrying in {15}s...")
                await asyncio.sleep(15)
            return "File can't be scanned"
        else:
            print("Error getting Analysis ID")
            return "File can't be scanned"


def ArchivesDiskImagesBombAnalysisAndExtraction(filePath: list, mountPoint: str, archiveLayer=0):
    def checkingFileExtension(fileContent: bytes, fname: str, verbose: bool = True):
        mime = magic.from_buffer(fileContent, mime=True)
        Ext = mimetypes.guess_extension(mime)
        if Ext:
            if Ext == ".bin":
                if fileContent.startswith(b'PK'):
                    if verbose:
                        print(f"Detected file extension .zip")
                    return '.zip'
                elif len(fileContent) > 512:
                    Last512bytes = fileContent[-512:]
                    if b'conectix' in Last512bytes:
                        if verbose:
                            print(f"Detected file extension .vhd")
                        return '.vhd'
                    elif b'koly' in Last512bytes or Last512bytes.startswith(b'EFI PART') or fileContent.startswith(b'EFI PART'):
                        if verbose:
                            print(f"Detected file extension .dmg")
                        return '.dmg'
                    else:
                        if verbose:
                            print(f"Python-Magic detect file extension .bin")
                        return ".bin"
            if Ext == ".webm" and fname.endswith(".weba"):
                if verbose:
                    print(f"Detected file extension .weba")
                return ".weba"
            elif Ext == ".webm" and fname.endswith(".wmv"):
                if verbose:
                    print(f"Detected file extension .wmv")
                return ".wmv"
            elif Ext == ".wmv" and fname.endswith(".wma"):
                if verbose:
                    print(f"Detected file extension .wma")
                return ".wma"
            elif Ext == ".ogv" and fname.endswith(".ogg"):
                if verbose:
                    print(f"Detected file extension .ogg")
                return ".ogg"
            elif Ext == ".asf" and fname.endswith(".wmv"):
                if verbose:
                    print(f"Detected file extension .wmv")
                return ".wmv"
            elif Ext == ".asf" and fname.endswith(".wma"):
                if verbose:
                    print(f"Detected file extension .wma")
                return ".wma"
            if Ext.endswith((".xz", ".bz2", ".gz")) and fname.endswith((".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz2", ".txz")):
                Ext = f".{'.'.join(fname.split(".")[1:])}"
                if verbose:
                    print(f"Detected extension {Ext}")
            else:
                if verbose:
                    print(f"Python-Magic detect file extension {Ext}")
            return Ext
        else:
            if fileContent.startswith(b'QFI\xfb'):
                if verbose:
                    print(f"Detected file extension .qcow2")
                return ".qcow2"
            elif fileContent.startswith(b'vhdxfile'):
                if verbose:
                    print(f"Detected file extension .vhdx")
                return ".vhdx"
            elif fileContent.startswith(b'KDMV'):
                if verbose:
                    print(f"Detected file extension .vmdk")
                return ".vmdk"
            elif fileContent[32768:32768 + 5].startswith((b"NSR02", b"NSR03")):
                if verbose:
                    print(f"Detected file extension .udf")
                return '.udf'
            else:
                if verbose:
                    print(f"Python-Magic did not detect")
                try:
                    if fileContent.decode("ascii").isascii():
                        if verbose:
                            print(f"ASCII file detected")
                        return ".txt"
                except UnicodeDecodeError:
                    if verbose:
                        print(f"Starting filetype module...")
                    Ext = filetype.guess(fileContent)
                    if Ext:
                        if verbose:
                            print(f"Filetype detected file extension {Ext.extension}")
                        return f".{Ext.extension}"
                    elif fileContent.startswith((b'\x0B\x77', b'\x0bwu\xacT@C')):
                        if verbose:
                            print(f"Detected file extension .ac3")
                        return ".ac3"
                    elif fname.endswith(".lzma"):
                        if verbose:
                            print(f"Detected file extension .lzma")
                        return ".lzma"
            if verbose:
                print(f"File extension can not be determined!")
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
            fileExt = checkingFileExtension(ArchiveDiskContent, os.path.basename(filePath[i]))
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
                        print(f"Creating subdirectories...")
                        """First Extraction Focusing On Checking Extraction Path and Directory Structure"""
                        for entry in zipRef.infolist():
                            totalFileCount += 1
                            DestinationPath = os.path.abspath(f"{mountPoint}{entry.filename}")
                            if not DestinationPath.startswith(mountPoint):
                                print(f"The uncompressed file name {entry.filename} formed an illegal path {DestinationPath} to cause directory transversal attack!")
                                return "Path Transversal Attack"
                            if "__MACOSX" not in DestinationPath and not os.path.basename(DestinationPath).startswith("._") and not ".DS_Store" in entry.filename:
                                if entry.filename.endswith('/') :
                                    os.makedirs(DestinationPath, exist_ok=True)
                                    print(f"Directory {entry.filename} created at path {DestinationPath}")
                            if totalFileCount // (totalDuplicatedFile + 1) <= 0.10:
                                return "Too many duplicated files!"

                        print(f"Extracting compressed file contents...")
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
                                    if checkingFileExtension(fileData, DestinationPath).endswith(CYBERBOTSCOPEOFORMATS):
                                        hashedData = hashlib.sha256(fileData).hexdigest()
                                        if hashedData not in DuplicatedFileDetection:
                                            with open(DestinationPath, 'wb') as f:
                                                f.write(fileData)
                                            print(f"{entry.filename} is written to path {DestinationPath}")
                                            DuplicatedFileDetection.append(hashedData)
                                        else:
                                            totalDuplicatedFile += 1
                                            if checkingFileExtension(fileData, DestinationPath).endswith(DISKIMAGEANDARCHIVEFORMATS):
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
                        print(f"Creating subdirectories...")
                        """First Extraction Focusing On Checking Extraction Path and Directory Structure"""
                        for entry in tarRef.getmembers():
                            totalFileCount += 1
                            DestinationPath = os.path.abspath(f"{mountPoint}{entry.name}")
                            if not DestinationPath.startswith(mountPoint):
                                print(f"The uncompressed file name {entry.name} formed an illegal path {DestinationPath} to cause directory transversal attack!")
                                return "Path Transversal Attack"
                            if "__MACOSX" not in DestinationPath and not os.path.basename( DestinationPath).startswith("._") and not ".DS_Store" in entry.name:
                                if "." not in entry.name:
                                    os.makedirs(DestinationPath, exist_ok=True)
                                    print(f"Directory {entry.name} created at path {DestinationPath}")
                            if totalFileCount // (totalDuplicatedFile + 1) <= 0.10:
                                return "Too many duplicated files!"

                        print(f"Extracting compressed file contents...")
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
                                        if checkingFileExtension(fileData, DestinationPath).endswith(CYBERBOTSCOPEOFORMATS):
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
                        print(f"Creating subdirectories...")
                        """First Extraction Focusing On Checking Extraction Path and Directory Structure"""
                        for entry in rar.infolist():
                            totalFileCount += 1
                            if entry.needs_password():
                                print(f"Compressed file {entry.filename} required password!")
                                return "Encrypted Error"
                            DestinationPath = os.path.abspath(f"{mountPoint}{entry.filename}")
                            if not DestinationPath.startswith(mountPoint):
                                print(f"The uncompressed file name {entry.filename} formed an illegal path {DestinationPath} to cause directory transversal attack!")
                                return "Path Transversal Attack"
                            if "__MACOSX" not in DestinationPath and not os.path.basename(DestinationPath).startswith("._") and not ".DS_Store" in entry.filename:
                                if entry.filename.endswith('/'):
                                    os.makedirs(DestinationPath, exist_ok=True)
                                    print(f"Directory {entry.filename} created at path {DestinationPath}")
                            if totalFileCount // (totalDuplicatedFile + 1) <= 0.10:
                                return "Too many duplicated files!"

                        print(f"Extracting compressed file contents...")
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
                                    if checkingFileExtension(fileData, DestinationPath).endswith(CYBERBOTSCOPEOFORMATS):
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
                        fileExt = checkingFileExtension(fileData, fileName, False)
                        if fileExt.endswith(ARCHIVEFILEFORMATS):
                            DestinationPath += fileExt
                        hashedData = hashlib.sha256(fileData).hexdigest()
                        if hashedData not in DuplicatedFileDetection:
                            if checkingFileExtension(fileData, fileName).endswith(CYBERBOTSCOPEOFORMATS):
                                with open(DestinationPath, "wb") as file:
                                    file.write(fileData)
                                print(f"{fileName} is written to path {DestinationPath}")
                            DuplicatedFileDetection.append(hashedData)
                        else:
                            totalDuplicatedFile += 1
                            if checkingFileExtension(fileData, fileName).endswith(DISKIMAGEANDARCHIVEFORMATS):
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
                fileExt = checkingFileExtension(fileData, filename, False)
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


async def checkingCleanData(hashedData: str, category: Literal["Archive/Disk File", "Executable/Compiled Files", "Script Files", "Document/PDF Files", "Audio Files", "Image Files", "Video Files", "All Extension", "URLs"]):
    async with CleanSignatureLock:
        async with aiofiles.open(CLEANSIGNATURESPATH, "r") as file:
            cleanHashedData = json.loads(await file.read())
    if category == "All Extension":
        for cat in cleanHashedData:
            if hashedData in cleanHashedData[cat]:
                return True
    else:
        if hashedData in cleanHashedData[category]:
            return True
    return False


async def checkingFlaggedMaliciousData(hashedData: str, category: Literal["Archive/Disk File", "Executable/Compiled Files", "Script Files", "Document/PDF Files", "Audio Files", "Image Files", "Video Files", "All Extension", "URLs"]):
    async with MaliciousSignatureLock:
        async with aiofiles.open(MALISCIOUSSIGNATUREPATH, "r") as file:
            maliciousHashedData = json.loads(await file.read())
    if category == "All Extension":
        for cat in maliciousHashedData:
            if hashedData in maliciousHashedData[cat]:
                return True
    else:
        if hashedData in maliciousHashedData[category]:
            return True
    return False


async def addingHashedData(hashedData: str, fileExt, malicious: bool, fileCategory=''):
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
        async with MaliciousSignatureLock:
            async with aiofiles.open(MALISCIOUSSIGNATUREPATH, "r") as file:
              currentMaliciousData = json.loads(await file.read())
            currentMaliciousData[fileCategory].append(hashedData)
            async with aiofiles.open(MALISCIOUSSIGNATUREPATH, "w") as file:
                await file.write(json.dumps(currentMaliciousData, indent=4))
        print(f"New malicious SHA256 signature was added to category {fileCategory}")
    else:
        async with CleanSignatureLock:
            async with aiofiles.open(CLEANSIGNATURESPATH, "r") as file:
                currentCleanData = json.loads(await file.read())
            currentCleanData[fileCategory].append(hashedData)
            async with aiofiles.open(CLEANSIGNATURESPATH, "w") as file:
                await file.write(json.dumps(currentCleanData, indent=4))
        print(f"New clean SHA256 signature was added to category {fileCategory}")


async def logScanSession(logData: str):
    async with ScanLogLock:
        async with aiofiles.open(SCANLOG, "a") as logFile:
            await logFile.write(logData)


def ghidraDecompile(filepath: str, mountPoint: str, filename: str) -> str:
    outputFile = os.path.join(mountPoint, f"{os.path.splitext(filename)[0]}_decompiled.txt")

    env = os.environ.copy()
    env["DYLD_LIBRARY_PATH"] = JEPLIBPATH

    cmd = [
        GHIDRAHEADLESS, # Calling the Ghidra analyzeHeadless program
        GHIDRAPROJECTPATH, # Ghidra project folder to create a temp project
        GHIDRAPROJECTNAME, # Ghidra project name
        "-import", filepath, # Importing the binary file to be decompiled
        "-scriptPath", GHIDRASCRIPTPATH, # The directory that contain the Python script contains the decompilation instructions to be execute by Ghidrathon
        "-postScript", "GhidraDecompile.py", outputFile, # The name of the Python script contains the decompilation instructions
        "-deleteProject", # Delete the temp project after decompilation
    ]

    print(f"Running Ghidra headless on: {filepath}")

    try:
        result = subprocess.run(
            cmd,
            # stdout=subprocess.PIPE, # Enable the program to be able to read the output of the running process, uncomment this if you want to see the ghidra decompilation result
            # stderr=subprocess.STDOUT, # Redirect stderr stream the same as stdout, uncomment this if you want to see the ghidra decompilation result
            # text=True, uncomment this if you want to see the ghidra decompilation result
            capture_output=False,
            timeout=600,
            env=env
        )

        '''
        # uncomment this if you want to see the ghidra decompilation result
        print("=== FULL GHIDRA OUTPUT ===")
        print(result.stdout)
        print("=== END OUTPUT ===")
        print(f"Return code: {result.returncode}")
        '''

        print(f"Decompilation and export complete. Cleaning up compiled file {filename}")
        os.remove(filepath)
        return outputFile
    except subprocess.TimeoutExpired:
        print("[ERROR] Ghidra timed out")
        os.remove(filepath)
        return "ERROR"
    except Exception as e:
        print(f"[ERROR] {e}")
        os.remove(filepath)
        return "ERROR"


@Cyberbot.tree.command(
    name="checking_cyberbot_configuration",
    description="Checking Cyberbot current configuration in the server"
)
async def checking_cyberbot_configuration(ctx):
    print(f"User {ctx.user.name} initiated /checking_cyberbot_configuration command")
    await ctx.response.defer(ephemeral=True)
    for account in CyberBotConfigData["Admins"]:
        if account["User ID"] == ctx.user.id and ctx.guild.id in account["Accessible Servers"]:
            # Adding new detected server ID
            if str(ctx.guild.id) not in CyberBotConfigData["Automation-Mode"]:
                CyberBotConfigData["Automation-Mode"][str(ctx.guild.id)] = "True"
            if str(ctx.guild.id) not in CyberBotConfigData["Silent-Mode"]:
                CyberBotConfigData["Silent-Mode"][str(ctx.guild.id)] = "False"
            if str(ctx.guild.id) not in CyberBotConfigData["Non-monitoring-Channels"]:
                CyberBotConfigData["Non-monitoring-Channels"][str(ctx.guild.id)] = []
            async with ConfigLock:
                async with aiofiles.open(CYBERBOTCONFIG, "w") as file:
                    await file.write(json.dumps(CyberBotConfigData, indent=4))

            nonMonitoringChannels = "Non monitoring channels in this server are:\n"
            for nonMonitoringChannelID in CyberBotConfigData["Non-monitoring-Channels"][str(ctx.guild.id)]:
                nonMonitoringChannel = Cyberbot.get_channel(nonMonitoringChannelID)
                if nonMonitoringChannel:
                    nonMonitoringChannels += f"Channel ID: {nonMonitoringChannel.id}\tChannel name: {nonMonitoringChannel.name}\n"
                else:
                    # Removing the server channel that no longer existed (Channel deleted by the owner)
                    CyberBotConfigData["Non-monitoring-Channels"][str(ctx.guild.id)].remove(nonMonitoringChannelID)
                    async with ConfigLock:
                        async with aiofiles.open(CYBERBOTCONFIG, "w") as file:
                            await file.write(json.dumps(CyberBotConfigData, indent=4))

            await ctx.followup.send(f"Automation scan mode for this server is {CyberBotConfigData["Automation-Mode"][str(ctx.guild.id)]}!\n"
                                    f"Silent scan mode for this server is {CyberBotConfigData["Silent-Mode"][str(ctx.guild.id)]}!\n{nonMonitoringChannels}")
            await LoggingCommandBeingExecuted(ctx.user.name, f"/checking_cyberbot_status\nCommand Status: Approved")
            return

    await LoggingCommandBeingExecuted(ctx.user.name, f"/checking_cyberbot_status\nCommand Status: Denied/User does not have admin account access to the server!")
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
    for admin in CyberBotConfigData["Admins"]:
        if admin["User ID"] == ctx.user.id:
            serverList = ''
            for serverID in admin["Accessible Servers"]:
                guild = Cyberbot.get_guild(serverID)
                serverList += f"Server Name: {guild.name}\tServer ID: {serverID}\tServer Owner: {guild.owner.name}\n"
            await LoggingCommandBeingExecuted(ctx.user.name,f"/get_list_of_accessible_servers\nCommand Status: Approved/Accessible Servers list sent to user!")
            await ctx.followup.send(f"Your Cyberbot admin account has access to the following servers:\n{serverList}")
            print(f"Process Finished!\n\n")
            return
    await LoggingCommandBeingExecuted(ctx.user.name, f"/get_list_of_accessible_servers\nCommand Status: Denied/User does not have a Cyberbot admin account yet!")
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
            await LoggingCommandBeingExecuted(ctx.user.name, f"/create_admin_account\nCommand Status: Denied/User already has an admin account!")
            await ctx.followup.send(f"You already have a Cyberbot admin account associated with email address {admin['User Email']}\nIf you want to change your password, use command /request_password_reset_token and /change_password with Cyberbot!")
            print("User already has an admin account!\n\n")
            break
        if admin["User Email"] == user_email:
            emailTaken = True
            await LoggingCommandBeingExecuted(ctx.user.name, f"/create_admin_account\nCommand Status: Denied/Email address already taken by other admin account!")
            await ctx.followup.send(f"The email address already associated with a different admin account!")
            print("Email address already associated with a different admin account!\n\n")
            break
    if not accountExist and not emailTaken:
        defaultPassword = await randomPasswordGenerator()
        if await asyncio.to_thread(sendEmail,"New Cyberbot Admin Account Created",
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
            async with ConfigLock:
                async with aiofiles.open(CYBERBOTCONFIG, "w") as file:
                    await file.write(json.dumps(CyberBotConfigData, indent=4))
            await LoggingCommandBeingExecuted(ctx.user.name, f"/create_admin_account\nCommand Status: Approved/New admin account registered for user {ctx.user.name}")
            await ctx.followup.send(f"A new admin account has been created for you! Please check the email you used to registered the account for more details!")
            print(f"New Admin account created for user {ctx.user.name}\n\n")
        else:
            await LoggingCommandBeingExecuted(ctx.user.name, f"/create_admin_account\nCommand Status: Denied/Error sending email!")
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
            await LoggingCommandBeingExecuted(ctx.user.name, f"/adding_admins {member}\nCommand Status: Denied/Member {member.name} can kick Cyberbot out of the server {ctx.guild.name}")
            await ctx.followup.send(f"{member.name} can kick Cyberbot out of the server! Therefore their admin account will not be allowed to work in the server! The reason is if their discord account is compromised, the attacker can kick Cyberbot out and does not need to be an admin to disable Cyberbot scan protection! Please ensure that Cyberbot always has the highest role than all the members in the server!")
            print(f"{member.name} can kick Cyberbot out of the server {ctx.guild.name}\n\n")
        else:
            for admin in CyberBotConfigData["Admins"]:
                if admin["User ID"] == member.id:
                    if ctx.guild.id not in admin["Accessible Servers"]:
                        if await asyncio.to_thread(sendEmail,"New Accessible Server Added",
                                     f"The owner {ctx.user.name} of server {ctx.guild.name} with server ID {ctx.guild.id} has granted your Cyberbot Admin Account access to the server",
                                     admin["User Email"]) == "Email sent successfully!":
                            admin["Accessible Servers"].append(ctx.guild.id)
                            async with ConfigLock:
                                async with aiofiles.open(CYBERBOTCONFIG, "w") as file:
                                    await file.write(json.dumps(CyberBotConfigData, indent=4))
                            await LoggingCommandBeingExecuted(ctx.user.name, f"/adding_admins {member}\nCommand Status: Approved/Access to the server {ctx.guild.name} ID {ctx.guild.id} for Admin User Account {admin['User ID']} added!")
                            await member.send(f"You have been authorized to have a Cyberbot admin account access on server {ctx.guild.name} by the server owner {ctx.user.name}\nPlease check your email {admin["User Email"]} for more details!")
                            await ctx.followup.send(f"{member.name} admin account can now be used in server {ctx.guild.name}")
                            print(f"{member.name} admin access to server {ctx.guild.name} added!\n\n")
                        else:
                            await LoggingCommandBeingExecuted(ctx.user.name,f"/adding_admins {member}\nCommand Status: Denied/Error sending email!")
                            await ctx.followup.send(f"Cyberbot can't register {member.name} admin account!")
                            print(f"Error sending email\n\n")
                    else:
                        await LoggingCommandBeingExecuted(ctx.user.name, f"/adding_admins {member}\nCommand Status: Denied/Admin account already has access to server {ctx.guild.name} ID {ctx.guild.id}")
                        await ctx.followup.send(f"{member.name} admin account already has access to the server!")
                        print(f"{member.name} admin account already has access to the server!\n\n")
                    return
            await LoggingCommandBeingExecuted(ctx.user.name, f"/adding_admins {member}\nCommand Status: Denied/Mentioned member does not have a Cyberbot admin account yet!")
            await ctx.followup.send(f"{member.name} does not have a Cyberbot admin account yet!")
            print(f"{member.name} does not have a Cyberbot admin account!\n\n")
    else:
        await LoggingCommandBeingExecuted(ctx.user.name, f"/adding_admins {member}\nCommand Status: Denied/Unauthorized User")
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
        for admin in CyberBotConfigData["Admins"]:
            if admin["User ID"] == member.id:
                if ctx.guild.id not in admin["Accessible Servers"]:
                    await LoggingCommandBeingExecuted(ctx.user.name, f"/removing_admins {member}\nCommand Status: Denied/Admin account already has no access to server {ctx.guild.name} ID {ctx.guild.id}")
                    await ctx.followup.send(f"{member.name} admin account already has no access to the server!")
                    print(f"{member.name} admin account already has no access to the server!\n\n")
                else:
                    if await asyncio.to_thread(sendEmail,"New Accessible Server Removed",
                                 f"The owner {ctx.user.name} of server {ctx.guild.name} with server ID {ctx.guild.id} has removed your Cyberbot Admin Account access from the server",
                                 admin["User Email"]) == "Email sent successfully!":
                        admin["Accessible Servers"].remove(ctx.guild.id)
                        async with ConfigLock:
                            async with aiofiles.open(CYBERBOTCONFIG, "w") as file:
                                await file.write(json.dumps(CyberBotConfigData, indent=4))
                        await LoggingCommandBeingExecuted(ctx.user.name,f"/removing_admins {member}\nCommand Status: Approved/Access to the server {ctx.guild.name} ID {ctx.guild.id} for Admin User Account {admin['User ID']} removed!")
                        await member.send(f"Your admin account access on server {ctx.guild.name} ID {ctx.guild.id} has been removed by the server owner {ctx.user.name}\nPlease check your email {admin["User Email"]} for more details!")
                        await ctx.followup.send(f"{member.name} admin account access removed from the server!")
                        print(f"{member.name} admin access to server {ctx.guild.name} removed!\n\n")
                    else:
                        await LoggingCommandBeingExecuted(ctx.user.name, f"/removing_admins {member}\nCommand Status: Denied/Error sending email!")
                        await ctx.followup.send(f"Cyberbot can't register {member.name} admin account!")
                        print(f"Error sending email\n\n")
                return
        await LoggingCommandBeingExecuted(ctx.user.name, f"/removing_admins {member}\nCommand Status: Denied/Mentioned member does not have a Cyberbot admin account yet!")
        await ctx.followup.send(f"{member.name} does not have a Cyberbot admin account yet!")
        print(f"{member.name} does not have a Cyberbot admin account!\n\n")
    else:
        await LoggingCommandBeingExecuted(ctx.user.name, f"/removing_admins {member}\nCommand Status: Denied/Unauthorized User")
        await ctx.followup.send("You're not the server's owner, the command /removing_admins is restricted to server owner ONLY!")
        print(f"User {ctx.user.name} not authorized to execute the command!\n\n")


@Cyberbot.tree.command(
    name="request_password_reset_token",
    description="Request a new password reset token"
)
async def request_password_reset_token(ctx):
    print(f"User {ctx.user.name} initiated /request_password_reset_token command")
    await ctx.response.defer(ephemeral=True)
    for adminAccount in CyberBotConfigData["Admins"]:
        if ctx.user.id == adminAccount["User ID"]:
            if time.time() > adminAccount["Current Account Locked Out Period"]:
                if time.time() >= adminAccount["Credential Minimum Age"]:
                    async with ResetTokenLock:
                        async with aiofiles.open(RESETPASSWORDTOKENPATH, "r") as file:
                            resetTokens = json.loads(await file.read())
                    token = ""
                    for i in range(7):
                        token += random.choice(f"ABCDEFGHIJKLNMOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%&*_+=")
                    resetTokens[adminAccount["User Email"]] = [token, time.time() + 180]
                    async with ResetTokenLock:
                        async with aiofiles.open(RESETPASSWORDTOKENPATH, "w") as file:
                            await file.write(json.dumps(resetTokens, indent=4))
                    await asyncio.to_thread(sendEmail,"Cyberbot Password Reset Token",
                              f"Your password reset token is {token}, it will expired in 3 minutes!",
                              adminAccount["User Email"])
                    await LoggingCommandBeingExecuted(ctx.user.name, f"/request_password_reset_token\nCommand Status: Approved/A reset token has been sent to user email!")
                    await ctx.followup.send(f"Please check your email {adminAccount["User Email"]}!")
                    print(f"A new reset token has been sent to user {ctx.user.name} via email {adminAccount['User Email']}!\n\n")
                else:
                    await LoggingCommandBeingExecuted(ctx.user.name, f"/request_password_reset_token\nCommand Status: Denied/User password age not above 3 hours yet")
                    await ctx.followup.send(f"You just changed your password. Your password must have a minimum age of 3 hours in order to be able to be changed again!")
                    print(f"User {ctx.user.name} just changed the admin account password!\n\n")
            else:
                await LoggingCommandBeingExecuted(ctx.user.name, f"/request_password_reset_token\nCommand Status: Denied/Admin account locked!")
                hours_remaining = (adminAccount["Current Account Locked Out Period"] - time.time()) / 3600
                minutes_remaining = round(float(f".{str(hours_remaining).split('.')[1]}") * 60)
                await ctx.followup.send(f"Your admin account is currently being locked out for {round(hours_remaining // 1)} hour(s) and {minutes_remaining} minute(s)")
                print(f"User {ctx.user.name} admin account is currently being locked out!\n\n")
            return

    await LoggingCommandBeingExecuted(ctx.user.name, f"/request_password_reset_token\nCommand Status: Denied/User does not have a Cyberbot admin account yet!")
    await ctx.followup.send(f"You do not have a Cyberbot admin account yet! Use command /create_admin_account to register a new Cyberbot admin account!")
    print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")


@Cyberbot.tree.command(
    name="change_password",
    description="Update your admin account password!"
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
    for adminAccount in CyberBotConfigData["Admins"]:
        if ctx.user.id == adminAccount["User ID"]:
            if time.time() > adminAccount["Current Account Locked Out Period"]:
                if accountemail == adminAccount["User Email"]:
                    async with ResetTokenLock:
                        async with aiofiles.open(RESETPASSWORDTOKENPATH, "r") as file:
                            resetTokens = json.loads(await file.read())
                    if accountemail in resetTokens:
                        if resetTokens[accountemail][0] == passwordresettoken and time.time() < resetTokens[accountemail][1]:
                            if time.time() >= adminAccount["Credential Minimum Age"]:
                                update = True
                                if custompassword == "True":
                                    hashednewpassword = hashlib.sha512(f"{newpassword}{ctx.user.id}".encode()).hexdigest()
                                    if len(newpassword) > 30:
                                        await LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/Password too long")
                                        await ctx.followup.send("Your new password is too long!")
                                        print(f"User {ctx.user.name} new password too long!\n\n")
                                        update = False
                                    elif hashednewpassword == adminAccount["User Credential"]:
                                        await LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/Password is the same as the old one")
                                        await ctx.followup.send("Your new password is the same as your old password!")
                                        print(f"User {ctx.user.name} reused password!\n\n")
                                        update = False
                                    elif hashednewpassword in adminAccount["Previous Credentials Used"]:
                                        await LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/Password already been used from the past!")
                                        await ctx.followup.send("You have used this password before, please set a new password!")
                                        print(f"User {ctx.user.name} reused password!\n\n")
                                        update = False
                                    elif None in [re.search(r'[a-z]', newpassword), re.search(r'[A-Z]', newpassword), re.search(r'\d', newpassword), re.search(r'[!@#$%&*_+=]', newpassword)] or len(newpassword) < 12:
                                        await LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/Password does not match the criteria")
                                        await ctx.followup.send("Your new password password must be:\n"
                                                                "At least 12 characters\n"
                                                                "Have mixed case ASCII letters and numbers\n"
                                                                "Contains any of the following special characters !@#$%&*_+=\n"
                                                                "Please provide a different password")
                                        print(f"User {ctx.user.name} new password not match the password policy!\n\n")
                                        update = False
                                    elif await CheckPasswordPwned(newpassword):
                                        await LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/New Password existed in a data breach database")
                                        await ctx.followup.send("The new password that you want to set was detected to already existed in a data breach database, please choose a different password!")
                                        print(f"User {ctx.user.name} new password existed in data breach database!\n\n")
                                        update = False
                                    else:
                                        passwordStrength, probability = await asyncio.to_thread(Prediction, newpassword, BERTtokenizer, BERTPasswordModel, "Password Strength")
                                        if passwordStrength < 3 and probability > 0.5:
                                            await LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/BERT model detected password strength at level {passwordStrength} out of 5 levels ranking system with probability value of {f"{probability}"}")
                                            await ctx.followup.send("Your new password contains patterns that Cyberbot pre-trained weak password classifier BERT encoder-transformer flagged as weak password!\nPlease provide a different password")
                                            print(f"User {ctx.user.name} new password flagged weak by BERT model!\n\n")
                                            update = False
                                        else:
                                            passwordStrength, probability = await asyncio.to_thread(Prediction, newpassword, AllenAItokenizer, AllenAIPasswordModel,"Password Strength")
                                            if passwordStrength < 3 and probability > 0.5:
                                                await LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/Allen AI model detected password strength at level {passwordStrength} out of 5 levels ranking system with probability value of {f"{probability}"}")
                                                await ctx.followup.send("Your new password contains patterns that Cyberbot pre-trained weak password classifier Allen AI encoder-transformer flagged as weak password!\nPlease provide a different password")
                                                print(f"User {ctx.user.name} new password flagged weak by Allen AI model!\n\n")
                                                update = False
                                            elif await GeminiCheckCommonPassword(newpassword):
                                                await LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/Password too common and easy to guess")
                                                await ctx.followup.send("Your new password contains keywords easy to guess or already in a common used password list!\nPlease provide a different password")
                                                print(f"User {ctx.user.name} new password too common and easy to guess!\n\n")
                                                update = False
                                else:
                                    newpassword = await randomPasswordGenerator()
                                    while hashlib.sha512(f"{newpassword}{ctx.user.id}".encode()).hexdigest() == adminAccount["User Credential"] or hashlib.sha512(f"{newpassword}{ctx.user.id}".encode()).hexdigest() in adminAccount["Previous Credentials Used"]:
                                        newpassword = randomPasswordGenerator()
                                    hashednewpassword = hashlib.sha512(f"{newpassword}{ctx.user.id}".encode()).hexdigest()
                                if update:
                                    adminAccount["User Credential"] = hashednewpassword
                                    adminAccount["Credential Minimum Age"] = time.time() + 10800
                                    adminAccount["Credential Expiration Age"] = time.time() + 15552000
                                    adminAccount["Previous Credentials Used"].append(adminAccount["User Credential"])
                                    async with ConfigLock:
                                        async with aiofiles.open(CYBERBOTCONFIG, "w") as file:
                                            await file.write(json.dumps(CyberBotConfigData, indent=4))
                                    if custompassword == "False":
                                        await asyncio.to_thread(sendEmail,"Cyberbot Admin Account Password Updated",
                                                  f"Your admin account password has been changed to {newpassword}\n"
                                                  f"Please delete this email once you have acknowledged your new password change!",
                                                  accountemail)
                                    await LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Approved/Admin account password updated")
                                    await ctx.followup.send(f"Your password has been updated to {newpassword}")
                                    print(f"User {ctx.user.name} admin account updated successfully!\n\n")
                                    return
                            else:
                                await LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/User password age not above 3 hours yet")
                                await ctx.followup.send(f"You just changed your password. Your password must have a minimum age of 3 hours in order to be able to be changed again!")
                                print(f"User {ctx.user.name} just changed the admin account password!\n\n")
                        else:
                            await LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/Expired or Invalid Password Reset Token")
                            await ctx.followup.send(f"The reset token provided is invalid or expired. Please request a new one again!")
                            print(f"User {ctx.user.name} password reset token Expired/Invalid!\n\n")
                    else:
                        await LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/No Password Reset Token Request Yet")
                        await ctx.followup.send(f"You have not request a reset token yet or the token is expired! Please use the command /request_password_reset_token to request one!")
                        print(f"User {ctx.user.name} did not request a password reset token yet!\n\n")
                else:
                    await LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/Wrong Email Address")
                    await ctx.followup.send("Your email address is wrong!")
                    print(f"User {ctx.user.name} provided wrong email address!\n\n")
            else:
                await LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/Admin account locked!")
                hours_remaining = (adminAccount["Current Account Locked Out Period"] - time.time()) / 3600
                minutes_remaining = round(float(f".{str(hours_remaining).split('.')[1]}") * 60)
                await ctx.followup.send( f"Your admin account is currently being locked out for {round(hours_remaining // 1)} hour(s) and {minutes_remaining} minute(s)")
                print(f"User {ctx.user.name} admin account is currently being locked out!\n\n")
            return

    await LoggingCommandBeingExecuted(ctx.user.name, f"/change_password\nCommand Status: Denied/User does not have a Cyberbot admin account yet!")
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
    for adminAccount in CyberBotConfigData["Admins"]:
        if adminAccount["User ID"] == ctx.user.id:
            if time.time() > adminAccount["Current Account Locked Out Period"]:
                if str(ctx.guild.id) in adminAccount["Current Admin Session Period"]:
                    if time.time() < adminAccount["Current Admin Session Period"][str(ctx.guild.id)]:
                        await LoggingCommandBeingExecuted(ctx.user.name,f"/admin_log_in\nCommand Status: Denied/User already logged in")
                        await ctx.followup.send("You already logged in! If you want to log out, please use the command /admin_log_out")
                        print(f"User {ctx.user.name} already logged in as an admin in the server!\n\n")
                        return

                if adminAccount["User Email"] == accountemail and adminAccount["User Credential"] == hashlib.sha512(f"{accountpassword}{ctx.user.id}".encode()).hexdigest():
                    if time.time() < adminAccount["Credential Expiration Age"]:
                        if ctx.guild.id in adminAccount["Accessible Servers"]:
                            adminAccount["Failed Log In Attempts"] = 0
                            adminAccount["Current Admin Session Period"][str(ctx.guild.id)] = time.time() + 3600
                            adminAccount["Last Time Logged In"] = time.ctime(time.time())
                            await LoggingCommandBeingExecuted(ctx.user.name,f"/admin_log_in\nCommand Status: Approved/New 1 hour admin session with admin account {adminAccount['User ID']} in server {ctx.guild.name} ID {ctx.user.id} created")
                            await ctx.followup.send("Cyberbot will now recognize you as an admin for 1 hour in this server before requiring you to log in again!")
                            print(f"User {ctx.user.name} logged in as an admin in the server!\n\n")
                        else:
                            await LoggingCommandBeingExecuted(ctx.user.name,f"/admin_log_in\nCommand Status: Denied/User does not have admin account access to the server!")
                            await ctx.followup.send(f"Your admin account is not permitted to access in this server, please contact the server owner {ctx.guild.owner.name} to give you admin account access to the server!")
                            print(f"User {ctx.user.name} does not have admin account access to the server!\n\n")
                    else:
                        await LoggingCommandBeingExecuted(ctx.user.name,f"/admin_log_in\nCommand Status: Denied/Expired Password")
                        await ctx.followup.send("Your password has expired. Please use /request_password_reset_token and /change_password to update your password!")
                        print(f"User {ctx.user.name} password expired!\n\n")
                else:
                    adminAccount["Failed Log In Attempts"] += 1
                    if adminAccount["Failed Log In Attempts"] != 7:
                        await LoggingCommandBeingExecuted(ctx.user.name,f"/admin_log_in\nCommand Status: Denied/Bad Credentials")
                        await ctx.followup.send(f"Invalid user email or password!!!\nYou have {7 - adminAccount["Failed Log In Attempts"]} attempts left to log in!")
                        print(f"User {ctx.user.name} input invalid credentials!\n\n")
                    else:
                        adminAccount["Locked Out History"].append(time.ctime(time.time()))
                        adminAccount["Current Account Locked Out Period"] = time.time() + 10800
                        adminAccount["Total Locked Out"] = len(adminAccount["Locked Out History"])
                        adminAccount["Failed Log In Attempts"] = 0
                        await asyncio.to_thread(sendEmail,"Admin Account Locked Out", f"Dear user {ctx.user.name},\n\n"
                                                                  f"You received this email from Cyberbot to notify that your admin account has been locked for 3 hours due too many invalid login attempts.\n"
                                                                  f"The current total lock outs associated with your account is: {len(adminAccount['Locked Out History'])}",
                                      adminAccount["User Email"])
                        await LoggingCommandBeingExecuted(ctx.user.name,f"/admin_log_in\nCommand Status: Denied/Bad Credentials and account has been locked!")
                        await ctx.followup.send("Too many failed login attempts! Your admin account has been locked for 3 hours!")
                        print(f"User {ctx.user.name} input too many invalid log in attempts, initiating admin account lock out!\n\n")

                async with ConfigLock:
                    async with aiofiles.open(CYBERBOTCONFIG, "w") as file:
                        await file.write(json.dumps(CyberBotConfigData, indent=4))
            else:
                await LoggingCommandBeingExecuted(ctx.user.name,f"/admin_log_in\nCommand Status: Denied/Admin account locked!")
                hours_remaining = (adminAccount["Current Account Locked Out Period"] - time.time()) / 3600
                minutes_remaining = round(float(f".{str(hours_remaining).split('.')[1]}") * 60)
                await ctx.followup.send(f"Your admin account is currently being locked out for {round(hours_remaining // 1)} hour(s) and {minutes_remaining} minute(s)")
                print(f"User {ctx.user.name} admin account is currently being locked out!\n\n")
            return

    await LoggingCommandBeingExecuted(ctx.user.name, f"/admin_log_in\nCommand Status: Denied/User does not have a Cyberbot admin account yet!")
    await ctx.followup.send(f"You do not have a Cyberbot admin account yet! Use command /create_admin_account to register a new Cyberbot admin account!")
    print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")


@Cyberbot.tree.command(
    name="admin_log_out",
    description="Logging out of your current Cyberbot admin account session in the server"
)
async def admin_log_out(ctx):
    print(f"User {ctx.user.name} initiated /admin_log_out command")
    await ctx.response.defer(ephemeral=True)
    for adminAccount in CyberBotConfigData["Admins"]:
        if ctx.user.id == adminAccount["User ID"]:
            if str(ctx.guild.id) in adminAccount["Current Admin Session Period"]:
                del adminAccount["Current Admin Session Period"][str(ctx.guild.id)]
                async with ConfigLock:
                    async with aiofiles.open(CYBERBOTCONFIG, "w") as file:
                        await file.write(json.dumps(CyberBotConfigData, indent=4))
                await ctx.followup.send("You have been logged out of your Cyberbot admin session with this server!")
                await LoggingCommandBeingExecuted(ctx.user.name, f"/admin_log_out\nCommand Status: Approved")
                print(f"User {ctx.user.name} admin account logged out successfully!\n\n")
            else:
                await ctx.followup.send("You do not have any admin account session in this server!")
                await LoggingCommandBeingExecuted(ctx.user.name, f"/admin_log_out\nCommand Status: Denied/User not logged in")
                print(f"User {ctx.user.name} not currently logged in as an admin in server!\n\n")
            return
    await LoggingCommandBeingExecuted(ctx.user.name, f"/admin_log_out\nCommand Status: Denied/User does not have a Cyberbot admin account yet!")
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
        await LoggingCommandBeingExecuted(ctx.user.name, f"/cyberbot_config {configuration} {action}\nCommand Status: Denied/Command runs in DM channel")
        print(f"Command forbidden to execute in DM channel!\n\n")
    else:
        for adminAccount in CyberBotConfigData["Admins"]:
            if ctx.user.id == adminAccount["User ID"]:
                if ctx.guild.id in adminAccount["Accessible Servers"]:
                    if str(ctx.guild.id) in adminAccount["Current Admin Session Period"]:
                        if time.time() < adminAccount["Current Admin Session Period"][str(ctx.guild.id)]:
                            if action == "ENABLE":
                                CyberBotConfigData[configuration][str(ctx.guild.id)] = "True"
                            else:
                                CyberBotConfigData[configuration][str(ctx.guild.id)] = "False"
                            await ctx.followup.send("DONE")
                            await ctx.followup.send(f"{configuration} for this server has been {'enabled' if (CyberBotConfigData[configuration][str(ctx.guild.id)] == "True") else 'disabled'} by user {ctx.user.mention}!")
                            await LoggingCommandBeingExecuted(ctx.user.name, f"/cyberbot_config {configuration} {action}\nCommand Status: Approved/{configuration} {action} in server {ctx.guild.name} - ID {ctx.guild.id}")
                            print(f"{configuration} been reconfigured!\n\n")
                        else:
                            del adminAccount["Current Admin Session Period"][str(ctx.guild.id)]
                            await LoggingCommandBeingExecuted(ctx.user.name,f"/cyberbot_config {configuration} {action}\nCommand Status: Denied/Admin session expired")
                            await ctx.followup.send(f"Your admin session with this server has expired! Please logging in again.")
                            print(f"User admin session expired!\n\n")

                        async with ConfigLock:
                            async with aiofiles.open(CYBERBOTCONFIG, "w") as file:
                                await file.write(json.dumps(CyberBotConfigData, indent=4))
                    else:
                        await LoggingCommandBeingExecuted(ctx.user.name, f"/cyberbot_config {configuration} {action}\nCommand Status: Denied/User need to log in as an admin")
                        await ctx.followup.send(f"You need to use /admin_log_in to log in as an admin in this server to execute this command!")
                        print(f"User {ctx.user.name} need to log in as an admin!\n\n")
                else:
                    await LoggingCommandBeingExecuted(ctx.user.name, f"/cyberbot_config {configuration} {action}\nCommand Status: Denied/User does not have admin account access to the server!")
                    await ctx.followup.send(f"You do not have an admin account access to the server, please contact the server owner {ctx.guild.owner.name} to add your admin account access to the server!")
                    print(f"User {ctx.user.name} not authorized to execute the command!\n\n")
                return
        await LoggingCommandBeingExecuted(ctx.user.name, f"/cyberbot_config {configuration} {action}\nCommand Status: Denied/User does not have a Cyberbot admin account yet!")
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
        await LoggingCommandBeingExecuted(ctx.user.name, f"/non_monitoring_channel {action}\nCommand Status: Denied/Command runs in DM channel")
        print(f"Command forbidden to execute in DM channel!\n\n")
    else:
        for adminAccount in CyberBotConfigData["Admins"]:
            if ctx.user.id == adminAccount["User ID"]:
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
                                    await LoggingCommandBeingExecuted(ctx.user.name,f"/non_monitoring_channel {action}\nCommand Status: Approved/Channel '{ctx.channel.name}' - ID {ctx.channel.id} has been added to the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                                else:
                                    await ctx.followup.send(f"Channel '{ctx.channel.name}' - ID {ctx.channel.id} already been added to the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                                    await LoggingCommandBeingExecuted(ctx.user.name,f"/non_monitoring_channel {action}\nCommand Status: Denied/Channel '{ctx.channel.name}' - ID {ctx.channel.id} already been added to the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                            else:
                                if ctx.channel.id in CyberBotConfigData["Non-monitoring-Channels"][str(ctx.guild.id)]:
                                    CyberBotConfigData["Non-monitoring-Channels"][str(ctx.guild.id)].remove(ctx.channel.id)
                                    await ctx.followup.send(f"Channel '{ctx.channel.name}' - ID {ctx.channel.id} has been removed from the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                                    await ctx.followup.send(f"Channel '{ctx.channel.name}' - ID {ctx.channel.id} has been removed from the server non monitoring channel list by user {ctx.user.mention}!")
                                    await LoggingCommandBeingExecuted(ctx.user.name,f"/non_monitoring_channel {action}\nCommand Status: Approved/Channel '{ctx.channel.name}' - ID {ctx.channel.id} has been removed from the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                                else:
                                    await ctx.followup.send(f"Channel '{ctx.channel.name}' - ID {ctx.channel.id} already been removed from the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                                    await LoggingCommandBeingExecuted(ctx.user.name,f"/non_monitoring_channel {action}\nCommand Status: Denied/Channel '{ctx.channel.name}' - ID {ctx.channel.id} already been removed from the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                        else:
                            del adminAccount["Current Admin Session Period"][str(ctx.guild.id)]
                            await LoggingCommandBeingExecuted(ctx.user.name, f"/non_monitoring_channel {action}\nCommand Status: Denied/Admin session expired")
                            await ctx.followup.send(f"Your admin session with this server has expired! Please logging in again.")
                            print(f"User admin session expired!\n\n")

                        async with ConfigLock:
                            async with aiofiles.open(CYBERBOTCONFIG, "w") as file:
                                await file.write(json.dumps(CyberBotConfigData, indent=4))
                    else:
                        await LoggingCommandBeingExecuted(ctx.user.name,f"/non_monitoring_channel {action}\nCommand Status: Denied/User need to log in as an admin")
                        await ctx.followup.send(f"You need to use /admin_log_in to log in as an admin in this server to execute this command!")
                        print(f"User {ctx.user.name} need to log in as an admin!\n\n")
                else:
                    await LoggingCommandBeingExecuted(ctx.user.name,f"/non_monitoring_channel {action}\nCommand Status: Denied/User does not have admin account access to the server!")
                    await ctx.followup.send(f"You do not have an admin account access to the server, please contact the server owner {ctx.guild.owner.name} to create an admin account for you!")
                    print(f"User {ctx.user.name} not authorized to execute the command!\n\n")
                return

        await LoggingCommandBeingExecuted(ctx.user.name, f"/non_monitoring_channel {action}\nCommand Status: Denied/User does not have a Cyberbot admin account yet!")
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
    fileExt = await checkingRealFileExtension(await file.read(), file.filename)
    await ctx.followup.send(f"The file extension is: {fileExt}\n\n")
    await LoggingCommandBeingExecuted(ctx.user.name, f"/checking_file_true_format file temporary URL: {file.url}\nCommand Status: Approved")


@Cyberbot.tree.command(
    name="semgrep_vulnerability_scan",
    description="Perform a static vulnerability scan with Semgrep"
)
@app_commands.describe(
    file="Upload a single file to scan",
    semgrep_rule="Please select any non-premium semgrep rules from https://semgrep.dev/p/default"
)
async def semgrep_vulnerability_scan(ctx, file: discord.Attachment, semgrep_rule: str):
    global FILEDOWNLOADCOUNTER
    print(f"User {ctx.user.name} initiated Semgrep Vulnerability Scan for file {file.filename}")
    await ctx.response.defer()
    if "../" in file.filename:
        await ctx.followup.sent("Vulnerability scan not performed for this file due to potential ../ attack in the file name scheme!")
        await LoggingCommandBeingExecuted(ctx.user.name, f"/semgrep_vulnerability_scan file temporary URL: {file.url} Rule: {semgrep_rule}\nCommand Status: Denied/File name hinted potential ../ attack!")
        print(f"Potential ../ attack! Reject scan process!\n\n")
    else:
        await LoggingCommandBeingExecuted(ctx.user.name,f"/semgrep_vulnerability_scan file temporary URL: {file.url} Rule: {semgrep_rule}\nCommand Status: Approved")
        print("Downloading file content...")
        FILEDOWNLOADCOUNTER += 1
        fileExt = await checkingRealFileExtension(await file.read(), file.filename)
        filePath = f"{DOWNLOADINGDIRPATH}{FILEDOWNLOADCOUNTER}{fileExt}"
        async with Cyberbot.session.get(file.url, headers=MAINHEADERS) as r:
            if r.status == 200:
                async with aiofiles.open(filePath, "wb") as data:
                    async for chunk in r.content.iter_chunked(8192):
                        await data.write(chunk)
        print("Downloading Success!!!")
        try:
            result = await asyncio.to_thread(subprocess.run,["semgrep", "--config", f"{semgrep_rule}", "--json", filePath], capture_output=True, text=True)
            semgrepRawData = json.loads(result.stdout)
            semgrepRawData.pop("paths", None)
            for finding in semgrepRawData["results"]:
                finding.pop("path", None)
            semGrepJSONResult = json.dumps(semgrepRawData, indent=2)
            buffer = BytesIO()
            buffer.write(semGrepJSONResult.encode('utf-8'))
            buffer.seek(0)
            resultFile = discord.File(fp=buffer, filename="SemgrepJSONResult.json")
            await ctx.followup.send("Here is the Semgrep vulnerability scan result!", file=resultFile)
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
    await LoggingCommandBeingExecuted(ctx.user.name,f"/phishing_email_scan on email Content: {email_content} with keep_output_secret: {keep_output_secret}\nCommand Status: Approved")
    BERTPhishingResult, BERTPhishingprobability = await asyncio.to_thread(Prediction, email_content, BERTtokenizer, BERTPhishingModel, "Phishing Emails")
    AllenAIPhishingResult, AllenAIPhishingprobability = await asyncio.to_thread(Prediction, email_content, AllenAItokenizer, AllenAIPhishingModel, "Phishing Emails")
    BERTSpamResult, BERTSpamprobability = await asyncio.to_thread(Prediction, email_content, BERTtokenizer, BERTSpamModel, "Spam Emails")
    AllenAISpamResult, AllenAISpamprobability = await asyncio.to_thread(Prediction, email_content, AllenAItokenizer, ALLENAISpamModel, "Spam Emails")

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

    global CURRENTSCANOPERATION

    await Cyberbot.process_commands(after)

    if after.author == Cyberbot.user:
        return

    if str(after.channel) == "Direct Message with Unknown User":
        return

    """Adding new server ID to Configuration file"""
    if not CyberBotConfigData["Non-monitoring-Channels"].get(str(after.guild.id), ""):
        CyberBotConfigData["Non-monitoring-Channels"][str(after.guild.id)] = []
    if not CyberBotConfigData["Silent-Mode"].get(str(after.guild.id), ""):
        CyberBotConfigData["Silent-Mode"][str(after.guild.id)] = "False"
    if not CyberBotConfigData["Automation-Mode"].get(str(after.guild.id), ""):
        CyberBotConfigData["Automation-Mode"][str(after.guild.id)] = "True"
    async with ConfigLock:
        async with aiofiles.open(CYBERBOTCONFIG, "w") as file:
            await file.write(json.dumps(CyberBotConfigData, indent=4))

    """Checking if the current channel is in the server non monitoring list"""
    if after.channel.id in CyberBotConfigData["Non-monitoring-Channels"][str(after.guild.id)]:
        return


    if before.content != after.content:
        print("Re-edited Message Detected!")
        if after.content:
            URLs = re.findall(r'https?://(?:(?!https?://)\S)+', after.content.replace(" ", ""))
            URLs = list(set(URLs))
        else:
            URLs = ""

        if URLs:
            logMessage = (f"{time.ctime(time.time())}\n"
                          f"ORIGIN AUTHOR: {after.author.name}\n"
                          f"ORIGIN AUTHOR ID: {after.author.id}\n"
                          f"ORIGIN DISCORD SERVER: {after.guild.name}\n"
                          f"ORIGIN SERVER ID: {after.guild.id}\n"
                          f"ORIGIN CHANNEL NAME: {after.channel.name}\n"
                          f"ORIGIN CHANNEL ID: {after.channel.id}\n")

            if CyberBotConfigData["Automation-Mode"][str(after.guild.id)] == "True":
                if URLs:
                    print("Detecting URLs in text content...")
                    if not CyberBotConfigData["Silent-Mode"][str(after.guild.id)] == "True":
                        await after.reply("Cyberbot detected URL(s) in text content. Begin scanning the URL(s) with Virus Total.")

                    """URL access validation"""
                    resolvedUrls = []
                    for url in URLs:
                        print(f"Found URL: {url}")
                        print(f"Found URL: {url}")
                        if "../" in unquote(url):
                            logMessage += f"URL SCAN SUMMARY: URL {url} name query hinted potential directory transversal attack!\n\n"
                            print(f"URL {url} contains ../ attack pattern!\n\n")
                            await logScanSession(logMessage)
                            await after.reply(f"URL contains a ../ scheme hinted potential directory transversal attack on the host web server!")
                            await after.delete()
                            return
                        if url.startswith("https://klipy.com/gifs/"):
                            print(f"URL {url} is a Klipy gif, getting the real gif URL...")
                            klipyUrl = await isKlipyURLValid(url)
                            if klipyUrl != "Invalid":
                                print(f"Klipy URL is valid!")
                                resolvedUrls.append(klipyUrl)
                            else:
                                print(f"Klipy URL is invalid!")
                                logMessage += f"URL SCAN SUMMARY: Can not retrieve URL {url}\n"
                                await after.reply(f"Cyberbot cannot access URL {url}")
                        else:
                            if url.startswith("https://tenor.com/view"):
                                print(f"URL {url} is a Tenor gif, getting the real gif URL...")
                                tenorUrl = await isTenorURLValid(url)
                                if tenorUrl != "Invalid":
                                    print(f"Tenor URL is valid!")
                                    resolvedUrls.append(tenorUrl)
                                else:
                                    print(f"Tenor URL is invalid!")
                                    logMessage += f"URL SCAN SUMMARY: Can not retrieve URL {url}\n"
                                    await after.reply(f"Cyberbot cannot access URL {url}")
                            else:
                                try:
                                    async with Cyberbot.session.get(url, headers=MAINHEADERS) as testValidURLResponse:
                                        if testValidURLResponse.status in range(400, 500):
                                            logMessage += f"URL SCAN SUMMARY: Can not retrieve URL {url} - Status Code {testValidURLResponse.status}\n"
                                            print(f"Can not access URL {url}\nStatus Code: {testValidURLResponse.status}")
                                            print(f"URL {url} status code: {testValidURLResponse.status}")
                                            await after.reply(f"Cyberbot cannot access URL {url} with status code: {testValidURLResponse.status}", suppress_embeds=True)
                                        else:
                                            resolvedUrls.append(url)
                                except Exception as error:
                                    print(f"Can not access URL {url}\nError: {error}")
                                    logMessage += f"URL SCAN SUMMARY: Can not retrieve URL {url} - Error {error}\n"
                                    await after.reply(f"Cyberbot can not scan URL {url}", suppress_embeds=True)
                    URLs = resolvedUrls

                    """VirusTotal URL scan"""
                    for url in URLs:
                        hashedUrl = hashlib.sha256(url.encode('utf-8')).hexdigest()
                        logMessage += f"URL IN MESSAGE: {url}\nSHA-256 HASH: {hashedUrl}\n"

                        """Checking if there is another subroutine scanning the same URL"""
                        if CURRENTSCANOPERATION.get(hashedUrl, "") == "In Progress":
                            print(f"URL {url} is currently being scanned by other subroutine!")
                            while True:
                                await asyncio.sleep(0)
                                if not CURRENTSCANOPERATION.get(hashedUrl, ""):
                                    break
                        else:
                            CURRENTSCANOPERATION[hashedUrl] = "In Progress"

                        if await checkingCleanData(hashedUrl, "URLs"):
                            logMessage += "URL SCAN SUMMARY: Already been scanned as safe to visit\n"
                            print(f"URL: {url} has been checked in Cyberbot scan history and recorded as safe to visit")
                            if not CyberBotConfigData["Silent-Mode"][str(after.guild.id)] == "True":
                                await after.reply(f"URL: {url} has been checked in Cyberbot scan history and recorded as safe to visit", suppress_embeds=True)
                        elif await checkingFlaggedMaliciousData(hashedUrl, "URLs"):
                            logMessage += "URL SCAN SUMMARY: Already been scanned as malicious\n\n"
                            print(f"URL: {url} has been checked in Cyberbot scan history and recorded as malicious\n\n")
                            await after.reply(f"URL: {url} has been checked in Cyberbot scan history and recorded as malicious", suppress_embeds=True)
                            await after.delete()
                        else:
                            UrlScanResult = await virusTotalURLScan(url)
                            if UrlScanResult == "URL can't be scanned":
                                logMessage += f"URL SCAN SUMMARY: VirusTotal can not scan\n"
                                print(f"URL {url} can't be scanned by Virus Total")
                                await after.reply(f"URL {url} can't be scanned by Virus Total", suppress_embeds=True)
                            elif int(UrlScanResult.split(":")[1]) > 0:
                                logMessage += f"URL SCAN SUMMARY: VirusTotal flagged as malicious\n"
                                print(f"URL {url} flagged malicious by Virus Total")
                                await addingHashedData(hashedUrl, "URLs", True)
                                await after.channel.send(f"URL {url} is flagged malicious by Virus Total", suppress_embeds=True)
                                await after.delete()
                            else:
                                logMessage += f"URL SCAN SUMMARY: VirusTotal scanned as Clean/Safe To Visit\n"
                                print(f"URL {url} passed Virus Total scan as Safe to visit!")
                                await addingHashedData(hashedUrl, "URLs", False)
                                if not CyberBotConfigData["Silent-Mode"][str(after.guild.id)] == "True":
                                    await after.reply(f"URL {url} is safe to visit", suppress_embeds=True)
                        if CURRENTSCANOPERATION.get(hashedUrl, ""):
                            del CURRENTSCANOPERATION[hashedUrl]
                    print(f"URLs scan finished!\n\n")
            else:
                logMessage += f"SCAN SUMMARY: Cyberbot detected the message but automation scan mode is disabled for this server, so no scan is done!\n\n"
                await logScanSession(logMessage)


@Cyberbot.event
async def on_message(message):
    global FILEDOWNLOADCOUNTER, CURRENTSCANOPERATION

    await Cyberbot.process_commands(message)

    if message.author == Cyberbot.user:
        return

    if str(message.channel) == "Direct Message with Unknown User":
        return

    """Adding new server ID to Configuration file"""
    if not CyberBotConfigData["Non-monitoring-Channels"].get(str(message.guild.id), ""):
        CyberBotConfigData["Non-monitoring-Channels"][str(message.guild.id)] = []
    if not CyberBotConfigData["Silent-Mode"].get(str(message.guild.id), ""):
        CyberBotConfigData["Silent-Mode"][str(message.guild.id)] = "False"
    if not CyberBotConfigData["Automation-Mode"].get(str(message.guild.id), ""):
        CyberBotConfigData["Automation-Mode"][str(message.guild.id)] = "True"
    async with ConfigLock:
        async with aiofiles.open(CYBERBOTCONFIG, "w") as file:
            await file.write(json.dumps(CyberBotConfigData, indent=4))

    """Checking if the current channel is in the server non monitoring list"""
    if message.channel.id in CyberBotConfigData["Non-monitoring-Channels"][str(message.guild.id)]:
        return

    if message.content:
        URLs = re.findall(r'https?://(?:(?!https?://)\S)+', message.content.replace(" ", ""))
        URLs = list(set(URLs))
    else:
        URLs = ""

    if URLs or len(message.attachments) > 0:
        logMessage = (f"{time.ctime(time.time())}\n"
                      f"ORIGIN AUTHOR: {message.author.name}\n"
                      f"ORIGIN AUTHOR ID: {message.author.id}\n"
                      f"ORIGIN DISCORD SERVER: {message.guild.name}\n"
                      f"ORIGIN SERVER ID: {message.guild.id}\n"
                      f"ORIGIN CHANNEL NAME: {message.channel.name}\n"
                      f"ORIGIN CHANNEL ID: {message.channel.id}\n")

        if CyberBotConfigData["Automation-Mode"][str(message.guild.id)] == "True":
            if URLs:
                print("Detecting URLs in text content...")
                if not CyberBotConfigData["Silent-Mode"][str(message.guild.id)] == "True":
                    await message.reply("Cyberbot detected URL(s) in text content. Begin scanning the URL(s) with Virus Total.")

                """URL access validation"""
                resolvedUrls = []
                for url in URLs:
                    print(f"Found URL: {url}")
                    if "../" in unquote(url):
                        logMessage += f"URL SCAN SUMMARY: URL {url} name query hinted potential directory transversal attack!\n\n"
                        print(f"URL {url} contains ../ attack pattern!\n\n")
                        await logScanSession(logMessage)
                        await message.reply(f"URL contains a ../ scheme hinted potential directory transversal attack on the host web server!")
                        await message.delete()
                        return
                    if url.startswith("https://klipy.com/gifs/"):
                        print(f"URL {url} is a Klipy gif, getting the real gif URL...")
                        klipyUrl = await isKlipyURLValid(url)
                        if klipyUrl != "Invalid":
                            print(f"Klipy URL is valid!")
                            resolvedUrls.append(klipyUrl)
                        else:
                            print(f"Klipy URL is invalid!")
                            logMessage += f"URL SCAN SUMMARY: Can not retrieve URL {url}\n"
                            await message.reply(f"Cyberbot cannot access URL {url}")
                    else:
                        if url.startswith("https://tenor.com/view"):
                            print(f"URL {url} is a Tenor gif, getting the real gif URL...")
                            tenorUrl = await isTenorURLValid(url)
                            if tenorUrl != "Invalid":
                                print(f"Tenor URL is valid!")
                                resolvedUrls.append(tenorUrl)
                            else:
                                print(f"Tenor URL is invalid!")
                                logMessage += f"URL SCAN SUMMARY: Can not retrieve URL {url}\n"
                                await message.reply(f"Cyberbot cannot access URL {url}")
                        else:
                            try:
                                async with Cyberbot.session.get(url, headers=MAINHEADERS) as testValidURLResponse:
                                    if testValidURLResponse.status in range(400, 500):
                                        logMessage += f"URL SCAN SUMMARY: Can not retrieve URL {url} - Status Code {testValidURLResponse.status}\n"
                                        print(f"Can not access URL {url}\nStatus Code: {testValidURLResponse.status}")
                                        print(f"URL {url} status code: {testValidURLResponse.status}")
                                        await message.reply(f"Cyberbot cannot access URL {url} with status code: {testValidURLResponse.status}", suppress_embeds=True)
                                    else:
                                        resolvedUrls.append(url)
                            except Exception as error:
                                print(f"Can not access URL {url}\nError: {error}")
                                logMessage += f"URL SCAN SUMMARY: Can not retrieve URL {url} - Error {error}\n"
                                await message.reply(f"Cyberbot can not scan URL {url}", suppress_embeds=True)
                URLs = resolvedUrls

                """VirusTotal URL scan"""
                for url in URLs:
                    hashedUrl = hashlib.sha256(url.encode('utf-8')).hexdigest()
                    logMessage += f"URL IN MESSAGE: {url}\nSHA-256 HASH: {hashedUrl}\n"

                    """Checking if there is another subroutine scanning the same URL"""
                    if CURRENTSCANOPERATION.get(hashedUrl, "") == "In Progress":
                        print(f"URL {url} is currently being scanned by other subroutine!")
                        while True:
                            await asyncio.sleep(0)
                            if not CURRENTSCANOPERATION.get(hashedUrl, ""):
                                break
                    else:
                        CURRENTSCANOPERATION[hashedUrl] = "In Progress"

                    if await checkingCleanData(hashedUrl, "URLs"):
                        logMessage += "URL SCAN SUMMARY: Already been scanned as safe to visit\n"
                        print(f"URL: {url} has been checked in Cyberbot scan history and recorded as safe to visit")
                        if not CyberBotConfigData["Silent-Mode"][str(message.guild.id)] == "True":
                            await message.reply(f"URL: {url} has been checked in Cyberbot scan history and recorded as safe to visit", suppress_embeds=True)
                    elif await checkingFlaggedMaliciousData(hashedUrl, "URLs"):
                        logMessage += "URL SCAN SUMMARY: Already been scanned as malicious\n\n"
                        print(f"URL: {url} has been checked in Cyberbot scan history and recorded as malicious\n\n")
                        await message.reply(f"URL: {url} has been checked in Cyberbot scan history and recorded as malicious", suppress_embeds=True)
                        await message.delete()
                    else:
                        UrlScanResult = await virusTotalURLScan(url)
                        if UrlScanResult == "URL can't be scanned":
                            logMessage += f"URL SCAN SUMMARY: VirusTotal can not scan\n"
                            print(f"URL {url} can't be scanned by Virus Total")
                            await message.reply(f"URL {url} can't be scanned by Virus Total", suppress_embeds=True)
                        elif int(UrlScanResult.split(":")[1]) > 0:
                            logMessage += f"URL SCAN SUMMARY: VirusTotal flagged as malicious\n"
                            print(f"URL {url} flagged malicious by Virus Total")
                            await addingHashedData(hashedUrl, "URLs", True)
                            await message.channel.send(f"URL {url} is flagged malicious by Virus Total", suppress_embeds=True)
                            await message.delete()
                        else:
                            logMessage += f"URL SCAN SUMMARY: VirusTotal scanned as Clean/Safe To Visit\n"
                            print(f"URL {url} passed Virus Total scan as Safe to visit!")
                            await addingHashedData(hashedUrl, "URLs", False)
                            if not CyberBotConfigData["Silent-Mode"][str(message.guild.id)] == "True":
                                await message.reply(f"URL {url} is safe to visit", suppress_embeds=True)
                    if CURRENTSCANOPERATION.get(hashedUrl, ""):
                        del CURRENTSCANOPERATION[hashedUrl]
                print(f"URLs scan finished!\n\n")

            if len(message.attachments) > 0:  # Check if the message has at least 1 file attachment and Automation Mode is Enable!
                print(f"User {message.author.name} uploads {len(message.attachments)} file attachment(s)!")

                for attachment in message.attachments:
                    print(f"Scanning file {attachment.filename}...")
                    if not CyberBotConfigData["Silent-Mode"][str(message.guild.id)] == "True":
                        await message.reply(f"Cyberbot is scanning the file {attachment.filename} in this message, please do not download until Cyberbot scan is clear of malware.")
                    logMessage += f"FILE ATTACHMENT: {attachment.filename}\n"

                    """Checking ../ attack in file name scheme"""
                    if "../" in attachment.filename:
                        logMessage += f"FILE SCAN SUMMARY: File name hinted potential directory transversal attack!\n"
                        print(f"File name {attachment.filename} hinted potential directory transversal attack!")
                        await message.reply(f"The file {attachment.filename} name hinted potential directory transversal attack, also known as ../ attack!")
                        await message.delete()
                        print("Scan Process Finish!\n\n")
                        await logScanSession(f"{logMessage}\n\n")
                        return

                    filePath = f"{DOWNLOADINGDIRPATH}{FILEDOWNLOADCOUNTER}"
                    scanOperation = False

                    """Checking if file size within the supported file size for scan"""
                    async with Cyberbot.session.head(attachment.url) as head:
                        FullContentLength = int(head.headers.get("Content-Length", 0))
                    logMessage += f"FILE SIZE: {FullContentLength} bytes\n"
                    if FullContentLength > 300000000:
                        logMessage += f"FILE SCAN SUMMARY: File attachment has a total size of {FullContentLength} bytes. Size exceeding Cyberbot file size limit of 300 MB\n"
                        await message.reply(
                            f"The file {attachment.filename} has a size {FullContentLength} bytes, which"
                            f" exceeding the file size limit that Cyberbot can support! The content won't be"
                            f" scanned!")
                    else:
                        async with Cyberbot.session.get(attachment.url, headers=MAINHEADERS) as response:
                            if not response.status in range(400, 500):
                                RootFileHashed = hashlib.sha256(await response.read()).hexdigest()
                                logMessage += f"SHA-256 HASH: {RootFileHashed}\n"

                                """Checking file true extension"""
                                RootFileTrueExt = await checkingRealFileExtension(await response.read(), attachment.filename)
                                logMessage += f"FILE EXTENSION: {RootFileTrueExt}\n"

                                if not CyberBotConfigData["Silent-Mode"][str(message.guild.id)] == "True":
                                    await message.reply(f"The file {attachment.filename} extension is: {RootFileTrueExt}")
                                filePath = f"{filePath}{RootFileTrueExt}"

                                """Checking if there is another subroutine scanning the same file"""
                                if CURRENTSCANOPERATION.get(RootFileHashed, "") == "In Progress":
                                    print(f"File {attachment.filename} is currently being scanned by other subroutine!")
                                    while True:
                                        await asyncio.sleep(0)
                                        if not CURRENTSCANOPERATION.get(RootFileHashed, ""):
                                            break
                                else:
                                    CURRENTSCANOPERATION[RootFileHashed] = "In Progress"

                                """Checking if file hashed signature already in clean or malicious data set"""
                                if await checkingCleanData(RootFileHashed, "All Extension"):
                                    logMessage += "FILE SCAN SUMMARY: File attachment already scanned as Safe To Download\n"
                                    print(f"File {attachment.filename} has already been checked and recorded in the clean data set!\n\n")
                                    if not CyberBotConfigData["Silent-Mode"][str(message.guild.id)] == "True":
                                        await message.reply(f"File {attachment.filename} has been checked in Cyberbot scan history and recorded in the safe to download dataset!")
                                elif await checkingFlaggedMaliciousData(RootFileHashed, "All Extension"):
                                    logMessage += "FILE SCAN SUMMARY: File attachment already flagged as Malicious\n"
                                    print(f"File {attachment.filename} has already been checked and recorded in the malicious file set!\n\n")
                                    await message.reply(f"File {attachment.filename} has been checked in Cyberbot scan history and recorded in the Malicious dataset! The content is deleted!")
                                    await message.delete()
                                    print(f"Scan Process Finish!\n\n")
                                    if CURRENTSCANOPERATION.get(RootFileHashed, ""):
                                        del CURRENTSCANOPERATION[RootFileHashed]
                                    return
                                else:

                                    """Checking if file is encrypted"""
                                    if RootFileTrueExt.endswith(ENCRYPTEDFILEFORMATS):
                                        logMessage += "FILE SCAN SUMMARY: File attachment is encrypted. Cyberbot can not scan\n"
                                        print("File is encrypted, can not open without the key!")
                                        await message.reply(
                                            f"The file {attachment.filename} is an encrypted file that may"
                                            f" contain confidential or malware information, it is encrypted,"
                                            f" so Cyberbot can not scan for the content. If you're intend to share the "
                                            f"encrypted file for sharing legitimate information with someone, please do "
                                            f"it via DM with the wanted party. If you received the file from someone"
                                            f" that you do not know, I advice not to download the file and decrypt it!"
                                            f" If you have the key, you can decrypt the file but do not open it and send"
                                            f" again for Cyberbot to scan!")

                                    if RootFileTrueExt in CYBERBOTSCOPEOFORMATS:
                                        print("Downloading attachment content...")
                                        async with aiofiles.open(filePath, "wb") as file:
                                            await file.write(await response.read())
                                        print("Attachment file downloaded!")
                                        mountPoint = f"{DOWNLOADINGDIRPATH}{FILEDOWNLOADCOUNTER}MainMountPoint/"
                                        os.mkdir(mountPoint)
                                        print(f"Mount point {mountPoint} created!")
                                        scanOperation = True
                                        FILEDOWNLOADCOUNTER += 1
                                    else:
                                        logMessage += "FILE SCAN SUMMARY: File attachment outside of Cyberbot scope of file formats for malware analysis!\n"
                                        print("File attachment outside of Cyberbot scope of file formats for malware analysis!")
                                        await message.reply(f"The file {attachment.filename} extension is outside of Cyberbot scope of file formats for malware analysis!")
                            else:
                                logMessage += "FILE SCAN SUMMARY: File attachment can not be downloaded by Cyberbot for malware analysis!\n"
                                print(f"Cyberbot can not retrieve the attachment for scan!")
                                await message.reply(f"Cyberbot can not retrieve {attachment.filename}!")
                                await message.delete()

                        if scanOperation:
                            print(f"Start scanning {attachment.filename} contents with Virus Total...")
                            virusTotalResult = (await virusTotalFileScan(filePath)).split(":")
                            if virusTotalResult != "File can't be scanned":
                                virusTotalReport = f"{virusTotalResult[0]} Malicious, {virusTotalResult[1]} Suspicious, {virusTotalResult[2]} Harmless, {virusTotalResult[3]} Undetected"
                                if int(virusTotalResult[0]) > 0:
                                    logMessage += "FILE SCAN SUMMARY: File attachment flagged as Malicious by VirusTotal\n"
                                    print(f"Virus Total analyzed file {attachment.filename} as malicious!")
                                    await message.reply(f"The file {attachment.filename} was flagged malicious by Virus Total!\n{virusTotalReport}")
                                    await message.delete()
                                    await addingHashedData(RootFileHashed, RootFileTrueExt, True)
                                    os.remove(filePath)
                                    print("Cleaning up process...")
                                    shutil.rmtree(mountPoint)
                                    print(f"Scan Process Finish!\n\n")
                                    if CURRENTSCANOPERATION.get(RootFileHashed, ""):
                                        del CURRENTSCANOPERATION[RootFileHashed]
                                    return
                                logMessage += "VIRUS TOTAL SCAN: Safe To Download"
                            else:
                                logMessage += "VIRUS TOTAL SCAN: Error\n"
                                print(f"VirusTotal can not scan the attachment!")
                                
                            if RootFileTrueExt.endswith(DISKIMAGEANDARCHIVEFORMATS):
                                print("Attachment is an Archive or Disk Image file, checking for Archive/Disk Image Bomb...")
                                FileUncompressedSize = await asyncio.to_thread(ArchivesDiskImagesBombAnalysisAndExtraction,[filePath], mountPoint)
                                if FileUncompressedSize.startswith(("Encrypted Error", "Path Transversal Attack", "Potential Archive Bomb!","Disk Image Error!", "Potential Recursive Archive Bomb Attack!", "Too many duplicated files!")):
                                    if FileUncompressedSize.startswith("Encrypted Error"):
                                        logMessage += f"FILE SCAN SUMMARY: File Attachment is an encrypted archive/disk file. Cyberbot can not scan encrypted content\n"
                                        print(f"Archive/Disk file encrypted!")
                                        await message.reply(
                                            f"The archive/disk file {attachment.filename} contains an encrypted file"
                                            f" that may contain confidential or malware, it is encrypted, so Cyberbot can not scan"
                                            f" for the content. If you're intend to share the encrypted file for sharing legitimate"
                                            f" information with someone, please do it via DM with the wanted party. If you received"
                                            f" the file from someone that you do not know, I advise not to download the file and"
                                            f" decrypt it!"
                                        )
                                    elif FileUncompressedSize.startswith("Path Transversal Attack"):
                                        logMessage += f"FILE SCAN SUMMARY: File Attachment contains an uncompressed content with potential path transversal attack scheme\n"
                                        print(f"Archive/Disk file detected potential path transversal attack!")
                                        await message.reply(
                                            f"The file {attachment.filename} contains a file content with file name that"
                                            f" can cause a path transversal attack! The archive file was deleted!"
                                        )
                                    elif FileUncompressedSize.startswith("Potential Archive Bomb!"):
                                        logMessage += f"FILE SCAN SUMMARY: File Attachment uncompressed size exceeding 32 GB. Potential archive/disk bomb\n"
                                        print(f"Archive/Disk file uncompressed size exceeding 32 GB!")
                                        await message.reply(
                                            f"The file {attachment.filename} has an uncompressed size exceeding 32 GB,"
                                            f" potential archive/diskImage bomb detected!"
                                        )
                                    elif FileUncompressedSize.startswith("Disk Image Error!"):
                                        logMessage += f"FILE SCAN SUMMARY: File Attachment has a corrupted disk image\n"
                                        print(f"Archive/Disk file has corrupted disk image")
                                        await message.reply(f"The file {attachment.filename} has a corrupted disk image!")
                                    elif FileUncompressedSize.startswith("Potential Recursive Archive Bomb Attack!"):
                                        logMessage += f"FILE SCAN SUMMARY: File Attachment has more than 3 duplicated archive/disk files. Potential recursive archive/disk bomb attack\n"
                                        print(f"Archive/Disk file has more than 3 duplicated archive/disk files")
                                        await message.reply(
                                            f"The file {attachment.filename} has more than 3 duplicated archive/disk files within it "
                                            f"compressed content! This could be a hint for a potential Recursive Archive/Disk Bomb Attack!"
                                        )
                                    else:
                                        logMessage += f"FILE SCAN SUMMARY: File Attachment is an archive/disk image with too many duplicated content. A hint for a potential Archive/Disk Bomb Attack Method that extract many duplicated content to fill up storage space!\n"
                                        print(f"Archive/Disk file has too many duplicated contents")
                                        await message.reply(
                                            f"The file {attachment.filename} has too many duplicated files within it "
                                            f"compressed content! This is a hint for a potential Archive/Disk Bomb Attack Method that"
                                            f" extract many duplicated content to fill up storage space!"
                                        )

                                    if not FileUncompressedSize.startswith("Encrypted Error"):
                                        await addingHashedData(RootFileHashed, RootFileTrueExt, True)
                                        await message.delete()
                                    logMessage += "\n\n"
                                    await logScanSession(logMessage)
                                    print("Cleaning up process...")
                                    shutil.rmtree(mountPoint)
                                    print(f"Scan Process Finish!\n\n")
                                    if CURRENTSCANOPERATION.get(RootFileHashed, ""):
                                        del CURRENTSCANOPERATION[RootFileHashed]
                                    return

                                def uncompressedFileStructure(path: str, indent=""):
                                    name = os.path.basename(path)
                                    result = ""
                                    if os.path.isdir(path):
                                        result += f"{indent}{name} (Directory)\n"
                                        for entry in sorted(os.listdir(path)):
                                            fullPath = os.path.join(path, entry)
                                            result += uncompressedFileStructure(fullPath, indent + "\t\t")
                                    else:
                                        result += f"{indent}{name} (File)\n"

                                    return result

                                ufs = uncompressedFileStructure(mountPoint, indent="")

                                logMessage += f"FILE UNCOMPRESSION SUMMARY: The file uncompressed size {FileUncompressedSize.split('|')[0]} bytes and {FileUncompressedSize.split('|')[1]} duplicated content.\nUNCOMPRESSED FILE STRUCTURE:\n{ufs}\n"
                                if not CyberBotConfigData["Silent-Mode"][str(message.guild.id)] == "True":
                                    await message.reply(
                                        f"The file {attachment.filename} has an uncompressed size of"
                                        f" {FileUncompressedSize.split('|')[0]} bytes, which below the standard "
                                        f"threshold uncompressed size of 32 GB to be flagged as archive/diskImage "
                                        f"bomb!\nBegin the scanning process on the uncompressed content"
                                        f", which may take quite some time. There are {FileUncompressedSize.split('|')[1]}"
                                        f" duplicated content to be aware of!")
                                    await message.reply(f"The Uncompressed File Structure of {attachment.filename} are:\n{ufs}")


                                print(f"Start scanning for the extracted file contents at {mountPoint} with Virus Total...")
                                for dirpath, _, filenames in os.walk(mountPoint):
                                    for filename in filenames:
                                        logMessage += f"UNCOMPRESSED FILE INSIDE ARCHIVE {attachment.filename}: {filename}\n"
                                        filepath = os.path.join(dirpath, filename)
                                        fileSize = os.path.getsize(filepath)
                                        async with aiofiles.open(filepath, mode="rb") as source:
                                            fileExt = await checkingRealFileExtension(await source.read(), filename)
                                            HashedFileData = hashlib.sha256(await source.read()).hexdigest()
                                        print(f"Found file: {filename} | Type: {fileExt} | Size: {fileSize} bytes | From path {filepath}")
                                        logMessage += f"SHA-256 HASH: {HashedFileData}\nFILE SIZE: {fileSize} bytes\nFILE EXT: {fileExt}\n"

                                        if await checkingCleanData(HashedFileData, "All Extension"):
                                            print(f"File {filename} has already been checked and recorded in the clean data set!\n")
                                            logMessage += "FILE SCAN SUMMARY: File already scanned as Safe To Download\n"
                                            if not CyberBotConfigData["Silent-Mode"][str(message.guild.id)] == "True":
                                                await message.reply(f"File {filename} inside archive/disk image {attachment.filename} has been checked in Cyberbot scan history and recorded in the safe to download dataset!")
                                            os.remove(filepath)
                                        elif await checkingFlaggedMaliciousData(HashedFileData, "All Extension"):
                                            logMessage += "FILE SCAN SUMMARY: File already flagged Malicious\n"
                                            print(f"File {filename} has already been checked and recorded in the malicious file set!")
                                            await message.reply(f"File {filename} inside {attachment.filename} has been checked in Cyberbot scan history and recorded in the Malicious dataset! The content is deleted!")
                                            await message.delete()
                                            await addingHashedData(RootFileHashed, RootFileTrueExt, True)
                                            print("Cleaning up process...")
                                            shutil.rmtree(mountPoint)
                                            print(f"Scan Process Finish!\n\n")
                                            if CURRENTSCANOPERATION.get(RootFileHashed, ""):
                                                del CURRENTSCANOPERATION[RootFileHashed]
                                            return
                                        else:
                                            print(f"Start Virus Total Scan on {filename}...")
                                            virusTotalResult = (await virusTotalFileScan(filepath)).split(":")
                                            virusTotalReport = f"{virusTotalResult[0]} Malicious, {virusTotalResult[1]} Suspicious, {virusTotalResult[2]} Harmless, {virusTotalResult[3]} Undetected"
                                            if int(virusTotalResult[0]) > 0:
                                                logMessage += "FILE SCAN SUMMARY: VirusTotal flagged as Malicious\n"
                                                print(f"Virus Total analyzed file {filename} as malicious!")
                                                await message.reply(f"File {filename} inside archive/disk image {attachment.filename} was flagged malicious by Virus Total!\n{virusTotalReport}")
                                                await message.delete()
                                                await addingHashedData(HashedFileData, fileExt, True)
                                                await addingHashedData(RootFileHashed, RootFileTrueExt, True)
                                                logMessage += "\n\n"
                                                await logScanSession(logMessage)
                                                print("Cleaning up process...")
                                                shutil.rmtree(mountPoint)
                                                print(f"Scan Process Finish!\n\n")
                                                if CURRENTSCANOPERATION.get(RootFileHashed, ""):
                                                    del CURRENTSCANOPERATION[RootFileHashed]
                                                return
                                            logMessage += "VIRUS TOTAL SCAN: Safe To Download"
                                            if not fileExt.endswith(SCRIPTFILEFORMATS) and not fileExt.endswith(EXECUTABLEFORMATS):
                                                await addingHashedData(HashedFileData, fileExt, False)
                                                os.remove(filepath)
                            else:
                                shutil.move(filePath, mountPoint)
                                print(f"Content has been moved to main scan directory {mountPoint}")

                            CompiledHashedMap = {}
                            print(f"Start scanning for COMPILED/EXECUTABLE file contents ONLY at {mountPoint}...")
                            for dirpath, _, filenames in os.walk(mountPoint):
                                for filename in filenames:
                                    filepath = os.path.join(dirpath, filename)
                                    fileSize = os.path.getsize(filepath)
                                    async with aiofiles.open(filepath, "rb") as source:
                                        fileExt = await checkingRealFileExtension(await source.read(), filename)
                                        HashedCompiledFileData = hashlib.sha256(await source.read()).hexdigest()
    
                                    if fileExt in EXECUTABLEFORMATS:
                                        print(f"Found compiled file: {filename} | Type: {fileExt} | Size: {fileSize} bytes | From path {filepath}")
                                        outputFilePath = await asyncio.to_thread(ghidraDecompile, filepath, mountPoint, filename)
                                        if outputFilePath != "ERROR":
                                            async with aiofiles.open(outputFilePath, "rb") as file:
                                                HashedDecompiledData = hashlib.sha256(await file.read()).hexdigest()
                                            CompiledHashedMap[HashedCompiledFileData] = HashedDecompiledData

                            print(f"Start scanning for SCRIPT file contents ONLY at {mountPoint}...")
                            for dirpath, _, filenames in os.walk(mountPoint):
                                for filename in filenames:
                                    filepath = os.path.join(dirpath, filename)
                                    fileSize = os.path.getsize(filepath)
                                    async with aiofiles.open(filepath, "rb") as source:
                                        fileExt = await checkingRealFileExtension(await source.read(), filename)
                                        HashedScriptFileData = hashlib.sha256(await source.read()).hexdigest()

                                    """SCAT Process with OpenAI and Gemini LLMs"""
                                    if fileExt in SCRIPTFILEFORMATS:
                                        print(f"Found script file: {filename} | Type: {fileExt} | Size: {fileSize} bytes | From path {filepath}")
                                        print(f"Converting script file {filename} to PDF...")
                                        pdf = FPDF()
                                        pdf.add_page()
                                        pdf.set_font("Arial", size=12)
                                        pdfpath = f"{filepath.split(".")[0]}.pdf"
                                        async with aiofiles.open(filepath, "r", encoding="utf-8") as SourceCodefile:
                                            pdf.multi_cell(0, 10, (await SourceCodefile.read()).encode("latin-1",errors="replace").decode("latin-1"))
                                            pdf.output(pdfpath)
                                        filepath = pdfpath
                                        print(f"Conversion successes!")
                                        flaggedMalicious = False
                                        if not flaggedMalicious:
                                            print(f"Start {GPTMODEL} scan on file {filename} for malware analysis...")
                                            GptScanResult = await openAISCAT(filepath, f"# ASK:\n"
                                                                                       f"Reads the source/script file contents and decides if it is a malware exhibits any malicious pattern.\n"
                                                                                       f"# RESPONSE FORMAT:\n"
                                                                                       f"If you suspect it is malware, **START** the response with **True** or **False** with **NO BOLD** and **NO ITALIC STYLE** and **EXPLAIN WHY!**")
                                            if GptScanResult.startswith(("True", "true")):
                                                logMessage += f"FILE SCAN SUMMARY: {GPTMODEL} flagged as Malicious\n"
                                                flaggedMalicious = True
                                                print(f"{GPTMODEL} analyzed the content of being a potential malware!")
                                                if len(GptScanResult) > 1500:
                                                    print(f"Scan result exceeding 1500 words, creating a txt file to send the report...")
                                                    buffer = BytesIO()
                                                    buffer.write(GptScanResult.encode('utf-8'))
                                                    buffer.seek(0)
                                                    resultFile = discord.File(fp=buffer, filename="GPTScanResult.txt")
                                                    await message.reply(
                                                        f"{GPTMODEL} scan result for file {os.path.basename(filepath)} suggested"
                                                        f" a potential malicious file, therefore it was deleted!",
                                                        file=resultFile)
                                                else:
                                                    await message.reply(
                                                        f"{GPTMODEL} scan result: {GptScanResult}\n\nThe file"
                                                        f" {os.path.basename(filepath)} was detected of being a"
                                                        f" potential malicious file, therefore it was"
                                                        f" deleted!")

                                        if not flaggedMalicious:
                                            print(f"Start Gemini Model {GEMINIMODEL} scan on file {filename} for malware analysis...")
                                            GeminiScanResult = await GeminiSCAT(filepath,f"# ROLE:\n"
                                                                          f"You are a cybersecurity analyst on a file for potential malware detection\n"
                                                                          f"# ASK:\n"
                                                                          f"Reads the source/script file contents and decides if it is a malware exhibits any malicious pattern.\n"
                                                                          f"# RESPONSE FORMAT:\n"
                                                                          f"If you suspect it is malware, **START** the response with **True** or **False** with **NO BOLD** and **NO ITALIC STYLE** and **EXPLAIN WHY!**")
    
                                            if GeminiScanResult.startswith(("True", "true")):
                                                logMessage += f"FILE SCAN SUMMARY: {GEMINIMODEL} flagged as Malicious\n"
                                                flaggedMalicious = True
                                                print(f"{GEMINIMODEL} analyzed the content of being a potential malware!")
                                                if len(GeminiScanResult) > 1500:
                                                    print(f"Scan result exceeding 1500 words, creating a txt file to send the report...")
                                                    buffer = BytesIO()
                                                    buffer.write(GeminiScanResult.encode('utf-8'))
                                                    buffer.seek(0)
                                                    resultFile = discord.File(fp=buffer, filename="GeminiScanResult.txt")
                                                    await message.reply(
                                                        f"{GEMINIMODEL} scan result for file {os.path.basename(filepath)} suggested"
                                                        f" a potential malicious file, therefore it was deleted!",
                                                        file=resultFile)
                                                else:
                                                    await message.reply(
                                                        f"{GEMINIMODEL} scan result: {GeminiScanResult}\n\nThe file"
                                                        f" {os.path.basename(filepath)} was detected of being a"
                                                        f" potential malicious file, therefore it was deleted!")
    
                                        if flaggedMalicious:
                                            logMessage += "\n\n"
                                            if HashedScriptFileData == RootFileHashed:
                                                await addingHashedData(RootFileHashed, RootFileTrueExt, True)
                                            else:
                                                await addingHashedData(HashedScriptFileData, fileExt, True)
                                                await addingHashedData(RootFileHashed, RootFileTrueExt, True)
                                                for HashedData in CompiledHashedMap:
                                                    if CompiledHashedMap[HashedData] == HashedScriptFileData and HashedData != RootFileHashed:
                                                        await addingHashedData(HashedData, ".exe", True)
                                                        break
                                            await logScanSession(logMessage)
                                            await message.delete()
                                            print("Cleaning up process...")
                                            shutil.rmtree(mountPoint)
                                            print(f"Scan Process Finish!\n\n")
                                            if CURRENTSCANOPERATION.get(RootFileHashed, ""):
                                                del CURRENTSCANOPERATION[RootFileHashed]
                                            return
                                        else:
                                            await addingHashedData(HashedScriptFileData, fileExt, False)
                                            for HashedData in CompiledHashedMap:
                                                if CompiledHashedMap[HashedData] == HashedScriptFileData and HashedData != RootFileHashed:
                                                    await addingHashedData(HashedData, ".exe", False)
                                                    break
                                            logMessage += f"FILE SCAN SUMMARY: File passed Virus Total, OpenAI and Gemini SCAT."
                            print("Cleaning up process...")
                            shutil.rmtree(mountPoint)
                            await addingHashedData(RootFileHashed, RootFileTrueExt, False)
                            if not CyberBotConfigData["Silent-Mode"][str(message.guild.id)] == "True":
                                await message.reply(f"The file {attachment.filename} is safe to download!")
                            print(f"Scan Process Finish!\n\n")
                        if CURRENTSCANOPERATION.get(RootFileHashed, ""):
                            del CURRENTSCANOPERATION[RootFileHashed]
            await logScanSession(f"{logMessage}\n\n")
        else:
            logMessage += f"SCAN SUMMARY: Cyberbot detected the message but automation scan mode is disabled for this server, so no scan is done!\n\n"
            await logScanSession(logMessage)

Cyberbot.run(BOTTOKEN)
