import discord
import ipaddress
import socket
from typing import Tuple
from urllib.parse import unquote, urlsplit, urljoin, urlunsplit
from aiohttp.abc import AbstractResolver
from discord.ext import commands
from dotenv import load_dotenv

import asyncio
import aiohttp
import re
import hashlib
import os
import requests
import random
import time

load_dotenv()

"""----API Tokens----"""
KLIPHY_API = os.environ.get("KLIPHY_API_KEY")

"""URL Inspection Rules"""
MAX_URL_REDIRECTS = 12 # Maximum 12 URL redirect follow for SSRF inspection
MAX_URL_INSPECTION_SECONDS = 15 # URL inspection should not exceed 15 seconds
MAX_URL_DNS_SECONDS = 3 # URL DNS inspection should not exceed 3 seconds
MAX_URL_LENGTH = 4096 # A long URL is already a suspicious sign of malicious URL
MAX_URL_DNS_ADDRESSES = 16 # Allow maximum 16 DNS address for the URL

"""SSRF Deny Lists"""
SSRF_LOCALHOST = [
    "localhost",
    "localhost.localdomain",
    "localhost6",
    "localhost6.localdomain6",
    "ip6-localhost",
    "ip6-loopback",
    "loopback",
    "local",
    "localdomain",
    "localtest.me",
    "lvh.me",
    "vcap.me",
    "nip.io",
    "sslip.io",
    "xip.io"
]

SSRF_CLOUD_METADATA = [
    "169.254.169.254",
    "metadata",
    "metadata.google.internal",
    "metadata.google",
    "metadata.azure.internal",
    "metadata.internal",
    "metadata.tencentyun.com",
    "metadata.tencentyun.com.cn",
    "100.100.100.200"
]

SSRF_CONTAINER = [
    "host.docker.internal",
    "gateway.docker.internal",
    "docker.for.mac.host.internal",
    "docker.for.mac.localhost",
    "docker.for.win.localhost",
    "host.containers.internal",
    "host.kubernetes.internal",
    "kubernetes",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
    "docker",
    "dockerhost",
    "containerhost"
]

"""Retrieving 100 ScrapeOps Mobile Browser Headers"""
ScrapeOPSResponse = requests.get(
  url='https://headers.scrapeops.io/v1/browser-headers',
  params={
      'api_key': os.environ.get("SCRAPEOPS_API_KEY"),
      'num_results': '100',
      'mobile': 'true'}
)
BROWSER_HEADERS = ScrapeOPSResponse.json().get('result',  [])
assert len(BROWSER_HEADERS) == 100
print(f"Successfully retrieving 100 ScrapeOps Mobile Browser Headers!")

"""Initialize aiohttp.ClientSession in setUpHook"""
class CyberBot(commands.Bot):
    async def setup_hook(self):
        self.session = aiohttp.ClientSession()
        print("aiohttp ClientSession initialized.")

    async def close(self):
        await super().close()
        await self.session.close()

intents = discord.Intents.all()
Cyberbot = CyberBot(command_prefix='/', intents=intents)


async def isKlipyURLValid(gifURL: str) -> bool:
    """
    Description: Klipy URL validation
    :param gifURL: The Klipy URL to check
    :return: True if the gif URL successfully authenticated with the official Klipy API else False
    """
    try:
        gifSlug = os.path.basename(gifURL)
        gifURL = f"https://api.klipy.com/api/v1/{KLIPHY_API}/gifs/items?slugs={gifSlug}"
        async with Cyberbot.session.get(gifURL) as response:
            if response.status == 200:
                data = await response.json()
                if data.get("result", {}):
                    return True
        return False
    except Exception as error:
        print(f"Klipy URL error: {error}")
        return False


class TerminateURLScan(Exception):
    pass

class URLRedirectSafetyError(Exception):
    def __init__(self, reason: str, redirectPath: list):
        super().__init__(reason)
        self.redirectPath = list(redirectPath)


class URLRedirectInspectionError(Exception):
    def __init__(self, reason: str, redirectPath: list):
        super().__init__(reason)
        self.redirectPath = list(redirectPath)


class _CyberbotPinnedDNSResolver(AbstractResolver):
    """Checked public IP addresses for the actual HTTP/TLS connection"""

    # https://nhimg.org/glossary/dns-pinning/
    def __init__(self, hostname: str, publicIPs: tuple):
        self.hostname = hostname.encode('idna').decode('ascii').lower().rstrip('.')
        self.publicIPs = publicIPs
        print(f"Begin pinned DNS resolver on hostname {self.hostname} and it Public IPs {self.publicIPs}")

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        checkedHost = host.encode('idna').decode('ascii').lower().rstrip('.')
        if checkedHost != self.hostname:
            raise OSError('Unexpected DNS hostname during pinned URL inspection')
        results = []
        for ip in self.publicIPs:
            address = ipaddress.ip_address(ip)
            addressFamily = socket.AF_INET if address.version == 4 else socket.AF_INET6
            if family not in (0, socket.AF_UNSPEC, addressFamily):
                continue
            results.append({
                'hostname': host, 'host': ip, 'port': port,
                'family': addressFamily, 'proto': 0, 'flags': socket.AI_NUMERICHOST
            })
        if not results:
            raise OSError('No validated IP address for requested address family')
        print("Hostname successfully pinned with the IP addresses!")
        return results

    async def close(self):
        pass


def _CyberbotURLHasTraversal(url: str) -> bool:
    """Checking for ../ pattern"""
    value = url
    for _ in range(4):
        if '../' in value.replace('\\', '/'):
            return True
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return '../' in value.replace('\\', '/')


async def _CyberbotCheckURLDestination(url: str, redirectPath: list):
    """
    Description: Inspecting URL hostname and it resolved IP addresses
    :param url: The URL to inspect
    :param redirectPath: Current list of redirect URLs to add on
    :return: The final clean URL format, hostname, and it IP addresses
    """
    print(f"URL length: {len(url):,}")
    if not isinstance(url, str) or len(url) > MAX_URL_LENGTH:
        raise URLRedirectSafetyError('Invalid and overly long URL', redirectPath)

    print(f"Checking directory transversal attempt...")
    if _CyberbotURLHasTraversal(url):
        raise URLRedirectSafetyError('Directory traversal pattern (../) detected', redirectPath)
    print(f"No ../ pattern detected!")

    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        port = parts.port
        print(f"URL hostname: {hostname}, port: {port}")
    except ValueError as error:
        raise URLRedirectSafetyError(f'Malformed URL: {error}', redirectPath) from error

    print("Inspecting URL protocol and checking embedded credentials...")
    if parts.scheme.lower() not in ('http', 'https') or not hostname:
        raise URLRedirectSafetyError('Unsupported URL scheme or missing hostname', redirectPath)
    if parts.username is not None or parts.password is not None:
        raise URLRedirectSafetyError(f'URL contains embedded username {parts.username} and password input {parts.password}. A potential attempt to force the victim browser to authenticate with the provided credentials!', redirectPath)

    # Cyberbot only ensure the URL is from standard web port 80 and 443
    expectedPort = 443 if parts.scheme.lower() == 'https' else 80
    if port not in (None, expectedPort):
        raise URLRedirectSafetyError(f'Disallowed URL port: {port}', redirectPath)
    port = expectedPort
    print(f"Valid URL protocol {parts.scheme.lower()} and no embedded credentials found!")

    print(f"Inspecting URL hostname {hostname}...")
    if '%' in hostname or '\\' in hostname or any(c.isspace() for c in hostname):
        raise URLRedirectSafetyError(f'Ambiguous or encoded hostname {hostname}', redirectPath)
    lowerHostname = hostname.lower().rstrip('.')

    # Checking malicious hostname point to internal IP
    if re.compile("|".join(map(re.escape, SSRF_LOCALHOST))).search(lowerHostname):
        raise URLRedirectSafetyError(f'URL redirect to Local/internal hostname {lowerHostname}', redirectPath)
    if re.compile("|".join(map(re.escape, SSRF_CLOUD_METADATA))).search(lowerHostname):
        raise URLRedirectSafetyError(f'URL redirect to Cloud Metadata Service {lowerHostname}', redirectPath)
    if re.compile("|".join(map(re.escape, SSRF_CONTAINER))).search(lowerHostname):
        raise URLRedirectSafetyError(f'URL redirect to internal container/virtualisation images {lowerHostname} blocked', redirectPath)
    print("Hostname passed SSRF DENY LIST!")

    print("Resolving for the hostname IP addresses...")
    try:
        literalIP = ipaddress.ip_address(lowerHostname)
        addresses = (str(literalIP),)
    except ValueError:
        try:
            infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(lowerHostname, port, type=socket.SOCK_STREAM), timeout=MAX_URL_DNS_SECONDS)
        except (OSError, asyncio.TimeoutError) as error:
            raise URLRedirectInspectionError(f'DNS lookup failed: {error}', redirectPath) from error
        addresses = tuple(dict.fromkeys(info[4][0] for info in infos))
        if not addresses or len(addresses) > MAX_URL_DNS_ADDRESSES:
            raise URLRedirectInspectionError('DNS lookup returned no addresses or too many answers', redirectPath)
    print(f"Hostname resolved to IP addresses {addresses}")

    for ip in addresses:
        print(f"Inspecting IP address {ip}...")
        address = ipaddress.ip_address(ip)
        if not address.is_global:
            raise URLRedirectSafetyError(f'URL leads to Non-public destination: {hostname} resolves to {ip}', redirectPath)
        print(f"IP address is a global address!")
    networkURL = urlunsplit((parts.scheme, parts.netloc, parts.path or '/', parts.query, ''))
    return networkURL, hostname, tuple(addresses)


async def _CyberbotReadRedirectResponse(url: str, hostname: str, publicIPs: tuple):
    connector = aiohttp.TCPConnector(resolver=_CyberbotPinnedDNSResolver(hostname, publicIPs), use_dns_cache=False, force_close=True, limit=1, )
    timeout = aiohttp.ClientTimeout(total=7, connect=3, sock_connect=3, sock_read=3)
    print("Begin checking for any URL redirects...")
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, trust_env=False, auto_decompress=False,) as session:
        async with session.get(url, allow_redirects=False, read_until_eof=False,  headers=random.choice(BROWSER_HEADERS), max_line_size=8192, max_field_size=8192,) as response:
            return response.status, response.headers.get('Location')


async def _CyberbotInspectURLRedirects(initialURL: str):
    """Walk every redirect and validate its destination BEFORE making the request"""
    redirectPath = []
    visited = set()
    currentURL = initialURL
    redirectStatusCodes = {301, 302, 303, 307, 308}

    async def inspect():
        nonlocal currentURL
        for redirectCount in range(MAX_URL_REDIRECTS + 1):
            print(f"Begin pre-processing URL: {currentURL}")
            redirectPath.append(currentURL)
            networkURL, hostname, publicIPs = await _CyberbotCheckURLDestination(currentURL, redirectPath)
            if networkURL in visited:
                raise URLRedirectInspectionError('URL creates a Redirect loop detected; cannot safely validate', redirectPath)
            visited.add(networkURL)

            try:
                status, location = await _CyberbotReadRedirectResponse(networkURL, hostname, publicIPs)
            except (aiohttp.ClientError, OSError, asyncio.TimeoutError, ValueError) as error:
                raise URLRedirectInspectionError(f'Unable to inspect HTTP redirect: {type(error).__name__}: {error}', redirectPath) from error

            if status in redirectStatusCodes:
                if not location:
                    raise URLRedirectInspectionError(f'HTTP {status} redirect with no Location header', redirectPath)
                print(f"Found redirect URL {location}")

                print(f"Checking directory transversal attempt...")
                if _CyberbotURLHasTraversal(location):
                    redirectPath.append(location)
                    raise URLRedirectSafetyError(f'Redirect URL {location} contains ../ traversal', redirectPath)
                print(f"No ../ pattern detected!")

                print(f"Redirect URL length: {len(location):,}")
                if len(location) > MAX_URL_LENGTH:
                    redirectPath.append(location[:MAX_URL_LENGTH])
                    raise URLRedirectSafetyError(f'Redirect URL {location} length {len(location)} too long!', redirectPath)
                nextURL = urljoin(networkURL, location)
                if redirectCount >= MAX_URL_REDIRECTS:
                    redirectPath.append(nextURL)
                    raise URLRedirectInspectionError('Maximum redirect count exceeded; cannot safely validate', redirectPath)
                currentURL = nextURL
                continue

            if 300 <= status < 400:
                raise URLRedirectInspectionError(f'Unsupported redirect HTTP status {status}', redirectPath)
            return networkURL, list(redirectPath)

        raise URLRedirectInspectionError('Maximum redirect count exceeded; cannot safely validate', redirectPath)

    try:
        return await asyncio.wait_for(inspect(), timeout=MAX_URL_INSPECTION_SECONDS)
    except asyncio.TimeoutError as error:
        raise URLRedirectInspectionError('Overall redirect inspection timed out', redirectPath) from error


def CyberbotURLScanMessageFormat(redirectPath: list, reason: str, status: str, url: str):
    displayPath = []
    for idx, value in enumerate(redirectPath, start=1):
        clean = str(value).replace('`', "'").replace('\r', '\\r').replace('\n', '\\n')
        displayPath.append(f'{idx}. {clean}')
    if len(displayPath) > 1:
        sendMessage = (f'**URL:** `{url}`\n'
                  f'**Scan Status:** `{status}`\n'
                  f'**Reason:** `{reason}`\n'
                  f'Redirect Path:\n'
                  f'```text\n'
                  f'{'\n  ->\n'.join(displayPath)}\n'
                  f'```')
    else:
        sendMessage = (f'**URL:** `{url}`\n'
                  f'**Scan Status:** `{status}`\n'
                  f'**Reason:** `{reason}`\n')
    return sendMessage


async def processingUrls(URLs: list, message: discord.message.Message, logMessage: str, silent: bool, AddingHashedData) -> Tuple[list, dict, str, bool]:
    """
    Description: Preprocessing URL by validating URL access code, checking for ../ pattern, and SSRF attempt
    :param URLs: The list of URLs to be pre-processed
    :param message: The Discord message object
    :param logMessage: The current scan log message
    :param silent: Is Cyberbot silent mode enable or not?
    :param AddingHashedData: Function to add hashed URL data if malicious or not
    :return: A list of pre-processed URls, a dictionary mapping the URL that actually a Discord attachment, the final scan log message, and a boolean value to continue the scan or not
    """
    print('Detecting URLs in text content...')
    if not silent:
        await message.reply('Cyberbot detected URL(s) in text content. Begin scanning the URL(s) with Virus Total.')
    resolvedUrls = []
    fileAttachmentUrls = {}
    logMessage += f'## URL Pre-Inspection Summary\n'
    UrlInspectionStartTime = time.perf_counter()
    try:
        for url in URLs:
            print(f'Found URL: {url}')
            logMessage += f'- **URL:** `{url}`\n'

            """Checking ../ attack pattern"""
            if _CyberbotURLHasTraversal(url):
                logMessage += (f'- **Inspection Result:** `MALICIOUS`\n'
                               f'- **Reason:** `URL name query hinted potential directory transversal attack!`\n')
                print(f'URL {url} contains ../ attack pattern!\n\n')
                sendMessage = CyberbotURLScanMessageFormat([], 'URL contains a ../ scheme hinted potential directory transversal attack on the host web server!', 'MALICIOUS', url)
                try:
                    await message.reply(sendMessage)
                    await message.delete()
                except discord.errors.HTTPException:
                    await message.channel.send(sendMessage )
                    pass
                raise TerminateURLScan
            try:
                finalURL, redirectPath = await _CyberbotInspectURLRedirects(url)
                print('URL redirect path: ' + ' -> '.join(redirectPath))
                if len(redirectPath) > 1:
                    fullPath = " -> ".join(redirectPath)
                    logMessage += (f'- **URL Redirect Path (Public Only):**\n'
                                   f'```commandline\n'
                                   f'{fullPath}\n'
                                   f'```\n'
                                   f'- **Final Destination Path:** `{finalURL}`\n')
                    if not silent:
                        sendMessage = (f"URL `{url}` redirect path are as follows:\n"
                                       f"```\n"
                                       f"{fullPath}\n"
                                       f"```\n"
                                       f"Cyberbot will scan the final destination URL {redirectPath[-1]}")
                        try:
                            await message.reply(sendMessage, suppress_embeds=True)
                        except discord.errors.HTTPException:
                            await message.channel.send(sendMessage, suppress_embeds=True)
                logMessage += f'- **URL SHA-256 Hash:** `{hashlib.sha256(finalURL.encode()).hexdigest()}`\n'
            except URLRedirectSafetyError as error:
                print(error)
                redirectPath = error.redirectPath
                if len(redirectPath) > 1:
                    fullPath = ' -> '.join(redirectPath)
                    logMessage += (f'- **URL Redirect Path (Public Only):**\n'
                                   f'```commandline\n'
                                   f'{fullPath}\n'
                                   f'```\n'
                                   f'- **Final Destination Path:** `{redirectPath[-1]}`\n')
                logMessage += (f'- **Inspection Result:** `MALICIOUS`\n'
                               f'- **Reason:** `{error}`\n')
                sendMessage = CyberbotURLScanMessageFormat(redirectPath, str(error), 'MALICIOUS', url)
                try:
                    await message.reply(sendMessage)
                    await message.delete()
                except discord.errors.HTTPException:
                    await message.channel.send(sendMessage)
                raise TerminateURLScan
            except URLRedirectInspectionError as error:
                print(error)
                redirectPath = error.redirectPath
                if len(redirectPath) > 1:
                    fullPath = ' -> '.join(redirectPath)
                    logMessage += (f'- **URL Redirect Path (Public Only):**\n'
                                   f'```commandline\n'
                                   f'{fullPath}\n'
                                   f'```\n'
                                   f'- **Final Destination Path:** `{redirectPath[-1]}`\n')
                logMessage += (f'- **Inspection Result:** `UNVERIFIED`\n'
                               f'- **Reason:** `{error}`\n')
                if not silent:
                    sendMessage = CyberbotURLScanMessageFormat(redirectPath, str(error), 'UNVERIFIED', url)
                    try:
                        await message.reply(sendMessage)
                    except discord.errors.HTTPException:
                        await message.channel.send(sendMessage)
                raise TerminateURLScan

            """Validate Klipy GIF URLs directly through the Klipy API"""
            if finalURL.startswith('https://klipy.com/gifs/'):
                gifValidation = await isKlipyURLValid(finalURL)
                gifHash = hashlib.sha256(finalURL.encode('utf-8')).hexdigest()
                if gifValidation:
                    print(f'Kliphy GIF URL is valid!')
                    status = 'CLEAN'
                    reason = f'The Kliphy Gif URL {finalURL} successfully authenticated with their official provider.'
                    await AddingHashedData(gifHash, '.gif', False)

                else:
                    print(f'Kliphy URL is invalid!')
                    status = 'MALICIOUS'
                    reason = f'The Kliphy URL {finalURL} is not a valid URL due to failure to authenticate with Kliphy official API!'
                    await AddingHashedData(gifHash, '.gif', True)

                if (gifValidation and not silent) or not gifValidation:
                    sendMessage = CyberbotURLScanMessageFormat([], reason, status, finalURL)
                    try:
                        await message.reply(sendMessage)
                        if not gifValidation:
                            await message.delete()
                    except discord.errors.HTTPException:
                        await message.channel.send(sendMessage)

                logMessage += (f"- **Inspection Result:** `{status}`\n"
                               f"- **Reason:** `{reason}`\n")

                raise TerminateURLScan
            else:
                """URL access validation"""
                parts = urlsplit(finalURL)
                if parts.scheme not in ('http', 'https') or not parts.hostname:
                    logMessage += (f"- **Inspection Result:** `UNVERIFIED`\n"
                                   f"- **Reason:** `The Final Destination URL Use Unsupported Web Protocol '{parts.scheme}' OR Have no valid hostname!`\n")
                    continue
                if parts.hostname.lower() == 'cdn.discordapp.com' and parts.port in (None, 443) and parts.username is None and parts.path.startswith('/attachments/'):
                    print('URL is a Discord attachment!!! Will scan URL as an attachment file!')
                    fileAttachmentUrls[finalURL] = unquote(os.path.basename(parts.path))
                    logMessage += (f"- **Inspection Result:** `NEED FURTHER SCANNING`\n"
                                   f"- **Reason:** `URL is a Discord attachment! Will scan URL as an attachment file!`\n")
                else:
                    resolvedUrls.append(finalURL)
                    logMessage += (f"- **Inspection Result:** `SAFE TO SCAN VIA VIRUS TOTAL`\n"
                                   f"- **Reason:** `URL hostname, IP addresses, and final destination are valid and safe to begin VirusTotal scan!`\n")
            print(f"URL inspection duration: {time.perf_counter() - UrlInspectionStartTime:.2f}s")
            logMessage += f"- **Inspection Duration In Second(s):** {time.perf_counter() - UrlInspectionStartTime:.2f}s\n"
            logMessage += "\n---\n\n"
    except TerminateURLScan:
        print(f"URL inspection duration: {time.perf_counter() - UrlInspectionStartTime:.2f}s")
        logMessage += f"- **Inspection Duration In Second(s):** {time.perf_counter() - UrlInspectionStartTime:.2f}s\n\n---\n\n"
        return [], {}, logMessage, False
    return resolvedUrls, fileAttachmentUrls, logMessage, True