from __future__ import annotations

from CyberBotRuntimeModule import *
from CyberBotFileUtilitiesModule import hashedScanLock
from CyberBotHashDatabaseModule import addingHashedData, checkingCleanData, checkingFlaggedMaliciousData
from CyberBotVirusTotalModule import virusTotalURLScan

async def scanOneURL(url: str,) -> URLScanResult:
    """Scan URLs concurrently, isolate results and avoid duplicate hash work."""

    async with URL_SCAN_SEMAPHORE:
        UrlScanStartTime = time.perf_counter()
        logMessage = f"- **URL:** `{url}`\n"
        try:
            hashedUrl = hashlib.sha256(url.encode("utf-8")).hexdigest()
            async with hashedScanLock("url:" + hashedUrl):
                """Checking URL SHA256 hash"""
                if await checkingFlaggedMaliciousData(hashedUrl, "URLs"):
                    print(f"URL {url} already recorded as malicious!")
                    logMessage += (f"- **Scan Result:** `MALICIOUS`\n"
                                   f"- **Reason:** `URL already recorded as malicious!`\n")
                    ScanResult = URLScanResult(url, "malicious", CyberbotURLScanMessageFormat([], "URL is already recorded as malicious!", "MALICIOUS", url), logMessage)
                    raise TerminateURLScan
                if await checkingCleanData(hashedUrl, "URLs"):
                    print(f"URL {url} has already been scanned as safe to visit.")
                    logMessage += (f"- **Scan Result:** `CLEAN`\n"
                                   f"- **Reason:** `URL has already been scanned as safe to visit.`\n")
                    ScanResult = URLScanResult(url, "clean", CyberbotURLScanMessageFormat([], "URL has already been scanned as safe to visit", "CLEAN", url), logMessage)
                    raise TerminateURLScan
                """VirusTotal URL scan"""
                VirusTotalURLScanResult = await virusTotalURLScan(url)
                if VirusTotalURLScanResult in ("URL can't be scanned!", "URL scan too long!"):
                    logMessage += (f"- **Scan Result:** `UNVERIFIED`\n"
                                   f"- **Reason:** `{VirusTotalURLScanResult}`\n")
                    ScanResult = URLScanResult(url, "unverified", CyberbotURLScanMessageFormat([], VirusTotalURLScanResult, "UNVERIFIED", url), logMessage)
                else:
                    try:
                        VirusTotalURLScanResult = int(VirusTotalURLScanResult.split(":")[1])
                    except (IndexError, ValueError):
                        print(f"URL {url} returned an invalid VirusTotal result.")
                        logMessage += (f"- **Scan Result:** `UNVERIFIED`\n"
                                       f"- **Reason:** `URL returned an invalid VirusTotal result.`\n")
                        ScanResult = URLScanResult(url, "unverified", CyberbotURLScanMessageFormat([], "Virus Total scan status as UNVERIFIED", "UNVERIFIED", url), logMessage)
                        raise TerminateURLScan
                    if VirusTotalURLScanResult > 0:
                        print(f"URL {url} was flagged malicious by Virus Total!")
                        await addingHashedData(hashedUrl, "URLs", True)
                        logMessage += (f"- **Scan Result:** `MALICIOUS`\n"
                                       f"- **Reason:** `{VirusTotalURLScanResult} scan engines through VirusTotal flagged the URL as malicious!`\n")
                        ScanResult = URLScanResult(url, "malicious", CyberbotURLScanMessageFormat([], f"{VirusTotalURLScanResult} scan engines through Virus Total flagged the URL as malicious!", "MALICIOUS", url), logMessage)
                    else:
                        print(f"URL {url} passed VirusTotal scanning.")
                        await addingHashedData(hashedUrl, "URLs", False)
                        logMessage += (f"- **Scan Result:** `CLEAN`\n"
                                       f"- **Reason:** `URL passed VirusTotal scanning.`\n")
                        ScanResult = URLScanResult(url, "clean",CyberbotURLScanMessageFormat([], f"URL passed VirusTotal scanning.", "CLEAN", url), logMessage)
        except TerminateURLScan:
            pass
        finally:
            print(f"URL scan duration: {time.perf_counter() - UrlScanStartTime:.2f}s")
            ScanResult.logMessage += f"- **Scan Duration In Second(s):** {time.perf_counter() - UrlScanStartTime:.2f}s\n\n---\n\n"
        return ScanResult
