from __future__ import annotations

from CyberBotRuntimeModule import *
from CyberBotFileUtilitiesModule import checkingHashFromDisk

async def VirusTotalRequestJSON(method: str, url: str, **kwargs) -> tuple[int, dict]:
    headers = {
        "x-apikey": virusTotalApiKey,
        "accept": "application/json",
    }
    headers.update(kwargs.pop("headers", {}))
    filePath = kwargs.pop("filePath", None)
    for attempt in range(3):
        try:
            # File and URL scans can be request at the same time
            async with VIRUSTOTAL_SEMAPHORE:
                if filePath is not None:
                    # Stream file objects without a full RAM copy.
                    with open(filePath, "rb") as file:
                        form = aiohttp.FormData()
                        form.add_field("file", file, filename=os.path.basename(filePath))
                        async with Cyberbot.session.request(method, url, headers=headers, data=form) as response:
                            status = response.status
                            retryAfter = response.headers.get("Retry-After")
                            try:
                                data = await response.json(content_type=None)
                            except (aiohttp.ContentTypeError, ValueError):
                                data = {}
                else:
                    async with Cyberbot.session.request(method, url, headers=headers, **kwargs) as response:
                        status = response.status
                        retryAfter = response.headers.get("Retry-After")
                        try:
                            data = await response.json(content_type=None)
                        except (aiohttp.ContentTypeError, ValueError):
                            data = {}
            if status not in (429, 500, 502, 503, 504):
                return status, data
            try:
                retryDelay = min(60, max(1, int(retryAfter))) if retryAfter else 2 ** (attempt + 1)
            except ValueError:
                retryDelay = 2 ** (attempt + 1)
            print(f"[Virus Total] Rate Limit. Retry after {retryAfter} seconds.")
            await asyncio.sleep(retryDelay)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as error:
            print(f"[Virus Total] API request failed (attempt {attempt + 1}): {error}")
            if attempt != 2:
                await asyncio.sleep(2 ** (attempt + 1))
    return 0, {}


async def virusTotalURLScan(url: str) -> str:
    """
    Description: Performing URL scan via Virus Total API
    :param url: URL to be analyzed
    :return: Virus Total Analysis Result
    """
    HostUrl = "https://www.virustotal.com/api/v3/urls"
    sha256 = hashlib.sha256(url.encode()).hexdigest()
    print("[Virus Total] Checking any existing past analysis based on the URL SHA-256 hash...")
    status, previousAnalysisData = await VirusTotalRequestJSON("GET", f"{HostUrl}/{sha256}")
    if status == 200:
        try:
            stats = previousAnalysisData["data"]["attributes"]["last_analysis_stats"]
            print("[Virus Total] Past analysis for the URL SHA-256 hash found!")
            return f"Malicious counted:{stats['malicious']}"
        except (KeyError, TypeError):
            print("[Virus Total] Error getting previous analysis data!")
            pass

    print("[Virus Total] No existing past analysis based on the URL SHA-256 hash found! Proceeding to submit the URL content for scan...")
    status, data = await VirusTotalRequestJSON("POST", HostUrl, data={"url": url})
    if status not in (200, 202):
        print("[Virus Total] Error getting Analysis ID")
        return "URL can't be scanned!"
    try:
        scanID = data["data"]["id"]
    except (KeyError, TypeError):
        print("[Virus Total] Error getting Analysis ID")
        return "URL can't be scanned!"

    AnalysisUrl = f"https://www.virustotal.com/api/v3/analyses/{scanID}"

    for attempt in range(15):
        status, analysis = await VirusTotalRequestJSON("GET", AnalysisUrl)
        if status != 200:
            print("[Virus Total] Error getting Analysis Results")
            return "URL can't be scanned!"
        try:
            status = analysis["data"]["attributes"]["status"]
            if status == "completed":
                print(f"[Virus Total] Malicious counted:{analysis["data"]["attributes"]["stats"]['malicious']}")
                return f"Malicious counted:{analysis["data"]["attributes"]["stats"]['malicious']}"
        except (KeyError, TypeError):
            print("[Virus Total] Error getting Analysis Status")
            return "URL can't be scanned!"
        print(f"[Virus Total] Scan for {url} not finished yet (status={status}), retrying in 15s...")
        await asyncio.sleep(15)
    print(f"[Virus Total] Scan for {url} took too long!")
    return "URL scan too long!"


async def virusTotalFileScan(filePath: str) -> str:
    """
    Description: Performing file scan via Virus Total API
    :param filePath: Path to the file to be analyzed
    :return: Virus Total Analysis Result
    """
    HostUrl = "https://www.virustotal.com/api/v3/files"
    sha256 = await checkingHashFromDisk(filePath)
    print("[Virus Total] Checking any existing past analysis based on the file SHA-256 hash...")
    status, previousAnalysisData = await VirusTotalRequestJSON("GET", f"{HostUrl}/{sha256}")
    if status == 200:
        try:
            stats = previousAnalysisData["data"]["attributes"]["last_analysis_stats"]
            print(
                f"[Virus Total] Scan complete for {filePath}: "
                f"{stats['malicious']} malicious, {stats['suspicious']} suspicious, "
                f"{stats['harmless']} harmless, {stats['undetected']} undetected."
            )
            malicious = stats["malicious"] if stats["malicious"] else 0
            suspicious = stats['suspicious'] if stats['suspicious'] else 0
            harmless = stats['harmless'] if stats['harmless'] else 0
            undetected = stats['undetected'] if stats['undetected'] else 0
            print("[Virus Total] Past analysis for the file SHA-256 hash found!")
            return f"{malicious}:{suspicious}:{harmless}:{undetected}"
        except (KeyError, TypeError):
            print("[Virus Total] Error getting previous analysis data!")
            pass

    print("[Virus Total] No existing past analysis based on the file SHA-256 hash found! Proceeding to upload file content for scan...")
    UploadUrl = HostUrl
    if os.path.getsize(filePath) > 32000000:
        status, uploadData = await VirusTotalRequestJSON("GET", f"{HostUrl}/upload_url")
        if status != 200:
            print("[Virus Total] Error uploading file for analysis!")
            return "Error uploading file for analysis!"
        try:
            UploadUrl = uploadData["data"]
        except (KeyError, TypeError):
            print("[Virus Total] Error retrieving file upload URL for analysis!")
            return "Error retrieving file upload URL!"
        if not isinstance(UploadUrl, str) or not UploadUrl.startswith(("https://", "http://")):
            print("[Virus Total] Error retrieving file upload URL for analysis!")
            return "Error retrieving file upload URL!"

    status, data = await VirusTotalRequestJSON("POST", UploadUrl, filePath=filePath)
    if status not in (200, 202):
        print("[Virus Total] Error getting Analysis ID")
        return "Error getting file analysis ID!"
    try:
        analysisId = data["data"]["id"]
    except (KeyError, TypeError):
        print("[Virus Total] Error getting Analysis ID")
        return "Error getting file analysis ID!"

    AnalysisUrl = f"https://www.virustotal.com/api/v3/analyses/{analysisId}"
    for attempt in range(15):
        status, analysis = await VirusTotalRequestJSON("GET", AnalysisUrl)
        if status != 200:
            print("[Virus Total] Error getting Analysis Results")
            return "Error getting file analysis results!"
        try:
            status = analysis["data"]["attributes"]["status"]
            if status == "completed":
                stats = analysis["data"]["attributes"]["stats"]
                print(
                    f"[Virus Total] Scan complete for {filePath}: "
                    f"{stats['malicious']} malicious, {stats['suspicious']} suspicious, "
                    f"{stats['harmless']} harmless, {stats['undetected']} undetected."
                )
                malicious = stats["malicious"] if stats["malicious"] else 0
                suspicious = stats['suspicious'] if stats['suspicious'] else 0
                harmless = stats['harmless'] if stats['harmless'] else 0
                undetected = stats['undetected'] if stats['undetected'] else 0
                return f"{malicious}:{suspicious}:{harmless}:{undetected}"
            print(f"[Virus Total] Scan for file {os.path.basename(filePath)} not finished yet (status={status}), retrying in {15}s...")
            await asyncio.sleep(15)
        except (KeyError, TypeError):
            print("[Virus Total] Error getting Analysis Status")
            return "Error getting file analysis status!"
    print(f"[Virus Total] Scan operation for file {os.path.basename(filePath)} has taken too long!")
    return "Error - File scan too long!"
