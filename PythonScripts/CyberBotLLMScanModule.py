from __future__ import annotations

from CyberBotRuntimeModule import *
from CyberBotAnalyticsModule import calculateUsageCost


SYSTEM_INSTRUCTION = "You are an expert reverse engineer analyzing a decompiled binary file with Ghidra for static analysis"
PROMPT = (f"# ASK:\n"
          f"Reads the source/script file contents and decides if it is a malware exhibits any malicious pattern.\n"
          f"# RESPONSE FORMAT:\n"
          f"If you suspect it is malware, **START** the response with **True** or **False** with **NO BOLD** and **NO ITALIC STYLE** and **EXPLAIN WHY!**")


def _segmentPDFToBase64(PDFReader: PdfReader, PDFPageCount: int, pagesPerSegment: int = 200) -> dict:
    """
    Description: Segment a PDF into smaller PDF documents and convert them to Base64
    :param PDFReader: The PdfReader object of the original PDF file
    :param PDFPageCount: The total number of pages of the original PDF file
    :param pagesPerSegment: Number of pages per segment
    :return: Base64 data string of each PDF segments
    """
    PDFBase64Datas = {}
    try:
        for startPage in range(0, PDFPageCount, pagesPerSegment):
            endPage = min(startPage + pagesPerSegment, PDFPageCount)
            PDFWriter = PdfWriter()
            for pageIndex in range(startPage, endPage):
                PDFWriter.add_page(PDFReader.pages[pageIndex])
            with io.BytesIO() as PDFBuffer:
                PDFWriter.write(PDFBuffer)
                PDFSegmentBytes = PDFBuffer.getvalue()
            PDFSegmentBase64 = base64.b64encode(PDFSegmentBytes).decode("ascii")
            PDFBase64Datas[f"Pages {startPage + 1} to {endPage}"] = PDFSegmentBase64
            print(f"Successfully obtained Base64 data for PDF pages {startPage + 1} to {endPage}")
        PDFSegmentBase64 = None
        PDFSegmentBase64 = None
        return PDFBase64Datas
    except Exception as e:
        print(f"Encountering error while segmenting the PDF pages: {e}")
        return {}


async def llmSCAT(model: str, pdfPath: str, logMessage: str) -> Tuple[str, str]:
    """
    Description: Static Code Analysis on PDF file that contains the decompiled script with OpenAI or Gemini
    :param model: The name of the model
    :param pdfPath: The PDF filepath of the file to analyze
    :param logMessage: Current Log Message
    :return: The analysis results and the updated log message
    """
    logMessage += (f"- **Begin SCAT Analysis With {model}**\n"
                   f"- **PDF File:** `{os.path.basename(pdfPath)}`\n")

    print(f"[{model} SCAT Analysis] Checking PDF file size and page count...")
    PDFsize = await asyncio.to_thread(os.path.getsize, pdfPath)
    PDFReader = await asyncio.to_thread(PdfReader, pdfPath, strict=False)
    PDFPageCount = len(PDFReader.pages)
    logMessage += (f"- **PDF Inspection Result**\n"
                   f"\t+ **PDF Size:** `{PDFsize:,} bytes`\n"
                   f"\t+ **Total Pages:** `{PDFPageCount:,} pages`\n")
    print(f"[{model} SCAT Analysis] PDF Size: {PDFsize:,} bytes | Total Pages: {PDFPageCount:,} pages\n")

    async with aiofiles.open(pdfPath, "rb") as PDFfile:
        PDFBase64Data = (await asyncio.to_thread(base64.b64encode, await PDFfile.read())).decode('utf-8')
        await PDFfile.seek(0)
        PDFBytes = await PDFfile.read()
    segmentPdf = False

    if PDFsize > 50_000_000:
        print(f"[{model} SCAT Analysis] PDF file size exceeds 50 MB, will scan by segments!")
        logMessage += f"- **PDF File Size Exceeds 50 MB**\n"
        segmentPdf = True

    if model.startswith("gemini") and PDFPageCount > 1000:
        print(f"[{model} SCAT Analysis] PDF page count exceeds 1000 pages, will scan by segments!")
        logMessage += f"- **PDF File Page Count Exceeds 1000 pages**\n"
        segmentPdf = True

    if not segmentPdf:
        if model.startswith("gpt"):
            inputPromptTokenCount = (await OPENAI_LLM_ENGINE.responses.input_tokens.count(model=model, instructions=SYSTEM_INSTRUCTION, input=[{"role": "user", "content": [{"type": "input_file", "filename": f"{uuid.uuid4().hex[0:5]}.pdf", "file_data": f"data:application/pdf;base64,{PDFBase64Data}"}, {"type": "input_text", "text": PROMPT}]}])).input_tokens
        else:
            inputPromptTokenCount = (await GEMINI_LLM_ENGINE.aio.models.count_tokens(model=model, contents=types.Content(role="user", parts=[types.Part.from_bytes(data=PDFBytes, mime_type="application/pdf"), types.Part.from_text(text=f"{SYSTEM_INSTRUCTION}\n{PROMPT}")]))).total_tokens
        logMessage += f"- **{model} pre-inspect input token count:** `{inputPromptTokenCount:,} tokens`\n"
        print(f"[{model} SCAT Analysis] pre-inspect Input token count: {inputPromptTokenCount:,} tokens\n")
        if inputPromptTokenCount > LLM_MODEL_INFORMATION[model]["Maximum Input Tokens"]:
            segmentPdf = True
            print(f"[{model} SCAT Analysis] Input token will exceed {model} context windows, will scan by segments!")
            logMessage += f"- **Input Token Exceed {model} Context Window**\n"
    else:
        inputPromptTokenCount = 0
    PDFBytes = None # Empty file content in RAM to free up resources

    if segmentPdf:
        print(f"[{model} SCAT Analysis] Begin finding the most optimized PDF segment value for {model}")
        logMessage += f"- **Finding the optimized PDF segment value for {model}**"
        segmentSize = PDFsize
        pageSegment = PDFPageCount
        contextWindowLimit = LLM_MODEL_INFORMATION[model][ "Maximum Input Tokens"]
        while inputPromptTokenCount >= contextWindowLimit or segmentSize > 50000000 or (model.startswith("gemini") and pageSegment > 1000):
            pageSegment = math.floor(pageSegment * 0.9)
            print(f"Testing PDF segment value of {pageSegment} pages")
            logMessage += f"\t + **Testing Input Token Count For Segment Value {pageSegment}**\n"
            PDFWriter = PdfWriter()
            for pageIndex in range(0, pageSegment):
                PDFWriter.add_page(PDFReader.pages[pageIndex])
            with io.BytesIO() as PDFBuffer:
                PDFWriter.write(PDFBuffer)
                PDFSegmentBytes = PDFBuffer.getvalue()
            segmentSize = len(PDFSegmentBytes)
            PDFSegmentBase64 = (await asyncio.to_thread(base64.b64encode, PDFSegmentBytes)).decode("utf-8")
            if model.startswith("gpt"):
                inputPromptTokenCount = (await OPENAI_LLM_ENGINE.responses.input_tokens.count(model=model, instructions=SYSTEM_INSTRUCTION, input=[{"role": "user", "content": [{"type": "input_file", "filename": f"{uuid.uuid4().hex[0:5]}.pdf", "file_data": f"data:application/pdf;base64,{PDFSegmentBase64}"}, {"type": "input_text", "text": PROMPT}]}])).input_tokens
            else:
                inputPromptTokenCount = (await GEMINI_LLM_ENGINE.aio.models.count_tokens(model=model, contents=types.Content(role="user", parts=[types.Part.from_bytes(data=PDFSegmentBytes, mime_type="application/pdf"), types.Part.from_text(text=f"{SYSTEM_INSTRUCTION}\n{PROMPT}")]))).total_tokens
            print(f"[{model} SCAT Analysis] Input Token Count For The Segment Value: {inputPromptTokenCount:,} tokens")
            print(f"[{model} SCAT Analysis] Total Size For The Segment Value: {segmentSize:,} bytes")
            logMessage += (f"\t\t + **Total Input Token Count:** `{inputPromptTokenCount:,}`\n"
                           f"\t\t + **Total Size:** `{segmentSize:,} bytes`\n")
            PDFSegmentBytes = None
            PDFSegmentBase64 = None
        print(f"[{model} SCAT Analysis] The optimal PDF segment value is: {pageSegment}")
        logMessage += f"\t + **Optimal PDF segment value is:** {pageSegment:,}\n"
        PDFBase64Datas = asyncio.to_thread(_segmentPDFToBase64, PDFReader, PDFPageCount, pageSegment)
    else:
        PDFBase64Datas = {"Full PDF Pages": PDFBase64Data}

    print(f"[{model} SCAT Analysis] Start scanning PDF frames with LLM model {model}")
    ScanResult = ""
    for segment, PDFBase64Data in PDFBase64Datas.items():
        print(f"[{model} SCAT Analysis] Scanning PDF segment: {segment}")
        logMessage += f"\t\t + **PDF Segment: {segment}**\n"
        for retryAttempt in range(0, 3):
            print(f"[{model} SCAT Analysis] Attempt #{retryAttempt + 1}")
            logMessage += f"\t\t + **{model} request attempt:** `{retryAttempt + 1}`\n"
            if model.startswith("gpt"):
                requestQuery = [{"role": "user", "content": [{"type": "input_file", "filename": f"{uuid.uuid4().hex[0:5]}.pdf", "file_data": f"data:application/pdf;base64,{PDFBase64Data}"}, {"type": "input_text", "text": PROMPT}]}]
            else:
                requestQuery = [{"type": "document", "data": PDFBase64Data, "mime_type": "application/pdf"}, {"type": "text", "text": PROMPT}]

            try:
                if model.startswith("gpt"):
                    # https://developers.openai.com/api/reference/resources/responses/methods/create/
                    response = await OPENAI_LLM_ENGINE.responses.create(model=model, instructions=SYSTEM_INSTRUCTION, input=requestQuery, max_output_tokens=2000, reasoning={"effort": "xhigh"}, store=True)
                    print(f"[{model} SCAT Analysis] Input Tokens: {response.usage.input_tokens}")
                    print(f"[{model} SCAT Analysis] Output Tokens: {response.usage.output_tokens}")
                    logMessage += (f"\t\t\t + **Input Token Count:** `{response.usage.input_tokens:,} tokens`\n"
                                   f"\t\t\t + **Output Token Count:** `{response.usage.output_tokens:,} tokens`\n")
                else:
                    # https://aistudio.google.com/api-reference/interactions-api/create-interaction
                    response = await GEMINI_LLM_ENGINE.aio.interactions.create(model=model, input=requestQuery, system_instruction=SYSTEM_INSTRUCTION, generation_config={"thinking_level": "high", "max_output_tokens": 2000}, store=True)
                    print(f"[{model} SCAT Analysis] Input Tokens: {response.usage.total_input_tokens}")
                    print(f"[{model} SCAT Analysis] Output Tokens: {response.usage.total_output_tokens}")
                    logMessage += (f"\t\t\t + **Input Token Count:** `{response.usage.total_input_tokens:,} tokens`\n"
                                   f"\t\t\t + **Output Token Count:** `{response.usage.total_output_tokens:,} tokens`\n")
                ScanResult = response.output_text
                print(f"[{model} SCAT Analysis] SCAT scan results: {ScanResult}")
                totalCost = await calculateUsageCost(model, response)
                print(f"[{model} SCAT Analysis] Total Cost: ${totalCost}")
                logMessage += f"\t\t\t + **Total Cost:** `${totalCost}`\n"
                logMessage += f"\t\t\t + **SCAT Results:** `{ScanResult}`\n"
                if ScanResult.startswith(("True", "true")):
                    return ScanResult, logMessage
                break

            except (openai.RateLimitError, openai.APITimeoutError) as Error:
                print(f"[{model} SCAT Analysis] Rate Limit/API Timeout Error: {Error}, attempt retry {retryAttempt + 1} in 15 seconds")
                logMessage += f"\t\t\t + **Rate Limit Error:** `{Error}`\n"
                await asyncio.sleep(15)

            except openai.BadRequestError as BadRequestError:
                print(f"[{model} SCAT Analysis] Bad Request Error: {BadRequestError}")
                logMessage += f"\t\t\t + **Bad Request Error:** `{BadRequestError}`\n"
                return f"ERROR::{BadRequestError}", logMessage

            except ConnectTimeout as e:
                print(f"[{model} SCAT Analysis] API Timeout Error: {e}, attempt retry {retryAttempt + 1} in 15 seconds")
                logMessage += f"\t\t\t + **Time Out Error:** `{e}`\n"
                await asyncio.sleep(15)

            except errors.APIError as GeminiAPIError:
                if GeminiAPIError.code == 429:
                    print(f"[{model} SCAT Analysis] Rate Limit Error: {GeminiAPIError.message}, attempt retry {retryAttempt + 1} in 15 seconds")
                    logMessage += f"\t\t\t + **Rate Limit Error:** `{GeminiAPIError.message}`\n"
                    await asyncio.sleep(15)
                else:
                    print(f"[{model} SCAT Analysis] Error: {GeminiAPIError.message}")
                    logMessage += f"\t\t\t + **LLM Request Error:** `{GeminiAPIError.message}`\n"
                    return f"ERROR::{GeminiAPIError.message}", logMessage

            except Exception as e:
                print(f"[{model} SCAT Analysis] Receive Error: {e}")
                logMessage += f"\t\t\t + **LLM Request Error:** `{e}`\n"
                return f"ERROR::{e}", logMessage

        if not ScanResult:
            print(f"Too Many Retry Attempts!")
            logMessage += f"\t\t\t + **Too Many Retry Attempts!**\n"
            return f"ERROR::TOO MANY RETRIES!", logMessage

    return "Nothing Malicious", logMessage # Return the last scan result


async def llmSCATOnText(model: str, filepath: str, logMessage: str) -> Tuple[str, str]:
    """
    Description: Static Code Analysis on the raw code content of the decompiled script with OpenAI and Gemini
    :param model: The name of the model
    :param filepath: The filepath to be analyzed
    :param logMessage: Current Log Message
    :param LLM: Which LLM provider to use
    :return: The result of the analysis and the updated log message
    """
    logMessage += (f"- **Begin SCAT Analysis With {model}**\n"
                   f"- **Decompiled File:** `{os.path.basename(filepath)}`\n")
    async with aiofiles.open(filepath, "r") as file:
        content = await file.readlines()

    contextWindow = LLM_MODEL_INFORMATION[model]["Maximum Input Tokens"]
    inputPromptTokenCount = 100000000000
    chunkSize = len(content)
    while inputPromptTokenCount > contextWindow - 4000:
        if model.startswith("gpt"):
            inputPromptTokenCount = (await OPENAI_LLM_ENGINE.responses.input_tokens.count(model=model, instructions=SYSTEM_INSTRUCTION, input=[{"role": "user", "content": [{"type": "input_text", "text": "".join(content[0:chunkSize])}]}])).input_tokens
        else:
            inputPromptTokenCount = (await GEMINI_LLM_ENGINE.aio.models.count_tokens(model=model, contents="".join(content[0:chunkSize]))).total_tokens
        chunkSize = math.floor(chunkSize * 0.9)

    summarization = ""
    for i in range(0, len(content), chunkSize):
        nextChunkSize = min(i + chunkSize, len(content))
        if i == 0:
            prompt = ("# Context\n"
                      "Below is a snippet of a large binary file decompiled by Ghidra (via Ghidhrathon)\n"
                      f"The snippet starts at **Line {i + 1}** to **Line {nextChunkSize}**\n"
                      f"```\n"
                      f"{"".join(content[i:i + chunkSize])}\n"
                      f"```\n"
                      f"# Ask\n"
                      f"Reads the source/script of the snippet and decides if it is a malware exhibits any malicious pattern.\n"
                      f"# RESPONSE FORMAT:\n"
                      f"If you suspect it is malware, **START** the response with **True** or **False** with **NO BOLD** and **NO ITALIC STYLE** and **EXPLAIN WHY!**")
        else:
            prompt = ("# Context\n"
                      "The following are the analysis summarization of a snippet of a large binary file decompiled by Ghidra (via Ghidhrathon)\n"
                      f"The snippet starts at **Line {i - chunkSize + 1}** to **Line {i}**\n"
                      f"# Analysis Summarization\n"
                      f"```\n"
                      f"{summarization}\n"
                      f"```\n"
                      f"# Ask\n"
                      f"Continue analyze the next snippet of the same file starts at **Line {i + 1}** to **Line {nextChunkSize}** and decides if it is a malware exhibits any malicious pattern. Please use the previous analysis summarization for contextual reference.\n"
                      f"```\n"
                      f"{"".join(content[i:i + chunkSize])}\n"
                      f"```\n"
                      f"# RESPONSE FORMAT:\n"
                      f"If you suspect it is malware, **START** the response with **True** or **False** with **NO BOLD** and **NO ITALIC STYLE** and **EXPLAIN WHY!**")

        logMessage += f"- **Partial {model} SCAT from Line {i + 1} to Line {i + chunkSize}:**\n"
        textResponse = ""
        for retryAttempt in range(1, 4):
            print(f"[{model} SCAT Analysis] Request Attempt {retryAttempt}")
            logMessage += f"\t- **Request Attempt {retryAttempt}**\n"
            try:
                if model.startswith("gpt"):
                    response = await OPENAI_LLM_ENGINE.responses.create(model=model, instructions=SYSTEM_INSTRUCTION, input=[{"role": "user", "content": [{"type": "input_text", "text": prompt}]}], reasoning={"effort": "xhigh"}, max_output_tokens=2000, store=True)
                    totalInputTokens = response.usage.input_tokens
                    totalOutputTokens = response.usage.output_tokens
                else:
                    response = await GEMINI_LLM_ENGINE.aio.interactions.create(model=model, input=prompt, system_instruction=SYSTEM_INSTRUCTION, generation_config={"thinking_level": "high", "max_output_tokens": 2000}, store=True)
                    totalInputTokens = response.usage.total_input_tokens
                    totalOutputTokens = response.usage.total_output_tokens
                totalCost = await calculateUsageCost(model, response)
                textResponse = response.output_text
                print(f"[{model} SCAT Analysis] SCAT analysis from line {i + 1} to line {nextChunkSize}")
                print(f"[{model} SCAT Analysis] Total Input Tokens: {totalInputTokens:,}")
                print(f"[{model} SCAT Analysis] Total Output Tokens: {totalOutputTokens:,}")
                print(f"[{model} SCAT Analysis] Total Cost: ${totalCost}")
                print(f"[{model} SCAT Analysis] Analysis Result: {textResponse}")
                logMessage += (f"\t+ **Total Input Tokens Count:** `{totalInputTokens:,} tokens`\n"
                               f"\t+ **Total Output Tokens Count:** `{totalOutputTokens:,} tokens`\n"
                               f"\t+ **Total Cost:** `${totalCost}`\n"
                               f"\t+ **SCAT Result:**\n{textResponse}\n")
                if textResponse.startswith(("True", "true")):
                    print(f"[{model} SCAT Analysis] Partial Analysis at line ** {i + 1} to {nextChunkSize} flagged malicious!!!")
                    return textResponse, logMessage
                summarization = textResponse
                break

            except (openai.RateLimitError, openai.APITimeoutError) as Error:
                print(f"[{model} SCAT Analysis] Rate Limit/API Timeout Error: {Error}, attempt retry {retryAttempt + 2} in 15 seconds")
                logMessage += f"\t + **Rate Limit Error:** `{Error}`\n"
                await asyncio.sleep(15)

            except openai.BadRequestError as BadRequestError:
                print(f"[{model} SCAT Analysis] Bad Request Error: {BadRequestError}")
                logMessage += f"\t + **Bad Request Error:** `{BadRequestError}`\n"
                return f"ERROR::{BadRequestError}", logMessage

            except ConnectTimeout as e:
                print(f"[{model} SCAT Analysis] API Timeout Error: {e}, attempt retry {retryAttempt + 1} in 15 seconds")
                logMessage += f"\t + **Time Out Error:** `{e}`\n"
                await asyncio.sleep(15)

            except errors.APIError as GeminiAPIError:
                if GeminiAPIError.code == 429:
                    print(f"[{model} SCAT Analysis] Rate Limit Error: {GeminiAPIError.message}, attempt retry {retryAttempt + 1} in 15 seconds")
                    logMessage += f"\t + **Rate Limit Error:** `{GeminiAPIError.message}`\n"
                    await asyncio.sleep(15)
                else:
                    print(f"[{model} SCAT Analysis] Error: {GeminiAPIError.message}")
                    logMessage += f"\t + **LLM Request Error:** `{GeminiAPIError.message}`\n"
                    return f"ERROR::{GeminiAPIError.message}", logMessage

            except Exception as e:
                print(f"[{model} SCAT Analysis] Receive Error: {e}")
                logMessage += f"\t + **LLM Request Error:** `{e}`\n"
                return f"ERROR::{e}", logMessage

        if not textResponse:
            print(f"Too Many Retry Attempts!")
            logMessage += f"\t + **Too Many Retry Attempts!**\n"
            return f"ERROR::TOO MANY RETRIES!", logMessage

    return "Nothing Malicious", logMessage
