from __future__ import annotations

import os.path

from CyberBotRuntimeModule import *
from CyberBotAnalyticsModule import calculateUsageCost, writingLLMUsageCsv

async def openAISCAT(filepath: str, logMessage: str, retryCount: int = 1) -> Tuple[str, str]:
    """
    Description: Static Code Analysis on a script of a decompiled file with OpenAI Codex
    :param filepath: The filepath of the file to analyze
    :param logMessage: Current Log Message
    :param retryCount: The number of current retries API call
    :return: The analysis results from OpenAI
    """
    print(f"[Open AI SCAT Model {GPT_MODEL}] API call attempt {retryCount}...")
    logMessage += (f"- **Begin SCAT Analysis With {GPT_MODEL}**\n"
                   f"- **File:** `{os.path.basename(filepath)}`\n")
    if retryCount == 3:
        print(f"[Open AI SCAT Model {GPT_MODEL}] Too many attempts, return inconclusive scan!")
        logMessage += f"- **{GPT_MODEL} SCAT Result:** `Too many retry attempts, inconclusive scan!`\n"
        return "TOO MANY RETRY ATTEMPTS", logMessage
    async with aiofiles.open(filepath, "rb") as PDFfile:
        fileResponse = await GPTclient.files.create(file=(f"{uuid.uuid4().hex}.pdf", await PDFfile.read()), purpose="assistants")
        fileID = fileResponse.id
    prompt = (f"# ASK:\n"
              f"Reads the source/script file contents and decides if it is a malware exhibits any malicious pattern.\n"
              f"# RESPONSE FORMAT:\n"
              f"If you suspect it is malware, **START** the response with **True** or **False** with **NO BOLD** and **NO ITALIC STYLE** and **EXPLAIN WHY!**")
    inputPromptTokenCount = (await GPTclient.responses.input_tokens.count(model=GPT_MODEL, instructions="You are a cybersecurity analyst on a disassemble file for potential malware detection", input=[{"role": "user", "content": [{"type": "input_text", "text": prompt}, {"type": "input_file", "file_id": fileID}]}])).input_tokens
    print(f"[Open AI SCAT Model {GPT_MODEL}] Total Input Tokens: {inputPromptTokenCount}")
    logMessage += f"- **Total Input Tokens Count:** `{inputPromptTokenCount:,} tokens`\n"
    if inputPromptTokenCount > LLM_MODEL_INFORMATION[GPT_MODEL]["Maximum Input Tokens"] or inputPromptTokenCount > LLM_MODEL_INFORMATION[GPT_MODEL]["TPM"]:
        print(f"[Open AI SCAT Model {GPT_MODEL}] MAXIMUM TOKEN LIMIT!!")
        await GPTclient.files.delete(fileID)
        logMessage += f"- **{GPT_MODEL} SCAT Result:** `Input token exceed model context window, proceed to scan the file partially!`\n"
        return "MAXIMUM INPUT TOKEN LIMIT", logMessage
    else:
        try:
            response = await GPTclient.responses.create(model=GPT_MODEL, instructions="You are a cybersecurity analyst on a file for potential malware detection", input=[{"role": "user", "content": [{"type": "input_text", "text": prompt}, {"type": "input_file", "file_id": fileID}]}], temperature=0, store=False, max_output_tokens=5000)
            totalCachedRead = response.usage.input_tokens_details.cached_tokens
            totalRawInputTokens = response.usage.input_tokens - totalCachedRead
            outputPromptTokenCount = response.usage.total_tokens - inputPromptTokenCount
            print(f"[Open AI SCAT Model {GPT_MODEL}] Total Output Tokens: {outputPromptTokenCount}")
            cMonth = time.ctime(time.time()).split()[1]
            cDay = time.ctime(time.time()).split()[2]
            totalCost = calculateUsageCost(GPT_MODEL, [totalRawInputTokens, totalCachedRead], outputPromptTokenCount)
            await writingLLMUsageCsv(f"{LLM_USAGE_LOG}LLMMonthlyUsage.csv", "a", [f"{cMonth} {cDay}", inputPromptTokenCount, outputPromptTokenCount, GPT_MODEL, totalCost], MonthlyCSVLock)
            await writingLLMUsageCsv(f"{LLM_USAGE_LOG}LLMYearlyUsage.csv", "a", [f"{cMonth} {cDay}", inputPromptTokenCount, outputPromptTokenCount, GPT_MODEL, totalCost], YearlyCSVLock)
            logMessage += f"- **Total Output Tokens Count:** `{outputPromptTokenCount:,} tokens`\n"
            logMessage += f"- **{GPT_MODEL} SCAT Result:**\n{response.output_text}\n"
            if response.output_text:
                return response.output_text, logMessage
            else:
                print(f"[Open AI SCAT Model {GPT_MODEL}] Got an empty response!")
                return "EMPTY RESPONSE", logMessage
        except (openai.APITimeoutError, openai.RateLimitError) as Error:
            print(f"[Open AI SCAT Model {GPT_MODEL}] Error {Error}\nAttempting SCAT process again after 15 seconds!")
            logMessage += (f"- **{GPT_MODEL} SCAT Result:** Error {Error}\n"
                           f"- **Retry {GPT_MODEL} SCAT after 15 seconds**\n")
            await asyncio.sleep(15)
            return await openAISCAT(filepath, logMessage, retryCount + 1)
        except Exception as Error:
            print(f"[Open AI SCAT Model {GPT_MODEL}] {Error}")
            logMessage += f"- **{GPT_MODEL} SCAT Result:** Error {Error}\n"
            return str(Error), logMessage
        finally:
            await GPTclient.files.delete(fileID)


async def GeminiSCAT(filepath: str, logMessage: str, retryCount: int = 1) -> Tuple[str, str]:
    """
    Description: Static Code Analysis on a script of a decompiled file with Google Gemini
    :param filepath: The filepath of the file to analyze
    :param logMessage: The current log message
    :param retryCount: The number of times to retry the scan
    :return: The analysis results from Gemini
    """
    print(f"[Gemini SCAT Model {GEMINI_MODEL}] API call attempt {retryCount}...")
    logMessage += f"- **Begin SCAT Analysis With {GEMINI_MODEL}**\n"
    if retryCount == 3:
        print(f"[Gemini SCAT Model {GEMINI_MODEL}] Too many attempts, return inclusive scan!")
        logMessage += f"- **{GEMINI_MODEL} SCAT Result:** `Too many retry attempts, inconclusive scan!`\n"
        return "TOO MANY RETRY ATTEMPTS", logMessage
    mainPrompt = (
        f"# ASK:\n"
        f"Reads the source/script file contents and decides if it is a malware exhibits any malicious pattern.\n"
        f"# RESPONSE FORMAT:\n"
        f"If you suspect it is malware, **START** the response with **True** or **False** with **NO BOLD** and **NO ITALIC STYLE** and **EXPLAIN WHY!**"
    )
    uploadedFile = await GeminiClient.aio.files.upload(file=filepath)
    uploadedFiles = [uploadedFile.name]
    print(f"[Gemini SCAT Model {GEMINI_MODEL}] Uploaded file '{uploadedFile.name}' as: {uploadedFile.uri}")
    prompts = [uploadedFile, mainPrompt]
    try:
        try:
            totalInputTokenCount = (await GeminiClient.aio.models.count_tokens(model=GEMINI_MODEL, contents=prompts)).total_tokens
        except Exception as error:
            print(f"[Gemini SCAT Model {GEMINI_MODEL}] Received error: {error}\nAttempting upload original source file")
            logMessage += f"- **{GEMINI_MODEL} SCAT Result:** `Received error: {error}, attempting upload original source file`\n"
            fallbackFilePath = os.path.splitext(filepath)[0] + ".txt"
            if not os.path.isfile(fallbackFilePath):
                print(f"Original file {fallbackFilePath} not found!")
                logMessage += f"- **{GEMINI_MODEL} SCAT Result:** `Original source file not found! Inconclusive Scan!`\n"
                return "INCONCLUSIVE SCAN", logMessage
            uploadedFile = await GeminiClient.aio.files.upload(file=fallbackFilePath)
            uploadedFiles.append(uploadedFile.name)
            print(f"[Gemini SCAT Model {GEMINI_MODEL}] Uploaded file '{uploadedFile.name}' as: {uploadedFile.uri}")
            prompts = [uploadedFile, mainPrompt]
            try:
                totalInputTokenCount = (await GeminiClient.aio.models.count_tokens(model=GEMINI_MODEL, contents=prompts)).total_tokens
                print(f"[Gemini SCAT Model {GEMINI_MODEL}] Total Input Tokens: {totalInputTokenCount}")
            except Exception as error:
                logMessage += f"- **{GEMINI_MODEL} SCAT Result:** `Error {error}`\n"
                return str(error), logMessage
        logMessage += f"- **Total Input Tokens Count:** `{totalInputTokenCount:,} tokens`\n"
        if (totalInputTokenCount > LLM_MODEL_INFORMATION[GEMINI_MODEL]["Maximum Input Tokens"] or totalInputTokenCount > LLM_MODEL_INFORMATION[GEMINI_MODEL]["TPM"]):
            print(f"[Gemini SCAT Model {GEMINI_MODEL}] MAXIMUM TOKEN LIMIT!!")
            logMessage += f"- **{GEMINI_MODEL} SCAT Result:** `Input token exceed model context window, proceed to scan the file partially!`\n"
            return "MAXIMUM INPUT TOKEN LIMIT", logMessage

        response = await GeminiClient.aio.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompts,
            config=types.GenerateContentConfig(
                system_instruction="You are a cybersecurity analyst on a disassemble file for potential malware detection",
                max_output_tokens=5000, temperature=0
            )
        )

        totalCachedRead = response.usage_metadata.cached_content_token_count or 0
        totalRawInputTokens = response.usage_metadata.prompt_token_count - totalCachedRead
        totalOutputTokenCount = (response.usage_metadata.total_token_count - response.usage_metadata.prompt_token_count)
        cMonth = time.ctime(time.time()).split()[1]
        cDay = time.ctime(time.time()).split()[2]
        totalCost = calculateUsageCost(GEMINI_MODEL, [totalRawInputTokens, totalCachedRead], totalOutputTokenCount)
        await writingLLMUsageCsv(f"{LLM_USAGE_LOG}LLMMonthlyUsage.csv", "a", [f"{cMonth} {cDay}", totalInputTokenCount, totalOutputTokenCount, GEMINI_MODEL, totalCost], MonthlyCSVLock)
        await writingLLMUsageCsv(f"{LLM_USAGE_LOG}LLMYearlyUsage.csv", "a", [f"{cMonth} {cDay}", totalInputTokenCount, totalOutputTokenCount, GEMINI_MODEL, totalCost], YearlyCSVLock)
        logMessage += (f"- **Total Output Tokens Count:** `{totalOutputTokenCount:,} tokens`\n"
                       f"- **{GEMINI_MODEL} SCAT Result:**\n{response.text}\n")
        if response.text:
            return response.text, logMessage
        else:
            print(f"[Gemini SCAT Model {GEMINI_MODEL}] Got an empty response!")
            return "EMPTY RESPONSE", logMessage
    except APIError as e:
        if e.code == 429:
            print(f"[Gemini SCAT Model {GEMINI_MODEL}] Rate Limit Error! Retry after 15 seconds!")
            raise ConnectTimeout("Rate Limit Error!")
        else:
            logMessage += f"- **{GEMINI_MODEL} SCAT Result:** Error {e}\n"
            print(f"[Gemini SCAT Model {GEMINI_MODEL}] {e.message}")
            return e.message, logMessage
    except ConnectTimeout as e:
        logMessage += (f"- **{GEMINI_MODEL} SCAT Result:** Error {e}\n"
                       f"- **Retry {GEMINI_MODEL} SCAT after 15 seconds**\n")
        if e != "Rate Limit Error!":
            print(f"[Gemini SCAT Model {GEMINI_MODEL}] Time Out Error! Retry after 15 seconds!")
        await asyncio.sleep(15)
        return await GeminiSCAT(filepath, logMessage, retryCount + 1)
    finally:
        for fileName in uploadedFiles:
            await GeminiClient.aio.files.delete(name=fileName)


async def partialLLMSCAT(filepath: str, logMessage: str, LLM: Literal["OpenAI", "Gemini"]) -> Tuple[bool, str, str]:
    """
    Description: Partial Static Code Analysis on a script of a large decompiled file with OpenAI Codex and Google Gemini
    :param filepath: The filepath to be analyzed
    :param logMessage: Current Log Message
    :param LLM: Which LLM provider to use
    :return: The result of the analysis
    """
    async with aiofiles.open(filepath, "r") as file:
        content = await file.readlines()
    smallestContextWindow = min([LLM_MODEL_INFORMATION[GPT_MODEL]["Maximum Input Tokens"], LLM_MODEL_INFORMATION[GPT_MODEL]["TPM"]])
    if LLM == "OpenAI":
        LLMModel = GPT_MODEL
    else:
        LLMModel = GEMINI_MODEL
    inputPromptTokenCount = 100000000000
    divideValue = 2
    chunkSize = max(1, int(len(content) // divideValue))
    while inputPromptTokenCount > smallestContextWindow - 4000:
        if LLM == "OpenAI":
            inputPromptTokenCount = (await GPTclient.responses.input_tokens.count(model=GPT_MODEL, instructions="You are a cybersecurity analyst on a disassemble file for potential malware detection", input=[{"role": "user", "content": [{"type": "input_text", "text": "".join(content[0:chunkSize])}]}])).input_tokens
        else:
            inputPromptTokenCount = (await GeminiClient.aio.models.count_tokens(model=GEMINI_MODEL, contents="".join(content[0:chunkSize]))).total_tokens
        divideValue += 0.5
        chunkSize = max(1, round(len(content) // divideValue))
    summarization = ""
    for i in range(0, len(content), chunkSize):
        nextChunkSize = i + chunkSize
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
            if nextChunkSize > len(content):
                nextChunkSize = i + (len(content) - i)
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
        if LLM == "OpenAI":
            try:
                response = await GPTclient.responses.create(model=GPT_MODEL, instructions="You are a cybersecurity analyst on a disassemble file for potential malware detection", input=[{"role": "user", "content": [{"type": "input_text", "text": prompt}]}], temperature=0, store=True, max_output_tokens=5000)
            except Exception as Error:
                print(f"[Open AI SCAT Model {LLMModel}] {Error}")
                logMessage += f"- **Partial {LLMModel} SCAT from Line {i + 1} to Line {i + chunkSize} Result:** `{Error}. Retry after 15s`\n"
                print(f"Attempt one more retry after 15s")
                await asyncio.sleep(15)
                try:
                    response = await GPTclient.responses.create(model=GPT_MODEL, instructions="You are a cybersecurity analyst on a disassemble file for potential malware detection", input=[{"role": "user", "content": [{"type": "input_text", "text": prompt}]}], temperature=0, store=True, max_output_tokens=5000)
                except Exception as Error:
                    print(f"[Open AI SCAT Model {LLMModel}] {Error}")
                    logMessage += f"- **Partial {LLMModel} SCAT from Line {i + 1} to Line {i + chunkSize} Result:** `{Error}`\n"
                    return False, "OpenAI API Error", logMessage
            inputPromptTokenCount = response.usage.input_tokens
            totalCachedRead = response.usage.input_tokens_details.cached_tokens
            totalRawInputTokens = response.usage.input_tokens - totalCachedRead
            outputPromptTokenCount = response.usage.output_tokens
            textResponse = response.output_text
            print(f"[Open AI SCAT Model {LLMModel}] Total Input Tokens: {inputPromptTokenCount}")
            print(f"[Open AI SCAT Model {LLMModel}] Total Output Tokens: {outputPromptTokenCount}")
        else:
            try:
                response = await GeminiClient.aio.models.generate_content(model=GEMINI_MODEL, contents=prompt, config=types.GenerateContentConfig(system_instruction="You are a cybersecurity analyst on a disassemble file for potential malware detection", max_output_tokens=5000, temperature=0))
            except Exception as Error:
                print(f"[Gemini AI SCAT Model {LLMModel}] {Error}")
                logMessage += f"- **Partial {LLMModel} SCAT from Line {i + 1} to Line {i + chunkSize} Result:** `{Error}. Retry after 15s`\n"
                print(f"Attempt one more retry after 15s")
                await asyncio.sleep(15)
                try:
                    response = await GeminiClient.aio.models.generate_content(model=GEMINI_MODEL, contents=prompt, config=types.GenerateContentConfig(system_instruction="You are a cybersecurity analyst on a disassemble file for potential malware detection", max_output_tokens=5000, temperature=0))
                except Exception as Error:
                    print(f"[Gemini AI SCAT Model {LLMModel}] {Error}")
                    logMessage += f"- **Partial {LLMModel} SCAT from Line {i + 1} to Line {i + chunkSize} Result:** `{Error}`\n"
                    return False, "Gemini API Error", logMessage
            inputPromptTokenCount = response.usage_metadata.prompt_token_count
            totalCachedRead = response.usage_metadata.cached_content_token_count or 0
            totalRawInputTokens = response.usage_metadata.prompt_token_count - totalCachedRead
            outputPromptTokenCount  = response.usage_metadata.total_token_count - inputPromptTokenCount
            textResponse = response.text
            print(f"[Gemini SCAT Model {LLMModel}] Total Input Tokens: {inputPromptTokenCount}")
            print(f"[Gemini SCAT Model {LLMModel}] Total Output Tokens: {outputPromptTokenCount}")
        cMonth = time.ctime(time.time()).split()[1]
        cDay = time.ctime(time.time()).split()[2]
        totalCost = calculateUsageCost(LLMModel, [totalRawInputTokens, totalCachedRead], outputPromptTokenCount)
        await writingLLMUsageCsv(f"{LLM_USAGE_LOG}LLMMonthlyUsage.csv", "a", [f"{cMonth} {cDay}", inputPromptTokenCount, outputPromptTokenCount, LLMModel, totalCost], MonthlyCSVLock)
        await writingLLMUsageCsv(f"{LLM_USAGE_LOG}LLMYearlyUsage.csv", "a", [f"{cMonth} {cDay}", inputPromptTokenCount, outputPromptTokenCount, LLMModel, totalCost], YearlyCSVLock)
        logMessage += (f"- **Partial {LLMModel} SCAT from Line {i + 1} to Line {i + chunkSize}:**\n"
                       f"\t+ **Total Input Tokens Count:** `{inputPromptTokenCount:,} tokens`\n"
                       f"\t+ **Total Output Tokens Count:** `{outputPromptTokenCount:,} tokens`\n"
                       f"\t+ **{LLMModel} SCAT Result:**\n{textResponse}\n")
        if textResponse.startswith(("True", "true")):
            print(f"[SCAT Model {LLMModel}] Partial Analysis at line ** {i + 1} to {nextChunkSize} flagged malicious!!!\nAnalysis Summary: {textResponse}")
            return True, textResponse, logMessage
        summarization = textResponse
    return False, "Nothing Malicious", logMessage
