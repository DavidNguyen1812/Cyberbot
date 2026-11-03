from __future__ import annotations

from CyberBotRuntimeModule import *
from CyberBotAnalyticsModule import calculateUsageCost, writingLLMUsageCsv

def sendEmail(subject: str, content: str, receiver_email: str) -> Literal["Email sent successfully!", "Email sent unsuccessfully!"]:
    """
    Description: Sending email to registered user with admin account
    :param subject: Email subject
    :param content: Email content
    :param receiver_email: Destination email address
    :return: Email sent status of either failed or successes
    """
    # Credit https://www.youtube.com/watch?v=g_j6ILT-X0k
    sender_email = "noreplycyberbot7777@gmail.com"  # You need to create your own email account for Cyberbot

    # Validate the destination email is valid
    try:
        validate_email(receiver_email, check_deliverability=True)
    except EmailNotValidError as error:
        print(f"[Cyberbot Email System] Error sending email: {error}")
        return "Email sent unsuccessfully!"

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
            server.login(sender_email, os.environ.get("EMAIL_CRED"))
            server.sendmail(sender_email, receiver_email, email.as_string())
    except smtplib.SMTPRecipientsRefused as clientError:
        print(f"[Cyberbot Email System] Error sending email to {receiver_email}: {clientError}")
        return "Email sent unsuccessfully!"
    except Exception as other_error:
        print(f"[Cyberbot Email System] Error sending email to {receiver_email}: {other_error}")
        return "Email sent unsuccessfully!"
    print(f"[Cyberbot Email System] Automation Email sent to {receiver_email} succesfully!")
    return "Email sent successfully!"


def txtToPDFConversion(txtFile: str, outputPDFPath: str):
    """
    Description: Converting the text/document content of a file to PDF frames
    :param txtFile: The ASCII content of a file
    :param outputPDFPath: The output PDF path
    :return: None
    """
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_author("Cyberbot")
        pdf.set_font("Arial", size=12)
        decodedContent = txtFile.encode("latin-1", errors="replace").decode("latin-1")
        pdf.multi_cell(0, 10, decodedContent)
        pdf.output(outputPDFPath)
        print("PDF Conversion successes!")
    except Exception as error:
        print(f"PDF Conversion error: {error}")


async def LoggingApplicationCommand(ctx, command: str, commandInputs: str, result: str) -> None:
    """
    DescriptionL Logging an event a user calling Cyberbot application command on Discord
    :param ctx: Discord Message context
    :param command: The application command being called
    :param commandInputs: The command inputs provided by the user
    :param result: The result of the command being called
    :return: None
    """
    async with CommandLogLock:
        async with aiofiles.open(CYBERBOT_APPLICATION_COMMAND_LOG, "a") as logFile:
            try:
                await logFile.write(f"# {time.ctime(time.time())}\n\n---\n\n"
                                    f"- **Discord User:** `{ctx.user.name}`\n"
                                    f"- **User ID:** `{ctx.user.id}`\n"
                                    f"- **Server:** `{ctx.guild.name}`\n"
                                    f"- **Server ID:** `{ctx.guild.id}`\n"
                                    f"- **Channel:** `{ctx.channel.name}`\n"
                                    f"- **Channel ID:** `{ctx.channel.id}`\n"
                                    f"- **Application Command:** `{command}`\n"
                                    f"- **Command Inputs:** `{commandInputs}`\n"
                                    f"- **Result:** `{result}`\n\n---\n\n")
            except (discord.app_commands.errors.CommandInvokeError, AttributeError):
                await logFile.write(f"# {time.ctime(time.time())}\n\n---\n\n"
                                    f"- **Discord User:** `{ctx.user.name}`\n"
                                    f"- **User ID:** `{ctx.user.id}`\n"
                                    f"- **Server:** `UNKNOWN`\n"
                                    f"- **Server ID:** `UNKNOWN`\n"
                                    f"- **Channel:** `Private Direct Message Channel`\n"
                                    f"- **Channel ID:** `UNKNOWN`\n"
                                    f"- **Application Command:** `{command}`\n"
                                    f"- **Command Inputs:** `{commandInputs}`\n"
                                    f"- **Result:** `{result}`\n\n---\n\n")

async def randomPasswordGenerator() -> str:
    """
    Description: Randomly generate a secure password.
    :return: A secure password following a defined Cyberbot password policy
    """
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


async def GeminiCheckCommonPassword(password: str) -> bool:
    """
    Description: Checking password strength using Gemini
    :param password: Password to be checked
    :return: True if the password is not secure, else False
    """
    response = await GeminiClient.aio.models.generate_content(
        model=GEMINI_MODEL,
        contents=f"Only say True if {password} seems to be from commonly used passwords, otherwise say False"
    )

    inputPromptTokenCount = response.usage_metadata.prompt_token_count
    totalCachedRead = response.usage_metadata.cached_content_token_count or 0
    totalRawInputTokens = response.usage_metadata.prompt_token_count - totalCachedRead
    outputPromptTokenCount = response.usage_metadata.total_token_count - response.usage_metadata.prompt_token_count
    cMonth = time.ctime(time.time()).split()[1]
    cDay = time.ctime(time.time()).split()[2]
    totalCost = calculateUsageCost(GEMINI_MODEL, [totalRawInputTokens, totalCachedRead], outputPromptTokenCount)
    await writingLLMUsageCsv(f"{LLM_USAGE_LOG}LLMMonthlyUsage.csv", "a", [f"{cMonth} {cDay}", inputPromptTokenCount, outputPromptTokenCount, GEMINI_MODEL, totalCost], MonthlyCSVLock)
    await writingLLMUsageCsv(f"{LLM_USAGE_LOG}LLMYearlyUsage.csv", "a", [f"{cMonth} {cDay}", inputPromptTokenCount, outputPromptTokenCount, GEMINI_MODEL, totalCost], YearlyCSVLock)

    if response.text.startswith(("True", "true")):
        return True
    else:
        return False


async def CheckPasswordPwned(password: str) -> bool:
    """
    Description: Checking if password already exist in breached password database
    :param password: Password to be checked
    :return: True if the password already been breached, else False
    """
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
