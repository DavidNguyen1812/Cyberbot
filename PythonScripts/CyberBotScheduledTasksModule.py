from __future__ import annotations

from CyberBotRuntimeModule import *
from CyberBotAnalyticsModule import plotBarCharts, plotModelCalls, writingLLMUsageCsv

async def CronTaskLog(logData: str) -> None:
    """
    Description: Logging Cyberbot Cron Task Job Results
    :param logData: The log data to write
    :return: None
    """
    async with CronTaskLock:
        async with aiofiles.open(CRON_TASK_LOG, "a") as logFile:
            await logFile.write(logData)


@tasks.loop(minutes=1)  # A task every 1 minute
async def checking_expired_tokens():

    async with OneTimeTokenLock:
            async with aiofiles.open(ONE_TIME_TOKEN_PATH, "r") as file:
                resetTokens = json.loads(await file.read())

    try:
        logMessage = f"# {time.ctime(time.time())}\n\n---\n\n"
        pending_delete_tokens = []

        logMessage += f"## Detected Expired One Time Password Reset Token\n"
        for tokenID in resetTokens["Password Reset Token"]:
            if time.time() >= resetTokens["Password Reset Token"][tokenID][1]:
                print(f"One Time Password Reset Token {resetTokens["Password Reset Token"][tokenID][0]} for {tokenID} expired.")
                logMessage += f"- One Time Password Reset Token `{resetTokens["Password Reset Token"][tokenID][0]}` for `{tokenID}` expired.\n"
                pending_delete_tokens.append(tokenID)

        logMessage += f"## Detected Expired Email Confirmation Token\n"
        for tokenID in resetTokens["Email Confirmation Token"]:
            if time.time() >= resetTokens["Email Confirmation Token"][tokenID][1]:
                print(f"Email Confirmation Token {resetTokens["Email Confirmation Token"][tokenID][0]} for {tokenID} expired.")
                logMessage += f"- Email Confirmation Token `{resetTokens["Email Confirmation Token"][tokenID][0]}` for `{tokenID}` expired.\n"
                pending_delete_tokens.append(tokenID)

        logMessage += f"## Detected Expired Admin Account Delete Confirmation Token\n"
        for tokenID in resetTokens["Account Delete Confirmation Token"]:
            if time.time() >= resetTokens["Account Delete Confirmation Token"][tokenID][1]:
                print(f"Admin Account Delete Confirmation Token {resetTokens["Account Delete Confirmation Token"][tokenID][0]} for {tokenID} expired.")
                logMessage += f"- Admin Account Delete Confirmation Token `{resetTokens["Account Delete Confirmation Token"][tokenID][0]}` for `{tokenID}` expired.\n"
                pending_delete_tokens.append(tokenID)

        logMessage += f"## Detected Admin Account Delete Cooldown\n"
        for userID in resetTokens["Recently Delete Admin Account"]:
            if time.time() >= resetTokens["Recently Delete Admin Account"][userID][0]:
                print(f"Admin Account Delete Cooldown for Discord User ID {userID}")
                logMessage += f"- Admin Account Delete Cooldown for Discord User ID `{userID}` expired.\n"
                pending_delete_tokens.append(userID)

        logMessage += f"## Deleting All Expired One Time Tokens\n"
        for tokenID in pending_delete_tokens:
            print(f"Removing one time token associated with {tokenID}...")
            try:
                if resetTokens["Password Reset Token"].get(tokenID):
                    del resetTokens["Password Reset Token"][tokenID]
                    logMessage += f"\t+ Password Reset Token for `{tokenID}` was removed and invalidated!\n"
            except Exception as e:
                logMessage += (f"\t+ Error Removing Password Reset Token for `{tokenID}`\n"
                               f"\t+ Error `{e}`\n")
                print(f"Encounter Error: {e}")
            try:
                if resetTokens["Email Confirmation Token"].get(tokenID):
                    logMessage += f"\t+ Email Confirmation Token for `{tokenID}` was removed and invalidated!\n"
                    del resetTokens["Email Confirmation Token"][tokenID]
                print(f"Removal Success!!!")
            except Exception as e:
                logMessage += (f"\t+ Error Removing Email Confirmation Token for `{tokenID}`\n"
                               f"\t+ Error `{e}`\n")
                print(f"Encounter Error: {e}")
            try:
                if resetTokens["Account Delete Confirmation Token"].get(tokenID):
                    del resetTokens["Admin Account Delete Confirmation Token"][tokenID]
                    logMessage += f"\t+ Admin Account Delete Confirmation Token for `{tokenID}` was removed and invalidated!\n"
            except Exception as e:
                logMessage += (f"\t+ Error Removing Admin Account Delete Confirmation Token for `{tokenID}`\n"
                               f"\t+ Error `{e}`\n")
                print(f"Encounter Error: {e}")
            async with aiofiles.open(ONE_TIME_TOKEN_PATH, "w") as file:
                await file.write(json.dumps(resetTokens, indent=4))
        logMessage += "\n---\n\n"
        if pending_delete_tokens:
            print("\n\n")
            await CronTaskLog(logMessage)
    finally:
        # Free content in RAM
        pending_delete_tokens = None
        logMessage = None
        resetTokens = None


@tasks.loop(seconds=15)  # A task every 15 seconds
async def checking_member_can_kick_cyberbot():
    for account in CyberBotConfigData["Admins"]:
        for serverID in account["Accessible Servers"]:
            guild = Cyberbot.get_guild(serverID)
            member = guild.get_member(account["User ID"])
            if guild.me.top_role.position < member.top_role.position and member.id != guild.owner.id:
                print(f"Member {member.name} can kick Cyberbot from server {guild.name} ID {serverID}.")
                logMessage = (f"# {time.ctime(time.time())}\n\n---\n\n"
                                  f"## Detected A Server Member Can Kick Cyberbot\n"
                                  f"- **Member:** `{member.name}`\n"
                                  f"- **User ID:** `{member.id}`\n"
                                  f"- **From Server:** `{guild.name}`\n"
                                  f"- **Server ID:** `{serverID}`\n")
                try:
                    await guild.owner.send(f"# WARNING\n"
                                           f"- **Member:** `{member.name}`\n"
                                           f"- **User ID:** `{member.id}`\n"
                                           f"- **From Server:** `{guild.name}`\n"
                                           f"- **Server ID:** `{serverID}`\n"
                                           f"- **WARNING REASON:** `Member can kick Cyberbot out of server, hence, prevent Cyberbot from protecting the server against malware!`\n"
                                           f"- **RECOMMENDATION:** `Please make sure Cyberbot has a higher role than all the members in the server.`")
                    logMessage += f"**Warning WAS SENT to the server owner {guild.owner.name} - ID {guild.owner.id}**\n\n---\n\n"
                    print("Warning was sent to the server owner!")
                except Exception as e:
                    print(f"Error: {e}")
                    print("Warning can not be sent to the server owner!")
                    logMessage += (f"Error: {e}\n"
                                   f"**Warning CAN NOT BE SENT to the server owner {guild.owner.name} - ID {guild.owner.id}**\n\n---\n\n")
                finally:
                    print("\n\n")
                    await CronTaskLog(logMessage)
                    logMessage = None


@tasks.loop(time=datetime.time(hour=0, minute=0, tzinfo=ZoneInfo("America/New_York")))  # A task every new day
async def daily_check_for_expired_credential_and_update_llm_usages():
    global previousYear, previousMonth, previousDate

    logMessage = f"# {time.ctime(time.time())}\n\n---\n\n"
    print("Checking for expired password...")
    log = False
    for account in CyberBotConfigData["Admins"]:
        if time.time() >= account["Credential Expiration Age"]:
            log = True
            print(f"Password for {account['User Email']} expired.")
            logMessage += ("## Detected Expired Admin Account Password\n"
                           f"- The Password for Admin Account Associated with the email `{account['User Email']}` Is EXPIRED!\n")
            try:
                user = Cyberbot.get_user(account["User ID"])
                await user.send(f"Your current admin account password has `EXPIRED`\nPlease use command **/request_password_reset_token** and **/change_password** to update your password!")
                logMessage += f"Password expire notification WAS SENT to user {user.name} - ID {user.id} via DM channel\n\n---\n\n"
                print(f"Password expire notification sent to {user.name} - ID {user.id} via DM channel!")
            except Exception as e:
                print(f"Error sending expire notification to user DM channel: {e}")
                logMessage += (f"Error: {e}\n"
                               f"Password expire notification CAN NOT BE SENT the user via DM channel\n\n---\n\n")
    print("Process Finished!\n\n")
    if log:
        await CronTaskLog(logMessage)
    currentTime = time.ctime(time.time()).split()

    # Checking new date
    if currentTime[2] != previousDate:
        logMessage = (f"# {time.ctime(time.time())}\n\n---\n\n"
                      f"## Updating LLMMonthlyUsageReport.png\n")
        print(f"New Day of the Month Change: {previousMonth} {previousDate} -> {currentTime[1]} {currentTime[2]}")
        MonthlyUsageReportPath = f"{LLM_USAGE_LOG}{previousYear}/{previousMonth}/LLMMonthlyUsageReport.png"
        MonthlyModelUsedReportPath = f"{LLM_USAGE_LOG}{previousYear}/{previousMonth}/LLMModelsUsed.png"
        try:
            print("Updating LLMMonthlyUsageReport.png...")
            async with MonthlyCSVLock:
                monthlyData = await asyncio.to_thread(pd.read_csv, f"{LLM_USAGE_LOG}LLMMonthlyUsage.csv")
            monthlyTotalInputToken = []
            monthlyTotalOutputToken = []
            monthlyTotalCost = []
            for day in range(1, int(previousDate) + 1):
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
                monthlyTotalCost.append(round(dailyTotalCost, 5))
            datasets = [
                {"values": monthlyTotalInputToken, "title": "Total Input Tokens", "color": "Blue"},
                {"values": monthlyTotalOutputToken, "title": "Total Output Tokens", "color": "Green"},
                {"values": monthlyTotalCost, "title": "Total Cost ($)", "color": "Orange"},
            ]
            dates = [str(date) for date in range(1, int(previousDate) + 1)]
            plotBarCharts(datasets, dates, "LLM Usage - Monthly Overview", MonthlyUsageReportPath)
            print("Successfully Updating LLMMonthlyUsageReport.png!")
            logMessage += f"- Successfully Updating LLMMonthlyUsageReport.png at `{MonthlyUsageReportPath}`\n"
            try:
                print("Updating LLMModelsUsed.png...")
                logMessage += "## Updating LLMModelsUsed.png\n"
                LLMModels = []
                LLMModelUses = []
                for _, row in monthlyData.iterrows():
                    if row["LLM Models"] not in LLMModels:
                        LLMModels.append(row["LLM Models"])
                        LLMModelUses.append(1)
                    else:
                        LLMModelUses[LLMModels.index(row["LLM Models"])] += 1
                plotModelCalls(LLMModels, LLMModelUses, MonthlyModelUsedReportPath)
                print("Successfully Updating LLMModelsUsed.png!")
                logMessage += f"- Successfully Updating LLMModelsUsed.png at `{MonthlyModelUsedReportPath}`\n"
            except Exception as error:
                print(f"An error occurs while updating LLMModelsUsed.png\n{error}")
                logMessage += f"An error occurs while updating LLMModelsUsed.png at `{MonthlyModelUsedReportPath}` - Error `{error}`\n"
        except Exception as error:
            print(f"An error occurs while updating LLMMonthlyUsageReport.png\n{error}")
            logMessage += f"An error occurs while updating LLMMonthlyUsageReport.png at `{MonthlyUsageReportPath}` - Error `{error}`\n"
        finally:
            logMessage += "\n---\n\n"
            await CronTaskLog(logMessage)
        previousDate = currentTime[2]

    # Checking new year
    if currentTime[4] != previousYear:
        logMessage = (f"# {time.ctime(time.time())}\n\n---\n\n"
                      f"## GENERATING LLM USAGE YEARLY REPORT\n")
        print(f"New Year Change: {previousYear} -> {currentTime[4]}")
        EndOfYearUsageReportPath = f"{LLM_USAGE_LOG}{previousYear}/FullYearUsageReport.png"
        LLMYearlyUsageLogPath = f"{LLM_USAGE_LOG}LLMYearlyUsage.csv"
        NewYearFolder = f"{LLM_USAGE_LOG}{currentTime[4]}"
        try:
            print("Generating LLM Usage Yearly Report...")
            async with YearlyCSVLock:
                yearlyData = await asyncio.to_thread(pd.read_csv, f"{LLM_USAGE_LOG}LLMYearlyUsage.csv")
            months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
            monthlyTotalInputTokens = []
            monthlyTotalOutputTokens = []
            monthlyTotalCosts = []
            for month in months:
                monthlyTotalInputToken = 0
                monthlyTotalOutputToken = 0
                monthlyTotalCost = 0
                for _, row in yearlyData.iterrows():
                    if row["Date"].split(" ")[0] == month:
                        monthlyTotalInputToken += row["Total Input Tokens"]
                        monthlyTotalOutputToken += row["Total Output Tokens"]
                        monthlyTotalCost += row["Total Cost"]
                monthlyTotalInputTokens.append(monthlyTotalInputToken)
                monthlyTotalOutputTokens.append(monthlyTotalOutputToken)
                monthlyTotalCosts.append(round(monthlyTotalCost, 5))
            datasets = [
                {"values": monthlyTotalInputTokens, "title": "Total Input Tokens", "color": "Blue"},
                {"values": monthlyTotalOutputTokens, "title": "Total Output Tokens", "color": "Green"},
                {"values": monthlyTotalCosts, "title": "Total Cost ($)", "color": "Orange"},
            ]
            plotBarCharts(datasets, months, "LLM Usage - End of Year Overview", EndOfYearUsageReportPath)
            print("Successfully Generating LLM Usage Yearly Report!")
            logMessage += f"- Successfully Generating LLM Usage Yearly Report at `{EndOfYearUsageReportPath}`\n"
            try:
                print("Resetting LLMYearlyUsage.csv...")
                logMessage += "## Resetting LLMYearlyUsage.csv\n"
                await writingLLMUsageCsv(LLMYearlyUsageLogPath, "w", ["Date", "Total Input Tokens", "Total Output Tokens", "LLM Models", "Total Cost"], YearlyCSVLock)
                logMessage += f"- Successfully Resetting LLMYearlyUsage.csv at `{LLMYearlyUsageLogPath}`\n"
                print("Successfully resetting LLMYearlyUsage.csv!")
                try:
                    print("Creating a new year folder...")
                    os.mkdir(NewYearFolder)
                    print("Successfully create a new year folder!")
                    logMessage += f"- Successfully creating a new year folder at `{NewYearFolder}`\n"
                except Exception as error:
                    print(f"An error occurs while creating a new year folder\n{error}")
                    logMessage += f"- An error occurs while creating a new year folder at `{NewYearFolder}` - Error `{error}`\n"
            except Exception as error:
                print(f"An error occurs while resetting LLMYearlyUsage.csv\n{error}")
                logMessage += f"- An error occurs while resetting LLMYearlyUsage.csv at `{LLMYearlyUsageLogPath}` - Error `{error}`\n"
        except Exception as error:
            print(f"An error occurs while generating LLM Usage Yearly Report\n{error}")
            logMessage += f"- An error occurs while generating LLM Usage Yearly Report at `{EndOfYearUsageReportPath}` - Error `{error}`\n"
        finally:
            logMessage += "\n---\n\n"
            await CronTaskLog(logMessage)
        previousYear = currentTime[4]

    # Checking new month
    if currentTime[1] != previousMonth:
        logMessage = (f"# {time.ctime(time.time())}\n\n---\n\n"
                      f"## Resetting LLMMonthlyUsage.csv\n")
        MonthlyUsagePath = f"{LLM_USAGE_LOG}LLMMonthlyUsage.csv"
        NewMonthFolder = f"{LLM_USAGE_LOG}{currentTime[4]}/{currentTime[1]}"
        print(f"New Month Change: {previousMonth} -> {currentTime[1]}")
        try:
            print("Resetting LLMMonthlyUsage.csv...")
            await writingLLMUsageCsv(MonthlyUsagePath, "w", ["Date", "Total Input Tokens", "Total Output Tokens", "LLM Models", "Total Cost"], MonthlyCSVLock)
            print("Successfully resetting LLMMonthlyUsage.csv!")
            logMessage += f"- Successfully Resetting LLMMonthlyUsage.csv at `{MonthlyUsagePath}`\n"
            try:
                print("Creating a new month folder...")
                os.mkdir(NewMonthFolder)
                print("Successfully create a new month folder!")
                logMessage += f"- Successfully create a new month folder at `{NewMonthFolder}`\n"
            except Exception as error:
                print(f"An error occurs while creating a new month folder\n{error}")
                logMessage += f"- An error occurs while creating a new month folder at `{NewMonthFolder}` - Error `{error}`\n"
        except Exception as error:
            print(f"An error occurs while resetting LLMMonthlyUsage.csv\n{error}")
            logMessage += f"- An error occurs while resetting LLMMonthlyUsage.csv at `{MonthlyUsagePath}` - Error {error}\n"
        finally:
            logMessage += "\n---\n\n"
            await CronTaskLog(logMessage)
        previousMonth = currentTime[1]
