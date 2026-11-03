from __future__ import annotations

from CyberBotRuntimeModule import *
from CyberBotSecurityUtilitiesModule import CheckPasswordPwned, GeminiCheckCommonPassword, LoggingApplicationCommand, randomPasswordGenerator, sendEmail

@Cyberbot.tree.command(
    name="create_admin_account",
    description="Register a Cyberbot admin account"
)
@app_commands.describe(
    user_email="Please provide a valid email address to register your Cyberbot admin account!"
)
async def create_admin_account(ctx, user_email: str):
    print(f"User {ctx.user.name} initiated /create_admin_account command")
    await ctx.response.defer(ephemeral=True)
    emailSHA512Hash = hashlib.sha512(user_email.encode()).hexdigest()
    accountExist = False
    emailTaken = False
    for admin in CyberBotConfigData["Admins"]:
        if admin["User ID"] == ctx.user.id:
            accountExist = True
            await LoggingApplicationCommand(ctx, "/create_admin_account", f"user_email -> REDACTED", "Denied/User already has an admin account!")
            await ctx.followup.send(f"You already have a registered Cyberbot admin account!\nIf you want to change your password, use command /request_password_reset_token and /change_password with Cyberbot!")
            print("User already has an admin account!\n\n")
            break
        if admin["User Email"] == emailSHA512Hash:
            emailTaken = True
            await LoggingApplicationCommand(ctx, f"/create_admin_account", f"user_email -> REDACTED", "Denied/Email address already taken by other user admin account!")
            await ctx.followup.send(f"The email address already associated with a different admin account!")
            print("Email address already associated with a different admin account!\n\n")
            break
    async with OneTimeTokenLock:
        async with aiofiles.open(ONE_TIME_TOKEN_PATH, "r") as file:
            resetTokens = json.loads(await file.read())
    if emailSHA512Hash in resetTokens["Email Confirmation Token"]:
        await LoggingApplicationCommand(ctx, "/create_admin_account", f"user_email -> REDACTED", "Denied/An Email Confirmation Token that still valid already sent to the user email!")
        await ctx.followup.send(f"You have already request an admin account registration and a 4 minutes OTP code was sent to the email! Please confirm your email using the command /confirm_admin_account with the OTP code or wait until the OTP expired to request a new one again using this command!")
        print(f"A valid OTP code already sent to email {emailSHA512Hash}\n\n")
    else:
        if not accountExist and not emailTaken:
            token = ""
            for i in range(10, 20):
                token += random.choice(f"ABCDEFGHIJKLNMOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%&*_+=")
            if await asyncio.to_thread(sendEmail, "Email Verification Code", f"Your Cyberbot Admin Account Email Verification Code is {token}\n\nThis code will expire in 4 minutes!\nIf you did not request this, please ignore this message.", user_email) == "Email sent successfully!":
                resetTokens["Email Confirmation Token"][emailSHA512Hash] = [hashlib.sha1(token.encode()).hexdigest(), time.time() + 240]
                async with OneTimeTokenLock:
                    async with aiofiles.open(ONE_TIME_TOKEN_PATH, "w") as file:
                        await file.write(json.dumps(resetTokens, indent=4))
                await ctx.followup.send(f"Please confirm your email using the command /confirm_admin_account with the OTP code sent at {user_email}!")
                print(f"New Email OTP code sent to {user_email}\n\n")
                await LoggingApplicationCommand(ctx, "/create_admin_account", f"user_email -> REDACTED", "Approved/An Email Confirmation Token was sent to the user email!")
            else:
                await ctx.followup.send(f"Cyberbot can't register a new admin account with the email address: {user_email}")
                print(f"Error sending email!\n\n")
                await LoggingApplicationCommand(ctx, "/create_admin_account", f"user_email -> REDACTED", "Denied/Error sending email!")
    resetTokens = None
    user_email = None


@Cyberbot.tree.command(
    name="confirm_admin_account",
    description="Confirm to finish creating a Cyberbot admin account"
)
@app_commands.describe(
    user_email="Please provide an email address to confirm your Cyberbot admin account!",
    otp="Please provide a valid Email Confirmation Code!"
)
async def confirm_admin_account(ctx, user_email: str, otp: str):
    print(f"User {ctx.user.name} initiated /confirm_admin_account command")
    await ctx.response.defer(ephemeral=True)
    emailSHA512Hash = hashlib.sha512(user_email.encode()).hexdigest()
    async with OneTimeTokenLock:
        async with aiofiles.open(ONE_TIME_TOKEN_PATH, "r") as file:
            resetTokens = json.loads(await file.read())
    if emailSHA512Hash in resetTokens["Email Confirmation Token"]:
        if resetTokens["Email Confirmation Token"][emailSHA512Hash][0] == hashlib.sha1(otp.encode()).hexdigest() and time.time() < resetTokens["Email Confirmation Token"][emailSHA512Hash][1]:
            defaultPassword = await randomPasswordGenerator()
            if await asyncio.to_thread(sendEmail, "New Cyberbot Admin Account Created",f"A new Cyberbot admin account was created with a default password:\n{defaultPassword}\nIf you want to change your password, use command /request_password_reset_token and /change_password with Cyberbot!", user_email) == "Email sent successfully!":
                del resetTokens["Email Confirmation Token"][emailSHA512Hash]
                async with OneTimeTokenLock:
                    async with aiofiles.open(ONE_TIME_TOKEN_PATH, "w") as file:
                        await file.write(json.dumps(resetTokens, indent=4))
                salt = bcrypt.gensalt(rounds=12)
                passwordHash = bcrypt.hashpw(f"{defaultPassword}{ctx.user.id}".encode(), salt).decode('utf-8')
                CyberBotConfigData["Admins"].append(
                    {"User ID": ctx.user.id,
                     "User Email": emailSHA512Hash,
                     "User Salt": salt.decode('utf-8'),
                     "User Credential": passwordHash,
                     "Credential Minimum Age": 0,
                     "Credential Expiration Age": time.time() + 15552000,
                     "Previous Credentials Used": [passwordHash],
                     "Current Admin Session Period": {},
                     "Last Time Logged In": "",
                     "Current Account Locked Out Period": 0,
                     "Failed Log In Attempts": 0,
                     "Locked Out History": [],
                     "Total Locked Out": 0,
                     "Total Failed Log In Attempts": 0,
                     "Accessible Servers": [],
                     "Account Creation Date": time.ctime(time.time())
                     }
                )
                async with ConfigLock:
                    async with aiofiles.open(CYBERBOT_CONFIG, "w") as file:
                        await file.write(json.dumps(CyberBotConfigData, indent=4))
                await ctx.followup.send(f"A new admin account has been created for you! Please check the email you used to registered the account for more details!")
                print(f"New Admin account created for user {ctx.user.name}\n\n")
                await LoggingApplicationCommand(ctx, "/confirm_admin_account", f"user_email -> REDACT, otp -> {otp}", f"Approved/New admin account registered for user {ctx.user.name}")
            else:
                await ctx.followup.send("Cyberbot can not send the account creation confirmation email to you! Please try the command again and ensure that you have not blocked Cyberbot automation email noreplycyberbot7777@gmail.com!")
                print(f"Error sending email!\n\n")
                await LoggingApplicationCommand(ctx, "/confirm_admin_account", f"user_email -> REDACT, otp -> {otp}", "Denied/Cyberbot can not send Account Creation Confirmation email to user email!")
        else:
            await ctx.followup.send(f"The Email Confirmation Code that you provided is invalid or already expired. Please use command /create_admin_account to register a new one again!")
            print(f"No Email Confirmation Token associated with the provided email!\n\n")
            await LoggingApplicationCommand(ctx, "/confirm_admin_account", f"user_email -> REDACT, otp -> {otp}", "Denied/Invalid or expired Email Confirmation Code!")
    else:
        await ctx.followup.send(f"There is no Email Confirmation Code associated with the provided email {user_email}. Please use command /create_admin_account to register one!")
        print(f"No Email Confirmation Token associated with the provided email!\n\n")
        await LoggingApplicationCommand(ctx, "/confirm_admin_account", f"user_email -> REDACT, otp -> {otp}", "Denied/No Email Confirmation Token associated with the provided email!")
    resetTokens = None
    user_email = None
    defaultPassword = None
    otp = None


@Cyberbot.tree.command(
    name="remove_admin_account",
    description="Removing a Cyberbot admin account"
)
@app_commands.describe(
    user_email="Please provide an email address associated with your Cyberbot admin account!",
    password="Please provide a password associated with your Cyberbot admin account!"
)
async def remove_admin_account(ctx, user_email: str, password: str):
    print(f"User {ctx.user.name} initiated /remove_admin_account command")
    await ctx.response.defer(ephemeral=True)
    try:
        emailSHA512Hash = hashlib.sha512(user_email.encode()).hexdigest()
        for adminAccount in CyberBotConfigData["Admins"]:
            if adminAccount["User ID"] == ctx.user.id:
                if time.time() > adminAccount["Current Account Locked Out Period"]:
                    if adminAccount["User Email"] == emailSHA512Hash and bcrypt.checkpw(f"{password}{ctx.user.id}".encode(), adminAccount["User Credential"].encode()):
                        adminAccount["Failed Log In Attempts"] = 0
                        if time.time() < adminAccount["Credential Expiration Age"]:
                            async with OneTimeTokenLock:
                                async with aiofiles.open(ONE_TIME_TOKEN_PATH, "r") as file:
                                    resetTokens = json.loads(await file.read())
                            token = ""
                            for i in range(10, 20):
                                token += random.choice(f"ABCDEFGHIJKLNMOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%&*_+=")
                            if await asyncio.to_thread(sendEmail, "Admin Account Delete Confirmation Token", f"Your Cyberbot Admin Account Delete Confirmation Token is {token}\n\nThis code will expire in 4 minutes!\nIf you did not request this, please ignore this message.", user_email) == "Email sent successfully!":
                                resetTokens["Account Delete Confirmation Token"][emailSHA512Hash] = [hashlib.sha1(token.encode()).hexdigest(), time.time() + 240]
                                await ctx.followup.send(f"For security reason, an Admin Account Delete Confirmation Token was sent to {user_email}. Please use the command /confirm_delete_admin_account to finalize your admin account deletion!")
                                await LoggingApplicationCommand(ctx, "/remove_admin_account", "user_email -> REDACT, password -> REDACT", "Denied/An Account Unregistration Confirmation Code was sent user email!")
                            else:
                                await ctx.followup.send("Cyberbot can not send the unregistration confirmation email to you! Please try the command again and ensure that you have not blocked Cyberbot automation email noreplycyberbot7777@gmail.com!")
                                print(f"Error sending email!\n\n")
                                await LoggingApplicationCommand(ctx, "/remove_admin_account", "user_email -> REDACT, password -> REDACT", "Denied/Cyberbot can not send Account Unregistration Confirmation Code to user email!")
                            resetTokens = None
                        else:
                            await ctx.followup.send("Your password has expired. Please use /request_password_reset_token and /change_password to update your password!")
                            print(f"User {ctx.user.name} password expired!\n\n")
                            await LoggingApplicationCommand(ctx, "/remove_admin_account", "user_email -> REDACT, password -> REDACT", "Denied/Expired Password")
                    else:
                        adminAccount["Failed Log In Attempts"] += 1
                        adminAccount["Total Failed Log In Attempts"] += 1
                        if adminAccount["Failed Log In Attempts"] % 7 != 0:
                            await ctx.followup.send(f"Invalid user email or password!!!\nYou have {7 - adminAccount["Failed Log In Attempts"] % 7} attempts left to authenticate!")
                            print(f"User {ctx.user.name} input invalid credentials!\n\n")
                            await LoggingApplicationCommand(ctx, "/remove_admin_account", "user_email -> REDACT, password -> REDACT", "Denied/Bad Credentials")
                        else:
                            adminAccount["Failed Log In Attempts"] = 0
                            adminAccount["Locked Out History"].append(time.ctime(time.time()))
                            adminAccount["Current Account Locked Out Period"] = time.time() + 10800
                            adminAccount["Total Locked Out"] = len(adminAccount["Locked Out History"])
                            adminAccount["Current Admin Session Period"] = {}
                            try:
                                await Cyberbot.get_user(adminAccount["User ID"]).send(f"You received this DM from Cyberbot to notify that your admin account has been locked for 3 hours due too many invalid authentication attempts while using command /remove_admin_account.\nThe current total lock outs associated with your account is: {len(adminAccount['Locked Out History'])}\nAll valid admin sessions are terminated!")
                            except Exception:
                                pass
                            await ctx.followup.send("Too many failed authentication attempts! Your admin account has been locked for 3 hours!")
                            print(f"User {ctx.user.name} input too many invalid authentication attempts, initiating admin account lock out!\n\n")
                            await LoggingApplicationCommand(ctx, "/remove_admin_account", "user_email -> REDACT, password -> REDACT", "Denied/Too Many Bad Credentials Attempts and account has been locked!")
                    async with ConfigLock:
                        async with aiofiles.open(CYBERBOT_CONFIG, "w") as file:
                            await file.write(json.dumps(CyberBotConfigData, indent=4))
                else:
                    hours_remaining = (adminAccount["Current Account Locked Out Period"] - time.time()) / 3600
                    minutes_remaining = round(float(f".{str(hours_remaining).split('.')[1]}") * 60)
                    await ctx.followup.send(f"Your admin account is currently being locked out for {round(hours_remaining // 1)} hour(s) and {minutes_remaining} minute(s)")
                    print(f"User {ctx.user.name} admin account is currently being locked out!\n\n")
                    await LoggingApplicationCommand(ctx, "/remove_admin_account", "user_email -> REDACT, password -> REDACT", "Denied/Admin account currently locked!")
                return
        await ctx.followup.send(f"You do not have a Cyberbot admin account yet! If you want to register one, use command /create_admin_account to register a new Cyberbot admin account!")
        print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")
        await LoggingApplicationCommand(ctx, "/remove_admin_account", "user_email -> REDACT, password -> REDACT", "Denied/User does not have a Cyberbot admin account yet!")
    finally:
        user_email = None
        password = None


@Cyberbot.tree.command(
    name="confirm_delete_admin_account",
    description="Confirm to finalize the deletion of a Cyberbot admin account"
)
@app_commands.describe(
    user_email="Please provide a valid email address to confirm your Cyberbot admin account deletion!",
    otp="Please provide a valid Admin Account Delete Confirmation Token!"
)
async def confirm_delete_admin_account(ctx, user_email: str, otp: str):
    print(f"User {ctx.user.name} initiated /confirm_delete_admin_account command")
    await ctx.response.defer(ephemeral=True)
    emailSHA512Hash = hashlib.sha512(user_email.encode()).hexdigest()
    idx = 0
    accountExist = False
    for adminAccount in CyberBotConfigData["Admins"]:
        if adminAccount["User ID"] == ctx.user.id and adminAccount["User Email"] == emailSHA512Hash:
            accountExist = True
            break
        idx += 1
    if accountExist:
        async with OneTimeTokenLock:
            async with aiofiles.open(ONE_TIME_TOKEN_PATH, "r") as file:
                resetTokens = json.loads(await file.read())
        if emailSHA512Hash in resetTokens["Account Delete Confirmation Token"]:
            if resetTokens["Account Delete Confirmation Token"][emailSHA512Hash][0] == hashlib.sha1(otp.encode()).hexdigest() and time.time() < resetTokens["Account Delete Confirmation Token"][emailSHA512Hash][1]:
                del resetTokens["Account Delete Confirmation Token"][emailSHA512Hash]
                if await asyncio.to_thread(sendEmail, "Admin Account Unregistration Confirmation", "You have requested an unregistration process of your Cyberbot admin account and your request has been approved! All data associated with the account are permanently deleted!", user_email) != "Email sent unsuccessfully!":
                    CyberBotConfigData["Admins"].pop(idx)
                    await ctx.followup.send("Your Cyberbot admin account has been deleted!")
                    print(f"User {ctx.user.name} admin account has been unregistered!\n\n")
                    await LoggingApplicationCommand(ctx, "/confirm_delete_admin_account", f"user_email -> REDACT, otp -> {otp}", "Approved/User admin account deleted!")
                else:
                    await ctx.followup.send("Cyberbot can not send the account deletion confirmation email to you! Please try the command again and ensure that you have not blocked Cyberbot automation email noreplycyberbot7777@gmail.com!")
                    print(f"Error sending email!\n\n")
                    await LoggingApplicationCommand(ctx, "/confirm_delete_admin_account", f"user_email -> REDACT, otp -> {otp}", "Denied/Cyberbot can not send Account Deletion Confirmation email to user email!")
            else:
                await ctx.followup.send(f"The Admin Account Delete Confirmation Token that you provided is invalid or already expired. Please use command /remove_admin_account to obtain a new one again!")
                print(f"No Admin Account Delete Confirmation Token associated with the provided email!\n\n")
                await LoggingApplicationCommand(ctx, "/confirm_delete_admin_account", f"user_email -> REDACT, otp -> {otp}", "Denied/Invalid or expired Admin Account Delete Confirmation Code!")
        else:
            await ctx.followup.send(f"There is no Admin Account Delete Confirmation Token associated with the provided email {user_email}. Please use command /remove_admin_account to obtain one!")
            print(f"No Admin Account Delete Confirmation Token associated with the provided email!\n\n")
            await LoggingApplicationCommand(ctx, "/confirm_delete_admin_account", f"user_email -> REDACT, otp -> {otp}", "Denied/No Admin Account Delete Confirmation Token associated with the provided email!")
        resetTokens = None
        user_email = None
    else:
        await ctx.followup.send(f"You do not have a Cyberbot admin account yet! Use command /create_admin_account to register a new Cyberbot admin account!")
        print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")
        await LoggingApplicationCommand(ctx, "/confirm_delete_admin_account", f"user_email -> REDACT, otp -> {otp}", "Denied/User does not have a Cyberbot admin account yet!")


# Command for server owner and in non-DM with Cyberbot ONLY!!
@Cyberbot.tree.command(
    name="viewing_admins",
    description="Viewing a list of members with Cyberbot admin privilege to your server!"
)
async def viewing_admins(ctx):
    print(f"User {ctx.user.name} initiated /viewing_admins command")
    await ctx.response.defer(ephemeral=True)
    if ctx.user.id == ctx.guild.owner.id:
        members = f"The following members are currently obtaining a Cyberbot admin privilege to this server **{ctx.guild.name}** - ID **{ctx.guild.id}**:\n\nServer Owner Name: **{ctx.user.name}**\nID: **{ctx.user.id}**\n\n"
        for admin in CyberBotConfigData["Admins"]:
            member = Cyberbot.get_user(admin["User ID"])
            if ctx.guild.id in admin["Accessible Servers"] and ctx.guild.owner.id != member.id:
                members += f"Member name: **{member.name}**\nID: **{member.id}**\n\n"
        await ctx.followup.send(members)
        print("List was sent!\n\n")
        await LoggingApplicationCommand(ctx, "/viewing_admins", f"NONE","Approved/A list of user with admin access was sent")
    else:
        await ctx.followup.send("You're not the server's owner, the command /viewing_admins is restricted to server owner ONLY!")
        print(f"User {ctx.user.name} not authorized to execute the command!\n\n")
        await LoggingApplicationCommand(ctx, f"/viewing_admins", "NONE", "Denied/Unauthorized User")


# Command for server owner and in non-DM with Cyberbot ONLY!!
@Cyberbot.tree.command(
    name="adding_admins",
    description="Granting member their admin account access to the server!"
)
@app_commands.describe(
    member="Please mention a member in the server to grant their admin account access!"
)
async def adding_admins(ctx, member: discord.Member):
    print(f"User {ctx.user.name} initiated /adding_admins command")
    await ctx.response.defer(ephemeral=True)
    if ctx.user.id == ctx.guild.owner.id:
        if ctx.guild.me.top_role.position < member.top_role.position and member.id != ctx.guild.owner.id:
            await ctx.followup.send( f"{member.name} can kick Cyberbot out of the server! Therefore their admin account will not be allowed to work in the server! The reason is if their discord account is compromised, the attacker can kick Cyberbot out and does not need to be an admin to disable Cyberbot scan protection! Please ensure that Cyberbot always has the highest role than all the members in the server!")
            print(f"{member.name} can kick Cyberbot out of the server {ctx.guild.name}\n\n")
            await LoggingApplicationCommand(ctx, "/adding_admins", f"member -> {member.name}", f"Denied/Member {member.name} can kick Cyberbot out of the server {ctx.guild.name}")
        else:
            if member.id == ctx.guild.owner.id:
                await ctx.followup.send(f"{member.name} is this server owner and will always have the admin access!")
                print(f"{member.name} is the server owner!\n\n")
                await LoggingApplicationCommand(ctx, "/adding_admins", f"member -> {member.name}", f"Denied/Member is the server owner and already has admin access")
            else:
                for admin in CyberBotConfigData["Admins"]:
                    if admin["User ID"] == member.id:
                        if ctx.guild.id not in admin["Accessible Servers"]:
                            try:
                                await member.send(f"You have been authorized to have a Cyberbot admin account access on server **{ctx.guild.name}** by the server owner **{ctx.user.name}**")
                                admin["Accessible Servers"].append(ctx.guild.id)
                                async with ConfigLock:
                                    async with aiofiles.open(CYBERBOT_CONFIG, "w") as file:
                                        await file.write(json.dumps(CyberBotConfigData, indent=4))
                                await ctx.followup.send(f"{member.name} admin account can now be used in server {ctx.guild.name}")
                                print(f"{member.name} admin access to server {ctx.guild.name} added!\n\n")
                                await LoggingApplicationCommand(ctx, "/adding_admins", f"member -> {member.name}", f"Approved/Access to the server {ctx.guild.name} ID {ctx.guild.id} for Admin User Account {admin['User ID']} added!")
                            except Exception as e:
                                await ctx.followup.send(f"Cyberbot can't register {member.name} admin account!")
                                print(f"Error sending DM message to {member.name}\n\n")
                                await LoggingApplicationCommand(ctx, "/adding_admins", f"member -> {member.name}", f"Denied/Error sending notification {e}")
                        else:
                            await LoggingApplicationCommand(ctx.user.name, f"/adding_admins {member}\nCommand Status: Denied/Admin account already has access to server {ctx.guild.name} ID {ctx.guild.id}")
                            await ctx.followup.send(f"{member.name} admin account already has access to the server!")
                            print(f"{member.name} admin account already has access to the server!\n\n")
                        return
                await ctx.followup.send(f"{member.name} does not have a Cyberbot admin account yet!")
                print(f"{member.name} does not have a Cyberbot admin account!\n\n")
                await LoggingApplicationCommand(ctx, "/adding_admins", f"member -> {member.name}", f"Denied/Mentioned member does not have a Cyberbot admin account yet!")
    else:
        await ctx.followup.send("You're not the server's owner, the command /adding_admins is restricted to server owner ONLY!")
        print(f"User {ctx.user.name} not authorized to execute the command!\n\n")
        await LoggingApplicationCommand(ctx, "/adding_admins", f"member -> {member.name}", "Denied/Unauthorized User")


# Command for server owner ONLY!
@Cyberbot.tree.command(
    name="removing_admins",
    description="Removing a member admin account access to the server!"
)
@app_commands.describe(
    member="Please mention a member in the server to remove their admin account access!"
)
async def removing_admins(ctx, member: discord.Member):
    print(f"User {ctx.user.name} initiated /removing_admins command")
    await ctx.response.defer(ephemeral=True)
    if ctx.user.id == ctx.guild.owner.id:
        if member.id == ctx.guild.owner.id:
            await ctx.followup.send(f"{member.name} is this server owner and will always have the admin access!")
            print(f"{member.name} is the server owner!\n\n")
            await LoggingApplicationCommand(ctx, "/removing_admins", f"member -> {member.name}", "Denied/Member is the server owner, admin access can be removed!")
        else:
            for admin in CyberBotConfigData["Admins"]:
                if admin["User ID"] == member.id:
                    if ctx.guild.id not in admin["Accessible Servers"]:
                        await ctx.followup.send(f"{member.name} admin account already has no access to the server!")
                        print(f"{member.name} admin account already has no access to the server!\n\n")
                        await LoggingApplicationCommand(ctx, "/removing_admins", f"member -> {member.name}", f"Denied/Admin account already has no access to server {ctx.guild.name} ID {ctx.guild.id}")
                    else:
                        try:
                            await member.send(f"Your admin account access on server **{ctx.guild.name}** ID **{ctx.guild.id}** has been removed by the server owner **{ctx.user.name}**")
                            await LoggingApplicationCommand(ctx, "/removing_admins", f"member -> {member.name}", f"Approved/Access to the server {ctx.guild.name} ID {ctx.guild.id} for Admin User Account {admin['User ID']} removed!")
                        except Exception as e:
                            print(f"Error sending DM to {member.name}\n\n")
                            await LoggingApplicationCommand(ctx, "/removing_admins", f"member -> {member.name}", f"Approved/Access to the server {ctx.guild.name} ID {ctx.guild.id} for Admin User Account {admin['User ID']} removed! Cyberbot, however, can not send DM to user!")
                        admin["Accessible Servers"].remove(ctx.guild.id)
                        if admin["Current Admin Session Period"].get(str(ctx.guild.id)):
                            del admin["Current Admin Session Period"][str(ctx.guild.id)]
                        async with ConfigLock:
                            async with aiofiles.open(CYBERBOT_CONFIG, "w") as file:
                                await file.write(json.dumps(CyberBotConfigData, indent=4))
                        await ctx.followup.send(f"{member.name} admin account access removed from the server!")
                        print(f"{member.name} admin access to server {ctx.guild.name} removed!\n\n")
                    return
            await ctx.followup.send(f"{member.name} does not have a Cyberbot admin account yet!")
            print(f"{member.name} does not have a Cyberbot admin account!\n\n")
            await LoggingApplicationCommand(ctx, "/removing_admins", f"member -> {member.name}", "Denied/Mentioned member does not have a Cyberbot admin account yet!")
    else:
        await ctx.followup.send("You're not the server's owner, the command /removing_admins is restricted to server owner ONLY!")
        print(f"User {ctx.user.name} not authorized to execute the command!\n\n")
        await LoggingApplicationCommand(ctx, "/removing_admins", f"member -> {member.name}", "Denied/Unauthorized User")


@Cyberbot.tree.command(
    name="request_password_reset_token",
    description="Request a new password reset token"
)
@app_commands.describe(
    user_email="Please enter the registered email address with your account!"
)
async def request_password_reset_token(ctx, user_email: str):
    print(f"User {ctx.user.name} initiated /request_password_reset_token command")
    await ctx.response.defer(ephemeral=True)
    emailSHA512Hash = hashlib.sha512(user_email.encode()).hexdigest()
    for adminAccount in CyberBotConfigData["Admins"]:
        if ctx.user.id == adminAccount["User ID"]:
            if time.time() > adminAccount["Current Account Locked Out Period"]:
                if adminAccount["User Email"] == emailSHA512Hash:
                    if time.time() >= adminAccount["Credential Minimum Age"]:
                        async with OneTimeTokenLock:
                            async with aiofiles.open(ONE_TIME_TOKEN_PATH, "r") as file:
                                resetTokens = json.loads(await file.read())
                        if emailSHA512Hash in resetTokens["Password Reset Token"]:
                            await ctx.followup.send(f"You just requested a 3 minutes Password Reset OTP code. Please check your email for it or wait until the token expired to request a new one again!")
                            print(f"A still valid Password Reset OTP code already sent!\n\n")
                            await LoggingApplicationCommand(ctx, "/request_password_reset_token", f"user_email -> REDACT", "Denied/A Passord Reset Token already sent to the user email!")
                        else:
                            token = ""
                            for i in range(7, 20):
                                token += random.choice(f"ABCDEFGHIJKLNMOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%&*_+=")
                            if await asyncio.to_thread(sendEmail, "Cyberbot Password Reset Token", f"Your password reset token is {token}, it will expired in 3 minutes!", user_email) == "Email sent successfully!":
                                resetTokens["Password Reset Token"][emailSHA512Hash] = [hashlib.sha1(token.encode()).hexdigest(), time.time() + 180]
                                async with OneTimeTokenLock:
                                    async with aiofiles.open(ONE_TIME_TOKEN_PATH, "w") as file:
                                        await file.write(json.dumps(resetTokens, indent=4))
                                await ctx.followup.send(f"Please check your email {user_email}!")
                                print(f"A new reset token has been sent to user {ctx.user.name} via email {emailSHA512Hash}!\n\n")
                                await LoggingApplicationCommand(ctx, "/request_password_reset_token", f"user_email -> REDACT", "Approved/A reset token has been sent to user email!")
                            else:
                                await ctx.followup.send(f"Cyberbot can't send the password reset OTP code to your account email {user_email}! Please try the command again and ensure that you have not blocked Cyberbot automation email noreplycyberbot7777@gmail.com!")
                                print(f"Can not send email!\n\n")
                                await LoggingApplicationCommand(ctx, "/request_password_reset_token", f"user_email -> REDACT", "Denied/Cyberbot can not send the password reset OTP to user email!")
                        resetTokens = None
                        user_email = None
                    else:
                        await ctx.followup.send(f"You just changed your password. Your password must have a minimum age of 3 hours in order to be able to be changed again!")
                        print(f"User {ctx.user.name} just changed the admin account password!\n\n")
                        await LoggingApplicationCommand(ctx, "/request_password_reset_token", f"user_email -> REDACT", "Denied/User password age not above 3 hours yet")
                else:
                    await ctx.followup.send(f"Your provided email address does not match the email that you used to register your admin account!")
                    print(f"Wrong email address!\n\n")
                    await LoggingApplicationCommand(ctx, "/request_password_reset_token", f"user_email -> REDACT", "Denied/User provide invalid email address!")
            else:
                hours_remaining = (adminAccount["Current Account Locked Out Period"] - time.time()) / 3600
                minutes_remaining = round(float(f".{str(hours_remaining).split('.')[1]}") * 60)
                await ctx.followup.send(f"Your admin account is currently being locked out for {round(hours_remaining // 1)} hour(s) and {minutes_remaining} minute(s)")
                print(f"User {ctx.user.name} admin account is currently being locked out!\n\n")
                await LoggingApplicationCommand(ctx, "/request_password_reset_token", f"user_email -> REDACT", "Denied/Admin account locked!")
            return
    await ctx.followup.send(f"You do not have a Cyberbot admin account yet! Use command /create_admin_account to register a new Cyberbot admin account!")
    print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")
    await LoggingApplicationCommand(ctx, "/request_password_reset_token", f"user_email -> REDACT", "Denied/User does not have a Cyberbot admin account yet!")



@Cyberbot.tree.command(
    name="change_password",
    description="Update your admin account password!"
)
@app_commands.describe(
    passwordresettoken="Please provide a valid password reset token sent to your email",
    accountemail="Please provide a valid email address associated with your admin account",
    custompassword="Create your own password, or let Cyberbot generate and email one to you",
    newpassword="Please provide a new password for your account"
)
async def change_password(ctx, passwordresettoken: str, accountemail: str, custompassword: Literal["False", "True"], newpassword: str = "Default"):
    print(f"User {ctx.user.name} initiated /change_password command")
    await ctx.response.defer(ephemeral=True)
    try:
        emailSHA512Hash = hashlib.sha512(accountemail.encode()).hexdigest()
        for adminAccount in CyberBotConfigData["Admins"]:
            if ctx.user.id == adminAccount["User ID"]:
                if time.time() > adminAccount["Current Account Locked Out Period"]:
                    if time.time() >= adminAccount["Credential Minimum Age"]:
                        if emailSHA512Hash == adminAccount["User Email"]:
                            async with OneTimeTokenLock:
                                async with aiofiles.open(ONE_TIME_TOKEN_PATH, "r") as file:
                                    resetTokens = json.loads(await file.read())
                            if emailSHA512Hash in resetTokens["Password Reset Token"]:
                                if resetTokens["Password Reset Token"][emailSHA512Hash][0] == hashlib.sha1(passwordresettoken.encode()).hexdigest() and time.time() < resetTokens["Password Reset Token"][emailSHA512Hash][1]:
                                    if time.time() >= adminAccount["Credential Minimum Age"]:
                                        async with OneTimeTokenLock:
                                            async with aiofiles.open(ONE_TIME_TOKEN_PATH, "w") as file:
                                                await file.write(json.dumps(resetTokens, indent=4))
                                        update = True
                                        if custompassword == "True":
                                            salt = adminAccount["User Salt"].encode()
                                            hashednewpassword = bcrypt.hashpw(f"{newpassword}{ctx.user.id}".encode(), salt).decode('utf-8')
                                            if len(newpassword) > 30:
                                                await ctx.followup.send("Your new password is too long!")
                                                print(f"User {ctx.user.name} new password too long!\n\n")
                                                update = False
                                                await LoggingApplicationCommand(ctx, "/change_password", f"passwordresettoken -> {passwordresettoken}, accountemail -> REDACT, custompassword -> {custompassword}, newpassword -> {newpassword}", f"Denied/Password too long!")
                                            elif hashednewpassword == adminAccount["User Credential"]:
                                                await ctx.followup.send("Your new password is the same as your old password!")
                                                print(f"User {ctx.user.name} reused password!\n\n")
                                                update = False
                                                await LoggingApplicationCommand(ctx, "/change_password", f"passwordresettoken -> {passwordresettoken}, accountemail -> REDACT, custompassword -> {custompassword}, newpassword -> REDACT", f"Denied/Password is the same as the old one!")
                                            elif hashednewpassword in adminAccount["Previous Credentials Used"]:
                                                await ctx.followup.send("You have used this password before, please set a new password!")
                                                print(f"User {ctx.user.name} reused password!\n\n")
                                                update = False
                                                await LoggingApplicationCommand(ctx, "/change_password", f"passwordresettoken -> {passwordresettoken}, accountemail -> REDACT, custompassword -> {custompassword}, newpassword -> REDACT", f"Denied/Password already been used from the past!")
                                            elif None in [re.search(r'[a-z]', newpassword), re.search(r'[A-Z]', newpassword), re.search(r'\d', newpassword), re.search(r'[!@#$%&*_+=]', newpassword)] or len(newpassword) < 12:
                                                await ctx.followup.send("Your new password password must be:\n"
                                                                        "At least 12 characters\n"
                                                                        "Have mixed case ASCII letters and numbers\n"
                                                                        "Contains any of the following special characters !@#$%&*_+=\n"
                                                                        "Please provide a different password")
                                                print(f"User {ctx.user.name} new password not match the password policy!\n\n")
                                                update = False
                                                await LoggingApplicationCommand(ctx, "/change_password", f"passwordresettoken -> {passwordresettoken}, accountemail -> REDACT, custompassword -> {custompassword}, newpassword -> {newpassword}", f"Denied/Password does not match the password policy")
                                            elif await CheckPasswordPwned(newpassword):
                                                await ctx.followup.send("The new password that you want to set was detected to already existed in a data breach database, please choose a different password!")
                                                print(f"User {ctx.user.name} new password existed in data breach database!\n\n")
                                                update = False
                                                await LoggingApplicationCommand(ctx, "/change_password", f"passwordresettoken -> {passwordresettoken}, accountemail -> REDACT, custompassword -> {custompassword}, newpassword -> {newpassword}", f"Denied/New Password existed in a data breach database")
                                            else:
                                                passwordStrength, probability = await asyncio.to_thread(Prediction, newpassword, BERTtokenizer, BERTPasswordClassifier, "Password Strength", hardware.lower())
                                                if passwordStrength < 3 and probability > 0.5:
                                                    await ctx.followup.send("Your new password contains patterns that Cyberbot pre-trained weak password classifier BERT encoder-transformer flagged as weak password!\nPlease provide a different password")
                                                    print(f"User {ctx.user.name} new password flagged weak by BERT model!\n\n")
                                                    update = False
                                                    await LoggingApplicationCommand(ctx, "/change_password", f"passwordresettoken -> {passwordresettoken}, accountemail -> REDACT, custompassword -> {custompassword}, newpassword -> {newpassword}", f"Denied/BERT model detected password strength at level {passwordStrength} out of 5 levels ranking system with probability value of {f"{probability}"}")
                                                else:
                                                    passwordStrength, probability = await asyncio.to_thread(Prediction, newpassword, AllenAItokenizer, AllenAIPasswordClassifier, "Password Strength", hardware.lower())
                                                    if passwordStrength < 3 and probability > 0.5:
                                                        await ctx.followup.send("Your new password contains patterns that Cyberbot pre-trained weak password classifier Allen AI encoder-transformer flagged as weak password!\nPlease provide a different password")
                                                        print(f"User {ctx.user.name} new password flagged weak by Allen AI model!\n\n")
                                                        update = False
                                                        await LoggingApplicationCommand(ctx, "/change_password", f"passwordresettoken -> {passwordresettoken}, accountemail -> REDACT, custompassword -> {custompassword}, newpassword -> {newpassword}", f" Denied/Allen AI model detected password strength at level {passwordStrength} out of 5 levels ranking system with probability value of {f"{probability}"}")
                                                    elif await GeminiCheckCommonPassword(newpassword):
                                                        await ctx.followup.send("Your new password contains keywords easy to guess or already in a common used password list!\nPlease provide a different password")
                                                        print(f"User {ctx.user.name} new password too common and easy to guess!\n\n")
                                                        update = False
                                                        await LoggingApplicationCommand(ctx, "/change_password", f"passwordresettoken -> {passwordresettoken}, accountemail -> REDACT, custompassword -> {custompassword}, newpassword -> {newpassword}", "Denied/Password too common and easy to guess")
                                        else:
                                            newpassword = await randomPasswordGenerator()
                                            while hashlib.sha512(f"{newpassword}{ctx.user.id}".encode()).hexdigest() == adminAccount["User Credential"] or hashlib.sha512(f"{newpassword}{ctx.user.id}".encode()).hexdigest() in adminAccount["Previous Credentials Used"]:
                                                newpassword = randomPasswordGenerator()
                                            hashednewpassword = hashlib.sha512(f"{newpassword}{ctx.user.id}".encode()).hexdigest()
                                        if update:
                                            del resetTokens["Password Reset Token"][emailSHA512Hash]
                                            adminAccount["Current Admin Session Period"] = {}
                                            adminAccount["User Credential"] = hashednewpassword
                                            adminAccount["Credential Minimum Age"] = time.time() + 10800
                                            adminAccount["Credential Expiration Age"] = time.time() + 15552000
                                            adminAccount["Previous Credentials Used"].append(adminAccount["User Credential"])
                                            async with ConfigLock:
                                                async with aiofiles.open(CYBERBOT_CONFIG, "w") as file:
                                                    await file.write(json.dumps(CyberBotConfigData, indent=4))
                                            if custompassword == "False":
                                                await asyncio.to_thread(sendEmail, "Cyberbot Admin Account Password Updated", f"Your admin account password has been changed to {newpassword}\nPlease delete this email once you have acknowledged your new password change!", accountemail)
                                            await ctx.followup.send(f"Your password has been updated to {newpassword}\nAll of your previous admin log in sessions had been terminated!")
                                            print(f"User {ctx.user.name} admin account updated successfully!\n\n")
                                            await LoggingApplicationCommand(ctx, "/change_password", f"passwordresettoken -> {passwordresettoken}, accountemail -> REDACT, custompassword -> {custompassword}, newpassword -> REDACT", "Approved/Admin account password updated")
                                            return
                                    else:
                                        await ctx.followup.send(f"You just changed your password. Your password must have a minimum age of 3 hours in order to be able to be changed again!")
                                        print(f"User {ctx.user.name} just changed the admin account password!\n\n")
                                        await LoggingApplicationCommand(ctx, "/change_password", f"passwordresettoken -> {passwordresettoken}, accountemail -> REDACT, custompassword -> {custompassword}, newpassword -> REDACT", "Denied/User password age not above 3 hours yet")
                                else:
                                    await ctx.followup.send(f"The reset token provided is invalid or expired. Please request a new one again!")
                                    print(f"User {ctx.user.name} password reset token Expired/Invalid!\n\n")
                                    await LoggingApplicationCommand(ctx, "/change_password", f"passwordresettoken -> {passwordresettoken}, accountemail -> REDACT, custompassword -> {custompassword}, newpassword -> REDACT", "Denied/Expired or Invalid Password Reset Token")
                            else:
                                await ctx.followup.send(f"You have not request a reset token yet or the token is expired! Please use the command /request_password_reset_token to request one!")
                                print(f"User {ctx.user.name} did not request a password reset token yet!\n\n")
                                await LoggingApplicationCommand(ctx, "/change_password", f"passwordresettoken -> {passwordresettoken}, accountemail -> REDACT, custompassword -> {custompassword}, newpassword -> REDACT", "Denied/No Password Reset Token Request Yet")
                            resetTokens = None
                        else:
                            await ctx.followup.send("Your email address is wrong!")
                            print(f"User {ctx.user.name} provided wrong email address!\n\n")
                            await LoggingApplicationCommand(ctx, "/change_password", f"passwordresettoken -> {passwordresettoken}, accountemail -> REDACT, custompassword -> {custompassword}, newpassword -> REDACT", "Denied/Wrong Email Address")
                    else:
                        await ctx.followup.send(f"You just changed your password. Your password must have a minimum age of 3 hours in order to be able to be changed again!")
                        print(f"User {ctx.user.name} just changed the admin account password!\n\n")
                        await LoggingApplicationCommand(ctx, "/change_password", f"passwordresettoken -> {passwordresettoken}, accountemail -> REDACT, custompassword -> {custompassword}, newpassword -> REDACT", "Denied/User password age not above 3 hours yet")
                else:
                    hours_remaining = (adminAccount["Current Account Locked Out Period"] - time.time()) / 3600
                    minutes_remaining = round(float(f".{str(hours_remaining).split('.')[1]}") * 60)
                    await ctx.followup.send(f"Your admin account is currently being locked out for {round(hours_remaining // 1)} hour(s) and {minutes_remaining} minute(s)")
                    print(f"User {ctx.user.name} admin account is currently being locked out!\n\n")
                    await LoggingApplicationCommand(ctx, "/change_password", f"passwordresettoken -> {passwordresettoken}, accountemail -> REDACT, custompassword -> {custompassword}, newpassword -> REDACT", "Denied/Admin account locked!")
                return
        await ctx.followup.send(f"You do not have a Cyberbot admin account yet! Use command /create_admin_account to register a new Cyberbot admin account!")
        print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")
        await LoggingApplicationCommand(ctx, "/change_password", f"passwordresettoken -> {passwordresettoken}, accountemail -> REDACT, custompassword -> {custompassword}, newpassword -> REDACT", "Denied/User does not have a Cyberbot admin account yet!")
    finally:
        passwordresettoken = None
        accountemail = None
        newpassword = None


# Command for Admins and in non-DM with Cyberbot ONLY!
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
    try:
        emailSHA512Hash = hashlib.sha512(accountemail.encode()).hexdigest()
        if str(ctx.channel.type).startswith("private"):
            await ctx.followup.send("/admin_log_in can only be used in server channels!")
            print(f"Command forbidden to execute in DM channel!\n\n")
            await LoggingApplicationCommand(ctx, "/admin_log_in", f"accountemail -> REDACT, accountpassword -> REDACT", "Denied/Command runs in DM channel")
        else:
            for adminAccount in CyberBotConfigData["Admins"]:
                if adminAccount["User ID"] == ctx.user.id:
                    if time.time() > adminAccount["Current Account Locked Out Period"]:
                        if str(ctx.guild.id) in adminAccount["Current Admin Session Period"]:
                            if time.time() < adminAccount["Current Admin Session Period"][str(ctx.guild.id)]:
                                await ctx.followup.send("You already logged in! If you want to log out, please use the command /admin_log_out")
                                print(f"User {ctx.user.name} already logged in as an admin in the server!\n\n")
                                await LoggingApplicationCommand(ctx, f"/admin_log_in", f"accountemail -> REDACT, accountpassword -> REDACT", "Denied/User already logged in")
                                return
                        salt = adminAccount["User Salt"].encode()
                        hashedPassword = bcrypt.hashpw(f"{accountpassword}{ctx.user.id}".encode(), salt).decode('utf-8')
                        if adminAccount["User Email"] == emailSHA512Hash and adminAccount["User Credential"] == hashedPassword:
                            adminAccount["Failed Log In Attempts"] = 0
                            if time.time() < adminAccount["Credential Expiration Age"]:
                                if ctx.guild.id in adminAccount["Accessible Servers"] or ctx.user.id == ctx.guild.owner.id:
                                    adminAccount["Current Admin Session Period"][str(ctx.guild.id)] = time.time() + 3600
                                    adminAccount["Last Time Logged In"] = time.ctime(time.time())
                                    await ctx.followup.send("Cyberbot will now recognize you as an admin for 1 hour in this server before requiring you to log in again!")
                                    print(f"User {ctx.user.name} logged in as an admin in the server!\n\n")
                                    await LoggingApplicationCommand(ctx, f"/admin_log_in", f"accountemail -> REDACT, accountpassword -> REDACT", f"Approved/New 1 hour admin session with admin account {adminAccount['User ID']} in server {ctx.guild.name} ID {ctx.user.id} created")
                                else:
                                    await ctx.followup.send(f"Your admin account is not permitted to access in this server, please contact the server owner {ctx.guild.owner.name} to give you admin account access to the server!")
                                    print(f"User {ctx.user.name} does not have admin account access to the server!\n\n")
                                    await LoggingApplicationCommand(ctx, f"/admin_log_in", f"accountemail -> REDACT, accountpassword -> REDACT", f"Denied/User does not have admin account access to the server!")
                            else:
                                await ctx.followup.send("Your password has expired. Please use /request_password_reset_token and /change_password to update your password!")
                                print(f"User {ctx.user.name} password expired!\n\n")
                                await LoggingApplicationCommand(ctx, f"/admin_log_in", f"accountemail -> REDACT, accountpassword -> REDACT", "Denied/Expired Password")
                        else:
                            adminAccount["Failed Log In Attempts"] += 1
                            adminAccount["Total Failed Log In Attempts"] += 1
                            if adminAccount["Failed Log In Attempts"] % 7 != 0:
                                await ctx.followup.send(f"Invalid user email or password!!!\nYou have {7 - adminAccount["Failed Log In Attempts"] % 7} attempts left to log in!")
                                print(f"User {ctx.user.name} input invalid credentials!\n\n")
                                await LoggingApplicationCommand(ctx, f"/admin_log_in", f"accountemail -> REDACT, accountpassword -> REDACT", "Denied/Bad Credentials")
                            else:
                                adminAccount["Failed Log In Attempts"] = 0
                                adminAccount["Locked Out History"].append(time.ctime(time.time()))
                                adminAccount["Current Account Locked Out Period"] = time.time() + 10800
                                adminAccount["Total Locked Out"] = len(adminAccount["Locked Out History"])
                                adminAccount["Current Admin Session Period"] = {}
                                try:
                                    await Cyberbot.get_user(adminAccount["User ID"]).send(f"You received this DM from Cyberbot to notify that your admin account has been locked for 3 hours due too many invalid authentication attempts while using command /admin_log_in.\nThe current total lock outs associated with your account is: {len(adminAccount['Locked Out History'])}\nAll valid admin sessions are terminated!")
                                except Exception:
                                    pass
                                await ctx.followup.send("Too many failed login attempts! Your admin account has been locked for 3 hours!")
                                print(f"User {ctx.user.name} input too many invalid log in attempts, initiating admin account lock out!\n\n")
                                await LoggingApplicationCommand(ctx, f"/admin_log_in", f"accountemail -> REDACT, accountpassword -> REDACT", "Denied/Too Many Bad Credentials and account has been locked!")
                        async with ConfigLock:
                            async with aiofiles.open(CYBERBOT_CONFIG, "w") as file:
                                await file.write(json.dumps(CyberBotConfigData, indent=4))
                    else:
                        hours_remaining = (adminAccount["Current Account Locked Out Period"] - time.time()) / 3600
                        minutes_remaining = round(float(f".{str(hours_remaining).split('.')[1]}") * 60)
                        await ctx.followup.send(f"Your admin account is currently being locked out for {round(hours_remaining // 1)} hour(s) and {minutes_remaining} minute(s)")
                        print(f"User {ctx.user.name} admin account is currently being locked out!\n\n")
                        await LoggingApplicationCommand(ctx, f"/admin_log_in", f"accountemail -> REDACT, accountpassword -> REDACT", "Denied/Admin account locked!")
                    return
            await ctx.followup.send( f"You do not have a Cyberbot admin account yet! Use command /create_admin_account to register a new Cyberbot admin account!")
            print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")
            await LoggingApplicationCommand(ctx, f"/admin_log_in", f"accountemail -> REDACT, accountpassword -> REDACT", "Denied/User does not have a Cyberbot admin account yet!")
    finally:
        accountemail = None
        accountpassword = None
        hashedPassword = None


# Command for Admins and in non-DM with Cyberbot ONLY!
@Cyberbot.tree.command(
    name="admin_log_out",
    description="Logging out of your current Cyberbot admin account session in the server"
)
async def admin_log_out(ctx):
    print(f"User {ctx.user.name} initiated /admin_log_out command")
    await ctx.response.defer(ephemeral=True)
    if str(ctx.channel.type).startswith("private"):
        await ctx.followup.send("/admin_log_out can only be used in server channels!")
        print(f"Command forbidden to execute in DM channel!\n\n")
        await LoggingApplicationCommand(ctx, f"/admin_log_out", "NONE", "Denied/Command runs in DM channel")
    else:
        for adminAccount in CyberBotConfigData["Admins"]:
            if ctx.user.id == adminAccount["User ID"]:
                if str(ctx.guild.id) in adminAccount["Current Admin Session Period"]:
                    del adminAccount["Current Admin Session Period"][str(ctx.guild.id)]
                    async with ConfigLock:
                        async with aiofiles.open(CYBERBOT_CONFIG, "w") as file:
                            await file.write(json.dumps(CyberBotConfigData, indent=4))
                    await ctx.followup.send("You have been logged out of your Cyberbot admin session with this server!")
                    print(f"User {ctx.user.name} admin account logged out successfully!\n\n")
                    await LoggingApplicationCommand(ctx, f"/admin_log_out", "NONE", "Approved")
                else:
                    await ctx.followup.send("You do not have any admin account session in this server!")
                    print(f"User {ctx.user.name} not currently logged in as an admin in server!\n\n")
                    await LoggingApplicationCommand(ctx, f"/admin_log_out", "NONE", "Denied/User not logged in")
                return
        await ctx.followup.send("You do not have a Cyberbot admin account yet! Use command /create_admin_account to register a new Cyberbot admin account!")
        print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")
        await LoggingApplicationCommand(ctx, f"/admin_log_out", "NONE", "Denied/User does not have a Cyberbot admin account yet!")


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
        print(f"Command forbidden to execute in DM channel!\n\n")
        await LoggingApplicationCommand(ctx, "/cyberbot_config", f"configuration -> {configuration}, action -> {action}", "Denied/Command runs in DM channel")
    else:
        for adminAccount in CyberBotConfigData["Admins"]:
            if ctx.user.id == adminAccount["User ID"]:
                if ctx.guild.id in adminAccount["Accessible Servers"] or ctx.user.id == ctx.guild.owner.id:
                    if str(ctx.guild.id) in adminAccount["Current Admin Session Period"]:
                        if time.time() < adminAccount["Current Admin Session Period"][str(ctx.guild.id)]:
                            if action == "ENABLE":
                                CyberBotConfigData[configuration][str(ctx.guild.id)] = "True"
                            else:
                                CyberBotConfigData[configuration][str(ctx.guild.id)] = "False"
                            await ctx.followup.send("DONE")
                            await ctx.followup.send(f"{configuration} for this server has been {'enabled' if (CyberBotConfigData[configuration][str(ctx.guild.id)] == "True") else 'disabled'} by user {ctx.user.mention}!")
                            print(f"{configuration} been reconfigured!\n\n")
                            await LoggingApplicationCommand(ctx, "/cyberbot_config", f"configuration -> {configuration}, action -> {action}", f"Approved/{configuration} {action} in server {ctx.guild.name} - ID {ctx.guild.id}")
                        else:
                            del adminAccount["Current Admin Session Period"][str(ctx.guild.id)]
                            await ctx.followup.send(f"Your admin session with this server has expired! Please logging in again.")
                            print(f"User admin session expired!\n\n")
                            await LoggingApplicationCommand(ctx, "/cyberbot_config", f"configuration -> {configuration}, action -> {action}", "Denied/Admin session expired")
                    else:
                        await ctx.followup.send(f"You need to use /admin_log_in to log in as an admin in this server to execute this command!")
                        print(f"User {ctx.user.name} need to log in as an admin!\n\n")
                        await LoggingApplicationCommand(ctx, "/cyberbot_config", f"configuration -> {configuration}, action -> {action}", "Denied/User need to log in as an admin")
                    async with ConfigLock:
                        async with aiofiles.open(CYBERBOT_CONFIG, "w") as file:
                            await file.write(json.dumps(CyberBotConfigData, indent=4))
                else:
                    await ctx.followup.send(f"You do not have an admin account access to the server, please contact the server owner {ctx.guild.owner.name} to add your admin account access to the server!")
                    print(f"User {ctx.user.name} not authorized to execute the command!\n\n")
                    await LoggingApplicationCommand(ctx, "/cyberbot_config", f"configuration -> {configuration}, action -> {action}", "Denied/User does not have admin account access to the server!")
                return
        await ctx.followup.send("You do not have a Cyberbot admin account yet! Use command /create_admin_account to register a new Cyberbot admin account!")
        print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")
        await LoggingApplicationCommand(ctx, "/cyberbot_config", f"configuration -> {configuration}, action -> {action}", "Denied/User does not have a Cyberbot admin account yet!")


# Command for Admins and in non-DM with Cyberbot ONLY!
@Cyberbot.tree.command(
    name="viewing_cyberbot_configuration",
    description="Checking Cyberbot current configuration in the server"
)
async def viewing_cyberbot_configuration(ctx):
    print(f"User {ctx.user.name} initiated /viewing_cyberbot_configurationcommand")
    await ctx.response.defer(ephemeral=True)
    if str(ctx.channel.type).startswith("private"):
        await ctx.followup.send("/viewing_cyberbot_configuration can only be used in server channels!")
        print(f"Command forbidden to execute in DM channel!\n\n")
        await LoggingApplicationCommand(ctx, "/viewing_cyberbot_configuration", f"NONE", "Denied/Command runs in DM channel")
    else:
        for adminAccount in CyberBotConfigData["Admins"]:
            if ctx.user.id == adminAccount["User ID"]:
                if ctx.guild.id in adminAccount["Accessible Servers"] or ctx.user.id == ctx.guild.owner.id:
                    if str(ctx.guild.id) in adminAccount["Current Admin Session Period"]:
                        if time.time() < adminAccount["Current Admin Session Period"][str(ctx.guild.id)]:
                            # Adding new detected server ID
                            if str(ctx.guild.id) not in CyberBotConfigData["Automation-Mode"]:
                                CyberBotConfigData["Automation-Mode"][str(ctx.guild.id)] = "True"
                            if str(ctx.guild.id) not in CyberBotConfigData["Silent-Mode"]:
                                CyberBotConfigData["Silent-Mode"][str(ctx.guild.id)] = "False"
                            if str(ctx.guild.id) not in CyberBotConfigData["Non-monitoring-Channels"]:
                                CyberBotConfigData["Non-monitoring-Channels"][str(ctx.guild.id)] = []
                            async with ConfigLock:
                                async with aiofiles.open(CYBERBOT_CONFIG, "w") as file:
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
                                        async with aiofiles.open(CYBERBOT_CONFIG, "w") as file:
                                            await file.write(json.dumps(CyberBotConfigData, indent=4))
                            await ctx.followup.send(
                                f"Automation scan mode for this server is **{CyberBotConfigData["Automation-Mode"][str(ctx.guild.id)]}**\n"
                                f"Silent scan mode for this server is **{CyberBotConfigData["Silent-Mode"][str(ctx.guild.id)]}**\n"
                                f"{nonMonitoringChannels}")
                            print(f"Cyberbot Server Configuration settings has been displayed to user!\n\n")
                            await LoggingApplicationCommand(ctx, "/viewing_cyberbot_configuration", f"NONE", "Approved/Cyberbot's Server Configuration settings has been displayed to user")
                        else:
                            del adminAccount["Current Admin Session Period"][str(ctx.guild.id)]
                            await ctx.followup.send(f"Your admin session with this server has expired! Please logging in again.")
                            print(f"User admin session expired!\n\n")
                            async with ConfigLock:
                                async with aiofiles.open(CYBERBOT_CONFIG, "w") as file:
                                    await file.write(json.dumps(CyberBotConfigData, indent=4))
                            await LoggingApplicationCommand(ctx, "/viewing_cyberbot_configuration", f"NONE", "Denied/Admin session expired")
                    else:
                        await ctx.followup.send(f"You need to use /admin_log_in to log in as an admin in this server to execute this command!")
                        print(f"User {ctx.user.name} need to log in as an admin!\n\n")
                        await LoggingApplicationCommand(ctx, "/viewing_cyberbot_configuration", f"NONE", "Denied/User need to log in as an admin")
                else:
                    await ctx.followup.send(f"You do not have an admin account access to the server, please contact the server owner {ctx.guild.owner.name} to add your admin account access to the server!")
                    print(f"User {ctx.user.name} not authorized to execute the command!\n\n")
                    await LoggingApplicationCommand(ctx, "/viewing_cyberbot_configuration", f"NONE", "Denied/User does not have admin account access to the server!")
                return
        await ctx.followup.send("You do not have a Cyberbot admin account yet! Use command /create_admin_account to register a new Cyberbot admin account!")
        print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")
        await LoggingApplicationCommand(ctx, "/viewing_cyberbot_configuration", f"NONE", "Denied/User does not have a Cyberbot admin account yet!")


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
        print(f"Command forbidden to execute in DM channel!\n\n")
        await LoggingApplicationCommand(ctx,"/non_monitoring_channel", f"action - {action}", f"Denied/Command runs in DM channel")
    else:
        for adminAccount in CyberBotConfigData["Admins"]:
            if ctx.user.id == adminAccount["User ID"]:
                if ctx.guild.id in adminAccount["Accessible Servers"] or ctx.user.id == ctx.guild.owner.id:
                    if str(ctx.guild.id) in adminAccount["Current Admin Session Period"]:
                        if time.time() < adminAccount["Current Admin Session Period"][str(ctx.guild.id)]:
                            if not str(ctx.guild.id) in CyberBotConfigData["Non-monitoring-Channels"]:
                                CyberBotConfigData["Non-monitoring-Channels"][str(ctx.guild.id)] = []
                            if action == "ADD":
                                if ctx.channel.id not in CyberBotConfigData["Non-monitoring-Channels"][str(ctx.guild.id)]:
                                    CyberBotConfigData["Non-monitoring-Channels"][str(ctx.guild.id)].append(ctx.channel.id)
                                    await ctx.followup.send(f"Channel '{ctx.channel.name}' - ID {ctx.channel.id} has been added to the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                                    await ctx.followup.send(f"Channel '{ctx.channel.name}' - ID {ctx.channel.id} has been added to the server non monitoring channel list by user {ctx.user.mention}!")
                                    await LoggingApplicationCommand(ctx,"/non_monitoring_channel", f"action - {action}", f"Approved/Channel '{ctx.channel.name}' - ID {ctx.channel.id} has been added to the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                                else:
                                    await ctx.followup.send(f"Channel '{ctx.channel.name}' - ID {ctx.channel.id} already been added to the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                                    await LoggingApplicationCommand(ctx,"/non_monitoring_channel", f"action - {action}", f"Denied/Channel '{ctx.channel.name}' - ID {ctx.channel.id} already been added to the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                            else:
                                if ctx.channel.id in CyberBotConfigData["Non-monitoring-Channels"][str(ctx.guild.id)]:
                                    CyberBotConfigData["Non-monitoring-Channels"][str(ctx.guild.id)].remove(ctx.channel.id)
                                    await ctx.followup.send(f"Channel '{ctx.channel.name}' - ID {ctx.channel.id} has been removed from the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                                    await ctx.followup.send(f"Channel '{ctx.channel.name}' - ID {ctx.channel.id} has been removed from the server non monitoring channel list by user {ctx.user.mention}!")
                                    await LoggingApplicationCommand(ctx,"/non_monitoring_channel", f"action - {action}", f"Approved/Channel '{ctx.channel.name}' - ID {ctx.channel.id} has been removed from the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                                else:
                                    await ctx.followup.send(f"Channel '{ctx.channel.name}' - ID {ctx.channel.id} already been removed from the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                                    await LoggingApplicationCommand(ctx,"/non_monitoring_channel", f"action - {action}", f"Denied/Channel '{ctx.channel.name}' - ID {ctx.channel.id} already been removed from the server '{ctx.guild.name}' - ID {ctx.guild.id} non monitoring channel list!")
                            print(f"Command Execution Success!\n\n")
                        else:
                            del adminAccount["Current Admin Session Period"][str(ctx.guild.id)]
                            await ctx.followup.send(f"Your admin session with this server has expired! Please logging in again.")
                            print(f"User admin session expired!\n\n")
                            await LoggingApplicationCommand(ctx,"/non_monitoring_channel", f"action - {action}", "Denied/Admin session expired")
                        async with ConfigLock:
                            async with aiofiles.open(CYBERBOT_CONFIG, "w") as file:
                                await file.write(json.dumps(CyberBotConfigData, indent=4))
                    else:
                        await ctx.followup.send(f"You need to use /admin_log_in to log in as an admin in this server to execute this command!")
                        print(f"User {ctx.user.name} need to log in as an admin!\n\n")
                        await LoggingApplicationCommand(ctx,"/non_monitoring_channel", f"action - {action}", "Denied/User need to log in as an admin")
                else:
                    await ctx.followup.send(f"You do not have an admin account access to the server, please contact the server owner {ctx.guild.owner.name} to create an admin account for you!")
                    print(f"User {ctx.user.name} not authorized to execute the command!\n\n")
                    await LoggingApplicationCommand(ctx,"/non_monitoring_channel", f"action - {action}", "Denied/User does not have admin account access to the server!")
                return
        await ctx.followup.send("You do not have a Cyberbot admin account yet! Use command /create_admin_account to register a new Cyberbot admin account!")
        print(f"{ctx.user.name} does not have a Cyberbot admin account!\n\n")
        await LoggingApplicationCommand(ctx,"/non_monitoring_channel", f"action - {action}", "Denied/User does not have a Cyberbot admin account yet!")
