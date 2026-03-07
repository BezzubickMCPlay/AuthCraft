# AuthCraft Player Guide

## How to Register, Login, and Protect Your Account

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Registration](#registration)
3. [Login](#login)
4. [Two-Factor Authentication](#two-factor-authentication)
5. [Account Security](#account-security)
6. [Troubleshooting](#troubleshooting)
7. [FAQ](#faq)

---

## Getting Started

Welcome! This guide will help you secure your Minecraft account on servers using AuthCraft.

### What is AuthCraft?

AuthCraft is a security plugin that protects your account with:
- **Secure password storage** - Your password is encrypted with bank-grade security
- **Two-factor authentication** - Optional extra protection for your account
- **Session management** - Stay logged in without re-entering your password

### First Time on the Server?

When you join for the first time, you'll see a message asking you to register:

```
Welcome to the server!
Please register using: /register <password> <confirmPassword>
```

---

## Registration

### Step 1: Choose a Strong Password

A strong password should have:
- At least 8 characters
- Mix of uppercase and lowercase letters
- Numbers and special characters
- No personal information

**Good passwords:**
- `MyS3cur3P@ss!`
- `Minecraft_2024_Safe`
- `Tr0ub4dor&Horse`

**Bad passwords:**
- `password`
- `12345678`
- `minecraft`
- Your username

### Step 2: Register Your Account

Type in chat:
```
/register MyS3cur3P@ss! MyS3cur3P@ss!
```

Replace `MyS3cur3P@ss!` with your chosen password.

### Step 3: Success!

If successful, you'll see:
```
Account registered successfully!
Please login using: /login <password>
```

### Password Requirements

Your password must meet these requirements:
- Minimum 8 characters
- Maximum 128 characters
- Cannot contain your username
- Not in common password list
- Sufficient complexity (entropy)

---

## Login

### Regular Login

After registering, login each time you join:
```
/login MyS3cur3P@ss!
```

### Session Restoration

If you've logged in before, you might be automatically logged in:
```
Session restored! Welcome back!
```

This happens when:
- You logged in recently
- You're using the same IP address
- Your session hasn't expired

### Failed Login

If you enter the wrong password:
```
Invalid password! Attempts remaining: 4
```

**Warning:** After 5 failed attempts, your account will be temporarily locked.

---

## Two-Factor Authentication

Two-factor authentication (2FA) adds an extra layer of security to your account.

### Available Methods

| Method | Description | Security Level |
|--------|-------------|----------------|
| TOTP | Google Authenticator app | ⭐⭐⭐⭐⭐ |
| Telegram | Telegram bot confirmation | ⭐⭐⭐⭐ |
| VK | VKontakte messages | ⭐⭐⭐⭐ |
| Email | Email verification codes | ⭐⭐⭐ |

### Enabling TOTP (Recommended)

1. **Install an authenticator app:**
   - Google Authenticator (Android/iOS)
   - Authy (Android/iOS/Desktop)
   - Microsoft Authenticator (Android/iOS)

2. **Enable 2FA:**
   ```
   /2fa enable totp
   ```

3. **Scan the QR code:**
   - A clickable link will appear in chat
   - Click it to open the QR code
   - Scan with your authenticator app

4. **Verify setup:**
   - Enter the 6-digit code from your app
   ```
   /2fa verify 123456
   ```

5. **Save backup codes:**
   ```
   /2fa backup
   ```
   Write these codes down and keep them safe!

### Enabling Telegram 2FA

1. **Enable Telegram 2FA:**
   ```
   /2fa enable telegram
   ```

2. **Start the bot:**
   - You'll receive a link to the server's Telegram bot
   - Open the link and click "Start"

3. **Link your account:**
   - Send the verification code shown in-game to the bot

4. **Confirm:**
   - You'll receive a confirmation message in Telegram

### Enabling VK 2FA

1. **Enable VK 2FA:**
   ```
   /2fa enable vk
   ```

2. **Open VK:**
   - You'll receive a link to the server's VK group
   - Send the verification code to the group

3. **Confirm:**
   - You'll receive a confirmation message in VK

### Enabling Email 2FA

1. **Enable Email 2FA:**
   ```
   /2fa enable email
   ```

2. **Enter your email:**
   ```
   /2fa email your-email@example.com
   ```

3. **Verify:**
   - Check your email for a verification code
   - Enter the code in-game

### Using 2FA at Login

When 2FA is enabled, after entering your password:
```
2FA required! Please enter code from your authenticator.
Use: /2fa verify <code>
```

Enter the code from your app:
```
/2fa verify 123456
```

### Managing 2FA

**Check status:**
```
/2fa status
```

**Disable a method:**
```
/2fa disable totp
```

**Get new backup codes:**
```
/2fa backup
```

### Backup Codes

Backup codes are used when you lose access to your 2FA method.

**Important:**
- You get 10 backup codes
- Each code can only be used once
- Store them securely (not in your Minecraft screenshots!)
- Generate new codes if you run low

**Using a backup code:**
```
/2fa verify ABCD-1234
```

---

## Account Security

### Changing Your Password

```
/changepassword OldP@ss! NewP@ss123!
```

Requirements for new password are the same as registration.

### Logging Out

To logout (required on some servers before leaving):
```
/logout
```

### Security Tips

1. **Use a unique password** - Don't reuse passwords from other services

2. **Enable 2FA** - Especially important for accounts with valuable items

3. **Keep backup codes safe** - Write them down, don't screenshot them

4. **Don't share your password** - Server staff will never ask for your password

5. **Use a password manager** - To generate and store strong passwords

6. **Check login notifications** - If you receive a login alert that wasn't you, change your password immediately

---

## Troubleshooting

### "Invalid password" but I'm sure it's correct

1. Check caps lock is off
2. Make sure you're using the right account
3. Contact an admin if you're locked out

### "Account locked"

Wait for the lockout to expire (usually 5-30 minutes) or contact an admin.

### "2FA code invalid"

1. Make sure your device's time is synchronized
2. Wait for a new code (codes change every 30 seconds)
3. Use a backup code if available

### Lost access to 2FA

1. Use a backup code
2. If no backup codes, contact an admin with proof of ownership

### "Session expired"

Simply login again:
```
/login YourP@ssword
```

### "IP changed, please login again"

This happens when your IP changes. Just login again.

---

## FAQ

### Q: Do I need to register every time I join?

**A:** No. You only register once. After that, just login.

### Q: Can I have multiple accounts?

**A:** Most servers limit accounts per IP (usually 3). Check server rules.

### Q: What happens if I forget my password?

**A:** Contact a server administrator. They can reset your password.

### Q: Is my password safe?

**A:** Yes! AuthCraft uses Argon2id, a bank-grade encryption algorithm. Even server admins cannot see your password.

### Q: Can I use the same password as other servers?

**A:** It's not recommended. If one server is compromised, all your accounts could be at risk.

### Q: What's the best 2FA method?

**A:** TOTP (Google Authenticator) is the most secure and doesn't require internet to generate codes.

### Q: Can I use multiple 2FA methods?

**A:** Yes! You can enable all methods for maximum security.

### Q: How long does my session last?

**A:** Usually 7 days, but it depends on server configuration.

### Q: Why was I kicked from the server?

**A:** Possible reasons:
- Didn't login in time
- Too many failed attempts
- Server restart
- Connection issues

---

## Quick Reference

| Command | Description |
|---------|-------------|
| `/register <pass> <pass>` | Create account |
| `/login <password>` | Login |
| `/changepassword <old> <new>` | Change password |
| `/2fa enable <method>` | Enable 2FA |
| `/2fa disable <method>` | Disable 2FA |
| `/2fa status` | Check 2FA status |
| `/2fa verify <code>` | Verify 2FA code |
| `/2fa backup` | Get backup codes |
| `/logout` | Logout |

---

## Need Help?

- **In-game:** Ask a server administrator
- **Discord:** Join the server's Discord
- **Website:** Check the server's website for support

---

*Stay safe and enjoy your game!*
