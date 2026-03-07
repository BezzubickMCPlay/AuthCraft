# AuthCraft Server Administrator Guide

## Complete Setup and Configuration Guide

---

## Table of Contents

1. [Introduction](#introduction)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Initial Configuration](#initial-configuration)
5. [Database Setup](#database-setup)
6. [Two-Factor Authentication](#two-factor-authentication)
7. [Security Features](#security-features)
8. [Integrations](#integrations)
9. [Commands Reference](#commands-reference)
10. [Permissions](#permissions)
11. [Troubleshooting](#troubleshooting)
12. [Migration](#migration)
13. [Backup and Recovery](#backup-and-recovery)

---

## Introduction

AuthCraft is a professional authentication plugin for Minecraft servers running in offline mode. This guide will walk you through the complete setup process, from installation to advanced configuration.

### What AuthCraft Does

- **Secure Registration/Login**: Bank-grade password hashing with Argon2id
- **Two-Factor Authentication**: TOTP, Telegram, VK, Email
- **Bot Protection**: Advanced AntiBot with pattern analysis
- **GeoIP Filtering**: Block connections by country
- **Security Auditing**: Automatic security checks on startup
- **Session Management**: Secure persistent sessions

---

## Requirements

### Server Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Java Version | 17+ | 21+ |
| RAM | 512MB | 1GB+ |
| Disk Space | 50MB | 100MB+ |
| CPU | 2 cores | 4+ cores |

### Supported Platforms

| Platform | Versions | Status |
|----------|----------|--------|
| Paper | 1.8.8 - 1.21 | ✅ Full Support |
| Spigot | 1.16+ | ✅ Full Support |
| Bukkit | 1.16+ | ✅ Full Support |
| BungeeCord | #1700+ | ✅ Full Support |
| Velocity | 3.0+ | ✅ Full Support |

### Database Support

- **SQLite** (default, no setup required)
- **MySQL** 5.7+
- **PostgreSQL** 12+

---

## Installation

### Step 1: Download

Download the latest release from GitHub:

```bash
# Using wget
wget https://github.com/authcraft/authcraft/releases/latest/download/AuthCraft.jar

# Using curl
curl -L -o AuthCraft.jar https://github.com/authcraft/authcraft/releases/latest/download/AuthCraft.jar
```

### Step 2: Install

Copy the JAR file to your plugins folder:

```bash
# For Bukkit/Spigot/Paper
cp AuthCraft.jar /path/to/server/plugins/

# For BungeeCord
cp AuthCraft.jar /path/to/bungee/plugins/

# For Velocity
cp AuthCraft.jar /path/to/velocity/plugins/
```

### Step 3: First Startup

1. Start your server
2. Wait for AuthCraft to generate default configuration
3. Stop the server
4. Edit `plugins/AuthCraft/config.yml`

### Step 4: Verify Installation

Check console output for:

```
[AuthCraft] AuthCraft v1.0 enabled
[AuthCraft] Database initialized: SQLite
[AuthCraft] Security audit: 0 critical, X warnings
```

---

## Initial Configuration

### Basic config.yml Structure

```yaml
# ═══════════════════════════════════════════════════════════
#                    AuthCraft Configuration
# ═══════════════════════════════════════════════════════════

# General Settings
general:
  # Language: en, ru, de, fr, es, zh
  language: en
  # Debug mode (enable for troubleshooting)
  debug: false

# Database Configuration
database:
  # Type: sqlite, mysql, postgresql
  type: sqlite
  
  # MySQL/PostgreSQL settings (ignored for SQLite)
  host: localhost
  port: 3306
  name: authcraft
  username: minecraft
  password: your_secure_password
  
  # Connection pool settings
  pool:
    max_connections: 10
    min_idle: 2
    connection_timeout: 30000

# Password Settings
password:
  # Minimum password length (6-32)
  min_length: 8
  # Maximum password length
  max_length: 128
  # Minimum entropy score (0-100)
  entropy_min: 50
  # Enable password blacklist
  blacklist: true
  # Check for common patterns
  check_patterns: true

# Session Settings
session:
  # Session duration in hours
  ttl_hours: 168  # 7 days
  # IP binding: strict, loose, none
  ip_binding: loose
  # Max sessions per player
  max_per_player: 3

# Lockout Settings
lockout:
  # Max failed attempts before lockout
  max_attempts: 5
  # Base lockout duration in seconds
  base_duration: 300  # 5 minutes
  # Multiplier for each subsequent lockout
  multiplier: 2.0
  # Maximum lockout duration in seconds
  max_duration: 86400  # 24 hours

# Registration Settings
registration:
  # Require password confirmation
  require_confirm: true
  # Max accounts per IP
  max_per_ip: 3
  # Blocked names (case-insensitive)
  blocked_names:
    - admin
    - moderator
    - console
```

---

## Database Setup

### SQLite (Default)

No configuration needed. Database file is created at:
```
plugins/AuthCraft/authcraft.db
```

### MySQL Setup

1. **Create database**:
```sql
CREATE DATABASE authcraft CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'authcraft'@'localhost' IDENTIFIED BY 'secure_password';
GRANT ALL PRIVILEGES ON authcraft.* TO 'authcraft'@'localhost';
FLUSH PRIVILEGES;
```

2. **Configure config.yml**:
```yaml
database:
  type: mysql
  host: localhost
  port: 3306
  name: authcraft
  username: authcraft
  password: secure_password
```

### PostgreSQL Setup

1. **Create database**:
```sql
CREATE DATABASE authcraft WITH ENCODING 'UTF8';
CREATE USER authcraft WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE authcraft TO authcraft;
```

2. **Configure config.yml**:
```yaml
database:
  type: postgresql
  host: localhost
  port: 5432
  name: authcraft
  username: authcraft
  password: secure_password
```

### Connection Pool Tuning

For high-traffic servers:

```yaml
database:
  pool:
    max_connections: 20
    min_idle: 5
    connection_timeout: 30000
    idle_timeout: 600000
    max_lifetime: 1800000
```

---

## Two-Factor Authentication

### TOTP (Google Authenticator)

Enabled by default, no additional setup required.

```yaml
two_factor:
  totp:
    enabled: true
    issuer: "MyServer"
    digits: 6
    period: 30
```

### Telegram Bot Setup

1. **Create bot**:
   - Open Telegram
   - Search for @BotFather
   - Send `/newbot`
   - Follow instructions
   - Save the bot token

2. **Configure**:
```yaml
integrations:
  telegram:
    enabled: true
    bot_token: "123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
    bot_username: "YourBotNameBot"
```

3. **Test**:
   - Start your server
   - In-game: `/2fa enable telegram`
   - Send `/start` to your bot
   - Follow instructions

### VK Bot Setup

1. **Create VK Group**:
   - Go to vk.com/groups
   - Create new group or use existing
   - Go to Settings → API
   - Create access token with messages permission

2. **Configure**:
```yaml
integrations:
  vk:
    enabled: true
    access_token: "vk1.a.XXXXX..."
```

### Email OTP Setup

1. **Configure SMTP**:
```yaml
integrations:
  email:
    enabled: true
    smtp:
      host: "smtp.gmail.com"
      port: 587
      username: "your-email@gmail.com"
      password: "your-app-password"
      from: "noreply@yourserver.com"
      from_name: "MyServer Auth"
```

2. **For Gmail**:
   - Enable 2FA on your Google account
   - Create an App Password
   - Use the App Password in config

---

## Security Features

### AntiBot Configuration

```yaml
security:
  antibot:
    enabled: true
    # Max connections per IP per minute
    ip_rate_limit: 5
    # Global connections per second
    global_rate_limit: 100
    # Confidence threshold (0.0-1.0)
    confidence_threshold: 0.7
    # Auto-enable attack mode
    auto_attack_mode: true
    # Blocked name patterns
    blocked_patterns:
      - "Bot[0-9]+"
      - "Player_[0-9]{5}"
      - "xXx_.*_xXx"
```

### GeoIP Filtering

1. **Download MaxMind Database**:
   - Sign up at maxmind.com (free account available)
   - Download GeoLite2 Country database
   - Place in `plugins/AuthCraft/GeoLite2-Country.mmdb`

2. **Configure**:
```yaml
security:
  geoip:
    enabled: true
    # Mode: whitelist, blacklist, disabled
    mode: blacklist
    # Country codes (ISO 3166-1 alpha-2)
    countries:
      - CN  # China
      - RU  # Russia (if needed)
    # Fallback to online API
    online_fallback: true
```

### Unicode Spoofing Protection

```yaml
security:
  unicode:
    enabled: true
    # Levenshtein distance threshold (percentage)
    similarity_threshold: 0.2
    # Block similar names
    block_similar: true
    # Notify admins
    notify_admins: true
```

### Security Audit

Runs automatically on startup. Configure:

```yaml
security:
  audit:
    enabled: true
    # Check open ports
    check_ports: true
    # Check file permissions
    check_permissions: true
    # Check for vulnerable plugins
    check_plugins: true
    # Check config files for passwords
    check_configs: true
```

---

## Integrations

### Vault Integration

```yaml
integrations:
  vault:
    enabled: true
    # Use Vault for permissions
    permissions: true
    # Use Vault for economy (optional)
    economy: false
```

### PlaceholderAPI

Available placeholders:

| Placeholder | Description |
|-------------|-------------|
| `%authcraft_logged_in%` | Is player logged in |
| `%authcraft_2fa_enabled%` | Is 2FA enabled |
| `%authcraft_2fa_method%` | Active 2FA method |
| `%authcraft_role%` | Player role |
| `%authcraft_last_login%` | Last login time |

### REST API

```yaml
api:
  enabled: true
  port: 8080
  # API keys for authentication
  api_keys:
    - "your-secure-api-key-here"
  # Allowed IPs (empty = all)
  allowed_ips: []
```

---

## Commands Reference

### Player Commands

| Command | Description | Permission |
|---------|-------------|------------|
| `/register <pass> <pass>` | Register account | `authcraft.register` |
| `/login <password>` | Login to account | `authcraft.login` |
| `/changepassword <old> <new>` | Change password | `authcraft.changepassword` |
| `/2fa enable <method>` | Enable 2FA | `authcraft.2fa` |
| `/2fa disable <method>` | Disable 2FA | `authcraft.2fa` |
| `/2fa status` | Check 2FA status | `authcraft.2fa` |
| `/2fa backup` | Get backup codes | `authcraft.2fa` |
| `/logout` | Logout from account | `authcraft.logout` |

### Admin Commands

| Command | Description | Permission |
|---------|-------------|------------|
| `/authcraft reload` | Reload config | `authcraft.admin.reload` |
| `/authcraft reset2fa <player>` | Reset player 2FA | `authcraft.admin.reset2fa` |
| `/authcraft unlock <player>` | Unlock account | `authcraft.admin.unlock` |
| `/authcraft setrole <player> <role>` | Set player role | `authcraft.admin.setrole` |
| `/authcraft migrate <from>` | Migrate data | `authcraft.admin.migrate` |
| `/authcraft audit` | Run security audit | `authcraft.admin.audit` |
| `/authcraft backup` | Create backup | `authcraft.admin.backup` |

---

## Permissions

### Player Permissions

```yaml
authcraft.register: true
authcraft.login: true
authcraft.changepassword: true
authcraft.logout: true
authcraft.2fa: true
```

### Admin Permissions

```yaml
authcraft.admin: op
authcraft.admin.reload: op
authcraft.admin.reset2fa: op
authcraft.admin.unlock: op
authcraft.admin.setrole: op
authcraft.admin.migrate: op
authcraft.admin.audit: op
authcraft.bypass.lockout: op
authcraft.bypass.geoip: op
```

### Role-Based Permissions

In `roles.yml`:

```yaml
vip:
  permissions:
    - authcraft.2fa
    - some.other.permission
  inherits: []
  requires_2fa: false

admin:
  permissions:
    - authcraft.admin
    - '*'
  inherits: []
  requires_2fa: true
```

---

## Troubleshooting

### Common Issues

#### "Database connection failed"

1. Check database credentials
2. Verify database server is running
3. Check firewall rules
4. Test connection manually

```bash
# MySQL
mysql -h localhost -u authcraft -p authcraft

# PostgreSQL
psql -h localhost -U authcraft -d authcraft
```

#### "Telegram bot not responding"

1. Verify bot token is correct
2. Check bot is not blocked
3. Enable debug mode:
```yaml
debug:
  enabled: true
  integrations: true
```

#### "Players getting kicked immediately"

1. Check if server is in online-mode (should be false)
2. Verify no conflicting auth plugins
3. Check for errors in console

#### "2FA codes not working"

1. Verify time synchronization on server
2. Check TOTP period matches (default: 30s)
3. Ensure player's phone time is correct

### Debug Mode

Enable detailed logging:

```yaml
debug:
  enabled: true
  integrations: true
  storage: true
  auth: true
```

Check logs in:
```
plugins/AuthCraft/logs/
```

---

## Migration

### From AuthMe

```bash
/authcraft migrate authme
```

Supported sources:
- AuthMe SQLite
- AuthMe MySQL
- AuthMe flat file

### From xAuth

```bash
/authcraft migrate xauth
```

### From LoginSecurity

```bash
/authcraft migrate loginsecurity
```

### Manual Migration

1. Export data from old plugin
2. Convert to AuthCraft format
3. Import via REST API

---

## Backup and Recovery

### Automatic Backups

```yaml
backup:
  enabled: true
  # Interval in hours
  interval: 24
  # Keep last N backups
  keep_count: 7
  # Compress backups
  compress: true
```

### Manual Backup

```bash
/authcraft backup
```

Backups stored in:
```
plugins/AuthCraft/backups/
```

### Recovery

1. Stop server
2. Locate backup file
3. Restore database:
```bash
# SQLite
cp backups/authcraft-2024-01-01.db authcraft.db

# MySQL
mysql -u authcraft -p authcraft < backup.sql
```

4. Start server

---

## Support

- **Documentation**: https://docs.authcraft.dev
- **GitHub Issues**: https://github.com/authcraft/authcraft/issues
- **Discord**: https://discord.authcraft.dev
- **Email**: support@authcraft.dev

---

*Last updated: 2026-03-04*
