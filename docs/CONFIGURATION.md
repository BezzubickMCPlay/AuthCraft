# AuthCraft Configuration Reference

## Complete Configuration File Documentation

---

## Table of Contents

1. [Overview](#overview)
2. [General Settings](#general-settings)
3. [Database Configuration](#database-configuration)
4. [Password Settings](#password-settings)
5. [Session Settings](#session-settings)
6. [Lockout Settings](#lockout-settings)
7. [Registration Settings](#registration-settings)
8. [Two-Factor Authentication](#two-factor-authentication)
9. [Security Settings](#security-settings)
10. [Integrations](#integrations)
11. [API Settings](#api-settings)
12. [Backup Settings](#backup-settings)
13. [Debug Settings](#debug-settings)
14. [Messages Configuration](#messages-configuration)
15. [Roles Configuration](#roles-configuration)

---

## Overview

AuthCraft configuration is stored in YAML format in the following files:

| File | Purpose |
|------|---------|
| `config.yml` | Main configuration |
| `roles.yml` | Role and permission definitions |
| `messages_en.yml` | English messages |
| `messages_ru.yml` | Russian messages |

### Configuration Location

```
plugins/AuthCraft/
├── config.yml
├── roles.yml
├── messages_en.yml
├── messages_ru.yml
└── authcraft.db (SQLite database)
```

---

## General Settings

```yaml
general:
  # Server language: en, ru, de, fr, es, zh, ja, ko
  language: en
  
  # Server name displayed in messages
  server_name: "My Minecraft Server"
  
  # Enable debug mode (not recommended for production)
  debug: false
  
  # Check for updates on startup
  check_updates: true
  
  # BStats metrics (anonymous usage statistics)
  metrics: true
```

### Language Options

| Code | Language |
|------|----------|
| `en` | English |
| `ru` | Russian |
| `de` | German |
| `fr` | French |
| `es` | Spanish |
| `zh` | Chinese |
| `ja` | Japanese |
| `ko` | Korean |

---

## Database Configuration

### SQLite (Default)

```yaml
database:
  type: sqlite
  # Database file location (relative to plugin folder)
  file: authcraft.db
```

### MySQL

```yaml
database:
  type: mysql
  host: localhost
  port: 3306
  name: authcraft
  username: minecraft
  password: your_secure_password
  
  # Connection pool settings
  pool:
    # Maximum connections
    max_connections: 10
    # Minimum idle connections
    min_idle: 2
    # Connection timeout (milliseconds)
    connection_timeout: 30000
    # Idle timeout (milliseconds)
    idle_timeout: 600000
    # Maximum connection lifetime (milliseconds)
    max_lifetime: 1800000
  
  # SSL settings
  ssl:
    enabled: false
    verify: true
  
  # Performance settings
  performance:
    # Cache size for query results
    cache_size: 1000
    # Query timeout (seconds)
    query_timeout: 30
```

### PostgreSQL

```yaml
database:
  type: postgresql
  host: localhost
  port: 5432
  name: authcraft
  username: minecraft
  password: your_secure_password
  
  # Same pool and SSL options as MySQL
```

### Connection Pool Tuning

| Server Size | Max Connections | Min Idle |
|-------------|-----------------|----------|
| Small (<50) | 5 | 1 |
| Medium (50-200) | 10 | 2 |
| Large (200-500) | 20 | 5 |
| Very Large (500+) | 30 | 10 |

---

## Password Settings

```yaml
password:
  # ═══════════════════════════════════════════════
  # Password Requirements
  # ═══════════════════════════════════════════════
  
  # Minimum password length (6-32)
  min_length: 8
  
  # Maximum password length
  max_length: 128
  
  # Minimum entropy score (0-100)
  # Higher = more complex password required
  entropy_min: 50
  
  # ═══════════════════════════════════════════════
  # Password Validation
  # ═══════════════════════════════════════════════
  
  # Check if password contains username
  check_username: true
  
  # Check if password contains reversed username
  check_username_reverse: true
  
  # Enable password blacklist
  blacklist: true
  
  # Check for common patterns (123, abc, qwerty)
  check_patterns: true
  
  # Minimum unique characters
  min_unique_chars: 4
  
  # ═══════════════════════════════════════════════
  # Hashing Algorithm
  # ═══════════════════════════════════════════════
  
  # Algorithm: argon2id, bcrypt, pbkdf2
  algorithm: argon2id
  
  # Argon2id parameters
  argon2id:
    iterations: 3
    memory: 65536  # KB
    parallelism: 1
  
  # BCrypt parameters
  bcrypt:
    cost: 12  # 4-31, higher = slower
  
  # PBKDF2 parameters
  pbkdf2:
    iterations: 100000
    key_length: 256
  
  # Auto-rehash when parameters change
  auto_rehash: true
```

### Algorithm Comparison

| Algorithm | Security | Performance | Recommended For |
|-----------|----------|-------------|-----------------|
| Argon2id | ⭐⭐⭐⭐⭐ | ~250ms | New servers |
| BCrypt | ⭐⭐⭐⭐ | ~200ms | Compatibility |
| PBKDF2 | ⭐⭐⭐ | ~150ms | Legacy systems |

---

## Session Settings

```yaml
session:
  # Session duration in hours
  ttl_hours: 168  # 7 days
  
  # IP binding mode
  # strict: Must match exact IP
  # loose: Must match /24 subnet
  # none: No IP check
  ip_binding: loose
  
  # Maximum sessions per player
  max_per_player: 3
  
  # Invalidate all sessions on password change
  invalidate_on_password_change: true
  
  # Invalidate all sessions on 2FA change
  invalidate_on_2fa_change: true
  
  # Session cleanup interval (hours)
  cleanup_interval: 24
  
  # Remember session across server restarts
  persist: true
```

### IP Binding Modes

| Mode | Description | Security | Convenience |
|------|-------------|----------|-------------|
| `strict` | Exact IP match | High | Low |
| `loose` | Same /24 subnet | Medium | Medium |
| `none` | No IP check | Low | High |

---

## Lockout Settings

```yaml
lockout:
  # Maximum failed attempts before lockout
  max_attempts: 5
  
  # Base lockout duration (seconds)
  base_duration: 300  # 5 minutes
  
  # Multiplier for each subsequent lockout
  # Duration = base_duration * (multiplier ^ lockout_count)
  multiplier: 2.0
  
  # Maximum lockout duration (seconds)
  max_duration: 86400  # 24 hours
  
  # Reset lockout count after successful login
  reset_on_success: true
  
  # Notify admins on lockout
  notify_admins: true
  
  # IP-based lockout (lock entire IP)
  ip_lockout:
    enabled: true
    max_attempts: 10
    duration: 3600  # 1 hour
```

### Lockout Duration Examples

| Attempt | Duration |
|---------|----------|
| 1st | 5 minutes |
| 2nd | 10 minutes |
| 3rd | 20 minutes |
| 4th | 40 minutes |
| 5th | 80 minutes |

---

## Registration Settings

```yaml
registration:
  # Require password confirmation
  require_confirm: true
  
  # Maximum accounts per IP address
  max_per_ip: 3
  
  # Blocked usernames (case-insensitive)
  blocked_names:
    - admin
    - moderator
    - console
    - server
    - system
  
  # Reserved usernames for VIPs
  reserved_names:
    - Notch
    - Jeb
  
  # Minimum time between registrations (seconds)
  cooldown: 60
  
  # Welcome message
  welcome_message: true
  
  # Auto-login after registration
  auto_login: true
```

---

## Two-Factor Authentication

```yaml
two_factor:
  # ═══════════════════════════════════════════════
  # Global 2FA Settings
  # ═══════════════════════════════════════════════
  
  # Allow multiple 2FA methods simultaneously
  allow_multiple: true
  
  # Require 2FA for all players
  require_for_all: false
  
  # Require 2FA for specific roles (see roles.yml)
  require_for_roles: true
  
  # Backup codes settings
  backup_codes:
    count: 10
    format: "XXXX-XXXX"
  
  # ═══════════════════════════════════════════════
  # TOTP Settings (Google Authenticator)
  # ═══════════════════════════════════════════════
  
  totp:
    enabled: true
    issuer: "MyServer"
    digits: 6
    period: 30
    algorithm: SHA1
  
  # ═══════════════════════════════════════════════
  # Login Confirmation Settings
  # ═══════════════════════════════════════════════
  
  login_confirmation:
    # Enable login confirmation via 2FA apps
    enabled: true
    # Expiration time for confirmation (minutes)
    expiration: 5
    # Show exact login time in confirmation message
    show_time: true
```

---

## Security Settings

```yaml
security:
  # ═══════════════════════════════════════════════
  # AntiBot Settings
  # ═══════════════════════════════════════════════
  
  antibot:
    enabled: true
    
    # Per-IP rate limiting
    ip_rate_limit: 5  # connections per minute
    
    # Global rate limiting
    global_rate_limit: 100  # connections per second
    
    # Confidence threshold (0.0-1.0)
    confidence_threshold: 0.7
    
    # Auto-enable attack mode
    auto_attack_mode: true
    
    # Attack mode thresholds
    attack_mode:
      trigger_rate: 50  # connections per second
      cooldown: 300  # seconds
    
    # Blocked name patterns (regex)
    blocked_patterns:
      - "Bot[0-9]+"
      - "Player_[0-9]{5}"
      - "xXx_.*_xXx"
      - "[A-Z]{3}[0-9]{6}"
  
  # ═══════════════════════════════════════════════
  # GeoIP Settings
  # ═══════════════════════════════════════════════
  
  geoip:
    enabled: false
    
    # Mode: whitelist, blacklist, disabled
    mode: blacklist
    
    # Country codes (ISO 3166-1 alpha-2)
    countries:
      - CN
      - RU
    
    # Path to MaxMind database
    database: "GeoLite2-Country.mmdb"
    
    # Fallback to online API
    online_fallback: true
    
    # Cache duration (hours)
    cache_duration: 24
  
  # ═══════════════════════════════════════════════
  # Unicode Spoofing Detection
  # ═══════════════════════════════════════════════
  
  unicode:
    enabled: true
    
    # Similarity threshold (0.0-1.0)
    similarity_threshold: 0.2
    
    # Block similar names
    block_similar: true
    
    # Notify admins on detection
    notify_admins: true
  
  # ═══════════════════════════════════════════════
  # Security Audit
  # ═══════════════════════════════════════════════
  
  audit:
    enabled: true
    
    # Check on startup
    check_on_startup: true
    
    # Check open ports
    check_ports: true
    
    # Check file permissions
    check_permissions: true
    
    # Check for vulnerable plugins
    check_plugins: true
    
    # Check config files for passwords
    check_configs: true
    
    # Ports to check
    ports:
      - 3306   # MySQL
      - 5432   # PostgreSQL
      - 6379   # Redis
      - 25575  # RCON
```

---

## Integrations

```yaml
integrations:
  # ═══════════════════════════════════════════════
  # Telegram Bot
  # ═══════════════════════════════════════════════
  
  telegram:
    enabled: false
    bot_token: ""
    bot_username: ""
    
    # Admin chat ID for notifications
    admin_chat_id: ""
    
    # Login notifications
    login_notifications: true
  
  # ═══════════════════════════════════════════════
  # VK Bot (Bots LongPoll API)
  # ═══════════════════════════════════════════════

  vk:
    enabled: false
    
    # Group access token (from Settings → API → Create Token)
    # Required permissions: messages
    access_token: ""

    # Group ID (optional, auto-detected from token)
    # Example: "123456789"
    group_id: ""

    # Admin ID for notifications (optional)
    admin_id: ""

    # Login confirmation settings
    login_confirmation:
      # Expiration time for confirmation (minutes)
      expiration: 5
      # Show exact login time in confirmation message
      show_time: true
      # Show IP address in confirmation message
      show_ip: true
      # Show location in confirmation message (requires GeoIP)
      show_location: true

  # VK 2FA Setup Instructions:
  # 1. Create VK Group or use existing one
  # 2. Go to Settings → API → Create Token
  # 3. Enable "messages" permission
  # 4. Go to Settings → API → LongPoll API
  # 5. Enable "LongPoll API" with version 5.131+
  # 6. Enable "Message events" in Event Types
  # 7. Copy access_token to config.yml
  
  # ═══════════════════════════════════════════════
  # Email
  # ═══════════════════════════════════════════════
  
  email:
    enabled: false
    
    smtp:
      host: "smtp.gmail.com"
      port: 587
      username: ""
      password: ""
      from: "noreply@yourserver.com"
      from_name: "MyServer Auth"
      
      # TLS settings
      starttls: true
      ssl: false
    
    # OTP settings
    otp:
      length: 6
      expiration: 300  # seconds
  
  # ═══════════════════════════════════════════════
  # Vault
  # ═══════════════════════════════════════════════
  
  vault:
    enabled: true
    permissions: true
    economy: false
  
  # ═══════════════════════════════════════════════
  # PlaceholderAPI
  # ═══════════════════════════════════════════════
  
  placeholderapi:
    enabled: true
```

---

## API Settings

```yaml
api:
  enabled: false
  port: 8080
  
  # API keys
  api_keys:
    - "your-secure-api-key-here"
  
  # IP whitelist
  allowed_ips:
    - "127.0.0.1"
    - "192.168.1.0/24"
  
  # CORS settings
  cors:
    enabled: true
    allowed_origins:
      - "https://yourwebsite.com"
    allowed_methods:
      - GET
      - POST
      - PUT
      - DELETE
    allowed_headers:
      - Authorization
      - Content-Type
  
  # Rate limiting
  rate_limit:
    per_key: 100  # requests per minute
    per_ip: 200
```

---

## Backup Settings

```yaml
backup:
  enabled: true
  
  # Backup interval (hours)
  interval: 24
  
  # Number of backups to keep
  keep_count: 7
  
  # Compress backups
  compress: true
  
  # Backup location
  location: "backups"
  
  # Include player data
  include_players: true
  
  # Include sessions
  include_sessions: true
  
  # Include audit logs
  include_audit: true
```

---

## Debug Settings

```yaml
debug:
  # Enable debug mode
  enabled: false
  
  # Debug specific components
  integrations: false
  storage: false
  auth: false
  security: false
  
  # Log level: TRACE, DEBUG, INFO, WARN, ERROR
  log_level: INFO
  
  # Log to file
  log_to_file: true
  
  # Log file location
  log_file: "logs/debug.log"
```

---

## Messages Configuration

Messages are stored in `messages_xx.yml` files.

```yaml
# messages_en.yml

# Registration
register:
  success: "&aAccount registered successfully!"
  password_mismatch: "&cPasswords do not match!"
  password_weak: "&cPassword is too weak. Use stronger password."
  already_registered: "&cYou are already registered!"
  
# Login
login:
  success: "&aWelcome back, {player}!"
  invalid_password: "&cInvalid password!"
  not_registered: "&cYou are not registered. Use /register"
  
# 2FA
twofa:
  enabled: "&aTwo-factor authentication enabled!"
  disabled: "&eTwo-factor authentication disabled."
  code_required: "&6Enter 2FA code: /2fa verify <code>"
  code_invalid: "&cInvalid 2FA code!"
  backup_codes: "&aYour backup codes:"
```

### Message Placeholders

| Placeholder | Description |
|-------------|-------------|
| `{player}` | Player name |
| `{server}` | Server name |
| `{time}` | Current time |
| `{ip}` | Player IP |
| `{code}` | 2FA code |
| `{role}` | Player role |

### Color Codes

| Code | Color |
|------|-------|
| `&0` | Black |
| `&1` | Dark Blue |
| `&2` | Dark Green |
| `&3` | Dark Aqua |
| `&4` | Dark Red |
| `&5` | Dark Purple |
| `&6` | Gold |
| `&7` | Gray |
| `&8` | Dark Gray |
| `&9` | Blue |
| `&a` | Green |
| `&b` | Aqua |
| `&c` | Red |
| `&d` | Light Purple |
| `&e` | Yellow |
| `&f` | White |
| `&k` | Obfuscated |
| `&l` | Bold |
| `&m` | Strikethrough |
| `&n` | Underline |
| `&o` | Italic |
| `&r` | Reset |

---

## Roles Configuration

Roles are defined in `roles.yml`:

```yaml
# roles.yml

# Default role for new players
default_role: player

# Role definitions
roles:
  player:
    permissions:
      - authcraft.register
      - authcraft.login
      - authcraft.changepassword
      - authcraft.logout
      - authcraft.2fa
    inherits: []
    requires_2fa: false
    priority: 0
  
  vip:
    permissions:
      - authcraft.register
      - authcraft.login
      - authcraft.changepassword
      - authcraft.logout
      - authcraft.2fa
      - vip.fly
      - vip.kit
    inherits:
      - player
    requires_2fa: false
    priority: 10
  
  moderator:
    permissions:
      - authcraft.admin.unlock
      - authcraft.admin.reset2fa
      - moderator.kick
      - moderator.mute
    inherits:
      - vip
    requires_2fa: true
    priority: 50
  
  admin:
    permissions:
      - "*"
    inherits: []
    requires_2fa: true
    priority: 100
```

### Permission Hierarchy

1. Direct permissions
2. Inherited permissions
3. Wildcard permissions (`*`)

---

## Configuration Best Practices

### Security

1. **Use strong passwords** for database connections
2. **Enable 2FA** for admin roles
3. **Restrict API access** by IP
4. **Use HTTPS** in production
5. **Regular backups**

### Performance

1. **Use connection pooling** for databases
2. **Enable caching** for sessions
3. **Tune rate limits** for your player count
4. **Use SQLite** for small servers
5. **Use MySQL/PostgreSQL** for large servers

### Maintenance

1. **Test changes** in development first
2. **Backup before** major changes
3. **Monitor logs** for issues
4. **Update regularly** for security fixes

---

## Support

For configuration help:
- **Documentation**: https://docs.authcraft.dev
- **Discord**: https://discord.authcraft.dev
- **GitHub**: https://github.com/authcraft/authcraft/issues

---

*Last updated: 2026-03-04*
