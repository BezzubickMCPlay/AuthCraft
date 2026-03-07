# AuthCraft REST API Documentation

## Overview

AuthCraft provides a REST API for external integrations, allowing you to manage players, roles, and authentication programmatically.

---

## Table of Contents

1. [Configuration](#configuration)
2. [Authentication](#authentication)
3. [Endpoints](#endpoints)
4. [Error Handling](#error-handling)
5. [Rate Limiting](#rate-limiting)
6. [Examples](#examples)
7. [SDKs and Libraries](#sdks-and-libraries)

---

## Configuration

### Enable REST API

In `config.yml`:

```yaml
api:
  enabled: true
  port: 8080
  # API keys for authentication
  api_keys:
    - "your-secure-api-key-here"
    - "another-api-key-for-different-service"
  # IP whitelist (empty = all IPs allowed)
  allowed_ips:
    - "127.0.0.1"
    - "192.168.1.0/24"
  # CORS settings
  cors:
    enabled: true
    allowed_origins:
      - "https://yourwebsite.com"
```

### Security Recommendations

1. **Use strong API keys** - Minimum 32 characters, random
2. **Restrict by IP** - Only allow known servers
3. **Use HTTPS** - In production, use reverse proxy with SSL
4. **Rotate keys** - Change API keys periodically

---

## Authentication

All API requests require authentication via API key.

### Header Authentication

```http
Authorization: Bearer your-api-key-here
```

### Example Request

```bash
curl -X GET "http://localhost:8080/api/player/Steve" \
  -H "Authorization: Bearer your-api-key-here" \
  -H "Content-Type: application/json"
```

---

## Endpoints

### Base URL

```
http://your-server:8080/api
```

### Player Endpoints

#### Get Player Information

```http
GET /api/player/{username}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "uuid": "cfa2a0ba-85db-3806-9d58-5cd040c8fa32",
    "username": "Steve",
    "role": "player",
    "registered": "2024-01-15T10:30:00Z",
    "last_login": "2024-03-04T12:00:00Z",
    "last_ip": "192.168.1.100",
    "two_factor_enabled": true,
    "two_factor_methods": ["totp", "telegram"],
    "status": "active"
  }
}
```

**Status Codes:**
- `200` - Success
- `404` - Player not found
- `401` - Unauthorized

#### Get Player by UUID

```http
GET /api/player/uuid/{uuid}
```

**Response:** Same as above

#### Set Player Role

```http
POST /api/player/{username}/role
Content-Type: application/json

{
  "role": "vip"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Role updated successfully",
  "data": {
    "username": "Steve",
    "old_role": "player",
    "new_role": "vip"
  }
}
```

**Status Codes:**
- `200` - Success
- `400` - Invalid role
- `404` - Player not found
- `401` - Unauthorized

#### Remove Player Role

```http
DELETE /api/player/{username}/role
```

**Response:**
```json
{
  "success": true,
  "message": "Role removed successfully"
}
```

#### Reset Player 2FA

```http
POST /api/player/{username}/reset2fa
```

**Response:**
```json
{
  "success": true,
  "message": "2FA reset successfully",
  "data": {
    "username": "Steve",
    "reset_methods": ["totp", "telegram"]
  }
}
```

#### Unlock Player Account

```http
POST /api/player/{username}/unlock
```

**Response:**
```json
{
  "success": true,
  "message": "Account unlocked successfully"
}
```

#### Get Player Sessions

```http
GET /api/player/{username}/sessions
```

**Response:**
```json
{
  "success": true,
  "data": {
    "username": "Steve",
    "sessions": [
      {
        "token": "abc123...",
        "ip": "192.168.1.100",
        "created": "2024-03-04T10:00:00Z",
        "expires": "2024-03-11T10:00:00Z",
        "active": true
      }
    ]
  }
}
```

#### Invalidate Player Sessions

```http
DELETE /api/player/{username}/sessions
```

**Response:**
```json
{
  "success": true,
  "message": "All sessions invalidated",
  "data": {
    "invalidated_count": 2
  }
}
```

### Role Endpoints

#### List All Roles

```http
GET /api/roles
```

**Response:**
```json
{
  "success": true,
  "data": {
    "roles": [
      {
        "name": "player",
        "permissions": ["authcraft.login", "authcraft.register"],
        "inherits": [],
        "requires_2fa": false
      },
      {
        "name": "vip",
        "permissions": ["authcraft.login", "authcraft.register", "vip.fly"],
        "inherits": ["player"],
        "requires_2fa": false
      },
      {
        "name": "admin",
        "permissions": ["*"],
        "inherits": [],
        "requires_2fa": true
      }
    ]
  }
}
```

#### Get Role Information

```http
GET /api/roles/{role_name}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "name": "vip",
    "permissions": ["authcraft.login", "authcraft.register", "vip.fly"],
    "inherits": ["player"],
    "requires_2fa": false,
    "player_count": 15
  }
}
```

#### Create Role

```http
POST /api/roles
Content-Type: application/json

{
  "name": "moderator",
  "permissions": ["authcraft.login", "moderator.kick", "moderator.mute"],
  "inherits": ["player"],
  "requires_2fa": true
}
```

**Response:**
```json
{
  "success": true,
  "message": "Role created successfully",
  "data": {
    "name": "moderator",
    "permissions": ["authcraft.login", "moderator.kick", "moderator.mute"],
    "inherits": ["player"],
    "requires_2fa": true
  }
}
```

#### Update Role

```http
PUT /api/roles/{role_name}
Content-Type: application/json

{
  "permissions": ["authcraft.login", "moderator.kick", "moderator.mute", "moderator.ban"],
  "requires_2fa": true
}
```

#### Delete Role

```http
DELETE /api/roles/{role_name}
```

**Response:**
```json
{
  "success": true,
  "message": "Role deleted successfully"
}
```

### Server Endpoints

#### Get Server Statistics

```http
GET /api/server/stats
```

**Response:**
```json
{
  "success": true,
  "data": {
    "total_players": 1250,
    "online_players": 45,
    "registered_today": 12,
    "logins_today": 89,
    "failed_logins_today": 5,
    "locked_accounts": 3,
    "2fa_enabled_count": 450,
    "2fa_methods": {
      "totp": 300,
      "telegram": 100,
      "vk": 30,
      "email": 20
    }
  }
}
```

#### Get Security Audit Results

```http
GET /api/server/audit
```

**Response:**
```json
{
  "success": true,
  "data": {
    "last_audit": "2024-03-04T00:00:00Z",
    "findings": [
      {
        "severity": "WARNING",
        "category": "PORT",
        "message": "MySQL port 3306 is open on localhost"
      },
      {
        "severity": "INFO",
        "category": "CONFIG",
        "message": "Server is in offline-mode"
      }
    ],
    "summary": {
      "critical": 0,
      "warning": 1,
      "info": 1
    }
  }
}
```

#### Run Security Audit

```http
POST /api/server/audit
```

**Response:**
```json
{
  "success": true,
  "message": "Security audit started",
  "data": {
    "audit_id": "audit-2024-03-04-120000"
  }
}
```

### Authentication Endpoints

#### Validate Session

```http
POST /api/auth/validate
Content-Type: application/json

{
  "username": "Steve",
  "session_token": "abc123..."
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "valid": true,
    "username": "Steve",
    "uuid": "cfa2a0ba-85db-3806-9d58-5cd040c8fa32",
    "role": "vip",
    "expires": "2024-03-11T10:00:00Z"
  }
}
```

#### Check Permission

```http
POST /api/auth/permission
Content-Type: application/json

{
  "username": "Steve",
  "permission": "vip.fly"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "has_permission": true,
    "username": "Steve",
    "permission": "vip.fly"
  }
}
```

---

## Error Handling

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "PLAYER_NOT_FOUND",
    "message": "Player 'NonExistent' not found",
    "details": {}
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `UNAUTHORIZED` | 401 | Invalid or missing API key |
| `FORBIDDEN` | 403 | IP not whitelisted |
| `PLAYER_NOT_FOUND` | 404 | Player does not exist |
| `ROLE_NOT_FOUND` | 404 | Role does not exist |
| `INVALID_REQUEST` | 400 | Malformed request body |
| `INVALID_ROLE` | 400 | Role name invalid |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |

---

## Rate Limiting

### Default Limits

- **Per API Key**: 100 requests per minute
- **Per IP**: 200 requests per minute

### Rate Limit Headers

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1709558400
```

### Rate Limit Response

```json
{
  "success": false,
  "error": {
    "code": "RATE_LIMITED",
    "message": "Rate limit exceeded. Try again in 30 seconds.",
    "details": {
      "limit": 100,
      "remaining": 0,
      "reset": 30
    }
  }
}
```

---

## Examples

### Python Example

```python
import requests

API_URL = "http://localhost:8080/api"
API_KEY = "your-api-key-here"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Get player info
response = requests.get(f"{API_URL}/player/Steve", headers=headers)
if response.status_code == 200:
    player = response.json()["data"]
    print(f"Player: {player['username']}")
    print(f"Role: {player['role']}")
    print(f"2FA Enabled: {player['two_factor_enabled']}")

# Set player role
data = {"role": "vip"}
response = requests.post(f"{API_URL}/player/Steve/role", 
                         headers=headers, json=data)
if response.status_code == 200:
    print("Role updated successfully!")
```

### JavaScript/Node.js Example

```javascript
const axios = require('axios');

const API_URL = 'http://localhost:8080/api';
const API_KEY = 'your-api-key-here';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Authorization': `Bearer ${API_KEY}`,
    'Content-Type': 'application/json'
  }
});

// Get player info
async function getPlayer(username) {
  try {
    const response = await api.get(`/player/${username}`);
    return response.data.data;
  } catch (error) {
    console.error('Error:', error.response?.data || error.message);
  }
}

// Set player role
async function setRole(username, role) {
  try {
    const response = await api.post(`/player/${username}/role`, { role });
    return response.data;
  } catch (error) {
    console.error('Error:', error.response?.data || error.message);
  }
}

// Usage
(async () => {
  const player = await getPlayer('Steve');
  console.log('Player:', player);
  
  await setRole('Steve', 'vip');
})();
```

### PHP Example

```php
<?php

$apiUrl = 'http://localhost:8080/api';
$apiKey = 'your-api-key-here';

function apiRequest($endpoint, $method = 'GET', $data = null) {
    global $apiUrl, $apiKey;
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $apiUrl . $endpoint);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $apiKey,
        'Content-Type: application/json'
    ]);
    
    if ($method === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    }
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    return json_decode($response, true);
}

// Get player info
$player = apiRequest('/player/Steve');
echo "Player: " . $player['data']['username'] . "\n";

// Set role
$result = apiRequest('/player/Steve/role', 'POST', ['role' => 'vip']);
echo "Result: " . $result['message'] . "\n";
```

### cURL Examples

```bash
# Get player info
curl -X GET "http://localhost:8080/api/player/Steve" \
  -H "Authorization: Bearer your-api-key-here"

# Set player role
curl -X POST "http://localhost:8080/api/player/Steve/role" \
  -H "Authorization: Bearer your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"role": "vip"}'

# Get server stats
curl -X GET "http://localhost:8080/api/server/stats" \
  -H "Authorization: Bearer your-api-key-here"

# Reset player 2FA
curl -X POST "http://localhost:8080/api/player/Steve/reset2fa" \
  -H "Authorization: Bearer your-api-key-here"
```

---

## SDKs and Libraries

### Official SDKs

- **Java**: `authcraft-api-client-java`
- **JavaScript/TypeScript**: `@authcraft/api-client`
- **Python**: `authcraft-api-client`

### Installation

**Java (Maven):**
```xml
<dependency>
    <groupId>com.authcraft</groupId>
    <artifactId>api-client</artifactId>
    <version>1.0.0</version>
</dependency>
```

**JavaScript:**
```bash
npm install @authcraft/api-client
```

**Python:**
```bash
pip install authcraft-api-client
```

---

## Webhooks (Planned)

Future versions will support webhooks for events:

- `player.registered`
- `player.login`
- `player.logout`
- `player.role_changed`
- `player.2fa_enabled`
- `player.2fa_disabled`
- `security.alert`

---

## Support

For API-related questions:
- **GitHub Issues**: https://github.com/authcraft/authcraft/issues
- **Discord**: https://discord.authcraft.dev
- **Email**: api@authcraft.dev

---

*API Version: 1.0.0*
*Last updated: 2026-03-04*
