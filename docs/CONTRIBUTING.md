# Contributing to AuthCraft

Thank you for your interest in contributing to AuthCraft! This document provides guidelines and instructions for contributing.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Testing](#testing)
- [Documentation](#documentation)
- [Security](#security)

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inspiring community for all.

### Standards

- Be respectful and inclusive
- Welcome newcomers
- Accept constructive criticism
- Focus on what's best for the community
- Show empathy towards others

---

## Getting Started

### Prerequisites

- Java 17 or higher
- Gradle 8.0+
- Git
- IntelliJ IDEA (recommended) or Eclipse

### Fork and Clone

```bash
# Fork the repository on GitHub
# Then clone your fork
git clone https://github.com/YOUR_USERNAME/authcraft.git
cd authcraft

# Add upstream remote
git remote add upstream https://github.com/authcraft/authcraft.git
```

### Keep Your Fork Updated

```bash
git fetch upstream
git checkout main
git merge upstream/main
```

---

## Development Setup

### IDE Configuration

#### IntelliJ IDEA

1. Import project: `File → Open → select project root`
2. Enable annotation processing: `Settings → Build → Compiler → Annotation Processors`
3. Install Minecraft Development plugin
4. Set Java SDK to 17+

#### Eclipse

1. Import: `File → Import → Gradle → Existing Gradle Project`
2. Set JRE to Java 17+

### Build Project

```bash
# Full build
./gradlew build

# Build without tests
./gradlew build -x test

# Clean build
./gradlew clean build

# Build specific module
./gradlew :authcraft-bukkit:build
```

### Run Test Server

```bash
# Start test server
./gradlew runServer

# Or manually
cd test-server
java -jar spigot.jar
```

---

## Project Structure

```
AuthCraft/
├── authcraft-core/           # Core logic (platform-independent)
│   ├── src/main/java/
│   │   └── com/authcraft/core/
│   │       ├── api/          # Interfaces and contracts
│   │       ├── config/       # Configuration handling
│   │       ├── crypto/       # Cryptographic implementations
│   │       ├── exception/    # Custom exceptions
│   │       ├── model/        # Data models
│   │       └── service/      # Business logic services
│   └── src/main/resources/   # Default configs, messages
│
├── authcraft-bukkit/         # Bukkit/Spigot/Paper implementation
│   ├── src/main/java/
│   │   └── com/authcraft/bukkit/
│   │       ├── adapter/      # Platform adapter
│   │       ├── command/      # Command handlers
│   │       ├── config/       # Bukkit config loader
│   │       ├── integration/  # Vault, PlaceholderAPI
│   │       └── listener/     # Event listeners
│   └── src/main/resources/
│       ├── config.yml        # Default config
│       ├── plugin.yml        # Plugin metadata
│       └── messages_*.yml    # Localizations
│
├── authcraft-bungee/         # BungeeCord implementation
├── authcraft-velocity/       # Velocity implementation
├── authcraft-storage/        # Database implementations
├── authcraft-security/       # Security modules
├── authcraft-integrations/   # External integrations (Telegram, VK, Email)
│
├── docs/                     # Documentation
├── test-server/              # Local test server
└── docker/                   # Docker configuration
```

### Module Dependencies

```
authcraft-bukkit
    └── authcraft-core
    └── authcraft-storage
    └── authcraft-security
    └── authcraft-integrations

authcraft-core
    └── (no internal dependencies)
```

---

## Coding Standards

### Java Style Guide

We follow standard Java conventions with some modifications:

#### Naming

```java
// Classes: PascalCase
public class AuthService { }

// Interfaces: PascalCase (no I prefix)
public interface StorageProvider { }

// Methods: camelCase
public CompletableFuture<Account> getAccount(UUID uuid) { }

// Constants: UPPER_SNAKE_CASE
public static final int MAX_ATTEMPTS = 5;

// Packages: lowercase
package com.authcraft.core.service;
```

#### Formatting

```java
// Braces on same line
if (condition) {
    // code
} else {
    // code
}

// Space after keywords
for (int i = 0; i < 10; i++) {
    // code
}

// Lambda formatting
list.stream()
    .filter(item -> item.isActive())
    .map(Item::getName)
    .collect(Collectors.toList());
```

#### Best Practices

```java
// Use Optional for nullable returns
public Optional<Account> getAccount(UUID uuid) { }

// Use CompletableFuture for async operations
public CompletableFuture<Boolean> saveAccount(Account account) { }

// Use try-with-resources
try (InputStream is = new FileInputStream(file)) {
    // code
}

// Prefer immutability
public record LoginResult(boolean success, String message) { }

// Document public APIs
/**
 * Authenticates a player with the given credentials.
 *
 * @param username the player's username
 * @param password the player's password
 * @param ip the player's IP address
 * @return authentication result
 */
public AuthResult login(String username, String password, String ip) { }
```

### Security Guidelines

**CRITICAL**: All security-related code must follow these rules:

1. **Never log passwords or secrets**
```java
// WRONG
logger.info("Login attempt: " + password);

// CORRECT
logger.info("Login attempt for user: " + username);
```

2. **Always use parameterized queries**
```java
// WRONG
String sql = "SELECT * FROM accounts WHERE name = '" + name + "'";

// CORRECT
PreparedStatement ps = conn.prepareStatement("SELECT * FROM accounts WHERE name = ?");
ps.setString(1, name);
```

3. **Use SecureRandom for security-sensitive randomness**
```java
// WRONG
Random random = new Random();

// CORRECT
SecureRandom random = new SecureRandom();
```

4. **Constant-time comparison for secrets**
```java
// Use SecureCompare for password/token comparison
if (SecureCompare.equalsHash(inputPassword, storedHash)) { }
```

---

## Commit Guidelines

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation |
| `style` | Formatting, no code change |
| `refactor` | Code refactoring |
| `test` | Adding tests |
| `chore` | Maintenance tasks |
| `security` | Security fix |

### Examples

```bash
# Feature
feat(2fa): add Discord integration

# Bug fix
fix(auth): resolve session restoration issue

# Security
security(crypto): update Argon2id parameters

# Breaking change
feat(api)!: change StorageProvider interface

BREAKING CHANGE: The getAccount method now returns Optional
```

---

## Pull Request Process

### Before Submitting

1. **Update from upstream**
```bash
git fetch upstream
git rebase upstream/main
```

2. **Run tests**
```bash
./gradlew test
```

3. **Check code style**
```bash
./gradlew spotlessCheck
```

4. **Update documentation** if needed

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests passed
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings
- [ ] Tests pass locally
```

### Review Process

1. At least 1 approval required
2. All CI checks must pass
3. No merge conflicts
4. Squash and merge to main

---

## Testing

### Unit Tests

```java
@Test
void testPasswordHashing() {
    String password = "testPassword123";
    String hash = hasher.hash(password);
    
    assertNotNull(hash);
    assertTrue(hasher.verify(password, hash));
}

@Test
void testFailedLogin() {
    when(storage.getAccount(any())).thenReturn(Optional.empty());
    
    AuthResult result = authService.login("user", "pass", "127.0.0.1");
    
    assertEquals(AuthResult.Status.FAILED, result.getStatus());
}
```

### Running Tests

```bash
# All tests
./gradlew test

# Specific module
./gradlew :authcraft-core:test

# Specific test class
./gradlew test --tests "AuthServiceTest"

# With coverage
./gradlew test jacocoTestReport
```

### Test Categories

- **Unit tests**: `src/test/java/`
- **Integration tests**: `src/integrationTest/java/`
- **Security tests**: `src/test/java/com/authcraft/security/`

---

## Documentation

### Code Documentation

```java
/**
 * Service for handling player authentication.
 * 
 * <p>This service provides methods for registration, login, and session
 * management. All operations are asynchronous and return CompletableFuture.
 * 
 * <h2>Thread Safety</h2>
 * <p>This class is thread-safe and can be used from any thread.
 * 
 * @see SessionService
 * @see TwoFactorService
 */
public class AuthService {
    // ...
}
```

### Updating Documentation

When adding features, update:

1. **README.md** - User-facing changes
2. **docs/CONFIGURATION.md** - New config options
3. **docs/API.md** - New API endpoints
4. **Javadoc** - Code documentation
5. **CHANGELOG.md** - Version history

---

## Security

### Reporting Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Email: security@authcraft.dev

Include:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Security Review

All security-related PRs require:
1. Code review by maintainer
2. Security assessment
3. Test coverage for attack vectors

---

## Getting Help

- **GitHub Discussions**: General questions
- **GitHub Issues**: Bug reports, features
- **Discord**: Real-time chat
- **Email**: security@authcraft.dev (security only)

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to AuthCraft! 🎉
