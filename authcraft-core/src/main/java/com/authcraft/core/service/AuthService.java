package com.authcraft.core.service;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.api.PlatformAdapter;
import com.authcraft.core.api.StorageProvider;
import com.authcraft.core.api.TwoFactorProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.exception.*;
import com.authcraft.core.model.*;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class AuthService {

    private final AuthCraftCore core;
    private final AuthCraftConfig config;
    private final StorageProvider storage;
    private final PlatformAdapter platform;
    private final PasswordValidator passwordValidator;
    private final SessionService sessionService;
    private final AuditService auditService;
    private final TwoFactorService twoFactorService;
    private final RoleService roleService;
    private final MessageService msg;
    private final Logger logger;
    private final LoginConfirmationService confirmationService;

    private final Map<UUID, PendingTwoFactor> pending2fa;
    private final Map<UUID, TwoFactorService.TwoFactorSetupResult> setupSessions;
    private final Map<UUID, Integer> reminderTasks;
    // Tracks players who logged in via session restore (not password)
    private final Set<UUID> sessionRestoredLogins;

    public AuthService(AuthCraftCore core, AuthCraftConfig config,
                       StorageProvider storage, PlatformAdapter platform,
                       PasswordValidator passwordValidator,
                       SessionService sessionService, AuditService auditService,
                       TwoFactorService twoFactorService, RoleService roleService) {
        this.core = core;
        this.config = config;
        this.storage = storage;
        this.platform = platform;
        this.passwordValidator = passwordValidator;
        this.sessionService = sessionService;
        this.auditService = auditService;
        this.twoFactorService = twoFactorService;
        this.roleService = roleService;
        this.msg = core.getMessageService();
        this.logger = platform.getLogger();
        this.confirmationService = new LoginConfirmationService();
        this.pending2fa = new ConcurrentHashMap<>();
        this.setupSessions = new ConcurrentHashMap<>();
        this.reminderTasks = new ConcurrentHashMap<>();
        this.sessionRestoredLogins = ConcurrentHashMap.newKeySet();
    }

    // ═══ JOIN ═══
    public void handleJoin(UUID uuid, String username, String ip) {
        sessionService.tryRestoreSession(uuid, ip)
                .thenCompose(optSession -> {
                    if (optSession.isPresent()) {
                        Session session = optSession.get();
                        return storage.getAccount(uuid).thenAccept(optAcc -> {
                            if (optAcc.isPresent()) {
                                Account acc = optAcc.get();
                                if (acc.isTwoFactorEnabled() && !session.isTwoFactorVerified()) {
                                    enterLimbo(uuid, username, "2fa.prompt");
                                    pending2fa.put(uuid, new PendingTwoFactor(acc));
                                } else {
                                    // Mark as session-restored login (not password authenticated)
                                    sessionRestoredLogins.add(uuid);
                                    completeLogin(uuid, acc, session, ip);
                                }
                            }
                        });
                    }
                    return storage.getAccountByName(username).thenAccept(optAcc -> {
                        if (optAcc.isPresent()) {
                            Account acc = optAcc.get();
                            if (acc.isLocked()) {
                                Duration rem = Duration.between(Instant.now(), acc.getLockedUntil());
                                platform.kickPlayer(uuid, msg.get("login.kicked-locked", "time", formatDuration(rem)));
                                return;
                            }
                            enterLimbo(uuid, username, "login.prompt");
                        } else {
                            enterLimbo(uuid, username, "register.prompt");
                        }
                    });
                })
                .exceptionally(ex -> {
                    logger.severe("[AuthCraft] Join error for " + username + ": " + ex.getMessage());
                    enterLimbo(uuid, username, "error.generic");
                    return null;
                });
    }

    private void enterLimbo(UUID uuid, String username, String messageKey) {
        core.setInLimbo(uuid, true);
        core.setAuthenticated(uuid, false);
        String message = msg.get(messageKey);
        platform.runSync(() -> {
            platform.setLimboState(uuid, true);
            platform.sendMessage(uuid, message);
            platform.sendTitle(uuid, msg.get("limbo.title"), msg.get("limbo.subtitle"), 10, 70, 20);
        });
        int taskId = platform.scheduleRepeating(() -> {
                    if (core.isInLimbo(uuid) && platform.isPlayerOnline(uuid))
                        platform.sendMessage(uuid, message);
                }, 20L * config.getLimboReminderIntervalSeconds(),
                20L * config.getLimboReminderIntervalSeconds());
        reminderTasks.put(uuid, taskId);
    }

    private void completeLogin(UUID uuid, Account account, Session session, String ip) {
        core.setAuthenticated(uuid, true);
        core.setInLimbo(uuid, false);
        platform.runSync(() -> {
            platform.setLimboState(uuid, false);
            platform.sendMessage(uuid, msg.get("login.success"));
            platform.sendTitle(uuid, msg.get("limbo.title-success"), msg.get("limbo.subtitle-success"), 5, 40, 10);
        });
        roleService.applyRole(uuid, account.getRole());
        cancelReminder(uuid);

        boolean newIp = account.getLastLoginIp() != null && !account.getLastLoginIp().equals(ip);
        account.setLastLoginIp(ip);
        account.setLastLoginDate(Instant.now());
        account.resetFailedAttempts();
        account.setStatus(AccountStatus.ACTIVE);
        storage.saveAccount(account);

        if (newIp && config.isNotifyNewIpLogin()) {
            auditService.log(AuditEventType.LOGIN_SUCCESS, uuid, account.getUsername(), ip,
                    "New IP (prev: " + account.getLastLoginIp() + ")");
            platform.broadcastPermission(
                    msg.get("notify.new-ip-login", Map.of(
                            "player", account.getUsername(), "ip", ip,
                            "old_ip", account.getLastLoginIp() != null ? account.getLastLoginIp() : "N/A")),
                    "authcraft.admin.notify");
        } else {
            auditService.log(AuditEventType.LOGIN_SUCCESS, uuid, account.getUsername(), ip, null);
        }
    }

    private void cancelReminder(UUID uuid) {
        Integer taskId = reminderTasks.remove(uuid);
        if (taskId != null) platform.cancelTask(taskId);
    }

    // ═══ REGISTER ═══
    public CompletableFuture<AuthResult> register(UUID uuid, String username,
                                                  String password, String confirm, String ip) {
        if (!core.isInLimbo(uuid))
            return done(AuthResult.failure(AuthResult.Status.ERROR, msg.get("login.already-authenticated")));
        if (!password.equals(confirm))
            return done(AuthResult.failure(AuthResult.Status.INVALID_PASSWORD, msg.get("register.passwords-mismatch")));

        try { passwordValidator.validate(password, username); }
        catch (WeakPasswordException e) {
            StringBuilder sb = new StringBuilder(msg.get("password.weak-header")).append("\n");
            for (String v : e.getViolations()) sb.append(msg.get("password.weak-item", "violation", v)).append("\n");
            return done(AuthResult.failure(AuthResult.Status.INVALID_PASSWORD, sb.toString()));
        }

        return storage.getAccountByName(username).thenCompose(existing -> {
            if (existing.isPresent())
                return done(AuthResult.failure(AuthResult.Status.ERROR, msg.get("register.already-registered")));
            return storage.countAccountsByIp(ip).thenCompose(count -> {
                if (count >= config.getMaxAccountsPerIp())
                    return done(AuthResult.failure(AuthResult.Status.RATE_LIMITED,
                            msg.get("register.too-many-accounts", "max", String.valueOf(config.getMaxAccountsPerIp()))));

                Account account = new Account();
                account.setUuid(uuid);
                account.setUsername(username);
                account.setNormalizedUsername(username.toLowerCase());
                account.setPasswordHash(core.hashPassword(password));
                account.setHashAlgorithm(config.getHashAlgorithm());
                account.setStatus(AccountStatus.ACTIVE);
                account.setRole(roleService.getDefaultRole());
                account.setRegistrationIp(ip);
                account.setLastLoginIp(ip);
                account.setLastLoginDate(Instant.now());

                return storage.saveAccount(account).thenCompose(v ->
                        sessionService.createSession(uuid, ip).thenApply(session -> {
                            completeLogin(uuid, account, session, ip);
                            auditService.log(AuditEventType.REGISTER, uuid, username, ip, null);
                            return AuthResult.success(session);
                        })
                );
            });
        });
    }

    // ═══ LOGIN ═══
    public CompletableFuture<AuthResult> login(UUID uuid, String username, String password, String ip) {
        if (!core.isInLimbo(uuid))
            return done(AuthResult.failure(AuthResult.Status.ERROR, msg.get("login.already-authenticated")));

        return storage.getAccountByName(username).thenCompose(optAccount -> {
            if (optAccount.isEmpty())
                return done(AuthResult.failure(AuthResult.Status.REGISTRATION_REQUIRED, msg.get("login.account-not-found")));

            Account account = optAccount.get();
            if (account.isLocked()) {
                Duration rem = Duration.between(Instant.now(), account.getLockedUntil());
                return done(AuthResult.failure(AuthResult.Status.ACCOUNT_LOCKED, msg.get("login.locked", "time", formatDuration(rem))));
            }

            if (!core.verifyPassword(password, account.getPasswordHash(), account.getHashAlgorithm()))
                return handleFailedLogin(account, uuid, username, ip);

            // Rehash if needed
            if (core.needsRehash(account.getPasswordHash(), account.getHashAlgorithm())) {
                account.setPasswordHash(core.hashPassword(password));
                account.setHashAlgorithm(config.getHashAlgorithm());
                storage.saveAccount(account);
            }

            // 2FA check
            if (account.isTwoFactorEnabled()) {
                // Handle multiple 2FA methods
                Set<TwoFactorMethod> enabledMethods = account.getEnabledTwoFactorMethods();
    
                // Send button-based confirmations for Telegram/VK
                boolean hasButtonMethod = false;
                if (enabledMethods.contains(TwoFactorMethod.TELEGRAM) && account.getTelegramChatId() != null) {
                    handle2FAWithButtons(uuid, account, ip, TwoFactorMethod.TELEGRAM);
                    hasButtonMethod = true;
                }
                if (enabledMethods.contains(TwoFactorMethod.VK) && account.getVkUserId() != null) {
                    handle2FAWithButtons(uuid, account, ip, TwoFactorMethod.VK);
                    hasButtonMethod = true;
                }
    
                // If TOTP is enabled, player can also enter code
                pending2fa.put(uuid, new PendingTwoFactor(account));
                account.setStatus(AccountStatus.PENDING_2FA);
    
                // Show appropriate prompt
                if (hasButtonMethod) {
                    // List all available methods
                    StringBuilder methodsList = new StringBuilder();
                    for (TwoFactorMethod m : enabledMethods) {
                        if (methodsList.length() > 0) methodsList.append(", ");
                        methodsList.append(m.name());
                    }
                    platform.sendMessage(uuid, msg.get("2fa.prompt") + " §7(" + methodsList + ")");
                } else {
                    platform.sendMessage(uuid, msg.get("2fa.prompt"));
                }
                return done(AuthResult.requires2FA());
            }

            // Clear session-restored flag since player authenticated with password
            sessionRestoredLogins.remove(uuid);
            return sessionService.createSession(uuid, ip).thenApply(session -> {
                completeLogin(uuid, account, session, ip);
                return AuthResult.success(session);
            });
        });
    }

    private CompletableFuture<AuthResult> handle2FAWithButtons(UUID uuid, Account account,
    String ip, TwoFactorMethod method) {
        String location = resolveLocation(ip);
        LoginConfirmation confirmation = confirmationService.createConfirmation(
            uuid, account.getUsername(), ip, location, method);

        TwoFactorProvider provider = core.getTwoFactorProviders().get(method);
        String targetId = method == TwoFactorMethod.TELEGRAM
            ? account.getTelegramChatId()
            : account.getVkUserId();

        if (provider != null && targetId != null) {
            // Use reflection to call sendLoginConfirmation to avoid circular dependency
            try {
                Object result = provider.getClass()
                    .getMethod("sendLoginConfirmation", String.class, LoginConfirmation.class)
                    .invoke(provider, targetId, confirmation);
                // The method returns CompletableFuture<Boolean>, we need to handle it properly
                if (result instanceof CompletableFuture) {
                    @SuppressWarnings("unchecked")
                    CompletableFuture<Boolean> future = (CompletableFuture<Boolean>) result;
                    future.thenAccept(sent -> {
                        if (!sent) {
                            logger.warning("[AuthCraft] Failed to send 2FA confirmation via " + method);
                        } else {
                            logger.info("[AuthCraft] 2FA confirmation sent successfully via " + method + " to " + targetId);
                        }
                    }).exceptionally(ex -> {
                        logger.warning("[AuthCraft] Error sending 2FA confirmation: " + ex.getMessage());
                        return null;
                    });
                }
            } catch (Exception e) {
                logger.warning("[AuthCraft] Failed to send 2FA confirmation: " + e.getMessage());
            }
        }

        pending2fa.put(uuid, new PendingTwoFactor(account));
        String methodName = method == TwoFactorMethod.TELEGRAM ? "Telegram" : "VK";
        platform.sendMessage(uuid, msg.get("2fa.login-waiting", "method", methodName));

        // Timeout after 120s
        platform.scheduleRepeating(() -> {
            LoginConfirmation c = confirmationService.getByPlayer(uuid);
            if ((c == null || c.isExpired()) && core.isInLimbo(uuid) && platform.isPlayerOnline(uuid)) {
                platform.sendMessage(uuid, msg.get("2fa.login-timeout"));
                platform.kickPlayer(uuid, msg.get("2fa.login-timeout"));
                pending2fa.remove(uuid);
            }
        }, 20L * 125, 20L * 9999); // Run once after ~125 sec

        return done(AuthResult.requires2FA());
    }

    private CompletableFuture<AuthResult> handleFailedLogin(Account account, UUID uuid, String username, String ip) {
        account.incrementFailedAttempts();
        int attempts = account.getFailedLoginAttempts();
        storage.recordLoginAttempt(new LoginAttempt(uuid, ip, false, "Invalid password"));
        auditService.log(AuditEventType.LOGIN_FAILURE, uuid, username, ip,
                "Attempt " + attempts + "/" + config.getMaxLoginAttempts());

        if (attempts >= config.getNotifyAdminAfterAttempts()) {
            platform.broadcastPermission(msg.get("notify.failed-login",
                            Map.of("player", username, "attempt", String.valueOf(attempts), "ip", ip)),
                    "authcraft.admin.notify");
        }

        if (attempts >= config.getMaxLoginAttempts()) {
            long lockMin = calculateLockDuration(attempts);
            account.setLockedUntil(Instant.now().plusSeconds(lockMin * 60));
            account.setStatus(AccountStatus.LOCKED);
            storage.saveAccount(account);
            auditService.log(AuditEventType.ACCOUNT_LOCKED, uuid, username, ip, "Locked " + lockMin + "m");
            platform.kickPlayer(uuid, msg.get("login.kicked-locked", "time", lockMin + "m"));
            return done(AuthResult.failure(AuthResult.Status.ACCOUNT_LOCKED, "Locked " + lockMin + "m"));
        }

        storage.saveAccount(account);
        int remaining = config.getMaxLoginAttempts() - attempts;
        return done(AuthResult.failure(AuthResult.Status.INVALID_PASSWORD,
                msg.get("login.wrong-password", "remaining", String.valueOf(remaining))));
    }

    private long calculateLockDuration(int failed) {
        int lockCount = failed / config.getMaxLoginAttempts();
        long min = (long) (config.getBaseLockDurationMinutes() *
                Math.pow(config.getLockExponentialBase(), Math.max(0, lockCount - 1)));
        return Math.min(min, config.getMaxLockDurationMinutes());
    }

    // ═══ 2FA VERIFY ═══
    public CompletableFuture<AuthResult> verify2FA(UUID uuid, String code, String ip) {
        PendingTwoFactor pending = pending2fa.get(uuid);
        if (pending == null) return done(AuthResult.failure(AuthResult.Status.ERROR, msg.get("2fa.no-pending")));
        Account account = pending.account;

        // Try all enabled 2FA methods
        Set<TwoFactorMethod> enabledMethods = account.getEnabledTwoFactorMethods();
        return tryVerifyWithMethods(uuid, account, code, ip, enabledMethods, pending);
    }

    /**
     * Try to verify 2FA code with any of the enabled methods.
     */
    private CompletableFuture<AuthResult> tryVerifyWithMethods(UUID uuid, Account account, String code, String ip,
                                                               Set<TwoFactorMethod> methods, PendingTwoFactor pending) {
        // Try TOTP first if enabled
        if (methods.contains(TwoFactorMethod.TOTP) && account.getTotpSecret() != null) {
            return twoFactorService.verifyCode(uuid, TwoFactorMethod.TOTP, account.getTotpSecret(), code)
                .thenCompose(verified -> {
                    if (verified) {
                        return complete2FAVerification(uuid, account, ip);
                    }
                    // Try next method
                    Set<TwoFactorMethod> remaining = new java.util.HashSet<>(methods);
                    remaining.remove(TwoFactorMethod.TOTP);
                    return tryVerifyWithMethods(uuid, account, code, ip, remaining, pending);
                });
        }

        // Try EMAIL if enabled
        if (methods.contains(TwoFactorMethod.EMAIL) && account.getEmail() != null) {
            return twoFactorService.verifyCode(uuid, TwoFactorMethod.EMAIL, account.getEmail(), code)
                .thenCompose(verified -> {
                    if (verified) {
                        return complete2FAVerification(uuid, account, ip);
                    }
                    Set<TwoFactorMethod> remaining = new java.util.HashSet<>(methods);
                    remaining.remove(TwoFactorMethod.EMAIL);
                    return tryVerifyWithMethods(uuid, account, code, ip, remaining, pending);
                });
        }

        // No more methods to try - handle failure
        pending.attempts++;
        if (pending.attempts >= config.getTwoFactorMaxAttempts()) {
            pending2fa.remove(uuid);
            platform.kickPlayer(uuid, msg.get("2fa.too-many-attempts"));
            return done(AuthResult.failure(AuthResult.Status.INVALID_2FA_CODE, msg.get("2fa.too-many-attempts")));
        }
        int rem = config.getTwoFactorMaxAttempts() - pending.attempts;
        return done(AuthResult.failure(AuthResult.Status.INVALID_2FA_CODE,
            msg.get("2fa.invalid-code", "remaining", String.valueOf(rem))));
    }

    /**
     * Complete 2FA verification and create session.
     */
    private CompletableFuture<AuthResult> complete2FAVerification(UUID uuid, Account account, String ip) {
        pending2fa.remove(uuid);
        return sessionService.createSession(uuid, ip).thenCompose(session -> {
            session.setTwoFactorVerified(true);
            return storage.saveSession(session).thenApply(v -> {
                completeLogin(uuid, account, session, ip);
                twoFactorService.getRemainingBackupCodes(uuid).thenAccept(rem -> {
                    if (rem <= 3 && rem > 0)
                        platform.sendMessage(uuid, msg.get("2fa.backup-remaining", "remaining", String.valueOf(rem)));
                });
                return AuthResult.success(session);
            });
        });
    }

    // ═══ CHANGE PASSWORD ═══
    public CompletableFuture<AuthResult> changePassword(UUID uuid, String oldPwd, String newPwd) {
        if (!core.isAuthenticated(uuid))
            return done(AuthResult.failure(AuthResult.Status.ERROR, msg.get("password.must-login")));

        return storage.getAccount(uuid).thenCompose(optAcc -> {
            if (optAcc.isEmpty())
                return done(AuthResult.failure(AuthResult.Status.ACCOUNT_NOT_FOUND, msg.get("admin.not-found")));
            Account account = optAcc.get();
            if (!core.verifyPassword(oldPwd, account.getPasswordHash(), account.getHashAlgorithm()))
                return done(AuthResult.failure(AuthResult.Status.INVALID_PASSWORD, msg.get("password.old-incorrect")));

            try { passwordValidator.validate(newPwd, account.getUsername()); }
            catch (WeakPasswordException e) {
                StringBuilder sb = new StringBuilder(msg.get("password.weak-header")).append("\n");
                for (String v : e.getViolations()) sb.append(msg.get("password.weak-item", "violation", v)).append("\n");
                return done(AuthResult.failure(AuthResult.Status.INVALID_PASSWORD, sb.toString()));
            }

            account.setPasswordHash(core.hashPassword(newPwd));
            account.setHashAlgorithm(config.getHashAlgorithm());
            account.setUpdatedAt(Instant.now());
            return storage.saveAccount(account).thenCompose(v ->
                    sessionService.invalidateAllSessions(uuid).thenApply(v2 -> {
                        auditService.log(AuditEventType.PASSWORD_CHANGE, uuid, account.getUsername(), platform.getPlayerIp(uuid), null);
                        platform.sendMessage(uuid, msg.get("password.changed"));
                        return AuthResult.success(null);
                    })
            );
        });
    }

    // ═══ 2FA SETUP ═══
    public TwoFactorService.TwoFactorSetupResult beginTwoFactorSetup(UUID uuid, String username, TwoFactorMethod method) {
        var result = twoFactorService.beginSetup(method, uuid, username);
        setupSessions.put(uuid, result);
        return result;
    }

    public CompletableFuture<List<String>> confirmTwoFactorSetup(UUID uuid, String code) {
        TwoFactorService.TwoFactorSetupResult setup = setupSessions.get(uuid);
        if (setup == null) return CompletableFuture.failedFuture(new IllegalStateException(msg.get("2fa.no-setup")));
        return twoFactorService.confirmSetup(uuid, setup.getMethod(), setup.getSecret(), code)
            .thenCompose(backupCodes -> storage.getAccount(uuid).thenCompose(optAcc -> {
                if (optAcc.isEmpty()) return CompletableFuture.<List<String>>failedFuture(new IllegalStateException("Account not found"));
                Account account = optAcc.get();
                // Add the new method to enabled methods (supports multiple methods)
                account.enableTwoFactorMethod(setup.getMethod());
                // Set the secret for this specific method
                account.setTwoFactorSecretForMethod(setup.getMethod(), setup.getSecret());
                return storage.saveAccount(account).thenCompose(v -> {
                    // Mark current session as 2FA verified so player doesn't need to verify again on reconnect
                    return sessionService.markTwoFactorVerified(uuid).thenApply(v2 -> {
                        setupSessions.remove(uuid);
                        auditService.log(AuditEventType.TWO_FACTOR_ENABLE, uuid, account.getUsername(), platform.getPlayerIp(uuid), "Method: " + setup.getMethod());
                        return backupCodes;
                    });
                });
            }));
    }

    /**
     * Disable a specific 2FA method.
     */
    public CompletableFuture<Boolean> disableTwoFactorMethod(UUID uuid, String password, TwoFactorMethod method) {
        return storage.getAccount(uuid).thenCompose(optAcc -> {
            if (optAcc.isEmpty()) return CompletableFuture.completedFuture(false);
            Account account = optAcc.get();
            if (!core.verifyPassword(password, account.getPasswordHash(), account.getHashAlgorithm()))
                return CompletableFuture.completedFuture(false);

            // Disable the specific method
            account.clearTwoFactorMethod(method);

            // If no methods left, delete backup codes
            if (!account.isTwoFactorEnabled()) {
                return storage.saveAccount(account).thenCompose(v -> storage.deleteBackupCodes(uuid)).thenApply(v -> {
                    auditService.log(AuditEventType.TWO_FACTOR_DISABLE, uuid, account.getUsername(), platform.getPlayerIp(uuid), "Disabled: " + method);
                    return true;
                });
            }

            return storage.saveAccount(account).thenApply(v -> {
                auditService.log(AuditEventType.TWO_FACTOR_DISABLE, uuid, account.getUsername(), platform.getPlayerIp(uuid), "Disabled: " + method);
                return true;
            });
        });
    }

    /**
     * Disable all 2FA methods (legacy method for backwards compatibility).
     */
    public CompletableFuture<Boolean> disableTwoFactor(UUID uuid, String password) {
        return storage.getAccount(uuid).thenCompose(optAcc -> {
            if (optAcc.isEmpty()) return CompletableFuture.completedFuture(false);
            Account account = optAcc.get();
            if (!core.verifyPassword(password, account.getPasswordHash(), account.getHashAlgorithm()))
                return CompletableFuture.completedFuture(false);
            account.clearAllTwoFactorMethods();
            return storage.saveAccount(account).thenCompose(v -> storage.deleteBackupCodes(uuid)).thenApply(v -> {
                auditService.log(AuditEventType.TWO_FACTOR_DISABLE, uuid, account.getUsername(), platform.getPlayerIp(uuid), "All methods disabled");
                return true;
            });
        });
    }

    // ═══ ADMIN ═══
    public CompletableFuture<Boolean> adminReset2FA(UUID adminUuid, String targetUsername) {
        return storage.getAccountByName(targetUsername).thenCompose(optAcc -> {
            if (optAcc.isEmpty()) return CompletableFuture.completedFuture(false);
            Account account = optAcc.get();
            account.setTwoFactorMethod(TwoFactorMethod.NONE);
            account.setTwoFactorSecret(null);
            account.setTelegramChatId(null);
            account.setVkUserId(null);
            return storage.saveAccount(account).thenCompose(v -> storage.deleteBackupCodes(account.getUuid())).thenApply(v -> {
                auditService.log(AuditEventType.TWO_FACTOR_RESET, account.getUuid(), targetUsername,
                        adminUuid != null ? platform.getPlayerIp(adminUuid) : "console", "Admin reset");
                return true;
            });
        });
    }

    public CompletableFuture<Boolean> adminUnlock(UUID adminUuid, String targetUsername) {
        return storage.getAccountByName(targetUsername).thenCompose(optAcc -> {
            if (optAcc.isEmpty()) return CompletableFuture.completedFuture(false);
            Account account = optAcc.get();
            account.setLockedUntil(null);
            account.resetFailedAttempts();
            account.setStatus(AccountStatus.ACTIVE);
            return storage.saveAccount(account).thenApply(v -> {
                auditService.log(AuditEventType.ACCOUNT_UNLOCKED, account.getUuid(), targetUsername,
                        adminUuid != null ? platform.getPlayerIp(adminUuid) : "console", "Admin unlock");
                return true;
            });
        });
    }

    public CompletableFuture<Boolean> setRole(UUID adminUuid, String targetUsername, String roleName) {
        if (!roleService.isValidRole(roleName)) return CompletableFuture.completedFuture(false);
        return storage.getAccountByName(targetUsername).thenCompose(optAcc -> {
            if (optAcc.isEmpty()) return CompletableFuture.completedFuture(false);
            Account account = optAcc.get();
            String oldRole = account.getRole();
            account.setRole(roleName);
            return storage.saveAccount(account).thenApply(v -> {
                if (platform.isPlayerOnline(account.getUuid())) {
                    roleService.removeRole(account.getUuid(), oldRole);
                    roleService.applyRole(account.getUuid(), roleName);
                }
                auditService.log(AuditEventType.ROLE_CHANGED, account.getUuid(), targetUsername,
                        adminUuid != null ? platform.getPlayerIp(adminUuid) : "console", oldRole + " → " + roleName);
                return true;
            });
        });
    }

    public void handleQuit(UUID uuid) {
        core.handlePlayerQuit(uuid);
        cancelReminder(uuid);
        pending2fa.remove(uuid);
        setupSessions.remove(uuid);
        confirmationService.cancelForPlayer(uuid);
        sessionRestoredLogins.remove(uuid);
    }

    /**
     * Check if the player's current login was from a session restore (not password authentication).
     * This is used to block 2FA enable for session-restored logins.
     */
    public boolean isSessionRestoredLogin(UUID uuid) {
        return sessionRestoredLogins.contains(uuid);
    }

    // ═══ UTILS ═══
    private String formatDuration(Duration d) {
        long s = d.getSeconds();
        if (s < 60) return s + "s";
        if (s < 3600) return (s / 60) + "m " + (s % 60) + "s";
        return (s / 3600) + "h " + ((s % 3600) / 60) + "m";
    }

    private String resolveLocation(String ip) {
        try {
            var url = new java.net.URL("http://ip-api.com/json/" + ip + "?fields=country,city&lang=ru");
            var conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(2000); conn.setReadTimeout(2000);
            if (conn.getResponseCode() == 200) {
                try (var r = new java.io.BufferedReader(new java.io.InputStreamReader(conn.getInputStream()))) {
                    String resp = r.readLine();
                    String country = extractJson(resp, "country"), city = extractJson(resp, "city");
                    if (country != null && city != null) return city + ", " + country;
                    if (country != null) return country;
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private String extractJson(String json, String key) {
        String search = "\"" + key + "\":\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;
        int start = idx + search.length(), end = json.indexOf("\"", start);
        return end < 0 ? null : json.substring(start, end);
    }

    private <T> CompletableFuture<T> done(T value) {
        return CompletableFuture.completedFuture(value);
    }

    public LoginConfirmationService getConfirmationService() { return confirmationService; }
    public Map<UUID, TwoFactorService.TwoFactorSetupResult> getSetupSessions() { return setupSessions; }

    private static class PendingTwoFactor {
        final Account account;
        int attempts;
        PendingTwoFactor(Account account) { this.account = account; this.attempts = 0; }
    }
}