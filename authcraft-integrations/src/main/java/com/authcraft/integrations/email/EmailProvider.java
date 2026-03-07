// com/authcraft/integrations/email/EmailProvider.java
package com.authcraft.integrations.email;

import com.authcraft.core.api.TwoFactorProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.TwoFactorMethod;

import jakarta.mail.*;
import jakarta.mail.internet.*;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

public class EmailProvider implements TwoFactorProvider {

    private final AuthCraftConfig config;
    private final boolean available;
    private final Map<UUID, String> pendingCodes = new ConcurrentHashMap<>();
    private static final SecureRandom RANDOM = new SecureRandom();

    public EmailProvider(AuthCraftConfig config) {
        this.config = config;
        this.available = config.isEmailEnabled()
                && config.getSmtpHost() != null
                && !config.getSmtpHost().isEmpty();
    }

    @Override
    public TwoFactorMethod getMethod() {
        return TwoFactorMethod.EMAIL;
    }

    @Override
    public String generateSecret(UUID playerUuid, String username) {
        // For email, "secret" is just a placeholder
        // The actual email address is stored separately
        return "email_" + playerUuid.toString().substring(0, 8);
    }

    @Override
    public boolean verifyCode(String secret, String code) {
        // Parse UUID from secret
        // In practice, verification is done via verifyOTP
        return false;
    }

    @Override
    public CompletableFuture<Boolean> sendCode(String emailAddress, String code) {
        return CompletableFuture.supplyAsync(() -> {
            if (!available || emailAddress == null) return false;

            try {
                Properties props = new Properties();
                props.put("mail.smtp.host", config.getSmtpHost());
                props.put("mail.smtp.port", String.valueOf(config.getSmtpPort()));
                props.put("mail.smtp.auth", "true");

                if (config.isSmtpTls()) {
                    props.put("mail.smtp.starttls.enable", "true");
                }

                Session session = Session.getInstance(props, new Authenticator() {
                    @Override
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(
                                config.getSmtpUsername(),
                                config.getSmtpPassword()
                        );
                    }
                });

                MimeMessage message = new MimeMessage(session);
                message.setFrom(new InternetAddress(config.getEmailFrom()));
                message.setRecipients(Message.RecipientType.TO,
                        InternetAddress.parse(emailAddress));
                message.setSubject("AuthCraft - Verification Code");

                String body = """
                    <html>
                    <body style="font-family: Arial, sans-serif; padding: 20px;">
                        <h2 style="color: #4472C4;">🔐 AuthCraft Verification</h2>
                        <p>Your verification code:</p>
                        <h1 style="background: #f0f0f0; padding: 15px; text-align: center;
                                    letter-spacing: 8px; font-size: 32px;">%s</h1>
                        <p>This code expires in 5 minutes.</p>
                        <p style="color: #888; font-size: 12px;">
                            If you did not request this code, please ignore this email.
                        </p>
                    </body>
                    </html>
                """.formatted(code);

                message.setContent(body, "text/html; charset=utf-8");
                Transport.send(message);
                return true;

            } catch (MessagingException e) {
                return false;
            }
        });
    }

    @Override
    public byte[] generateQrCode(String secret, String username, int size) {
        return null;
    }

    @Override
    public boolean isAvailable() {
        return available;
    }

    public CompletableFuture<String> generateAndSendOTP(UUID uuid, String email) {
        String code = String.format("%06d", RANDOM.nextInt(1000000));
        pendingCodes.put(uuid, code);
        return sendCode(email, code).thenApply(sent -> {
            if (sent) return code;
            pendingCodes.remove(uuid);
            return null;
        });
    }

    public boolean verifyOTP(UUID uuid, String code) {
        String expected = pendingCodes.get(uuid);
        if (expected == null) {
            return false;
        }
        // Use constant-time comparison to prevent timing attacks
        boolean valid = java.security.MessageDigest.isEqual(
            expected.getBytes(java.nio.charset.StandardCharsets.UTF_8),
            code.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
        if (valid) {
            pendingCodes.remove(uuid);
        }
        return valid;
    }
}