// com/authcraft/security/SecurityAudit.java
package com.authcraft.security;

import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.AuditEventType;
import com.authcraft.core.service.AuditService;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.*;
import java.util.*;
import java.util.logging.Logger;

/**
 * Proactive security audit on server startup.
 * Checks for common misconfigurations and vulnerabilities.
 */
public class SecurityAudit {

    private final AuthCraftConfig config;
    private final AuditService auditService;
    private final Logger logger;
    private final File serverRoot;

    // Known vulnerable plugins
    private static final Map<String, String> VULNERABLE_PLUGINS =
            Map.of(
                    "PermissionsEx", "CVE-2020-XXXXX - RCE via YAML deserialization",
                    "EssentialsX-2.18", "Known command injection vulnerability",
                    "WorldEdit-7.2.0", "Arbitrary file read vulnerability"
            );

    // Ports to check
    private static final Map<Integer, String> SENSITIVE_PORTS = Map.of(
            3306, "MySQL",
            5432, "PostgreSQL",
            6379, "Redis",
            27017, "MongoDB",
            25575, "RCON"
    );

    public SecurityAudit(AuthCraftConfig config,
                         AuditService auditService,
                         Logger logger,
                         File serverRoot) {
        this.config = config;
        this.auditService = auditService;
        this.logger = logger;
        this.serverRoot = serverRoot;
    }

    /**
     * Run the full security audit.
     * Returns a list of findings.
     */
    public List<AuditFinding> runAudit() {
        if (!config.isSecurityAuditOnStartup()) {
            return List.of();
        }

        logger.info("[AuthCraft] ╔══════════════════════════════════╗");
        logger.info("[AuthCraft] ║     SECURITY AUDIT STARTING     ║");
        logger.info("[AuthCraft] ╚══════════════════════════════════╝");

        List<AuditFinding> findings = new ArrayList<>();

        if (config.isSecurityAuditCheckPorts()) {
            findings.addAll(checkOpenPorts());
        }

        if (config.isSecurityAuditCheckRcon()) {
            findings.addAll(checkServerProperties());
        }

        if (config.isSecurityAuditCheckPlugins()) {
            findings.addAll(checkPlugins());
        }

        if (config.isSecurityAuditCheckPermissions()) {
            findings.addAll(checkFilePermissions());
        }

        findings.addAll(checkConfigPasswords());

        // Log results
        int critical = 0, warning = 0, info = 0;
        for (AuditFinding finding : findings) {
            String prefix = switch (finding.severity) {
                case CRITICAL -> { critical++; yield "§c[CRITICAL]"; }
                case WARNING -> { warning++; yield "§e[WARNING]"; }
                case INFO -> { info++; yield "§b[INFO]"; }
            };
            logger.info("[AuthCraft Audit] " + prefix + " §f"
                    + finding.description);
        }

        logger.info("[AuthCraft] ══════════════════════════════════");
        logger.info(String.format(
                "[AuthCraft] Audit complete: %d critical, "
                        + "%d warnings, %d info",
                critical, warning, info
        ));
        logger.info("[AuthCraft] ══════════════════════════════════");

        // Log to audit service
        String summary = String.format(
                "Security audit: %d critical, %d warnings, %d info",
                critical, warning, info
        );
        auditService.logSystem(AuditEventType.SECURITY_AUDIT, summary);

        return findings;
    }

    private List<AuditFinding> checkOpenPorts() {
        List<AuditFinding> findings = new ArrayList<>();

        for (var entry : SENSITIVE_PORTS.entrySet()) {
            int port = entry.getKey();
            String service = entry.getValue();

            if (isPortOpen("127.0.0.1", port)) {
                findings.add(new AuditFinding(
                        Severity.WARNING,
                        service + " port " + port
                                + " is open on localhost. "
                                + "Ensure it's not exposed externally."
                ));
            }
        }

        return findings;
    }

    private List<AuditFinding> checkServerProperties() {
        List<AuditFinding> findings = new ArrayList<>();

        File propsFile = new File(serverRoot, "server.properties");
        if (!propsFile.exists()) return findings;

        try {
            Properties props = new Properties();
            try (FileInputStream fis = new FileInputStream(propsFile)) {
                props.load(fis);
            }

            // Check online-mode
            String onlineMode = props.getProperty(
                    "online-mode", "true"
            );
            if ("false".equalsIgnoreCase(onlineMode)) {
                findings.add(new AuditFinding(
                        Severity.INFO,
                        "Server is in offline-mode. "
                                + "AuthCraft is handling authentication."
                ));
            }

            // Check RCON
            String rconEnabled = props.getProperty(
                    "enable-rcon", "false"
            );
            if ("true".equalsIgnoreCase(rconEnabled)) {
                String rconPassword = props.getProperty(
                        "rcon.password", ""
                );
                if (rconPassword.isEmpty()) {
                    findings.add(new AuditFinding(
                            Severity.CRITICAL,
                            "RCON is enabled WITHOUT a password! "
                                    + "Anyone can execute console commands."
                    ));
                } else if (rconPassword.length() < 8) {
                    findings.add(new AuditFinding(
                            Severity.WARNING,
                            "RCON password is shorter than "
                                    + "8 characters."
                    ));
                } else if (isWeakPassword(rconPassword)) {
                    findings.add(new AuditFinding(
                            Severity.WARNING,
                            "RCON password is weak/common."
                    ));
                }
            }

            // Check max players vs our limits
            String maxPlayers = props.getProperty(
                    "max-players", "20"
            );
            try {
                int max = Integer.parseInt(maxPlayers);
                if (max > 500) {
                    findings.add(new AuditFinding(
                            Severity.INFO,
                            "High max-players (" + max + "). "
                                    + "Ensure DB pool size is adequate."
                    ));
                }
            } catch (NumberFormatException ignored) {}

        } catch (IOException e) {
            findings.add(new AuditFinding(
                    Severity.INFO,
                    "Could not read server.properties: "
                            + e.getMessage()
            ));
        }

        return findings;
    }

    private List<AuditFinding> checkPlugins() {
        List<AuditFinding> findings = new ArrayList<>();

        File pluginsDir = new File(serverRoot, "plugins");
        if (!pluginsDir.exists()) return findings;

        File[] files = pluginsDir.listFiles(
                (dir, name) -> name.endsWith(".jar")
        );
        if (files == null) return findings;

        for (File jar : files) {
            String name = jar.getName();
            for (var entry : VULNERABLE_PLUGINS.entrySet()) {
                if (name.toLowerCase()
                        .contains(entry.getKey().toLowerCase())) {
                    findings.add(new AuditFinding(
                            Severity.WARNING,
                            "Potentially vulnerable plugin: "
                                    + name + " - " + entry.getValue()
                    ));
                }
            }
        }

        return findings;
    }

    private List<AuditFinding> checkFilePermissions() {
        List<AuditFinding> findings = new ArrayList<>();

        // Check if config files are world-readable
        String[] sensitiveFiles = {
                "plugins/AuthCraft/config.yml",
                "plugins/AuthCraft/roles.yml",
                "server.properties",
                "plugins/AuthCraft/authcraft.db"
        };

        for (String filePath : sensitiveFiles) {
            File file = new File(serverRoot, filePath);
            if (file.exists()) {
                // On Unix, check if world-readable
                try {
                    Set<java.nio.file.attribute.PosixFilePermission> perms =
                            Files.getPosixFilePermissions(file.toPath());
                    if (perms.contains(
                            java.nio.file.attribute.PosixFilePermission
                                    .OTHERS_READ)) {
                        findings.add(new AuditFinding(
                                Severity.WARNING,
                                file.getName()
                                        + " is world-readable. "
                                        + "Restrict permissions."
                        ));
                    }
                } catch (UnsupportedOperationException e) {
                    // Windows — skip POSIX check
                } catch (IOException e) {
                    // Cannot check — skip
                }
            }
        }

        return findings;
    }

    private List<AuditFinding> checkConfigPasswords() {
        List<AuditFinding> findings = new ArrayList<>();

        // Check our own config for plaintext passwords
        if (config.getDatabasePassword() != null
                && !config.getDatabasePassword().isEmpty()
                && isWeakPassword(config.getDatabasePassword())) {
            findings.add(new AuditFinding(
                    Severity.WARNING,
                    "Database password appears to be weak."
            ));
        }

        if (config.getSmtpPassword() != null
                && !config.getSmtpPassword().isEmpty()
                && config.getSmtpPassword().length() < 8) {
            findings.add(new AuditFinding(
                    Severity.WARNING,
                    "SMTP password is shorter than 8 characters."
            ));
        }

        return findings;
    }

    private boolean isPortOpen(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(
                    new InetSocketAddress(host, port), 1000
            );
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private boolean isWeakPassword(String password) {
        Set<String> weak = Set.of(
                "password", "123456", "12345678", "admin",
                "root", "server", "minecraft", "changeme",
                "default", "test", "qwerty"
        );
        return weak.contains(password.toLowerCase())
                || password.length() < 6;
    }

    // =============================================
    // Supporting types
    // =============================================

    public enum Severity {
        CRITICAL, WARNING, INFO
    }

    public static class AuditFinding {
        public final Severity severity;
        public final String description;

        public AuditFinding(Severity severity, String description) {
            this.severity = severity;
            this.description = description;
        }
    }
}