// com/authcraft/core/service/BackupService.java
package com.authcraft.core.service;

import com.authcraft.core.api.PlatformAdapter;
import com.authcraft.core.api.StorageProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.Account;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.*;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class BackupService {

    private final StorageProvider storage;
    private final PlatformAdapter platform;
    private final AuthCraftConfig config;
    private final Logger logger;
    private final Gson gson;

    private static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss")
                    .withZone(ZoneId.systemDefault());

    public BackupService(StorageProvider storage, PlatformAdapter platform,
                         AuthCraftConfig config) {
        this.storage = storage;
        this.platform = platform;
        this.config = config;
        this.logger = platform.getLogger();
        this.gson = new GsonBuilder().setPrettyPrinting().create();
    }

    /**
     * Create a backup of all accounts.
     */
    public CompletableFuture<File> createBackup() {
        return storage.getAllAccounts().thenApply(accounts -> {
            File backupDir = new File(platform.getDataFolder(), "backups");
            if (!backupDir.exists()) backupDir.mkdirs();

            String timestamp = DATE_FORMAT.format(Instant.now());
            String filename = "authcraft-backup-" + timestamp;

            File backupFile;
            if (config.isAutoBackupCompress()) {
                backupFile = new File(backupDir, filename + ".json.gz");
                writeCompressed(backupFile, accounts);
            } else {
                backupFile = new File(backupDir, filename + ".json");
                writePlain(backupFile, accounts);
            }

            logger.info("[AuthCraft] Backup created: " + backupFile.getName()
                    + " (" + accounts.size() + " accounts)");

            // Cleanup old backups
            cleanupOldBackups(backupDir);

            return backupFile;
        });
    }

    /**
     * Restore from a backup file.
     */
    public CompletableFuture<Integer> restoreBackup(File backupFile) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String json;
                if (backupFile.getName().endsWith(".gz")) {
                    json = readCompressed(backupFile);
                } else {
                    json = readPlain(backupFile);
                }

                Account[] accounts = gson.fromJson(json, Account[].class);
                int count = 0;

                for (Account account : accounts) {
                    try {
                        storage.saveAccount(account).join();
                        count++;
                    } catch (Exception e) {
                        logger.warning("[AuthCraft] Restore error for "
                                + account.getUsername() + ": " + e.getMessage());
                    }
                }

                logger.info("[AuthCraft] Restored " + count + " accounts from "
                        + backupFile.getName());
                return count;

            } catch (Exception e) {
                logger.severe("[AuthCraft] Restore failed: " + e.getMessage());
                return 0;
            }
        });
    }

    /**
     * List available backups.
     */
    public File[] listBackups() {
        File backupDir = new File(platform.getDataFolder(), "backups");
        if (!backupDir.exists()) return new File[0];

        File[] files = backupDir.listFiles((dir, name) ->
                name.startsWith("authcraft-backup-")
                        && (name.endsWith(".json") || name.endsWith(".json.gz"))
        );

        if (files != null) {
            Arrays.sort(files, Comparator.comparingLong(File::lastModified).reversed());
        }

        return files != null ? files : new File[0];
    }

    private void writeCompressed(File file, List<Account> accounts) {
        try (GZIPOutputStream gzos = new GZIPOutputStream(new FileOutputStream(file));
             Writer writer = new OutputStreamWriter(gzos)) {
            gson.toJson(accounts, writer);
        } catch (IOException e) {
            logger.severe("[AuthCraft] Backup write error: " + e.getMessage());
        }
    }

    private void writePlain(File file, List<Account> accounts) {
        try (Writer writer = new FileWriter(file)) {
            gson.toJson(accounts, writer);
        } catch (IOException e) {
            logger.severe("[AuthCraft] Backup write error: " + e.getMessage());
        }
    }

    private String readCompressed(File file) throws IOException {
        try (GZIPInputStream gzis = new GZIPInputStream(new FileInputStream(file));
             Reader reader = new InputStreamReader(gzis)) {
            StringBuilder sb = new StringBuilder();
            char[] buffer = new char[8192];
            int read;
            while ((read = reader.read(buffer)) != -1) {
                sb.append(buffer, 0, read);
            }
            return sb.toString();
        }
    }

    private String readPlain(File file) throws IOException {
        try (Reader reader = new FileReader(file)) {
            StringBuilder sb = new StringBuilder();
            char[] buffer = new char[8192];
            int read;
            while ((read = reader.read(buffer)) != -1) {
                sb.append(buffer, 0, read);
            }
            return sb.toString();
        }
    }

    private void cleanupOldBackups(File backupDir) {
        File[] backups = listBackups();
        if (backups == null) return;

        long retentionMs = config.getAutoBackupRetentionDays() * 24L * 3600L * 1000L;
        long cutoff = System.currentTimeMillis() - retentionMs;

        for (File backup : backups) {
            if (backup.lastModified() < cutoff) {
                if (backup.delete()) {
                    logger.info("[AuthCraft] Deleted old backup: " + backup.getName());
                }
            }
        }
    }

    /**
     * Schedule automatic backups.
     */
    public void scheduleAutoBackups() {
        if (!config.isAutoBackupEnabled()) return;

        long intervalTicks = config.getAutoBackupIntervalHours() * 3600L * 20L;
        platform.scheduleRepeating(() -> {
            createBackup().exceptionally(ex -> {
                logger.severe("[AuthCraft] Auto-backup failed: " + ex.getMessage());
                return null;
            });
        }, intervalTicks, intervalTicks);

        logger.info("[AuthCraft] Auto-backup scheduled every "
                + config.getAutoBackupIntervalHours() + " hours");
    }
}