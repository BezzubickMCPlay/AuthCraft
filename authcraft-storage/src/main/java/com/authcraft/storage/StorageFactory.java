// com/authcraft/storage/StorageFactory.java
package com.authcraft.storage;

import com.authcraft.core.api.StorageProvider;
import com.authcraft.core.config.AuthCraftConfig;

import java.io.File;
import java.util.logging.Logger;

public class StorageFactory {

    public static StorageProvider create(AuthCraftConfig config,
                                         Logger logger,
                                         File dataFolder) {
        return switch (config.getDatabaseType().toLowerCase()) {
            case "mysql" -> new MySQLStorage(config, logger);
            case "postgresql", "postgres" ->
                    new PostgreSQLStorage(config, logger);
            default -> new SQLiteStorage(config, logger, dataFolder);
        };
    }
}