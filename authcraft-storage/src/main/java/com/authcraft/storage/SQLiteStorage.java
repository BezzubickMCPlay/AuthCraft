// com/authcraft/storage/SQLiteStorage.java
package com.authcraft.storage;

import com.authcraft.core.config.AuthCraftConfig;

import java.io.File;
import java.util.logging.Logger;

public class SQLiteStorage extends AbstractSQLStorage {

    private final File dataFolder;

    public SQLiteStorage(AuthCraftConfig config, Logger logger,
                         File dataFolder) {
        super(config, logger);
        this.dataFolder = dataFolder;
    }

    @Override
    protected String getJdbcUrl() {
        File dbFile = new File(dataFolder, config.getDatabaseFile());
        return "jdbc:sqlite:" + dbFile.getAbsolutePath();
    }

    @Override
    protected String getDriverClassName() {
        return "org.sqlite.JDBC";
    }

    @Override
    protected String autoIncrementType() {
        return "INTEGER PRIMARY KEY AUTOINCREMENT";
    }
}