// com/authcraft/storage/PostgreSQLStorage.java
package com.authcraft.storage;

import com.authcraft.core.config.AuthCraftConfig;

import java.util.logging.Logger;

public class PostgreSQLStorage extends AbstractSQLStorage {

    public PostgreSQLStorage(AuthCraftConfig config, Logger logger) {
        super(config, logger);
    }

    @Override
    protected String getJdbcUrl() {
        return String.format(
                "jdbc:postgresql://%s:%d/%s",
                config.getDatabaseHost(),
                config.getDatabasePort(),
                config.getDatabaseName()
        );
    }

    @Override
    protected String getDriverClassName() {
        return "org.postgresql.Driver";
    }

    @Override
    protected String autoIncrementType() {
        return "BIGSERIAL PRIMARY KEY";
    }
}