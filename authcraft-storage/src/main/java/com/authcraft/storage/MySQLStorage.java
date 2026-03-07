// com/authcraft/storage/MySQLStorage.java
package com.authcraft.storage;

import com.authcraft.core.config.AuthCraftConfig;

import java.util.logging.Logger;

public class MySQLStorage extends AbstractSQLStorage {

    public MySQLStorage(AuthCraftConfig config, Logger logger) {
        super(config, logger);
    }

    @Override
    protected String getJdbcUrl() {
        return String.format(
                "jdbc:mysql://%s:%d/%s?useSSL=false"
                        + "&allowPublicKeyRetrieval=true"
                        + "&characterEncoding=utf8"
                        + "&serverTimezone=UTC",
                config.getDatabaseHost(),
                config.getDatabasePort(),
                config.getDatabaseName()
        );
    }

    @Override
    protected String getDriverClassName() {
        return "com.mysql.cj.jdbc.Driver";
    }

    @Override
    protected String autoIncrementType() {
        return "BIGINT AUTO_INCREMENT PRIMARY KEY";
    }
}