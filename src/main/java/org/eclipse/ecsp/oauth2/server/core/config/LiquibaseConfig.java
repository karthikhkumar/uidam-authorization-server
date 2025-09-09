/********************************************************************************
 * Copyright (c) 2023-24 Harman International 
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0  
 *  
 * <p> Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.config;

import liquibase.integration.spring.SpringLiquibase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.Statement;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Liquibase configuration for the tenants.
 */ 
@Configuration
@ConditionalOnProperty(name = "spring.liquibase.enabled", havingValue = "true")
// Skip LiquibaseConfig when liquibase is disabled (e.g., in tests)
public class LiquibaseConfig  {

    private static final Logger LOGGER = LoggerFactory.getLogger(LiquibaseConfig.class);

    private static final String TENANT_HEADER = "tenantId";

    private final DataSource dataSource;
    
    @Value("#{'${tenant.ids}'.split(',')}")
    private List<String> tenantIds;
    
    @Value("${uidam.liquibase.change-log.path}")
    private String liquibaseChangeLogPath;
    
    @Value("${uidam.default.db.schema}")
    private String defaultUidamSchema;
    
    public LiquibaseConfig(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    /**
     * Programmatically run Liquibase to run and create table schema and insert default data.
     * It runover all tenants and create schema if not exists.
     *
     * @return SpringLiquibase
     */
    @Bean
    @Primary
    @ConditionalOnProperty(name = "spring.liquibase.enabled", havingValue = "true")
    // Bean creation will be skipped when spring.liquibase.enabled=false (e.g., in tests)
    public SpringLiquibase createSchemaForTenant() {
        SpringLiquibase liquibase = new SpringLiquibase();
        for (String tenantId : tenantIds) {
            TenantContext.setCurrentTenant(tenantId);
            MDC.put(TENANT_HEADER, tenantId);
            AbstractRoutingDataSource abstractRoutingDataSource = (AbstractRoutingDataSource) dataSource;
            liquibase.setDataSource(abstractRoutingDataSource.getResolvedDataSources().get(tenantId));
            liquibase.setChangeLog(liquibaseChangeLogPath);
            liquibase.setContexts(tenantId);
            liquibase.setDefaultSchema(defaultUidamSchema);
            Map<String, String> liquibaseParams = new HashMap<>();
            liquibaseParams.put("schema", defaultUidamSchema);
            liquibase.setChangeLogParameters(liquibaseParams);

            // Validate schema name to prevent SQL injection
            if (!defaultUidamSchema.matches("^[a-zA-Z0-9_]+$")) {
                throw new IllegalArgumentException("Invalid schema name: " + defaultUidamSchema);
            }

            try (Connection conn = dataSource.getConnection();
                 Statement stmt = conn.createStatement()) {
                // Create schema if it doesn't exist
                stmt.execute("CREATE SCHEMA IF NOT EXISTS " + defaultUidamSchema);

                // Run Liquibase migration
                LOGGER.info("Liquibase configuration Start run for tenant {}", tenantId);
                liquibase.afterPropertiesSet();
                LOGGER.info("Liquibase configuration Completed run for tenant {}", tenantId);
                MDC.remove(TENANT_HEADER);
                TenantContext.clear();
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize Liquibase : " + tenantId, e);
            } finally {
                MDC.remove(TENANT_HEADER);
                TenantContext.clear();
            }
        }
        return null;
    }
}
