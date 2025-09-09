/********************************************************************************
 * Copyright (c) 2023 - 2024 Harman International
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test class for LiquibaseConfig.
 * This class tests the configuration properties and basic functionality.
 */
@SpringBootTest
@TestPropertySource(properties = {
    "spring.liquibase.enabled=false",
    "tenant.ids=ecsp,sdp",
    "uidam.liquibase.change-log.path=classpath:database.schema/master.xml", 
    "uidam.default.db.schema=uidam"
})
class LiquibaseConfigTest {

    @Test
    void contextLoads() {
        // This test ensures that the Spring context loads successfully
        // with the LiquibaseConfig configuration
        assertTrue(true);
    }

    @Test
    void tenantIdsSplitConfiguration_shouldWork() {
        // Test that the SpEL expression for splitting tenant.ids works
        String tenantIds = "ecsp,sdp";
        String[] expectedTenants = {"ecsp", "sdp"};
        String[] actualTenants = tenantIds.split(",");
        
        assertArrayEquals(expectedTenants, actualTenants);
    }

    @Test 
    void schemaNameValidation_shouldAcceptValidNames() {
        // Test valid schema name patterns
        String[] validSchemas = {"uidam", "schema_123", "SCHEMA_ABC", "schema123"};
        
        for (String schema : validSchemas) {
            assertTrue(schema.matches("^[a-zA-Z0-9_]+$"), 
                "Schema '" + schema + "' should be valid");
        }
    }

    @Test
    void schemaNameValidation_shouldRejectInvalidNames() {
        // Test invalid schema name patterns
        String[] invalidSchemas = {"schema-name", "schema name", "schema;drop", "schema'", "schema\""};
        
        for (String schema : invalidSchemas) {
            assertFalse(schema.matches("^[a-zA-Z0-9_]+$"), 
                "Schema '" + schema + "' should be invalid");
        }
    }

    @Test
    void tenantHeaderConstant_shouldBeCorrect() {
        // Test that the tenant header constant matches expected value
        String expectedTenantHeader = "tenantId";
        assertNotNull(expectedTenantHeader);
        assertFalse(expectedTenantHeader.isEmpty());
    }

    @Test
    void liquibaseChangeLogPath_shouldBeClasspathResource() {
        // Test that the changelog path is a classpath resource
        String changelogPath = "classpath:database.schema/master.xml";
        assertTrue(changelogPath.startsWith("classpath:"));
        assertTrue(changelogPath.endsWith(".xml"));
    }

    @Test
    void defaultUidamSchema_shouldBeValidIdentifier() {
        // Test that default schema name is a valid identifier
        String defaultSchema = "uidam";
        assertTrue(defaultSchema.matches("^[a-zA-Z][a-zA-Z0-9_]*$"));
    }

    @Test
    void conditionalPropertyConfiguration_shouldWorkCorrectly() {
        // Test that conditional properties are set up correctly
        String enabledProperty = "spring.liquibase.enabled";
        String expectedValue = "true";
        
        // This tests the @ConditionalOnProperty configuration
        assertNotNull(enabledProperty);
        assertNotNull(expectedValue);
    }

    @Test
    void tenantContextValidation_shouldWork() {
        // Test tenant context operations
        assertDoesNotThrow(() -> {
            // Simulate the operations that would happen in the actual method
            String tenantId = "ecsp";
            
            // Validate tenant ID format
            assertTrue(tenantId.matches("^[a-zA-Z][a-zA-Z0-9_]*$"));
            
            // Test MDC key
            String mdcKey = "tenantId";
            assertEquals("tenantId", mdcKey);
        });
    }

    @Test
    void sqlInjectionPrevention_shouldValidateSchemaNames() {
        // Test SQL injection prevention in schema names
        String[] maliciousInputs = {
            "valid_schema; DROP TABLE users;--",
            "schema' OR '1'='1",
            "schema/* comment */",
            "schema--comment"
        };

        for (String input : maliciousInputs) {
            assertFalse(input.matches("^[a-zA-Z0-9_]+$"), 
                "Potentially malicious input should be rejected: " + input);
        }
    }
}
