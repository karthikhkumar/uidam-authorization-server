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

package org.eclipse.ecsp.oauth2.server.core.config.tenantproperties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Test class for UiProperties.
 * Tests the tenant-specific UI configuration functionality.
 */
class UiPropertiesTest {

    private UiProperties uiProperties;

    @BeforeEach
    void setUp() {
        uiProperties = new UiProperties();
    }

    @Test
    void constructor_shouldInitializeWithDefaultValues() {
        // Test default constructor
        UiProperties properties = new UiProperties();
        assertNotNull(properties);
    }

    @Test
    void getLogoPath_shouldReturnConfiguredPath_whenLogoPathIsSet() {
        // Arrange
        String customLogoPath = "/custom/logo.png";
        uiProperties.setLogoPath(customLogoPath);

        // Act
        String result = uiProperties.getLogoPath("ecsp");

        // Assert
        assertEquals(customLogoPath, result);
    }

    @Test
    void getLogoPath_shouldReturnTenantSpecificDefault_whenLogoPathIsNull() {
        // Arrange
        String tenantId = "ecsp";
        uiProperties.setLogoPath(null);

        // Act
        String result = uiProperties.getLogoPath(tenantId);

        // Assert
        assertEquals("/images/ecsp-logo.svg", result);
    }

    @Test
    void getLogoPath_shouldReturnTenantSpecificDefault_whenLogoPathIsEmpty() {
        // Arrange
        String tenantId = "sdp";
        uiProperties.setLogoPath("");

        // Act
        String result = uiProperties.getLogoPath(tenantId);

        // Assert
        assertEquals("/images/sdp-logo.svg", result);
    }

    @Test
    void getLogoPath_shouldReturnTenantSpecificDefault_whenLogoPathIsWhitespace() {
        // Arrange
        String tenantId = "test-tenant";
        uiProperties.setLogoPath("   ");

        // Act
        String result = uiProperties.getLogoPath(tenantId);

        // Assert
        assertEquals("/images/test-tenant-logo.svg", result);
    }

    @Test
    void getStylesheetPath_shouldReturnConfiguredPath_whenStylesheetPathIsSet() {
        // Arrange
        String customStylesheetPath = "/custom/styles.css";
        uiProperties.setStylesheetPath(customStylesheetPath);

        // Act
        String result = uiProperties.getStylesheetPath();

        // Assert
        assertEquals(customStylesheetPath, result);
    }

    @Test
    void getStylesheetPath_shouldReturnDefaultPath_whenStylesheetPathIsNull() {
        // Arrange
        uiProperties.setStylesheetPath(null);

        // Act
        String result = uiProperties.getStylesheetPath();

        // Assert
        assertEquals("/css/style.css", result);
    }

    @Test
    void getStylesheetPath_shouldReturnDefaultPath_whenStylesheetPathIsEmpty() {
        // Arrange
        uiProperties.setStylesheetPath("");

        // Act
        String result = uiProperties.getStylesheetPath();

        // Assert
        assertEquals("/css/style.css", result);
    }

    @Test
    void getStylesheetPath_shouldReturnDefaultPath_whenStylesheetPathIsWhitespace() {
        // Arrange
        uiProperties.setStylesheetPath("   ");

        // Act
        String result = uiProperties.getStylesheetPath();

        // Assert
        assertEquals("/css/style.css", result);
    }

    @Test
    void setAndGetLogoPath_shouldWorkCorrectly() {
        // Arrange
        String logoPath = "/tenant/logo.jpg";

        // Act
        uiProperties.setLogoPath(logoPath);
        String result = uiProperties.getLogoPath();

        // Assert
        assertEquals(logoPath, result);
    }

    @Test
    void setAndGetStylesheetPath_shouldWorkCorrectly() {
        // Arrange
        String stylesheetPath = "/tenant/custom.css";

        // Act
        uiProperties.setStylesheetPath(stylesheetPath);
        String result = uiProperties.getStylesheetPath();

        // Assert
        assertEquals(stylesheetPath, result);
    }

    @Test
    void getLogoPath_shouldHandleSpecialCharactersInTenantId() {
        // Arrange
        String tenantId = "tenant_123";
        uiProperties.setLogoPath(null);

        // Act
        String result = uiProperties.getLogoPath(tenantId);

        // Assert
        assertEquals("/images/tenant_123-logo.svg", result);
    }

    @Test
    void getLogoPath_shouldHandleNullTenantId() {
        // Arrange
        uiProperties.setLogoPath(null);

        // Act
        String result = uiProperties.getLogoPath(null);

        // Assert
        assertEquals("/images/null-logo.svg", result);
    }
}
