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

package org.eclipse.ecsp.oauth2.server.core.client;

import io.prometheus.client.CollectorRegistry;
import jakarta.servlet.http.HttpServletRequest;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.request.dto.RegisteredClientDetails;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockitoAnnotations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;


import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * This class tests the functionality of the AuthManagementClient.
 */
@ExtendWith(SpringExtension.class)
@EnableConfigurationProperties(value = TenantProperties.class)
@ContextConfiguration(classes = { AuthManagementClient.class })
@TestPropertySource("classpath:application-test.properties")
@ComponentScan(basePackages = {"org.eclipse.ecsp"})
class AuthManagementClientTest {

    @Autowired
    AuthManagementClient authManagementClient;

    @MockitoBean
    private HttpServletRequest httpServletRequest;

    /**
     * This method sets up the test environment before each test.
     * It opens the mocks.
     */
    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);
    }

    /**
     * This method cleans up the test environment after each test.
     * It clears the default registry of the CollectorRegistry.
     */
    @BeforeEach
    @AfterEach
    void cleanup() {
        CollectorRegistry.defaultRegistry.clear();
    }

    /**
     * This method tests the getClientDetails method of the AuthManagementClient.
     * It calls the getClientDetails method with a test client and asserts that the returned RegisteredClientDetails is
     * null.
     */
    @Test
    void testGetClientDetails() {
        RegisteredClientDetails rc = authManagementClient.getClientDetails("testClient");
        assertNull(rc);
    }

}