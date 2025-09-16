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

package org.eclipse.ecsp.oauth2.server.core.cache;

import io.prometheus.client.CollectorRegistry;
import org.eclipse.ecsp.oauth2.server.core.cache.impl.CacheClientServiceImpl;
import org.eclipse.ecsp.oauth2.server.core.client.AuthManagementClient;
import org.eclipse.ecsp.oauth2.server.core.request.dto.RegisteredClientDetails;
import org.eclipse.ecsp.oauth2.server.core.service.RegisteredClientMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.eclipse.ecsp.oauth2.server.core.test.TestCommonStaticData.getClient;
import static org.eclipse.ecsp.oauth2.server.core.test.TestRegisteredClients.registeredClient;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;

/**
 * This class tests the functionality of the CacheClientServiceImpl.
 */
@SpringBootTest
@ContextConfiguration(classes = { CacheClientServiceImpl.class })
class CacheClientServiceTest {

    @Autowired
    private CacheClientService cacheClientService;

    @MockitoBean
    AuthManagementClient authManagementClient;

    @MockitoBean
    RegisteredClientMapper registeredClientMapper;

    /**
     * Cleans up the default Prometheus CollectorRegistry before and after each test.
     */
    @BeforeEach
    @AfterEach
    void cleanup() {
        CollectorRegistry.defaultRegistry.clear();
    }

    /**
     * Tests the retrieval of client details with synchronization enabled.
     * It mocks the AuthManagementClient to return predefined client details and verifies that the cacheClientService
     * correctly retrieves and maps these details to a ClientCacheDetails instance.
     */
    @Test
    void getClientDetailsWithSync() {
        RegisteredClientDetails registeredClientDetails = getClient();
        doReturn(registeredClientDetails).when(authManagementClient).getClientDetails(anyString());
        doReturn(registeredClient().build()).when(registeredClientMapper).toRegisteredClient(registeredClientDetails);
        ClientCacheDetails clientCacheDetails = cacheClientService.getClientDetailsWithSync("ecsp", "token-mgmt");
        assertNotNull(clientCacheDetails);
    }

    /**
     * Tests the retrieval of client details without synchronization.
     * It mocks the AuthManagementClient to return predefined client details and verifies that the cacheClientService
     * correctly retrieves and maps these details to a ClientCacheDetails instance.
     */
    @Test
    void getClientDetailsWithoutSync() {
        RegisteredClientDetails registeredClientDetails = getClient();
        doReturn(registeredClientDetails).when(authManagementClient).getClientDetails(anyString());
        doReturn(registeredClient().build()).when(registeredClientMapper).toRegisteredClient(registeredClientDetails);
        ClientCacheDetails clientCacheDetails = cacheClientService.getClientDetailsWithoutSync("ecsp", "token-mgmt");
        assertNotNull(clientCacheDetails);
    }

    /**
     * Tests the retrieval of client details from the cache for a different client ID.
     * It mocks the AuthManagementClient to return predefined client details and verifies that the cacheClientService
     * correctly retrieves and maps these details to a ClientCacheDetails instance.
     */
    @Test
    void getClientDetailsWithoutSync2() {
        RegisteredClientDetails registeredClientDetails = getClient();
        doReturn(registeredClientDetails).when(authManagementClient).getClientDetails(anyString());
        doReturn(registeredClient().build()).when(registeredClientMapper).toRegisteredClient(registeredClientDetails);
        ClientCacheDetails clientCacheDetails = cacheClientService.getClientDetailsWithoutSync("ecsp", "test");
        assertNotNull(clientCacheDetails);
    }

}