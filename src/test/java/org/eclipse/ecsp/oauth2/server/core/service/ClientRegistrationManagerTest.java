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

package org.eclipse.ecsp.oauth2.server.core.service;

import org.eclipse.ecsp.oauth2.server.core.cache.CacheClientUtils;
import org.eclipse.ecsp.oauth2.server.core.cache.ClientCacheDetails;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.test.context.ActiveProfiles;

import static org.eclipse.ecsp.oauth2.server.core.test.TestRegisteredClients.registeredClient;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * This class tests the functionality of the ClientRegistrationManager.
 */
@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
class ClientRegistrationManagerTest {

    @Mock
    CacheClientUtils cacheClientUtils;

    @InjectMocks
    ClientRegistrationManager clientRegistrationManager;

    /**
     * This method sets up the test environment before each test.
     * It initializes the mocks.
     */
    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);
    }

    /**
     * This test method tests the scenario where the client details are retrieved successfully.
     * It sets up a mock response from the cacheClientService and then calls the findByClientId method.
     * The test asserts that the returned client is not null and the client ID is as expected.
     */
    @Test
    void testGetClientDetails() {
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        Mockito.when(cacheClientUtils.getClientDetails("testClient")).thenReturn(clientCacheDetails);
        RegisteredClient registeredClient = clientRegistrationManager.findByClientId("testClient");
        assert registeredClient != null;
        assertEquals("testClientId", registeredClient.getClientId());
    }

    /**
     * This test method tests the scenario where the client details are not found.
     * It sets up a mock response from the cacheClientService to return null and then calls the findByClientId method.
     * The test asserts that the returned client is null.
     */
    @Test
    void testGetClientDetails_clientNotFound() {
        Mockito.when(cacheClientUtils.getClientDetails("testClient")).thenReturn(null);
        RegisteredClient registeredClient = clientRegistrationManager.findByClientId("testClient");
        assertNull(registeredClient);
    }

    /**
     * This test method tests the scenario where the client details are retrieved successfully by ID.
     * It sets up a mock response from the cacheClientService and then calls the findById method.
     * The test asserts that the returned client is not null and the client ID is as expected.
     */
    @Test
    void testGetClientDetailsById() {
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        Mockito.when(cacheClientUtils.getClientDetails("testClient")).thenReturn(clientCacheDetails);
        RegisteredClient registeredClient = clientRegistrationManager.findById("testClient");
        assert registeredClient != null;
        assertEquals("testClientId", registeredClient.getClientId());
    }

    /**
     * This test method tests the scenario where the client details are not found by ID.
     * It sets up a mock response from the cacheClientService to return null and then calls the findById method.
     * The test asserts that the returned client is null.
     */
    @Test
    void testGetClientDetailsById_clientNotFound() {
        Mockito.when(cacheClientUtils.getClientDetails("testClient")).thenReturn(null);
        RegisteredClient registeredClient = clientRegistrationManager.findById("testClient");
        assertNull(registeredClient);
    }

}