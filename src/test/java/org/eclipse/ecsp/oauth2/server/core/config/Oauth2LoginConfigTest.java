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

import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ExternalIdpRegisteredClient;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class Oauth2LoginConfigTest {

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    @Mock
    private TenantProperties tenantProperties;

    private Oauth2LoginConfig oauth2LoginConfig;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(tenantConfigurationService.getTenantProperties(anyString())).thenReturn(tenantProperties);
        oauth2LoginConfig = new Oauth2LoginConfig(tenantConfigurationService);
    }

    @Test
    void testClientRegistrationRepository_NoExternalIdpClients() {
        ExternalIdpRegisteredClient externalClient = new ExternalIdpRegisteredClient();
        externalClient.setRegistrationId("default-id");
        externalClient.setClientId("default-client-id");
        externalClient.setClientSecret("default-client-secret");
        externalClient.setClientAuthenticationMethod("client_secret_basic");
        externalClient.setAuthorizationUri("http://default-auth-uri");
        externalClient.setTokenUri("http://default-token-uri");
        externalClient.setUserInfoUri("http://default-user-info-uri");
        externalClient.setUserNameAttributeName("username");
        externalClient.setJwkSetUri("http://default-jwk-uri");
        externalClient.setClientName("Default Client");
        externalClient.setScope("read");

        when(tenantProperties.getExternalIdpRegisteredClientList()).thenReturn(List.of(externalClient));

        ClientRegistrationRepository repository = oauth2LoginConfig.clientRegistrationRepository();

        assertNotNull(repository, "ClientRegistrationRepository should not be null");
    }

    @Test
    void testClientRegistrationRepository_WithExternalIdpClients() {
        ExternalIdpRegisteredClient externalClient = new ExternalIdpRegisteredClient();
        externalClient.setRegistrationId("test-id");
        externalClient.setClientId("test-client-id");
        externalClient.setClientSecret("test-client-secret");
        externalClient.setClientAuthenticationMethod("client_secret_basic");
        externalClient.setAuthorizationUri("http://auth-uri");
        externalClient.setTokenUri("http://token-uri");
        externalClient.setUserInfoUri("http://user-info-uri");
        externalClient.setUserNameAttributeName("username");
        externalClient.setJwkSetUri("http://jwk-uri");
        externalClient.setClientName("Test Client");
        externalClient.setScope("read,write");

        when(tenantProperties.getExternalIdpRegisteredClientList())
                .thenReturn(Collections.singletonList(externalClient));

        ClientRegistrationRepository repository = oauth2LoginConfig.clientRegistrationRepository();

        assertNotNull(repository, "ClientRegistrationRepository should not be null");
        ClientRegistration clientRegistration = repository.findByRegistrationId("test-id");
        assertNotNull(clientRegistration, "ClientRegistration should not be null");
        assertEquals("test-client-id", clientRegistration.getClientId(), "Client ID should match");
    }


    @Test
    void testAuthorizedClientService() {
        ClientRegistrationRepository mockRepository = mock(ClientRegistrationRepository.class);
        OAuth2AuthorizedClientService authorizedClientService = oauth2LoginConfig
                .authorizedClientService(mockRepository);

        assertNotNull(authorizedClientService, "OAuth2AuthorizedClientService should not be null");
    }

    @Test
    void testAuthorizedClientRepository() {
        OAuth2AuthorizedClientService mockService = mock(OAuth2AuthorizedClientService.class);
        OAuth2AuthorizedClientRepository authorizedClientRepository = oauth2LoginConfig
                .authorizedClientRepository(mockService);

        assertNotNull(authorizedClientRepository, "OAuth2AuthorizedClientRepository should not be null");
    }

    @Test
    void testExternalIdpClientRegistration() {
        ExternalIdpRegisteredClient externalClient = new ExternalIdpRegisteredClient();
        externalClient.setRegistrationId("test-id");
        externalClient.setClientId("test-client-id");
        externalClient.setClientSecret("test-client-secret");
        externalClient.setClientAuthenticationMethod("client_secret_basic");
        externalClient.setAuthorizationUri("http://auth-uri");
        externalClient.setTokenUri("http://token-uri");
        externalClient.setUserInfoUri("http://user-info-uri");
        externalClient.setUserNameAttributeName("username");
        externalClient.setJwkSetUri("http://jwk-uri");
        externalClient.setClientName("Test Client");
        externalClient.setScope("read,write");

        ClientRegistration clientRegistration = oauth2LoginConfig.externalIdpClientRegistration(externalClient);

        assertNotNull(clientRegistration, "ClientRegistration should not be null");
        assertEquals("test-id", clientRegistration.getRegistrationId(), "Registration ID should match");
        assertEquals("test-client-id", clientRegistration.getClientId(), "Client ID should match");
        assertEquals("test-client-secret", clientRegistration.getClientSecret(), "Client Secret should match");
        assertEquals("http://auth-uri", clientRegistration.getProviderDetails().getAuthorizationUri(),
                "Authorization URI should match");
        assertEquals("http://token-uri", clientRegistration.getProviderDetails().getTokenUri(),
                "Token URI should match");
        assertEquals("http://user-info-uri", clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri(),
                "User Info URI should match");
        assertEquals("username",
                clientRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName(),
                "User Name Attribute should match");
        assertEquals("http://jwk-uri", clientRegistration.getProviderDetails().getJwkSetUri(),
                "JWK Set URI should match");
        assertEquals("Test Client", clientRegistration.getClientName(), "Client Name should match");
    }
}