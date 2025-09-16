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

import org.apache.commons.lang3.StringUtils;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ExternalIdpRegisteredClient;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.Arrays;
import java.util.List;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.COMMA_DELIMITER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.IDP_REDIRECT_URI;

/**
 * The Oauth2LoginConfig class is responsible for configuring OAuth2 login for the application. It provides OAuth2
 * client registration for external identity providers when configured.
 */
@Configuration
public class Oauth2LoginConfig {
    @Value("${ignite.oauth2.issuer.protocol:http}")
    private String issuerProtocol;

    @Value("${ignite.oauth2.issuer.host:localhost}")
    private String issuerHost;

    @Value("${ignite.oauth2.issuer.prefix:}")
    private String issuerPrefix;

    private static final Logger LOGGER = LoggerFactory.getLogger(Oauth2LoginConfig.class);

    private final TenantConfigurationService tenantConfigurationService;

    /**
     * Constructor for the Oauth2LoginConfig class. It stores the TenantConfigurationService for dynamic tenant property
     * resolution.
     *
     * @param tenantConfigurationService the service to fetch tenant properties
     */
    public Oauth2LoginConfig(TenantConfigurationService tenantConfigurationService) {
        this.tenantConfigurationService = tenantConfigurationService;
        LOGGER.info("Initialized Oauth2LoginConfig with tenant configuration service");
    }

    
    /**
     * Creates a ClientRegistrationRepository that holds all external IDP client registrations for all tenants.
     * It retrieves tenant properties and constructs ClientRegistrations for each external IDP registered client.
     * If no clients are configured, it returns an empty repository.
     *
     * @return ClientRegistrationRepository containing all external IDP client registrations.
     */
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        LOGGER.debug("## clientRegistrationRepository - START");

        try {
            // Get all available tenants and process them using streams
            java.util.Set<String> allTenants = tenantConfigurationService.getAllTenants();
            LOGGER.info("Found {} tenant(s) for external IDP configuration", allTenants.size());
            List<ClientRegistration> clientRegistrationList = allTenants.stream().flatMap(tenantId -> {
                try {
                    TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties(tenantId);
                    if (tenantProperties != null && tenantProperties.getExternalIdpRegisteredClientList() != null
                            && !tenantProperties.getExternalIdpRegisteredClientList().isEmpty()) {
                        LOGGER.info("Registering external IDP clients for tenant: {}", tenantId);
                        return tenantProperties.getExternalIdpRegisteredClientList().stream()
                                .map(externalIdpRegisteredClient -> {
                                    // Use tenant-prefixed registration ID to avoid conflicts between tenants
                                    String registrationId = tenantId + "-"
                                            + externalIdpRegisteredClient.getRegistrationId();
                                    return externalIdpClientRegistration(externalIdpRegisteredClient, registrationId);
                                });
                    } else {
                        LOGGER.debug("No external IDP clients configured for tenant: {}", tenantId);
                        return java.util.stream.Stream.empty();
                    }
                } catch (Exception e) {
                    LOGGER.warn("Error loading external IDP configuration for tenant {}: {}", tenantId, e.getMessage());
                    return java.util.stream.Stream.empty();
                }
            }).collect(java.util.stream.Collectors.toList());

            if (!clientRegistrationList.isEmpty()) {
                LOGGER.info("Successfully registered {} external IDP client(s) across all tenants",
                        clientRegistrationList.size());
                LOGGER.debug("## clientRegistrationRepository - END");
                return new InMemoryClientRegistrationRepository(clientRegistrationList);
            } else {
                LOGGER.info(
                        "No external IDP clients configured across "
                        + "all tenants - using empty client registration repository");
                LOGGER.debug("## clientRegistrationRepository - END");
                return createEmptyClientRegistrationRepository();
            }
        } catch (Exception e) {
            LOGGER.error("Error setting up client registration repository: {}", e.getMessage(), e);
            return createEmptyClientRegistrationRepository();
        }
    }

    /**
     * Creates an empty client registration repository that doesn't throw exceptions.
     *
     * @return ClientRegistrationRepository that returns null for any registration ID
     */
    private ClientRegistrationRepository createEmptyClientRegistrationRepository() {
        return registrationId -> {
            LOGGER.warn("No client registration found for registrationId: {}", registrationId);
            return null;
        };
    }

    /**
     * This method creates an instance of InMemoryOAuth2AuthorizedClientService using the provided
     * ClientRegistrationRepository. The OAuth2AuthorizedClientService is used to manage the OAuth2AuthorizedClients
     * associated with a ClientRegistration.
     *
     * @param clientRegistrationRepository the ClientRegistrationRepository to be used by the
     *     OAuth2AuthorizedClientService.
     * @return an instance of OAuth2AuthorizedClientService.
     */
    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(
            ClientRegistrationRepository clientRegistrationRepository) {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
    }

    /**
     * This method creates an instance of AuthenticatedPrincipalOAuth2AuthorizedClientRepository using the provided
     * OAuth2AuthorizedClientService. The OAuth2AuthorizedClientRepository is used to manage the OAuth2AuthorizedClients
     * associated with an authenticated principal.
     *
     * @param authorizedClientService the OAuth2AuthorizedClientService to be used by the
     *     OAuth2AuthorizedClientRepository.
     * @return an instance of OAuth2AuthorizedClientRepository.
     */
    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository(
            OAuth2AuthorizedClientService authorizedClientService) {
        return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
    }

    /**
     * Creates a ClientRegistration for an external identity provider. This method uses the details of the external
     * identity provider, which are provided as an ExternalIdpRegisteredClient object, to create a ClientRegistration.
     * The ClientRegistration includes details such as the client ID, client secret, authorization URI, token URI, user
     * info URI, and the JWK set URI. The method also constructs the redirect URI by calling the buildIssuerBaseUrl
     * method and appending the registration ID.
     *
     * @param externalIdpRegisteredClient the details of the external identity provider.
     * @param registrationId the registration ID to use (may be tenant-prefixed).
     * @return the created ClientRegistration.
     */
    private ClientRegistration externalIdpClientRegistration(ExternalIdpRegisteredClient externalIdpRegisteredClient,
            String registrationId) {
        LOGGER.debug("## externalIdpClientRegistration - START");
        LOGGER.info("Registering client of provider: {} with registrationId: {}",
                externalIdpRegisteredClient.getClientName(), registrationId);
        
        // Extract tenant from registration ID (format: "tenant-provider")
        String tenant = registrationId.contains("-") ? registrationId.split("-")[0] : "default";
        String tenantPrefixedRedirectUri = buildIssuerBaseUrl() + "/" + tenant + IDP_REDIRECT_URI + registrationId;
        
        return ClientRegistration.withRegistrationId(registrationId).clientId(externalIdpRegisteredClient.getClientId())
                .clientSecret(externalIdpRegisteredClient.getClientSecret())
                .clientAuthenticationMethod(externalIdpRegisteredClient.getClientAuthMethod())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(tenantPrefixedRedirectUri)
                .scope(Arrays
                        .asList(externalIdpRegisteredClient.getScope().replaceAll("\\s", "").split(COMMA_DELIMITER)))
                .authorizationUri(externalIdpRegisteredClient.getAuthorizationUri())
                .tokenUri(externalIdpRegisteredClient.getTokenUri())
                .userInfoUri(externalIdpRegisteredClient.getUserInfoUri())
                .userNameAttributeName(externalIdpRegisteredClient.getUserNameAttributeName())
                .jwkSetUri(externalIdpRegisteredClient.getJwkSetUri())
                .clientName(externalIdpRegisteredClient.getClientName()).build();
    }


    /**
     * Constructs the base URL for the issuer. This method uses the issuer protocol, host, and prefix to construct the
     * base URL. If the issuer prefix is empty, it is ignored during the construction of the URL.
     *
     * @return the constructed issuer base URL as a string.
     */
    private String buildIssuerBaseUrl() {

        if (StringUtils.isEmpty(issuerPrefix)) {
            issuerPrefix = StringUtils.EMPTY;
        }

        return issuerProtocol + "://" + issuerHost + issuerPrefix;
    }

}