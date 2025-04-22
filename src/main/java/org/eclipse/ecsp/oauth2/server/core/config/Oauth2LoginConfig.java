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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.UIDAM;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.COMMA_DELIMITER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.IDP_REDIRECT_URI;

/**
 * The Oauth2LoginConfig class is responsible for configuring OAuth2 login for the application.
 * It is conditionally loaded when the property "tenant.external-idp-enabled" is set to true.
 */
@Configuration
@ConditionalOnProperty(name = "tenant.external-idp-enabled", havingValue = "true")
public class Oauth2LoginConfig {
    @Value("${ignite.oauth2.issuer.protocol:http}")
    private String issuerProtocol;

    @Value("${ignite.oauth2.issuer.host:localhost}")
    private String issuerHost;

    @Value("${ignite.oauth2.issuer.prefix:}")
    private String issuerPrefix;
    private TenantProperties tenantProperties;

    private static final Logger LOGGER = LoggerFactory.getLogger(Oauth2LoginConfig.class);

    /**
     * Constructor for the Oauth2LoginConfig class.
     * It initializes the tenant properties using the provided TenantConfigurationService.
     *
     * @param tenantConfigurationService the service to fetch tenant properties
     */
    @Autowired
    public Oauth2LoginConfig(TenantConfigurationService tenantConfigurationService) {
        tenantProperties = tenantConfigurationService.getTenantProperties(UIDAM);
    }

    /**
     * This method is used to register IDP clients in UIDAM.
     * It creates a list of ClientRegistrations by iterating over the list of external identity providers
     * fetched from the tenant properties. Each external identity provider is converted into a ClientRegistration
     * by calling the externalIdpClientRegistration method.
     * The method then returns a ClientRegistrationRepository that is created using the list of ClientRegistrations.
     *
     * @return ClientRegistrationRepository that contains the ClientRegistrations for the external identity providers.
     */
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        LOGGER.debug("## clientRegistrationRepository - START");

        List<ClientRegistration> clientRegistrationList = new ArrayList<>();
        if (!CollectionUtils.isEmpty(tenantProperties.getExternalIdpRegisteredClientList())) {
            LOGGER.info("Registering external IDP clients in UIDAM");
            for (ExternalIdpRegisteredClient externalIdpRegisteredClient : tenantProperties
                    .getExternalIdpRegisteredClientList()) {
                clientRegistrationList.add(externalIdpClientRegistration(externalIdpRegisteredClient));
            }
        } else {
            LOGGER.info("No external IDP clients configured in UIDAM");
        }
        LOGGER.debug("## clientRegistrationRepository - END");
        return new InMemoryClientRegistrationRepository(clientRegistrationList);
    }

    /**
     * This method creates an instance of InMemoryOAuth2AuthorizedClientService using the provided
     * ClientRegistrationRepository. The OAuth2AuthorizedClientService is used to manage the OAuth2AuthorizedClients
     * associated with a ClientRegistration.
     *
     * @param clientRegistrationRepository the ClientRegistrationRepository to be used by the
     *                                     OAuth2AuthorizedClientService.
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
     *                                OAuth2AuthorizedClientRepository.
     * @return an instance of OAuth2AuthorizedClientRepository.
     */
    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository(
            OAuth2AuthorizedClientService authorizedClientService) {
        return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
    }

    /**
     * Creates a ClientRegistration for an external identity provider.
     * This method uses the details of the external identity provider, which are provided as an
     * ExternalIdpRegisteredClient object, to create a ClientRegistration. The ClientRegistration includes details such
     * as the client ID, client secret, authorization URI, token URI, user info URI, and the JWK set URI.
     * The method also constructs the redirect URI by calling the buildIssuerBaseUrl method and appending the
     * registration ID.
     *
     * @param externalIdpRegisteredClient the details of the external identity provider.
     * @return the created ClientRegistration.
     */
    protected ClientRegistration externalIdpClientRegistration(
            ExternalIdpRegisteredClient externalIdpRegisteredClient) {
        LOGGER.debug("## externalIdpClientRegistration - START");
        LOGGER.info("Registering client of provider, {}", externalIdpRegisteredClient.getClientName());
        return ClientRegistration.withRegistrationId(externalIdpRegisteredClient.getRegistrationId())
                .clientId(externalIdpRegisteredClient.getClientId())
                .clientSecret(externalIdpRegisteredClient.getClientSecret())
                .clientAuthenticationMethod(externalIdpRegisteredClient.getClientAuthMethod())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(buildIssuerBaseUrl() + IDP_REDIRECT_URI + externalIdpRegisteredClient.getRegistrationId())
                .scope(Arrays.asList(externalIdpRegisteredClient.getScope().replaceAll("\\s", "")
                        .split(COMMA_DELIMITER)))
                .authorizationUri(externalIdpRegisteredClient.getAuthorizationUri())
                .tokenUri(externalIdpRegisteredClient.getTokenUri())
                .userInfoUri(externalIdpRegisteredClient.getUserInfoUri())
                .userNameAttributeName(externalIdpRegisteredClient.getUserNameAttributeName())
                .jwkSetUri(externalIdpRegisteredClient.getJwkSetUri())
                .clientName(externalIdpRegisteredClient.getClientName())
                .build();
    }

    /**
     * Constructs the base URL for the issuer.
     * This method uses the issuer protocol, host, and prefix to construct the base URL.
     * If the issuer prefix is empty, it is ignored during the construction of the URL.
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