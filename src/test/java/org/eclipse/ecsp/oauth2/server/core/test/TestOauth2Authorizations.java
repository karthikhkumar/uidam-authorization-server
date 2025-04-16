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

package org.eclipse.ecsp.oauth2.server.core.test;


import org.eclipse.ecsp.oauth2.server.core.entities.Authorization;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.CollectionUtils;

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.DUMMY_TOKEN;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.ID;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.SECONDS_TO_ADD;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.SECONDS_TO_ADD1;

/**
 * This class provides utility methods to support test cases for Token Generation.
 */
public class TestOauth2Authorizations {

    private static final RegisteredClient REGISTERED_CLIENT = TestRegisteredClients.registeredDummyClient().build();


    protected TestOauth2Authorizations() {
    }

    /**
     * Creates an OAuth2Authorization instance with a dummy RegisteredClient.
     *
     * @return An OAuth2Authorization.Builder instance.
     */
    public static OAuth2Authorization.Builder authorization() {
        return authorization(TestRegisteredClients.registeredClient().build());
    }

    /**
     * Creates an OAuth2Authorization instance with the specified RegisteredClient.
     *
     * @param registeredClient The RegisteredClient to use in the creation of the OAuth2Authorization instance.
     * @return An OAuth2Authorization.Builder instance.
     */
    public static OAuth2Authorization.Builder authorization(RegisteredClient registeredClient) {
        return authorization(registeredClient, Collections.emptyMap());
    }

    /**
     * Creates an OAuth2Authorization instance with the specified RegisteredClient and additional parameters.
     *
     * @param registeredClient The RegisteredClient to use in the creation of the OAuth2Authorization instance.
     * @param authRequestAdditionalParameters Additional parameters to include in the OAuth2AuthorizationRequest.
     * @return An OAuth2Authorization.Builder instance.
     */
    public static OAuth2Authorization.Builder authorization(RegisteredClient registeredClient,
                                                            Map<String, Object> authRequestAdditionalParameters) {
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
            "code", Instant.now(), Instant.now().plusSeconds(SECONDS_TO_ADD));
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER, "access-token", Instant.now(), Instant.now().plusSeconds(
            SECONDS_TO_ADD1));
        return authorization(registeredClient, authorizationCode, accessToken,
            Collections.emptyMap(), authRequestAdditionalParameters);
    }

    /**
     * Creates an OAuth2Authorization instance with the specified RegisteredClient and OAuth2AuthorizationCode.
     *
     * @param registeredClient The RegisteredClient to use in the creation of the OAuth2Authorization instance.
     * @param authorizationCode The OAuth2AuthorizationCode to include in the OAuth2Authorization instance.
     * @return An OAuth2Authorization.Builder instance.
     */
    public static OAuth2Authorization.Builder authorization(RegisteredClient registeredClient,
                                                            OAuth2AuthorizationCode authorizationCode) {
        return authorization(registeredClient, authorizationCode, null, Collections.emptyMap(), Collections.emptyMap());
    }

    /**
     * Creates an OAuth2Authorization instance with the specified RegisteredClient, OAuth2AccessToken, and access token
     * claims.
     *
     * @param registeredClient The RegisteredClient to use in the creation of the OAuth2Authorization instance.
     * @param accessToken The OAuth2AccessToken to include in the OAuth2Authorization instance.
     * @param accessTokenClaims The claims of the access token.
     * @return An OAuth2Authorization.Builder instance.
     */
    public static OAuth2Authorization.Builder authorization(RegisteredClient registeredClient,
                                                            OAuth2AccessToken accessToken,
                                                            Map<String, Object> accessTokenClaims) {
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
            "code", Instant.now(), Instant.now().plusSeconds(SECONDS_TO_ADD));
        return authorization(registeredClient, authorizationCode, accessToken, accessTokenClaims,
            Collections.emptyMap());
    }

    /**
     * Creates an OAuth2Authorization instance with the specified RegisteredClient, OAuth2AuthorizationCode,
     * OAuth2AccessToken, access token claims, and additional parameters.
     *
     * @param registeredClient The RegisteredClient to use in the creation of the OAuth2Authorization instance.
     * @param authorizationCode The OAuth2AuthorizationCode to include in the OAuth2Authorization instance.
     * @param accessToken The OAuth2AccessToken to include in the OAuth2Authorization instance.
     * @param accessTokenClaims The claims of the access token.
     * @param authRequestAdditionalParameters Additional parameters to include in the OAuth2AuthorizationRequest.
     * @return An OAuth2Authorization.Builder instance.
     */
    private static OAuth2Authorization.Builder authorization(RegisteredClient registeredClient,
                                                             OAuth2AuthorizationCode authorizationCode,
                                                             OAuth2AccessToken accessToken,
                                                             Map<String, Object> accessTokenClaims,
                                                             Map<String, Object> authRequestAdditionalParameters) {
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri("https://localhost/oauth2/authorize")
            .clientId(registeredClient.getClientId())
            .redirectUri(registeredClient.getRedirectUris().iterator().next())
            .scopes(registeredClient.getScopes())
            .additionalParameters(authRequestAdditionalParameters)
            .state("state")
            .build();
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .id("id")
            .principalName("principal")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizedScopes(authorizationRequest.getScopes())
            .token(authorizationCode)
            .attribute(OAuth2ParameterNames.STATE, "consent-state")
            .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest)
            .attribute(Principal.class.getName(),
                new TestingAuthenticationToken("principal", null, "ROLE_A", "ROLE_B"));
        if (accessToken != null) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                "refresh-token", Instant.now(), Instant.now().plus(1, ChronoUnit.HOURS));
            builder
                .token(accessToken, metadata -> metadata.putAll(tokenMetadata(accessTokenClaims)))
                .refreshToken(refreshToken);
        }

        return builder;
    }

    /**
     * Creates a map of metadata for the token with the specified claims.
     *
     * @param tokenClaims The claims of the token.
     * @return A map of metadata for the token.
     */
    private static Map<String, Object> tokenMetadata(Map<String, Object> tokenClaims) {
        Map<String, Object> tokenMetadata = new HashMap<>();
        tokenMetadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
        if (CollectionUtils.isEmpty(tokenClaims)) {
            tokenClaims = defaultTokenClaims();
        }
        tokenMetadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, tokenClaims);
        return tokenMetadata;
    }

    /**
     * Creates a map of default token claims.
     *
     * @return A map of default token claims.
     */
    private static Map<String, Object> defaultTokenClaims() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("claim1", "value1");
        claims.put("claim2", "value2");
        claims.put("claim3", "value3");
        return claims;
    }

    /**
     * Creates an Authorization instance with predefined values.
     *
     * @return An Authorization instance.
     */
    public static Authorization createAuthorization() {
        Authorization expAuthorization = new Authorization();
        expAuthorization.setRegisteredClientId(REGISTERED_CLIENT.getClientId());
        expAuthorization.setState("Active");
        expAuthorization.setAuthorizationGrantType("client_credentials");
        expAuthorization.setAttributes("{\"@class\":\"java.util.Collections$UnmodifiableMap\"}");
        expAuthorization.setPrincipalName(REGISTERED_CLIENT.getClientName());
        expAuthorization.setId(ID);
        return expAuthorization;
    }

    /**
     * Creates an Authorization instance representing an access token.
     *
     * @return An Authorization instance representing an access token.
     */
    public static Authorization createAccTokenAuthorization() {
        Authorization expAuthorization = new Authorization();
        expAuthorization.setRegisteredClientId(REGISTERED_CLIENT.getClientId());
        expAuthorization.setState("Active");
        expAuthorization.setAuthorizationGrantType("authorization_code");
        expAuthorization.setAttributes("{\"@class\":\"java.util.Collections$UnmodifiableMap\"}");
        expAuthorization.setPrincipalName(REGISTERED_CLIENT.getClientName());
        expAuthorization.setId(ID);

        expAuthorization.setAccessTokenValue(DUMMY_TOKEN);
        expAuthorization.setAccessTokenScopes(String.valueOf(REGISTERED_CLIENT.getScopes()));
        expAuthorization.setAccessTokenIssuedAt(REGISTERED_CLIENT.getClientIdIssuedAt());
        expAuthorization.setAccessTokenMetadata("{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.claims\":{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"sub\":\"testClientAK2\",\"aud\":[\"java.util.Collections$SingletonList\",[\"testClientAK2\"]],\"nbf\":[\"java.time.Instant\",1694546771.402723700],\"scope\":[\"java.util.LinkedHashSet\",[\"IgniteSystem\",\"SelfManage\"]],\"iss\":[\"java.net.URL\",\"http://localhost:9000\"],\"exp\":[\"java.time.Instant\",1694547771.402723700],\"iat\":[\"java.time.Instant\",1694546771.402723700],\"client_id\":\"testClientAK2\"},\"metadata.token.invalidated\":false}");
        return expAuthorization;
    }

    /**
     * Creates an Authorization instance representing a refresh token.
     *
     * @return An Authorization instance representing a refresh token.
     */
    public static Authorization createRefreshTokenAuthorization() {

        Authorization expAuthorization = new Authorization();
        expAuthorization.setRegisteredClientId(REGISTERED_CLIENT.getClientId());
        expAuthorization.setState("Active");
        expAuthorization.setAuthorizationGrantType("refresh_token");
        expAuthorization.setAttributes("{\"@class\":\"java.util.Collections$UnmodifiableMap\"}");
        expAuthorization.setPrincipalName(REGISTERED_CLIENT.getClientName());
        expAuthorization.setId(ID);
        expAuthorization.setRefreshTokenMetadata("{\"@class\":\"java.util.Collections$UnmodifiableMap\"}");
        expAuthorization.setRefreshTokenValue("Refresh_Token");
        return expAuthorization;
    }

    /**
     * Creates an Authorization instance representing a device code.
     *
     * @return An Authorization instance representing a device code.
     */
    public static Authorization createDeviceCodeAuthorization() {

        Authorization expAuthorization = new Authorization();
        expAuthorization.setRegisteredClientId(REGISTERED_CLIENT.getClientId());
        expAuthorization.setState("Active");
        expAuthorization.setAuthorizationGrantType("device_code");
        expAuthorization.setAttributes("{\"@class\":\"java.util.Collections$UnmodifiableMap\"}");
        expAuthorization.setPrincipalName(REGISTERED_CLIENT.getClientName());
        expAuthorization.setId(ID);
        expAuthorization.setDeviceCodeMetadata("{\"@class\":\"java.util.Collections$UnmodifiableMap\"}");
        expAuthorization.setDeviceCodeValue("Device_code");
        return expAuthorization;
    }

    /**
     * Creates an Authorization instance representing a user code.
     *
     * @return An Authorization instance representing a user code.
     */
    public static Authorization createUserCodeAuthorization() {

        Authorization expAuthorization = new Authorization();
        expAuthorization.setRegisteredClientId(REGISTERED_CLIENT.getClientId());
        expAuthorization.setState("Active");
        expAuthorization.setAuthorizationGrantType("user_code");
        expAuthorization.setAttributes("{\"@class\":\"java.util.Collections$UnmodifiableMap\"}");
        expAuthorization.setPrincipalName(REGISTERED_CLIENT.getClientName());
        expAuthorization.setId(ID);
        expAuthorization.setUserCodeMetadata("{\"@class\":\"java.util.Collections$UnmodifiableMap\"}");
        expAuthorization.setUserCodeValue("user_code");
        return expAuthorization;
    }
}