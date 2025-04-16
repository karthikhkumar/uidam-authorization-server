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

import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.cache.CacheClientUtils;
import org.eclipse.ecsp.oauth2.server.core.cache.ClientCacheDetails;
import org.eclipse.ecsp.oauth2.server.core.client.AuthManagementClient;
import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.common.CustomOauth2TokenGenErrorCodes;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.request.dto.ClaimsToUserMapper;
import org.eclipse.ecsp.oauth2.server.core.request.dto.FederatedUserDto;
import org.eclipse.ecsp.oauth2.server.core.service.ClaimMappingService;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.test.TestOauth2Authorizations;
import org.eclipse.ecsp.oauth2.server.core.test.TestRegisteredClients;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.HashMap;
import java.util.Map;

import static org.eclipse.ecsp.oauth2.server.core.test.TestCommonStaticData.getUser;
import static org.eclipse.ecsp.oauth2.server.core.test.TestCommonStaticData.getUserWithEmptyScope;
import static org.eclipse.ecsp.oauth2.server.core.test.TestCommonStaticData.jwsHeader;
import static org.eclipse.ecsp.oauth2.server.core.test.TestCommonStaticData.jwtClaimsSet;
import static org.eclipse.ecsp.oauth2.server.core.test.TestCommonStaticData.jwtClaimsSetWithCustomScope;
import static org.eclipse.ecsp.oauth2.server.core.test.TestCommonStaticData.jwtClaimsSetWithScope;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.ATTRIBUTE_SUB;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.REGISTRATION_ID_GOOGLE;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_ACCOUNT_NAME;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_PASSWORD;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_USER_NAME;
import static org.eclipse.ecsp.oauth2.server.core.test.TestRegisteredClients.registeredClient;
import static org.eclipse.ecsp.oauth2.server.core.test.TestRegisteredClients.registeredClientWithEmptyScope;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;

/**
 * This class tests the functionality of the ClaimsConfigManager.
 */
@SpringBootTest
@ContextConfiguration(classes = { ClaimsConfigManager.class, TenantConfigurationService.class,
  ClaimMappingService.class,
  ClaimsToUserMapper.class })
@EnableConfigurationProperties(value = TenantProperties.class)
@TestPropertySource("classpath:application-test.properties")
@TestPropertySource("classpath:external-idp-application.properties")
class ClaimsConfigManagerTest {

    @Autowired
    OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;

    @MockitoBean
    CacheClientUtils cacheClientUtils;

    @MockitoBean
    UserManagementClient userManagementClient;
    
    @MockitoBean
    AuthManagementClient authManagementClient;

    @MockitoBean
    ClaimMappingService claimMappingService;

    /**
     * This test method tests the scenario where the token customization for
     * authorization code grant access token type is successful.
     */
    @Test
    void jwtTokenCustomizerForAuthCodeGrantAccessTokenType() {
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClientWithEmptyScope().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for
     * authorization code grant access token type with scope is successful.
     */
    @Test
    void jwtTokenCustomizerForAuthCodeGrantAccessTokenType2() {
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClientWithEmptyScope().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSetWithScope())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for
     * authorization code grant access token type with multi-role client and user
     * with empty scope is successful.
     */
    @Test
    void jwtTokenCustomizerForAuthCodeGrantAccessTokenType3() {
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        clientCacheDetails.setClientType("multi_role");
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUserWithEmptyScope()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for
     * authorization code grant access token type with multi-role client is
     * successful.
     */
    @Test
    void jwtTokenCustomizerForAuthCodeGrantAccessTokenType4() {
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        clientCacheDetails.setClientType("multi_role");
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for authorization code grant access token type
     * with empty scope and multi-role client is successful.
     */
    @Test
    void jwtTokenCustomizerForAuthCodeGrantAccessTokenType5() {
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClientWithEmptyScope().build());
        clientCacheDetails.setClientType("multi_role");
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
            TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(
            OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
            "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
            .registeredClient(registeredClient)
            .principal(principal)
            .authorization(authorization)
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrant(authorizationGrant)
            .put("custom-key-1", "custom-value-1")
            .context(ctx -> ctx.put("custom-key-2", "custom-value-2"))
            .build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for authorization code grant access token type
     * with empty scope and multi-role client and scope is successful.
     */
    @Test
    void jwtTokenCustomizerForAuthCodeGrantAccessTokenType6() {
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClientWithEmptyScope().build());
        clientCacheDetails.setClientType("multi_role");
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
            TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(
            OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
            "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSetWithScope())
            .registeredClient(registeredClient)
            .principal(principal)
            .authorization(authorization)
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrant(authorizationGrant)
            .put("custom-key-1", "custom-value-1")
            .context(ctx -> ctx.put("custom-key-2", "custom-value-2"))
            .build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     *  This test method tests the scenario where the token customization for
     * authorization code grant ID token type is successful.
     */
    @Test
    void jwtTokenCustomizerForAuthCodeGrantIdTokenType() {
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(new OAuth2TokenType("id_token"))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for client
     * credentials grant access token type with scope is successful.
     */
    @Test
    void jwtTokenCustomizerForClientCredsGrantAccessTokenType() {
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        clientCacheDetails.setAccountType("Root");
        clientCacheDetails.setAccountName("ignite");
        clientCacheDetails.setAccountId("456");
        clientCacheDetails.setTenantId("789");
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());

        RegisteredClient registeredClient = registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2ClientCredentialsAuthenticationToken authorizationGrant = new OAuth2ClientCredentialsAuthenticationToken(
                clientPrincipal, null, null);
        //doReturn(getClient()).when(authManagementClient).getClientDetails(anyString());
        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSetWithScope())
                .registeredClient(registeredClient).principal(clientPrincipal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for client
     * credentials grant access token type is successful.
     */
    @Test
    void jwtTokenCustomizerForClientCredsGrantAccessTokenType2() {
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClientWithEmptyScope().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());

        RegisteredClient registeredClient = registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2ClientCredentialsAuthenticationToken authorizationGrant = new OAuth2ClientCredentialsAuthenticationToken(
                clientPrincipal, null, null);
        //doReturn(getClientWithEmptyScope()).when(authManagementClient).getClientDetails(anyString());
        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(clientPrincipal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for client
     * credentials grant access token type with multi-role client is successful.
     */
    @Test
    void jwtTokenCustomizerForClientCredsGrantAccessTokenType3() {
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        clientCacheDetails.setClientType("multi_role");
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());

        RegisteredClient registeredClient = registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2ClientCredentialsAuthenticationToken authorizationGrant = new OAuth2ClientCredentialsAuthenticationToken(
                clientPrincipal, null, null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(clientPrincipal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for client
     * credentials grant access token type with multi-role client and scope is
     * successful.
     */
    @Test
    void jwtTokenCustomizerForClientCredsGrantAccessTokenType4() {
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        clientCacheDetails.setClientType("multi_role");
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());

        RegisteredClient registeredClient = registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2ClientCredentialsAuthenticationToken authorizationGrant = new OAuth2ClientCredentialsAuthenticationToken(
                clientPrincipal, null, null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSetWithScope())
                .registeredClient(registeredClient).principal(clientPrincipal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for client
     * credentials grant access token type with multi-role client and custom scope
     * is successful.
     */
    @Test
    void jwtTokenCustomizerForClientCredsGrantAccessTokenType5() {
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        clientCacheDetails.setClientType("multi_role");
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());

        RegisteredClient registeredClient = registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2ClientCredentialsAuthenticationToken authorizationGrant = new OAuth2ClientCredentialsAuthenticationToken(
                clientPrincipal, null, null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSetWithCustomScope())
                .registeredClient(registeredClient).principal(clientPrincipal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for client credentials grant access token type
     * with empty scope and multi-role client is successful.
     */
    @Test
    void jwtTokenCustomizerForClientCredsGrantAccessTokenType6() {
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClientWithEmptyScope().build());
        clientCacheDetails.setClientType("multi_role");
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());

        RegisteredClient registeredClient = registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2ClientCredentialsAuthenticationToken authorizationGrant = new OAuth2ClientCredentialsAuthenticationToken(
            clientPrincipal, null, null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
            .registeredClient(registeredClient)
            .principal(clientPrincipal)
            .authorization(authorization)
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .authorizationGrant(authorizationGrant)
            .put("custom-key-1", "custom-value-1")
            .context(ctx -> ctx.put("custom-key-2", "custom-value-2"))
            .build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /* This test method tests the scenario where the token customization for refresh
     * grant access token type is successful.
     */
    @Test
    void jwtTokenCustomizerForRefreshGrantAccessTokenType() {
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for
     * external IDP is successful.
     */
    @Test
    void jwtTokenCustomizerForExternalIdp() {
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), any());

        RegisteredClient registeredClient = registeredClient().build();
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);
        OAuth2AuthenticationToken principal = new OAuth2AuthenticationToken(oauth2User, null, REGISTRATION_ID_GOOGLE);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    @Test
    void getUserDetailsForFederatedUser_Success() {
        // Setup
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);
        OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(oauth2User, null, REGISTRATION_ID_GOOGLE);

        doReturn(getUser()).when(userManagementClient)
                .getUserDetailsByUsername(REGISTRATION_ID_GOOGLE + "_" + TEST_USER_NAME, null);

        // Execute & Verify
        assertDoesNotThrow(() -> jwtCustomizer.customize(createTestContext(token)));
    }

    @Test
    void getUserDetailsForFederatedUser_CreateNewUser() {
        // Setup
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);

        OAuth2AuthenticationException userNotFound = new OAuth2AuthenticationException(
                new OAuth2Error(CustomOauth2TokenGenErrorCodes.USER_NOT_FOUND.name()));

        doThrow(userNotFound).doReturn(getUser()).when(userManagementClient)
                .getUserDetailsByUsername(REGISTRATION_ID_GOOGLE + "_" + TEST_USER_NAME, null);

        doReturn(true).when(claimMappingService).validateClaimCondition(eq(REGISTRATION_ID_GOOGLE), any());

        doReturn(new FederatedUserDto()).when(claimMappingService).mapClaimsToUserRequest(eq(REGISTRATION_ID_GOOGLE),
                any(), any());
        OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(oauth2User, null, REGISTRATION_ID_GOOGLE);
        doReturn(getUser()).when(userManagementClient).createFedratedUser(any());

        // Execute & Verify
        assertDoesNotThrow(() -> jwtCustomizer.customize(createTestContext(token)));
    }

    @Test
    void getUserDetailsForFederatedUser_ClaimValidationFails() {
        // Setup
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);
        OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(oauth2User, null, REGISTRATION_ID_GOOGLE);

        OAuth2AuthenticationException userNotFound = new OAuth2AuthenticationException(
                new OAuth2Error(CustomOauth2TokenGenErrorCodes.USER_NOT_FOUND.name()));

        doThrow(userNotFound).when(userManagementClient)
                .getUserDetailsByUsername(REGISTRATION_ID_GOOGLE + "_" + TEST_USER_NAME, null);

        doReturn(false).when(claimMappingService).validateClaimCondition(eq(REGISTRATION_ID_GOOGLE), any());

        // Execute & Verify
        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> customizeToken(token));

        assertEquals("invalid_claim_validation", exception.getError().getErrorCode());
        assertEquals("Claim validation failed for registrationId: " + REGISTRATION_ID_GOOGLE,
                exception.getError().getDescription());
    }

    @Test
    void getUserDetailsForFederatedUser_InvalidIdpConfiguration() {
        // Setup
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);
        OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(oauth2User, null, "invalid_idp");

        // Execute & Verify
        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> customizeToken(token));

        assertEquals("invalid_idp_configuration", exception.getError().getErrorCode());
        assertEquals("No external IDP configuration found for: invalid_idp", exception.getError().getDescription());
    }

    
    @Test
    void findExternalIdpClient_InvalidRegistrationId_ThrowsException() {
        // Setup
        String invalidRegistrationId = "invalid_registration_id";
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);
        OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(oauth2User, null, invalidRegistrationId);

        // Execute & Verify
        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> customizeToken(token));

        assertEquals("invalid_idp_configuration", exception.getError().getErrorCode());
        assertEquals("No external IDP configuration found for: " + invalidRegistrationId, 
                exception.getError().getDescription());
    }

    private void customizeToken(OAuth2AuthenticationToken token) {
        jwtCustomizer.customize(createTestContext(token));
    }

    private JwtEncodingContext createTestContext(OAuth2AuthenticationToken principal) {
        RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        return JwtEncodingContext.with(jwsHeader(), jwtClaimsSet()).registeredClient(registeredClient)
                .principal(principal).authorization(authorization).tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).build();
    }

}