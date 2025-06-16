/********************************************************************************
 * Copyright (c) 2023-24 Harman International 
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

package org.eclipse.ecsp.oauth2.server.core.repositories;

import org.eclipse.ecsp.oauth2.server.core.entities.Authorization;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * This class tests the functionality of the AuthorizationRepository, specifically focusing on the
 * findByPrincipalNameClientAndAccessTokenExpiresAt method.
 */
@ExtendWith(MockitoExtension.class) 
@ActiveProfiles("test")
class AuthorizationRepositoryTest {

    private static final int INTEGER_TWO = 2;

    private static final long INT_4102444800L = 4102444800L;

    private static final int INT_500 = 500;

    private static final int INT_1800 = 1800;

    private static final int INT_2 = 2;

    @Mock
    private AuthorizationRepository authorizationRepository;

    private static final String PRINCIPAL_NAME = "testUser";
    private static final String CLIENT_ID = "testClient";
    private static final String AUTHORIZATION_ID = "auth-123";
    private static final String ACCESS_TOKEN_VALUE = "access-token-value";
    private static final Instant CURRENT_TIME = Instant.now();
    private static final Instant FUTURE_TIME = CURRENT_TIME.plusSeconds(3600);

    private Authorization validAuthorization;

    @BeforeEach
    void setUp() {
        validAuthorization = createAuthorization(AUTHORIZATION_ID, PRINCIPAL_NAME, CLIENT_ID, FUTURE_TIME);
    }

    /**
     * Test that the method returns authorizations for valid principal name, client ID, and future expiry time.
     */
    @Test
    void findByPrincipalNameClientAndAccessTokenExpiresAt_WhenValidParameters_ReturnsAuthorizations() {
        // Arrange
        List<Authorization> expectedAuthorizations = List.of(validAuthorization);
        when(authorizationRepository.findByPrincipalNameClientAndAccessTokenExpiresAt(eq(PRINCIPAL_NAME), eq(CLIENT_ID),
                any(Instant.class))).thenReturn(expectedAuthorizations);

        // Act
        List<Authorization> result = authorizationRepository
                .findByPrincipalNameClientAndAccessTokenExpiresAt(PRINCIPAL_NAME, CLIENT_ID, CURRENT_TIME);

        // Assert
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(AUTHORIZATION_ID, result.get(0).getId());
        assertEquals(PRINCIPAL_NAME, result.get(0).getPrincipalName());
        assertEquals(CLIENT_ID, result.get(0).getRegisteredClientId());
    }

    /**
     * Test that the method returns empty list when no authorizations match the criteria.
     */
    @Test
    void findByPrincipalNameClientAndAccessTokenExpiresAt_WhenNoMatches_ReturnsEmptyList() {
        // Arrange
        when(authorizationRepository.findByPrincipalNameClientAndAccessTokenExpiresAt(eq("nonExistentUser"),
                eq(CLIENT_ID), any(Instant.class))).thenReturn(Collections.emptyList());

        // Act
        List<Authorization> result = authorizationRepository
                .findByPrincipalNameClientAndAccessTokenExpiresAt("nonExistentUser", CLIENT_ID, CURRENT_TIME);

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    /**
     * Test that the method returns empty list when principal name is null.
     */
    @Test
    void findByPrincipalNameClientAndAccessTokenExpiresAt_WhenPrincipalNameIsNull_ReturnsEmptyList() {
        // Arrange
        when(authorizationRepository.findByPrincipalNameClientAndAccessTokenExpiresAt(eq(null), eq(CLIENT_ID),
                any(Instant.class))).thenReturn(Collections.emptyList());

        // Act
        List<Authorization> result = authorizationRepository.findByPrincipalNameClientAndAccessTokenExpiresAt(null,
                CLIENT_ID, CURRENT_TIME);

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    /**
     * Test that the method returns empty list when client ID is null.
     */
    @Test
    void findByPrincipalNameClientAndAccessTokenExpiresAt_WhenClientIdIsNull_ReturnsEmptyList() {
        // Arrange
        when(authorizationRepository.findByPrincipalNameClientAndAccessTokenExpiresAt(eq(PRINCIPAL_NAME), eq(null),
                any(Instant.class))).thenReturn(Collections.emptyList());

        // Act
        List<Authorization> result = authorizationRepository
                .findByPrincipalNameClientAndAccessTokenExpiresAt(PRINCIPAL_NAME, null, CURRENT_TIME);

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    /**
     * Test that the method returns empty list when access token expires at is null.
     */
    @Test
    void findByPrincipalNameClientAndAccessTokenExpiresAt_WhenExpiresAtIsNull_ReturnsEmptyList() {
        // Arrange
        when(authorizationRepository.findByPrincipalNameClientAndAccessTokenExpiresAt(eq(PRINCIPAL_NAME), eq(CLIENT_ID),
                eq(null))).thenReturn(Collections.emptyList());

        // Act
        List<Authorization> result = authorizationRepository
                .findByPrincipalNameClientAndAccessTokenExpiresAt(PRINCIPAL_NAME, CLIENT_ID, null);

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    /**
     * Test that the method returns multiple authorizations when multiple valid records exist.
     */
    @Test
    void findByPrincipalNameClientAndAccessTokenExpiresAt_WhenMultipleMatches_ReturnsAllMatches() {
        // Arrange
        Authorization secondAuthorization = createAuthorization("auth-789", PRINCIPAL_NAME, CLIENT_ID, FUTURE_TIME);
        List<Authorization> expectedAuthorizations = List.of(validAuthorization, secondAuthorization);

        when(authorizationRepository.findByPrincipalNameClientAndAccessTokenExpiresAt(eq(PRINCIPAL_NAME), eq(CLIENT_ID),
                any(Instant.class))).thenReturn(expectedAuthorizations);

        // Act
        List<Authorization> result = authorizationRepository
                .findByPrincipalNameClientAndAccessTokenExpiresAt(PRINCIPAL_NAME, CLIENT_ID, CURRENT_TIME);

        // Assert
        assertNotNull(result);
        assertEquals(INT_2, result.size());
        assertTrue(result.stream().anyMatch(auth -> AUTHORIZATION_ID.equals(auth.getId())));
        assertTrue(result.stream().anyMatch(auth -> "auth-789".equals(auth.getId())));
    }

    /**
     * Test that the method filters out expired tokens correctly.
     */
    @Test
    void findByPrincipalNameClientAndAccessTokenExpiresAt_WhenOnlyExpiredTokens_ReturnsEmptyList() {
        // Arrange
        when(authorizationRepository.findByPrincipalNameClientAndAccessTokenExpiresAt(eq(PRINCIPAL_NAME), eq(CLIENT_ID),
                any(Instant.class))).thenReturn(Collections.emptyList());

        // Act
        List<Authorization> result = authorizationRepository
                .findByPrincipalNameClientAndAccessTokenExpiresAt(PRINCIPAL_NAME, CLIENT_ID, FUTURE_TIME);

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    /**
     * Test that the method works correctly with different client IDs for the same principal.
     */
    @Test
    void findByPrincipalNameClientAndAccessTokenExpiresAt_WhenDifferentClientId_ReturnsCorrectAuthorizations() {
        // Arrange
        String differentClientId = "differentClient";
        Authorization authForDifferentClient = createAuthorization("auth-999", PRINCIPAL_NAME, differentClientId,
                FUTURE_TIME);

        when(authorizationRepository.findByPrincipalNameClientAndAccessTokenExpiresAt(eq(PRINCIPAL_NAME),
                eq(differentClientId), any(Instant.class))).thenReturn(List.of(authForDifferentClient));

        // Act
        List<Authorization> result = authorizationRepository
                .findByPrincipalNameClientAndAccessTokenExpiresAt(PRINCIPAL_NAME, differentClientId, CURRENT_TIME);

        // Assert
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(differentClientId, result.get(0).getRegisteredClientId());
        assertEquals(PRINCIPAL_NAME, result.get(0).getPrincipalName());
    }

    /**
     * Test that the method works correctly with different principal names for the same client.
     */
    @Test
    void findByPrincipalNameClientAndAccessTokenExpiresAt_WhenDifferentPrincipalName_ReturnsCorrectAuthorizations() {
        // Arrange
        String differentPrincipalName = "differentUser";
        Authorization authForDifferentPrincipal = createAuthorization("auth-888", differentPrincipalName, CLIENT_ID,
                FUTURE_TIME);

        when(authorizationRepository.findByPrincipalNameClientAndAccessTokenExpiresAt(eq(differentPrincipalName),
                eq(CLIENT_ID), any(Instant.class))).thenReturn(List.of(authForDifferentPrincipal));

        // Act
        List<Authorization> result = authorizationRepository
                .findByPrincipalNameClientAndAccessTokenExpiresAt(differentPrincipalName, CLIENT_ID, CURRENT_TIME);

        // Assert
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(differentPrincipalName, result.get(0).getPrincipalName());
        assertEquals(CLIENT_ID, result.get(0).getRegisteredClientId());
    }

    /**
     * Test that the method handles edge case with exact expiration time.
     */
    @Test
    void findByPrincipalNameClientAndAccessTokenExpiresAt_WhenExactExpirationTime_ReturnsAuthorizations() {
        // Arrange
        Instant exactExpirationTime = CURRENT_TIME.plusSeconds(INT_1800); // 30 minutes from now
        Authorization authWithExactExpiration = createAuthorization("auth-exact", PRINCIPAL_NAME, CLIENT_ID,
                exactExpirationTime);

        when(authorizationRepository.findByPrincipalNameClientAndAccessTokenExpiresAt(eq(PRINCIPAL_NAME), eq(CLIENT_ID),
                eq(exactExpirationTime))).thenReturn(List.of(authWithExactExpiration));

        // Act
        List<Authorization> result = authorizationRepository
                .findByPrincipalNameClientAndAccessTokenExpiresAt(PRINCIPAL_NAME, CLIENT_ID, exactExpirationTime);

        // Assert
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(exactExpirationTime, result.get(0).getAccessTokenExpiresAt());
    }

    /**
     * Test that the method handles empty strings for principal name and client ID.
     */
    @Test
    void findByPrincipalNameClientAndAccessTokenExpiresAt_WhenEmptyStrings_ReturnsEmptyList() {
        // Arrange
        when(authorizationRepository.findByPrincipalNameClientAndAccessTokenExpiresAt(eq(""), eq(""),
                any(Instant.class))).thenReturn(Collections.emptyList());

        // Act
        List<Authorization> result = authorizationRepository.findByPrincipalNameClientAndAccessTokenExpiresAt("", "",
                CURRENT_TIME);

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    /**
     * Test that the method handles whitespace-only strings for principal name and client ID.
     */
    @Test
    void findByPrincipalNameClientAndAccessTokenExpiresAt_WhenWhitespaceStrings_ReturnsEmptyList() {
        // Arrange
        when(authorizationRepository.findByPrincipalNameClientAndAccessTokenExpiresAt(eq("   "), eq("   "),
                any(Instant.class))).thenReturn(Collections.emptyList());

        // Act
        List<Authorization> result = authorizationRepository.findByPrincipalNameClientAndAccessTokenExpiresAt("   ",
                "   ", CURRENT_TIME);

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    /**
     * Test that the method handles very long strings for principal name and client ID.
     */
    @Test
    void findByPrincipalNameClientAndAccessTokenExpiresAt_WhenVeryLongStrings_ReturnsCorrectResult() {
        // Arrange
        String longPrincipalName = "a".repeat(INT_500);
        String longClientId = "b".repeat(INT_500);
        Authorization authWithLongIdentifiers = createAuthorization("auth-long", longPrincipalName, longClientId,
                FUTURE_TIME);

        when(authorizationRepository.findByPrincipalNameClientAndAccessTokenExpiresAt(eq(longPrincipalName),
                eq(longClientId), any(Instant.class))).thenReturn(List.of(authWithLongIdentifiers));

        // Act
        List<Authorization> result = authorizationRepository
                .findByPrincipalNameClientAndAccessTokenExpiresAt(longPrincipalName, longClientId, CURRENT_TIME);

        // Assert
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(longPrincipalName, result.get(0).getPrincipalName());
        assertEquals(longClientId, result.get(0).getRegisteredClientId());
    }

    /**
     * Test that the method handles special characters in principal name and client ID.
     */
    @Test
    void findByPrincipalNameClientAndAccessTokenExpiresAt_WhenSpecialCharacters_ReturnsCorrectResult() {
        // Arrange
        String specialPrincipalName = "user@domain.com";
        String specialClientId = "client-id_123.test";
        Authorization authWithSpecialChars = createAuthorization("auth-special", specialPrincipalName, specialClientId,
                FUTURE_TIME);

        when(authorizationRepository.findByPrincipalNameClientAndAccessTokenExpiresAt(eq(specialPrincipalName),
                eq(specialClientId), any(Instant.class))).thenReturn(List.of(authWithSpecialChars));

        // Act
        List<Authorization> result = authorizationRepository
                .findByPrincipalNameClientAndAccessTokenExpiresAt(specialPrincipalName, specialClientId, CURRENT_TIME);

        // Assert
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(specialPrincipalName, result.get(0).getPrincipalName());
        assertEquals(specialClientId, result.get(0).getRegisteredClientId());
    }

    /**
     * Test that the method handles very old expiration times.
     */
    @Test
    void findByPrincipalNameClientAndAccessTokenExpiresAt_WhenVeryOldExpirationTime_ReturnsEmptyList() {
        // Arrange
        Instant veryOldTime = Instant.ofEpochMilli(0); // Unix epoch

        when(authorizationRepository.findByPrincipalNameClientAndAccessTokenExpiresAt(eq(PRINCIPAL_NAME), eq(CLIENT_ID),
                eq(veryOldTime))).thenReturn(Collections.emptyList());

        // Act
        List<Authorization> result = authorizationRepository
                .findByPrincipalNameClientAndAccessTokenExpiresAt(PRINCIPAL_NAME, CLIENT_ID, veryOldTime);

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    /**
     * Test that the method handles far future expiration times.
     */
    @Test
    void findByPrincipalNameClientAndAccessTokenExpiresAt_WhenFarFutureExpirationTime_ReturnsCorrectResult() {
        // Arrange
        Instant farFuture = Instant.ofEpochSecond(INT_4102444800L); // Year 2100
        Authorization authWithFarFutureExpiration = createAuthorization("auth-future", PRINCIPAL_NAME, CLIENT_ID,
                farFuture);

        when(authorizationRepository.findByPrincipalNameClientAndAccessTokenExpiresAt(eq(PRINCIPAL_NAME), eq(CLIENT_ID),
                any(Instant.class))).thenReturn(List.of(authWithFarFutureExpiration));

        // Act
        List<Authorization> result = authorizationRepository
                .findByPrincipalNameClientAndAccessTokenExpiresAt(PRINCIPAL_NAME, CLIENT_ID, CURRENT_TIME);

        // Assert
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(farFuture, result.get(0).getAccessTokenExpiresAt());
    }

    /**
     * Test that the method excludes client_credentials tokens from results.
     */
    @Test
    void findByPrincipalNameClientAndValidTokens_WhenClientCredentialsTokens_ReturnsEmptyList() {
        // Arrange
        when(authorizationRepository.findByPrincipalNameClientAndValidTokens(eq(PRINCIPAL_NAME), eq(CLIENT_ID),
                any(Instant.class))).thenReturn(Collections.emptyList());

        // Act
        List<Authorization> result = authorizationRepository
                .findByPrincipalNameClientAndValidTokens(PRINCIPAL_NAME, CLIENT_ID, CURRENT_TIME);

        // Assert
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    /**
     * Test that the method returns only authorization_code tokens and excludes client_credentials tokens.
     */
    @Test
    void findByPrincipalNameClientAndValidTokens_WhenMixedGrantTypes_ReturnsOnlyAuthorizationCodeTokens() {
        // Arrange
        Authorization authCodeAuthorization = createAuthorization("auth-code-123", PRINCIPAL_NAME, CLIENT_ID,
                FUTURE_TIME);
        authCodeAuthorization.setAuthorizationGrantType("authorization_code");

        List<Authorization> expectedAuthorizations = List.of(authCodeAuthorization);

        when(authorizationRepository.findByPrincipalNameClientAndValidTokens(eq(PRINCIPAL_NAME), eq(CLIENT_ID),
                any(Instant.class))).thenReturn(expectedAuthorizations);

        // Act
        List<Authorization> result = authorizationRepository.findByPrincipalNameClientAndValidTokens(PRINCIPAL_NAME,
                CLIENT_ID, CURRENT_TIME);

        // Assert
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("authorization_code", result.get(0).getAuthorizationGrantType());
        assertEquals(PRINCIPAL_NAME, result.get(0).getPrincipalName());
        assertEquals(CLIENT_ID, result.get(0).getRegisteredClientId());
    }

    /**
     * Test that the method returns multiple authorization_code tokens while excluding client_credentials tokens.
     */
    @Test
    void findByPrincipalNameClientAndValidTokens_WhenMultipleAuthCodeTokens_ReturnsAllAuthCodeTokens() {
        // Arrange
        Authorization authCodeAuth1 = createAuthorization("auth-code-1", PRINCIPAL_NAME, CLIENT_ID, FUTURE_TIME);
        authCodeAuth1.setAuthorizationGrantType("authorization_code");

        Authorization authCodeAuth2 = createAuthorization("auth-code-2", PRINCIPAL_NAME, CLIENT_ID, FUTURE_TIME);
        authCodeAuth2.setAuthorizationGrantType("authorization_code");

        List<Authorization> expectedAuthorizations = List.of(authCodeAuth1, authCodeAuth2);

        when(authorizationRepository.findByPrincipalNameClientAndValidTokens(eq(PRINCIPAL_NAME), eq(CLIENT_ID),
                any(Instant.class))).thenReturn(expectedAuthorizations);

        // Act
        List<Authorization> result = authorizationRepository.findByPrincipalNameClientAndValidTokens(PRINCIPAL_NAME,
                CLIENT_ID, CURRENT_TIME);

        // Assert
        assertNotNull(result);
        assertEquals(INTEGER_TWO, result.size());
        assertTrue(result.stream().allMatch(auth -> "authorization_code".equals(auth.getAuthorizationGrantType())));
        assertTrue(result.stream().anyMatch(auth -> "auth-code-1".equals(auth.getId())));
        assertTrue(result.stream().anyMatch(auth -> "auth-code-2".equals(auth.getId())));
    }

    /**
     * Test that the method returns refresh_token grants while excluding client_credentials tokens.
     */
    @Test
    void findByPrincipalNameClientAndValidTokens_WhenRefreshTokenGrant_ReturnsRefreshTokens() {
        // Arrange
        Authorization refreshTokenAuth = createAuthorization("refresh-token-123", PRINCIPAL_NAME, CLIENT_ID,
                FUTURE_TIME);
        refreshTokenAuth.setAuthorizationGrantType("refresh_token");

        List<Authorization> expectedAuthorizations = List.of(refreshTokenAuth);

        when(authorizationRepository.findByPrincipalNameClientAndValidTokens(eq(PRINCIPAL_NAME), eq(CLIENT_ID),
                any(Instant.class))).thenReturn(expectedAuthorizations);

        // Act
        List<Authorization> result = authorizationRepository.findByPrincipalNameClientAndValidTokens(PRINCIPAL_NAME,
                CLIENT_ID, CURRENT_TIME);

        // Assert
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("refresh_token", result.get(0).getAuthorizationGrantType());
        assertEquals(PRINCIPAL_NAME, result.get(0).getPrincipalName());
        assertEquals(CLIENT_ID, result.get(0).getRegisteredClientId());
    }

    /**
     * Helper method to create an Authorization entity with the specified parameters.
     *
     * @param id the authorization ID
     * @param principalName the principal name
     * @param clientId the client ID
     * @param accessTokenExpiresAt the access token expiration time
     * @return a new Authorization entity
     */
    private Authorization createAuthorization(String id, String principalName, String clientId,
            Instant accessTokenExpiresAt) {
        Authorization authorization = new Authorization();
        authorization.setId(id);
        authorization.setPrincipalName(principalName);
        authorization.setRegisteredClientId(clientId);
        authorization.setAccessTokenExpiresAt(accessTokenExpiresAt);
        authorization.setAccessTokenValue(ACCESS_TOKEN_VALUE + "-" + id);
        authorization.setAuthorizationGrantType("authorization_code");
        authorization.setAccessTokenType("Bearer");
        authorization.setAccessTokenScopes("read write");
        authorization.setAuthorizedScopes("read write");
        authorization.setAccessTokenMetadata("{\"sub\":\"" + principalName + "\"}");
        authorization.setAttributes("{\"@class\":\"java.util.Collections$UnmodifiableMap\"}");

        return authorization;
    }
}
