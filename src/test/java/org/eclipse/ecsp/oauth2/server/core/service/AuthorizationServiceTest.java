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

import org.eclipse.ecsp.oauth2.server.core.entities.Authorization;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationRepository;
import org.eclipse.ecsp.oauth2.server.core.test.TestRegisteredClients;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.AMOUNT_TO_ADD;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.AMOUNT_TO_ADD1;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.DUMMY_TOKEN;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.ID;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.PRINCIPAL_NAME;
import static org.eclipse.ecsp.oauth2.server.core.test.TestOauth2Authorizations.createAccTokenAuthorization;
import static org.eclipse.ecsp.oauth2.server.core.test.TestOauth2Authorizations.createAuthorization;
import static org.eclipse.ecsp.oauth2.server.core.test.TestOauth2Authorizations.createDeviceCodeAuthorization;
import static org.eclipse.ecsp.oauth2.server.core.test.TestOauth2Authorizations.createRefreshTokenAuthorization;
import static org.eclipse.ecsp.oauth2.server.core.test.TestOauth2Authorizations.createUserCodeAuthorization;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * This class tests the functionality of the IgniteOauth2AuthorizationService.
 */
@ActiveProfiles("test")
class AuthorizationServiceTest {

    @Mock
    AuthorizationService authorizationService;
    @Mock
    RegisteredClientRepository registeredClientRepository;
    @Mock
    AuthorizationRepository authorizationRepository;

    private static final RegisteredClient REGISTERED_CLIENT = TestRegisteredClients.registeredDummyClient().build();
    private static final AuthorizationGrantType AUTHORIZATION_GRANT_TYPE = AuthorizationGrantType.CLIENT_CREDENTIALS;

    /**
     * This method sets up the test environment before each test.
     * It initializes the mocks.
     */
    @BeforeEach
    void setUp() {
        this.authorizationRepository = mock(AuthorizationRepository.class);
        this.registeredClientRepository = mock(RegisteredClientRepository.class);
        this.authorizationService = Mockito.mock(AuthorizationService.class);
    }

    /**
     * This test method tests the scenario where an attempt to save a null authorization throws an exception.
     * It sets up the necessary parameters and then calls the save method.
     * The test asserts that an IllegalArgumentException is thrown.
     */
    @Test
    void saveWhenAuthorizationNullThrowsException() {
        authorizationService = new AuthorizationService(authorizationRepository,
            registeredClientRepository);
        OAuth2Authorization authorization = null;
        assertThrows(IllegalArgumentException.class, () -> authorizationService.save(authorization));
    }

    /**
     * This test method tests the scenario where an attempt to remove a null authorization throws an exception.
     * It sets up the necessary parameters and then calls the remove method.
     * The test asserts that an IllegalArgumentException is thrown.
     */
    @Test
    void removeWhenAuthorizationNullThrowsException() {
        authorizationService = new AuthorizationService(authorizationRepository,
            registeredClientRepository);
        OAuth2Authorization authorization = null;
        assertThrows(IllegalArgumentException.class, () -> authorizationService.remove(authorization));

    }

    /**
     * This test method tests the scenario where an attempt to find an authorization by a null ID throws an exception.
     * It sets up the necessary parameters and then calls the findById method.
     * The test asserts that an IllegalArgumentException is thrown.
     */
    @Test
    void findByIdWhenAuthorizationNullThrowsException() {
        authorizationService = new AuthorizationService(authorizationRepository,
            registeredClientRepository);
        String id = "";
        assertThrows(IllegalArgumentException.class, () -> authorizationService.findById(id));
    }

    /**
     * This test method tests the scenario where an attempt to find an authorization by an ID that is not present
     * returns null.
     * It sets up the necessary parameters and then calls the findById method.
     * The test asserts that the returned authorization is null.
     */
    @Test
    void findByIdReturnNullWhenIdNotPresent() {
        authorizationService = new AuthorizationService(authorizationRepository,
            registeredClientRepository);
        OAuth2Authorization authorization = this.authorizationService.findById("1");
        assertNull(authorization);

    }

    /**
     * This test method tests the scenario where an attempt to find an authorization by a token that does not exist
     * returns null.
     * It sets up the necessary parameters and then calls the findByToken method.
     * The test asserts that the returned authorization is null.
     */
    @Test
    void findByTokenReturnNullWhenTokenNotExist() {
        authorizationService = new AuthorizationService(authorizationRepository,
            registeredClientRepository);

        OAuth2TokenType oauth2TokenType = OAuth2TokenType.ACCESS_TOKEN;
        String dummyToken = DUMMY_TOKEN;
        OAuth2Authorization authorization = this.authorizationService.findByToken(dummyToken, oauth2TokenType);
        assertNull(authorization);
    }

    /**
     * This test method tests the scenario where a new authorization is saved successfully.
     * It sets up the necessary parameters and then calls the save method.
     * The test asserts that the returned authorization is not null and the ID is as expected.
     */
    @Test
    void saveWhenAuthorizationNewThenSaved() {
        authorizationService = new AuthorizationService(authorizationRepository,
            registeredClientRepository);
        when(this.registeredClientRepository.findById(Mockito.anyString()))
            .thenReturn(REGISTERED_CLIENT);
        Authorization expAuthorization = createAuthorization();
        OAuth2Authorization expectedAuthorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
            .id(ID)
            .principalName(PRINCIPAL_NAME)
            .authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
            //  .token(AUTHORIZATION_CODE)
            .build();
        when(this.authorizationRepository.findById(Mockito.anyString()))
            .thenReturn(Optional.of(expAuthorization));

        this.authorizationService.save(expectedAuthorization);

        OAuth2Authorization authorization = this.authorizationService.findById(ID);
        assert authorization != null;
        assertThat(authorization.getId()).isEqualTo(expectedAuthorization.getId());
    }

    /**
     * This test method tests the scenario where an authorization with an access token is saved successfully.
     * It sets up the necessary parameters and then calls the save method.
     * The test asserts that the returned authorization is not null and the ID is as expected.
     */
    @Test
    void saveWhenAccessTokenInAuthorizationThenSaved() {

        authorizationService = new AuthorizationService(authorizationRepository,
            registeredClientRepository);
        when(this.registeredClientRepository.findById(Mockito.anyString()))
            .thenReturn(REGISTERED_CLIENT);
        Authorization expAuthorization = createAccTokenAuthorization();

        OAuth2Authorization expectedAuthorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
            .id(ID)
            .principalName(PRINCIPAL_NAME)
            .authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
            //  .token(AUTHORIZATION_CODE)
            .build();
        when(this.authorizationRepository.findById(Mockito.anyString()))
            .thenReturn(Optional.of(expAuthorization));

        this.authorizationService.save(expectedAuthorization);

        OAuth2Authorization authorization = this.authorizationService.findById(ID);
        assert authorization != null;
        assertThat(authorization.getId()).isEqualTo(expectedAuthorization.getId());
    }

    /**
     * This test method tests the scenario where an authorization with a refresh token is saved successfully.
     * It sets up the necessary parameters and then calls the save method.
     * The test asserts that the returned authorization is not null and the ID is as expected.
     */
    @Test
    void saveWhenRefreshTokenInAuthorizationThenSaved() {

        authorizationService = new AuthorizationService(authorizationRepository,
            registeredClientRepository);
        when(this.registeredClientRepository.findById(Mockito.anyString()))
            .thenReturn(REGISTERED_CLIENT);
        Authorization expAuthorization = createRefreshTokenAuthorization();
        OAuth2Authorization expectedAuthorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
            .id(ID)
            .principalName(PRINCIPAL_NAME)
            .authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
            //  .token(AUTHORIZATION_CODE)
            .build();
        when(this.authorizationRepository.findById(Mockito.anyString()))
            .thenReturn(Optional.of(expAuthorization));

        this.authorizationService.save(expectedAuthorization);

        OAuth2Authorization authorization = this.authorizationService.findById(ID);
        assert authorization != null;
        assertThat(authorization.getId()).isEqualTo(expectedAuthorization.getId());
    }

    /**
     * This test method tests the scenario where an attempt to find an authorization by a wrong token type returns null.
     * It sets up the necessary parameters and then calls the findByToken method.
     * The test asserts that the returned authorization is null.
     */
    @Test
    void findByTokenWhenWrongTokenTypeThenNotFound() {
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token",
            Instant.now().truncatedTo(ChronoUnit.MILLIS));
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
            .id(ID)
            .principalName(PRINCIPAL_NAME)
            .authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
            .refreshToken(refreshToken)
            .build();
        this.authorizationService.save(authorization);

        OAuth2Authorization result = this.authorizationService.findByToken(
            refreshToken.getTokenValue(), OAuth2TokenType.ACCESS_TOKEN);
        assertThat(result).isNull();
    }

    /**
     * This test method tests the scenario where an authorization is found successfully by a device code.
     * It sets up the necessary parameters and then calls the findByToken method.
     * The test asserts that the returned authorization is not null and the ID is as expected.
     */
    @Test
    void findByTokenWhenDeviceCodeExistsThenFound() {
        authorizationService = new AuthorizationService(authorizationRepository,
            registeredClientRepository);
        when(this.registeredClientRepository.findById(Mockito.anyString()))
            .thenReturn(REGISTERED_CLIENT);
        OAuth2DeviceCode deviceCode = new OAuth2DeviceCode("device-code",
            Instant.now().truncatedTo(ChronoUnit.MILLIS),
            Instant.now().plus(AMOUNT_TO_ADD, ChronoUnit.MINUTES).truncatedTo(ChronoUnit.MILLIS));
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
            .id(ID)
            .principalName(PRINCIPAL_NAME)
            .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
            .token(deviceCode)
            .build();
        this.authorizationService.save(authorization);
        when(this.authorizationRepository.findByDeviceCodeValue(Mockito.anyString()))
            .thenReturn(Optional.of(createDeviceCodeAuthorization()));
        OAuth2Authorization result = this.authorizationService.findByToken(
            deviceCode.getTokenValue(), new OAuth2TokenType(OAuth2ParameterNames.DEVICE_CODE));
        assert result != null;
        assertThat(authorization.getId()).isEqualTo(result.getId());
    }

    /**
     * This test method tests the scenario where an authorization is found successfully by a user code.
     * It sets up the necessary parameters and then calls the findByToken method.
     * The test asserts that the returned authorization is not null and the ID is as expected.
     */
    @Test
    void findByTokenWhenUserCodeExistsThenFound() {
        authorizationService = new AuthorizationService(authorizationRepository,
            registeredClientRepository);
        when(this.registeredClientRepository.findById(Mockito.anyString()))
            .thenReturn(REGISTERED_CLIENT);
        OAuth2UserCode userCode = new OAuth2UserCode("user-code",
            Instant.now().truncatedTo(ChronoUnit.MILLIS),
            Instant.now().plus(AMOUNT_TO_ADD, ChronoUnit.MINUTES).truncatedTo(ChronoUnit.MILLIS));
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
            .id(ID)
            .principalName(PRINCIPAL_NAME)
            .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
            .token(userCode)
            .build();
        this.authorizationService.save(authorization);

        when(this.authorizationRepository.findByUserCodeValue(Mockito.anyString()))
            .thenReturn(Optional.of(createUserCodeAuthorization()));
        OAuth2Authorization result = this.authorizationService.findByToken(
            userCode.getTokenValue(), new OAuth2TokenType(OAuth2ParameterNames.USER_CODE));
        assert result != null;
        assertThat(authorization.getId()).isEqualTo(result.getId());
    }

    /**
     * This test method tests the scenario where an authorization is found successfully by an ID token.
     * It sets up the necessary parameters and then calls the findByToken method.
     * The test asserts that the returned authorization is not null and the ID is as expected.
     */
    @Test
    void findByTokenWhenIdTokenExistsThenFound() {
        authorizationService = new AuthorizationService(authorizationRepository,
            registeredClientRepository);
        when(this.registeredClientRepository.findById(Mockito.anyString()))
            .thenReturn(REGISTERED_CLIENT);
        OidcIdToken idToken =  OidcIdToken.withTokenValue("id-token")
            .issuer("https://localhost.com")
            .subject("subject")
            .issuedAt(Instant.now().minusSeconds(AMOUNT_TO_ADD1).truncatedTo(ChronoUnit.MILLIS))
            .expiresAt(Instant.now().truncatedTo(ChronoUnit.MILLIS))
            .build();
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
            .id(ID)
            .principalName(PRINCIPAL_NAME)
            .authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
            .token(idToken, metadata ->
                metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()))
            .build();
        this.authorizationService.save(authorization);
        when(this.authorizationRepository.findByOidcIdTokenValue(Mockito.anyString()))
            .thenReturn(Optional.of(createAuthorization()));

        OAuth2Authorization result = this.authorizationService.findByToken(
            idToken.getTokenValue(), new OAuth2TokenType(OidcParameterNames.ID_TOKEN));
        assert result != null;
        assertThat(authorization.getId()).isEqualTo(result.getId());

    }


}