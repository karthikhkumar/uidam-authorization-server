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

package org.eclipse.ecsp.oauth2.server.core.authentication.handlers;

import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.service.DatabaseSecurityContextRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.ATTRIBUTE_SUB;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.REGISTRATION_ID_GOOGLE;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.SECONDS_TO_ADD;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.STATE;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_ACCOUNT_NAME;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_CLIENT_ID;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_PASSWORD;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_USER_NAME;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.URI;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.VALID_URI;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * This class tests the functionality of the CustomAuthCodeSuccessHandler.
 */
class CustomAuthCodeSuccessHandlerTest {

    private CustomAuthCodeSuccessHandler successHandler;
    @Mock
    DatabaseSecurityContextRepository databaseSecurityContextRepository;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    /**
     * This method sets up the test environment before each test.
     * It initializes the CustomAuthCodeSuccessHandler and the mock HttpServletRequest and HttpServletResponse.
     */
    @BeforeEach
    void setUp() {
        this.databaseSecurityContextRepository = mock(DatabaseSecurityContextRepository.class);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        successHandler = new CustomAuthCodeSuccessHandler(databaseSecurityContextRepository, true);
    }

    /**
     * This method tests the scenario where the authentication is successful.
     * It sets up the necessary parameters and then calls the onAuthenticationSuccess method.
     * The test asserts that no exception is thrown and that the unauthenticatedContextInDb method of the
     * DatabaseSecurityContextRepository is called once.
     */
    @Test
     void testOnAuthenticationSuccess() {
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME,
                TEST_PASSWORD, TEST_ACCOUNT_NAME, null);
        WebAuthenticationDetails webAuthenticationDetails = new WebAuthenticationDetails("", "");
        principal.setDetails(webAuthenticationDetails);
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                "code", Instant.now(), Instant.now().plusSeconds(SECONDS_TO_ADD));
        OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken =
                new OAuth2AuthorizationCodeRequestAuthenticationToken(URI, TEST_CLIENT_ID, principal, authorizationCode,
                        VALID_URI, STATE, null);
        assertDoesNotThrow(() -> this.successHandler.onAuthenticationSuccess(this.request, this.response,
                authenticationToken));
        verify(databaseSecurityContextRepository, times(1)).unauthenticatedContextInDb(anyString());
    }

    @Test
    void testOnAuthenticationInvalidRedirectUri() {
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME,
                TEST_PASSWORD, TEST_ACCOUNT_NAME, null);
        WebAuthenticationDetails webAuthenticationDetails = new WebAuthenticationDetails("", "");
        principal.setDetails(webAuthenticationDetails);
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                "code", Instant.now(), Instant.now().plusSeconds(SECONDS_TO_ADD));
        OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken =
                new OAuth2AuthorizationCodeRequestAuthenticationToken(URI, TEST_CLIENT_ID, principal, authorizationCode,
                        URI, STATE, null);
        assertDoesNotThrow(() -> this.successHandler.onAuthenticationSuccess(this.request, this.response,
                authenticationToken));
    }

    /**
     * This method tests the scenario when authenticating with an external identity provider (IdP).
     * It sets up the necessary parameters and then calls the onAuthenticationSuccess method.
     * The test asserts that no exception is thrown and that the unauthenticatedContextInDb method of the
     * DatabaseSecurityContextRepository is called once.
     */
    @Test
    void testOnAuthenticationSuccessExternalIdp() {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);
        OAuth2AuthenticationToken principal = new OAuth2AuthenticationToken(oauth2User, null,
            REGISTRATION_ID_GOOGLE);
        WebAuthenticationDetails webAuthenticationDetails = new WebAuthenticationDetails("", "");
        principal.setDetails(webAuthenticationDetails);
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
            "code", Instant.now(), Instant.now().plusSeconds(SECONDS_TO_ADD));
        OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken =
            new OAuth2AuthorizationCodeRequestAuthenticationToken(URI, TEST_CLIENT_ID, principal, authorizationCode,
                VALID_URI, STATE, null);
        assertDoesNotThrow(() -> this.successHandler.onAuthenticationSuccess(this.request, this.response,
            authenticationToken));
        verify(databaseSecurityContextRepository, times(1)).unauthenticatedContextInDb(anyString());
    }

    /**
     * This method tests the scenario when the redirect URI is null.
     * It sets up the necessary parameters and then calls the onAuthenticationSuccess method.
     * The test asserts that no exception is thrown and that the unauthenticatedContextInDb method of the
     * DatabaseSecurityContextRepository is not called.
     */
    @Test
    void testOnAuthenticationNullRedirectUri() {
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME,
            TEST_PASSWORD, TEST_ACCOUNT_NAME, null);
        WebAuthenticationDetails webAuthenticationDetails = new WebAuthenticationDetails("", "");
        principal.setDetails(webAuthenticationDetails);
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
            "code", Instant.now(), Instant.now().plusSeconds(SECONDS_TO_ADD));
        OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken =
            new OAuth2AuthorizationCodeRequestAuthenticationToken(URI, TEST_CLIENT_ID, principal, authorizationCode,
                null, STATE, null);
        assertDoesNotThrow(() -> this.successHandler.onAuthenticationSuccess(this.request, this.response,
            authenticationToken));
        verify(databaseSecurityContextRepository, times(0)).unauthenticatedContextInDb(anyString());
    }

}