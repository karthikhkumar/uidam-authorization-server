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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.ServletException;
import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.common.CustomOauth2ErrorResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;

import java.io.IOException;

import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.BAD_REQUEST;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.INVALID_CLIENT;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.RESPONSE_STATUS_CODE_UNAUTHORIZED;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.STATE;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_ACCOUNT_NAME;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_CLIENT_ID;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_PASSWORD;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_USER_NAME;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.URI;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * This class tests the functionality of the CustomAuthCodeFailureHandler.
 */
class CustomAuthCodeFailureHandlerTest {

    private CustomAuthCodeFailureHandler failureHandler;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    /**
     * This method sets up the test environment before each test.
     * It initializes the CustomAuthCodeFailureHandler and the mock HttpServletRequest and HttpServletResponse.
     */
    @BeforeEach
    void setUp() {
        failureHandler = new CustomAuthCodeFailureHandler();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    /**
     * This method tests the scenario where the authentication fails due to an invalid scope.
     * It sets up the necessary parameters and then calls the onAuthenticationFailure method.
     * The test asserts that the response error message is null.
     */
    @Test
     void testOnAuthenticationFailureForInvalidScope() throws IOException, ServletException {
        OAuth2AuthenticationException validationException = createValidationException();
        failureHandler.onAuthenticationFailure(request, response, validationException);
        assertNull(response.getErrorMessage());
    }

    /**
     * This method tests the scenario where the authentication fails due to an invalid client.
     * It sets up the necessary parameters and then calls the onAuthenticationFailure method.
     * The test asserts that the response status code and content are as expected.
     */
    @Test
     void testOnAuthenticationFailureForInvalidClient() throws IOException, ServletException {
        OAuth2AuthenticationException validationException = createValidationExceptionForInvalidClient();
        failureHandler.onAuthenticationFailure(request, response, validationException);

        // Assert that the response status code is set correctly
        assertEquals(RESPONSE_STATUS_CODE_UNAUTHORIZED, response.getStatus());

        // Assert that the response content is as expected
        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        CustomOauth2ErrorResponse expectedErrorResponse = CustomOauth2ErrorResponse.builder()
                .error(INVALID_CLIENT)
                .errorCode("TG-002")
                .errorDescription("Request Client Is Invalid")
                .build();
        CustomOauth2ErrorResponse
            actualResponse = objectMapper.readValue(response.getContentAsString(), CustomOauth2ErrorResponse.class);
        assertEquals(expectedErrorResponse.errorCode(), actualResponse.errorCode());
        assertEquals(expectedErrorResponse.error(), actualResponse.error());
        assertEquals(expectedErrorResponse.errorDescription(), actualResponse.errorDescription());
    }

    /**
     * This method tests the scenario where the authentication fails due to an invalid request client error.
     * It sets up the necessary parameters and then calls the onAuthenticationFailure method.
     * The test asserts that the response status code and content are as expected.
     */
    @Test
    void testOnAuthenticationFailureForInvalidRequestClientError() throws IOException, ServletException {
        OAuth2AuthenticationException validationException = createValidationExceptionForInvalidRequestClientError();
        failureHandler.onAuthenticationFailure(request, response, validationException);

        // Assert that the response status code is set correctly
        assertEquals(RESPONSE_STATUS_CODE_UNAUTHORIZED, response.getStatus());

        // Assert that the response content is as expected
        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        CustomOauth2ErrorResponse expectedErrorResponse = CustomOauth2ErrorResponse.builder()
            .error("INVALID_CLIENT")
            .errorCode("TG-002")
            .errorDescription("Request Client Is Invalid")
            .build();
        CustomOauth2ErrorResponse
            actualResponse = objectMapper.readValue(response.getContentAsString(), CustomOauth2ErrorResponse.class);
        assertEquals(expectedErrorResponse.errorCode(), actualResponse.errorCode());
        assertEquals(expectedErrorResponse.error(), actualResponse.error());
        assertEquals(expectedErrorResponse.errorDescription(), actualResponse.errorDescription());
    }

    /**
     * This method tests the scenario where the authentication fails due to an invalid request redirect error.
     * It sets up the necessary parameters and then calls the onAuthenticationFailure method.
     * The test asserts that the response status code and content are as expected.
     */
    @Test
    void testOnAuthenticationFailureForInvalidRequestRedirectError() throws IOException, ServletException {
        OAuth2AuthenticationException validationException = createValidationExceptionForInvalidRequestRedirectError();
        failureHandler.onAuthenticationFailure(request, response, validationException);

        // Assert that the response status code is set correctly
        assertEquals(BAD_REQUEST, response.getStatus());

        // Assert that the response content is as expected
        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        CustomOauth2ErrorResponse expectedErrorResponse = CustomOauth2ErrorResponse.builder()
            .error("INVALID_REDIRECT_URI")
            .errorCode("TG-014")
            .errorDescription("Redirect URI is invalid")
            .build();
        CustomOauth2ErrorResponse
            actualResponse = objectMapper.readValue(response.getContentAsString(), CustomOauth2ErrorResponse.class);
        assertEquals(expectedErrorResponse.errorCode(), actualResponse.errorCode());
        assertEquals(expectedErrorResponse.error(), actualResponse.error());
        assertEquals(expectedErrorResponse.errorDescription(), actualResponse.errorDescription());
    }

    /**
     * This method creates an OAuth2AuthenticationException for an invalid scope.
     *
     * @return An OAuth2AuthenticationException with an OAuth2Error for an invalid scope.
     */
    private OAuth2AuthenticationException createValidationException() {
        OAuth2Error error = new OAuth2Error(
                OAuth2ErrorCodes.INVALID_SCOPE,
                "Invalid scope",
                "https://example.com/error"
        );

        CustomUserPwdAuthenticationToken authentication = new CustomUserPwdAuthenticationToken(TEST_USER_NAME,
                TEST_PASSWORD, TEST_ACCOUNT_NAME, null);
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationToken =
                new OAuth2AuthorizationCodeRequestAuthenticationToken(URI, TEST_CLIENT_ID, authentication, URI,
                        STATE, null, null);
        return new OAuth2AuthorizationCodeRequestAuthenticationException(error,
                authorizationCodeRequestAuthenticationToken);
    }

    /**
     * This method creates an OAuth2AuthenticationException for an invalid client.
     *
     * @return An OAuth2AuthenticationException with an OAuth2Error for an invalid client.
     */
    private OAuth2AuthenticationException createValidationExceptionForInvalidClient() {
        OAuth2Error error = new OAuth2Error(
                OAuth2ErrorCodes.INVALID_CLIENT,
                "Invalid client",
                "https://example.com/error"
        );

        return new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }

    /**
     * This method creates an OAuth2AuthenticationException for an invalid request client error.
     *
     * @return An OAuth2AuthenticationException with an OAuth2Error for an invalid request client error.
     */
    private OAuth2AuthenticationException createValidationExceptionForInvalidRequestClientError() {
        OAuth2Error error = new OAuth2Error(
            OAuth2ErrorCodes.INVALID_REQUEST,
            "OAuth 2.0 Parameter: client_id",
            "https://example.com/error"
        );

        return new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }

    /**
     * This method creates an OAuth2AuthenticationException for an invalid request redirect error.
     *
     * @return An OAuth2AuthenticationException with an OAuth2Error for an invalid request redirect error.
     */
    private OAuth2AuthenticationException createValidationExceptionForInvalidRequestRedirectError() {
        OAuth2Error error = new OAuth2Error(
            OAuth2ErrorCodes.INVALID_REQUEST,
            "OAuth 2.0 Parameter: redirect_uri",
            "https://example.com/error"
        );

        return new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }

}