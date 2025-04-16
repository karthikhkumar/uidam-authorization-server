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
import org.eclipse.ecsp.oauth2.server.core.common.CustomOauth2ErrorResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.io.IOException;

import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.RESPONSE_STATUS_CODE_UNAUTHORIZED;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * This class tests the functionality of the CustomAccessTokenFailureHandler.
 */
class CustomAccessTokenFailureHandlerTest {

    private CustomAccessTokenFailureHandler failureHandler;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    /**
     * This method sets up the test environment before each test.
     * It initializes the CustomAccessTokenFailureHandler and the mock HttpServletRequest and HttpServletResponse.
     */
    @BeforeEach
    void setUp() {
        failureHandler = new CustomAccessTokenFailureHandler();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    /**
     * This method tests the scenario where the authentication fails due to an invalid token.
     * It sets up the necessary parameters and then calls the onAuthenticationFailure method.
     * The test asserts that the response status code and content are as expected.
     */
    @Test
     void testOnAuthenticationFailureForInvalidToken() throws IOException, ServletException {
        OAuth2AuthenticationException validationException = createValidationException();
        failureHandler.onAuthenticationFailure(request, response, validationException);

        // Assert that the response status code is set correctly
        assertEquals(RESPONSE_STATUS_CODE_UNAUTHORIZED, response.getStatus());

        // Assert that the response content is as expected
        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        CustomOauth2ErrorResponse expectedErrorResponse = CustomOauth2ErrorResponse.builder()
                .error("INVALID_TOKEN")
                .errorCode("TG-008")
                .errorDescription("Token is invalid")
                .build();
        CustomOauth2ErrorResponse
            actualResponse = objectMapper.readValue(response.getContentAsString(), CustomOauth2ErrorResponse.class);
        assertEquals(expectedErrorResponse.errorCode(), actualResponse.errorCode());
        assertEquals(expectedErrorResponse.error(), actualResponse.error());
        assertEquals(expectedErrorResponse.errorDescription(), actualResponse.errorDescription());
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
     * This method creates an OAuth2AuthenticationException for an invalid token.
     *
     * @return An OAuth2AuthenticationException with an OAuth2Error for an invalid token.
     */
    private OAuth2AuthenticationException createValidationException() {
        OAuth2Error error = new OAuth2Error(
                OAuth2ErrorCodes.INVALID_TOKEN,
                "Invalid access token",
                "https://example.com/error"
        );

        return new OAuth2AuthenticationException(error, "");
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

        return new OAuth2AuthenticationException(error, "OAuth 2.0 Parameter: client_id");
    }
}