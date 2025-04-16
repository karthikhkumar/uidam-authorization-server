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

package org.eclipse.ecsp.oauth2.server.core.utils;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * This class tests the functionality of the CustomOauth2ErrorMessage class.
 */
class CustomOauth2ErrorMessageTest {

    private MockHttpServletResponse response;

    /**
     * This method sets up the test environment before each test.
     * It initializes the MockHttpServletResponse object.
     */
    @BeforeEach
    void setUp() {
        response = new MockHttpServletResponse();
    }

    /**
     * This test method tests the setCustomErrorMessage method of the CustomOauth2ErrorMessage class with an
     * OAuth2AuthenticationException for an invalid client.
     * It asserts that the returned string is not null.
     */
    @Test
    void testSetCustomErrorMessageForInvalidClient() {
        OAuth2AuthenticationException validationException = createValidationExceptionForInvalidClient();
        assertNotNull(CustomOauth2ErrorMessage.setCustomErrorMessage(validationException, response));
    }

    /**
     * This test method tests the setCustomErrorMessage method of the CustomOauth2ErrorMessage class with an
     * OAuth2AuthenticationException for an invalid request.
     * It asserts that the returned string is not null.
     */
    @Test
    void testSetCustomErrorMessageForInvalidRequest() {
        OAuth2AuthenticationException validationException = createValidationExceptionForInvalidRequest();
        assertNotNull(CustomOauth2ErrorMessage.setCustomErrorMessage(validationException, response));
    }

    /**
     * This test method tests the setCustomErrorMessage method of the CustomOauth2ErrorMessage class with a null
     * exception.
     * It asserts that the returned string is not null.
     */
    @Test
    void testSetCustomErrorMessageExceptionNull() {
        assertNotNull(CustomOauth2ErrorMessage.setCustomErrorMessage(null, response));
    }

    /**
     * This method creates an OAuth2AuthenticationException for an invalid client.
     *
     * @return OAuth2AuthenticationException for an invalid client.
     */
    private OAuth2AuthenticationException createValidationExceptionForInvalidClient() {
        OAuth2Error error = new OAuth2Error(
                OAuth2ErrorCodes.INVALID_CLIENT,
                "Invalid client",
                "https://example.com/error"
        );

        return new OAuth2AuthenticationException(error, "");
    }

    /**
     * This method creates an OAuth2AuthenticationException for an invalid request.
     *
     * @return OAuth2AuthenticationException for an invalid request.
     */
    private OAuth2AuthenticationException createValidationExceptionForInvalidRequest() {
        OAuth2Error error = new OAuth2Error(
                OAuth2ErrorCodes.INVALID_REQUEST,
                "OAuth 2.0 Parameter: client_id",
                "https://example.com/error"
        );

        return new OAuth2AuthenticationException(error, "OAuth 2.0 Parameter: client_id");
    }

}