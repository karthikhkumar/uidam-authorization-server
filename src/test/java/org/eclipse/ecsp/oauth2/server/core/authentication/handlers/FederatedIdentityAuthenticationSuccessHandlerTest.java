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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * This class tests the functionality of the FederatedIdentityAuthenticationSuccessHandler.
 */
class FederatedIdentityAuthenticationSuccessHandlerTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private OAuth2AuthenticationToken authentication;

    @Mock
    private OAuth2User oauth2User;

    private FederatedIdentityAuthenticationSuccessHandler handler;

    /**
     * This method sets up the test environment before each test.
     * It initializes the FederatedIdentityAuthenticationSuccessHandler and opens the mocks.
     */
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        handler = new FederatedIdentityAuthenticationSuccessHandler();
    }

    /**
     * This method tests the scenario where the authentication is successful.
     * It sets up the necessary parameters and then calls the onAuthenticationSuccess method.
     * The test asserts that the getPrincipal method of the authentication is called once.
     */
    @Test
    void onAuthenticationSuccess() throws Exception {
        when(authentication.getPrincipal()).thenReturn(oauth2User);
        handler.onAuthenticationSuccess(request, response, authentication);
        verify(authentication, times(1)).getPrincipal();
    }
}