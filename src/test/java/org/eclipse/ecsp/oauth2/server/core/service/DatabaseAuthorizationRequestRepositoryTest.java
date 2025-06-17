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

import org.eclipse.ecsp.oauth2.server.core.entities.AuthorizationRequest;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationRequestRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;

import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.EXTERNAL_IDP_ADDITIONAL_PARAMETERS;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.EXTERNAL_IDP_ATTRIBUTES;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.REGISTRATION_ID_GOOGLE;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.REQUESTED_SESSION_ID;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.STATE;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_CLIENT_ID;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.URI;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * This class tests the functionality of the DatabaseAuthorizationRequestRepository.
 */
class DatabaseAuthorizationRequestRepositoryTest {

    DatabaseAuthorizationRequestRepository databaseAuthorizationRequestRepository;
    @Mock
    AuthorizationRequestRepository authorizationRequestRepository;
    @Mock
    private ClientRegistrationRepository clientRegistrationRepository;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    /**
     * This method sets up the test environment before each test.
     * It initializes the mocks.
     */
    @BeforeEach
    void setUp() {
        this.authorizationRequestRepository = mock(AuthorizationRequestRepository.class);
        this.clientRegistrationRepository = mock(ClientRegistrationRepository.class);
        request = new MockHttpServletRequest();
        request.setRequestedSessionId(REQUESTED_SESSION_ID);
        // Create a MockHttpSession
        MockHttpSession session = new MockHttpSession() {
            @Override
            public String getId() {
                return REQUESTED_SESSION_ID; // Return your desired session ID
            }
        };

        // Attach the session to the request
        request.setSession(session);
        response = new MockHttpServletResponse();
        databaseAuthorizationRequestRepository = new DatabaseAuthorizationRequestRepository(
            authorizationRequestRepository, clientRegistrationRepository);
    }

    /**
     * This test method tests the loadAuthorizationRequest method of the DatabaseAuthorizationRequestRepository.
     * It asserts that the returned value is not null.
     */
    @Test
    void loadAuthorizationRequestSuccess() {
        findBySessionIdMock();
        findByRegistrationIdMock();
        OAuth2AuthorizationRequest oauth2AuthorizationRequest = databaseAuthorizationRequestRepository
            .loadAuthorizationRequest(request);
        assertNotNull(oauth2AuthorizationRequest);
    }

    /**
     * This test method tests the loadAuthorizationRequest method of the DatabaseAuthorizationRequestRepository
     * where no OAuth2AuthorizationRequest is found.
     * It asserts that the returned value is null.
     */
    @Test
    void loadAuthorizationRequestNullAuthorizationRequest() {
        OAuth2AuthorizationRequest oauth2AuthorizationRequest = databaseAuthorizationRequestRepository
            .removeAuthorizationRequest(request, response);
        assertNull(oauth2AuthorizationRequest);
    }

    /**
     * This test method tests the saveAuthorizationRequest method.
     * It asserts that no exception is thrown and the save method of the AuthorizationRequestRepository is called once.
     */
    @Test
    void saveAuthorizationRequestSuccess() {
        OAuth2AuthorizationRequest oauth2AuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri(URI).clientId(TEST_CLIENT_ID).redirectUri(URI).state(STATE).authorizationRequestUri(URI)
            .build();
        assertDoesNotThrow(() -> databaseAuthorizationRequestRepository
            .saveAuthorizationRequest(oauth2AuthorizationRequest, request, response));
        verify(authorizationRequestRepository, times(1)).save(any());
    }


    /**
     * This test method tests the saveAuthorizationRequest method when an existing session is found.
     * It asserts that no exception is thrown and the save method of the AuthorizationRequestRepository is called once.
     */
    @Test
    void saveAuthorizationRequestUpdate() {
        findBySessionIdMock();
        OAuth2AuthorizationRequest oauth2AuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri(URI).clientId(TEST_CLIENT_ID).redirectUri(URI).state(STATE).authorizationRequestUri(URI)
            .build();
        assertDoesNotThrow(() -> databaseAuthorizationRequestRepository
            .saveAuthorizationRequest(oauth2AuthorizationRequest, request, response));
        verify(authorizationRequestRepository, times(1)).save(any());
    }

    /**
     * This helper method sets up the necessary parameters for the findBySessionId method.
     * It creates an AuthorizationRequest and sets its properties based on the provided parameters.
     * The method then mocks the findBySessionId method of the AuthorizationRequestRepository to return the created
     * AuthorizationRequest.
     */
    void findBySessionIdMock() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest();
        authorizationRequest.setState(STATE);
        authorizationRequest.setAdditionalParameters(EXTERNAL_IDP_ADDITIONAL_PARAMETERS);
        authorizationRequest.setAuthorizationRequestUri(URI);
        authorizationRequest.setAttributes(EXTERNAL_IDP_ATTRIBUTES);
        authorizationRequest.setSessionId(REQUESTED_SESSION_ID);
        Timestamp currentTimestamp = Timestamp.from(Instant.now());
        authorizationRequest.setCreatedDate(currentTimestamp);
        when(authorizationRequestRepository.findBySessionId(REQUESTED_SESSION_ID)).thenReturn(
            Optional.of(authorizationRequest));
    }

    /**
     * This helper method sets up the necessary parameters for the findByRegistrationId method.
     * It creates an ClientRegistration and sets its properties based on the provided parameters.
     * The method then mocks the findByRegistrationId method of the ClientRegistrationRepository to return the
     * created ClientRegistration.
     */
    void findByRegistrationIdMock() {
        ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID_GOOGLE)
            .clientId(TEST_CLIENT_ID).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(URI).authorizationUri(URI).tokenUri(URI).build();
        when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID_GOOGLE)).thenReturn(clientRegistration);
    }

}