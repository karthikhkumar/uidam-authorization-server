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

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.ecsp.oauth2.server.core.entities.AuthorizationRequest;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationRequestRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.Assert;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.eclipse.ecsp.oauth2.server.core.utils.ObjectMapperUtils.parseMap;
import static org.eclipse.ecsp.oauth2.server.core.utils.ObjectMapperUtils.writeMap;

/**
 * A AuthorizationRequestRepository implementation which stores the AuthorizationRequest entities in the Database.
 * This class is responsible for managing the OAuth2AuthorizationRequest entities for each session.
 */
public class DatabaseAuthorizationRequestRepository implements
    org.springframework.security.oauth2.client.web.AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseAuthorizationRequestRepository.class);

    private final AuthorizationRequestRepository authorizationRequestRepository;

    private ClientRegistrationRepository clientRegistrationRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * This is a parameterized constructor for the DatabaseAuthorizationRequestRepository class.
     * It initializes the AuthorizationRequestRepository and ClientRegistrationRepository instance.
     * It also registers the security modules with the ObjectMapper.
     *
     * @param authorizationRequestRepository an instance of AuthorizationRequestRepository, used to interact with the
     *                                       AuthorizationRequest entities stored in the database
     * @param clientRegistrationRepository an instance of ClientRegistrationRepository, used to interact with the client
     *                                     registration entities stored
     */
    public DatabaseAuthorizationRequestRepository(AuthorizationRequestRepository authorizationRequestRepository,
                                                  ClientRegistrationRepository clientRegistrationRepository) {
        Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
        Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
        this.authorizationRequestRepository = authorizationRequestRepository;
        this.clientRegistrationRepository = clientRegistrationRepository;

        ClassLoader classLoader = DatabaseAuthorizationRequestRepository.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.objectMapper.registerModules(securityModules);
    }

    /**
     * This method is used to load the OAuth2AuthorizationRequest for a given HttpServletRequest.
     * If an authorization request is found, it is reconstructed from the stored data and returned.
     *
     * @param request the HttpServletRequest
     * @return the OAuth2AuthorizationRequest for the request, or null if none exists
     */
    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        String requestedSessionId = request.getRequestedSessionId();
        LOGGER.info("Retrieving Authorization Request for Session Id: {}", requestedSessionId);
        AuthorizationRequest authorizationRequest = getAuthorizationRequestFromDb(requestedSessionId);
        if (authorizationRequest == null) {
            LOGGER.debug("Did not find Authorization Request in Database for Session Id: {}", requestedSessionId);
            return null;
        }
        Map<String, Object> additionalParameters = new HashMap<>(parseMap(this.objectMapper,
            authorizationRequest.getAdditionalParameters()));
        Map<String, Object> attributes = new HashMap<>(parseMap(this.objectMapper,
            authorizationRequest.getAttributes()));
        String registrationId = attributes.get("registration_id") + "";
        ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
        OAuth2AuthorizationRequest oauth2AuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
            .clientId(clientRegistration.getClientId()).redirectUri(clientRegistration.getRedirectUri())
            .scopes(clientRegistration.getScopes()).state(authorizationRequest.getState())
            .additionalParameters(additionalParameters)
            .authorizationRequestUri(authorizationRequest.getAuthorizationRequestUri()).attributes(attributes)
            .build();
        LOGGER.debug("Retrieved Authorization Request: {}", oauth2AuthorizationRequest);
        return oauth2AuthorizationRequest;
    }

    /**
     * This method is used to save the OAuth2AuthorizationRequest for a given HttpServletRequest and
     * HttpServletResponse.
     * If an AuthorizationRequest associated with the session ID does not exist in the database, a new
     * AuthorizationRequest object is created. Otherwise, the existing AuthorizationRequest is updated.
     *
     * @param oauth2AuthorizationRequest the OAuth2AuthorizationRequest
     * @param request the HttpServletRequest
     * @param response the HttpServletResponse
     */
    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest oauth2AuthorizationRequest,
                                         HttpServletRequest request, HttpServletResponse response) {
        String requestedSessionId = request.getRequestedSessionId();
        LOGGER.info("Storing Authorization Request to Database for Session Id: {}", requestedSessionId);
        Timestamp currentTimestamp = Timestamp.from(Instant.now());
        AuthorizationRequest authorizationRequest = getAuthorizationRequestFromDb(requestedSessionId);
        if (authorizationRequest == null) {
            authorizationRequest = new AuthorizationRequest();
            authorizationRequest.setSessionId(requestedSessionId);
            authorizationRequest.setCreatedDate(currentTimestamp);
        } else {
            authorizationRequest.setUpdatedDate(currentTimestamp);
        }
        authorizationRequest.setState(oauth2AuthorizationRequest.getState());
        authorizationRequest.setAdditionalParameters(writeMap(this.objectMapper,
            oauth2AuthorizationRequest.getAdditionalParameters()));
        authorizationRequest.setAuthorizationRequestUri(oauth2AuthorizationRequest.getAuthorizationRequestUri());
        authorizationRequest.setAttributes(writeMap(this.objectMapper, oauth2AuthorizationRequest.getAttributes()));
        authorizationRequestRepository.save(authorizationRequest);
        LOGGER.debug("Stored Authorization Request to Database: {}", authorizationRequest);
    }

    /**
     * This method is used to remove the OAuth2AuthorizationRequest for a given HttpServletRequest and
     * HttpServletResponse.
     * It effectively simulates the removal of an authorization request by retrieving it, but does not explicitly delete
     * it from the underlying storage.
     *
     * @param request the HttpServletRequest
     * @param response the HttpServletResponse
     * @return the OAuth2AuthorizationRequest for the request, or null if none exists
     */
    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request,
                                                                 HttpServletResponse response) {
        return loadAuthorizationRequest(request);
    }

    /**
     * This method is used to get the AuthorizationRequest for a given session id from the database.
     *
     * @param sessionId the session id
     * @return the AuthorizationRequest for the session id, or null if none exists
     */
    private AuthorizationRequest getAuthorizationRequestFromDb(String sessionId) {
        LOGGER.info("Retrieving Authorization Request from Database for Session Id: {}", sessionId);
        Optional<AuthorizationRequest> authorizationRequestOptional = authorizationRequestRepository
            .findBySessionId(sessionId);
        if (authorizationRequestOptional.isEmpty()) {
            LOGGER.debug("Did not find Authorization Request in Database for Session Id: {}", sessionId);
            return null;
        }
        AuthorizationRequest authorizationRequest = authorizationRequestOptional.get();
        LOGGER.debug("Retrieved Authorization Request from Database: {}", authorizationRequest);
        return authorizationRequest;
    }

}