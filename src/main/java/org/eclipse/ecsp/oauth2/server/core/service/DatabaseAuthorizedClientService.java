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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;

/**
 * A OAuth2AuthorizedClientService implementation which stores OAuth2 authorized clients in the Database.
 * This class is responsible for managing the OAuth2 authorized clients.
 */
public class DatabaseAuthorizedClientService implements OAuth2AuthorizedClientService {

    private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseAuthorizedClientService.class);

    /**
     * This method is used to load the OAuth2AuthorizedClient based on the client registration ID and principal name.
     * Currently, this method does not perform any operation.
     *
     * @param clientRegistrationId the client registration ID
     * @param principalName the name of the principal
     * @return null
     */
    @Override
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId,
                                                                     String principalName) {
        LOGGER.info("loadAuthorizedClient - do nothing");
        return null;
    }

    /**
     * This method is used to save the OAuth2AuthorizedClient associated with a given authentication principal.
     * Currently, this method does not perform any operation.
     *
     * @param authorizedClient the authorized client to save
     * @param principal the authentication principal associated with the authorized client
     */
    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
        LOGGER.info("saveAuthorizedClient - do nothing");
    }

    /**
     * This method is used to remove the OAuth2AuthorizedClient associated with the given client registration ID and
     * principal name.
     * Currently, this method does not perform any operation.
     *
     * @param clientRegistrationId the client registration ID
     * @param principalName the name of the principal
     */
    @Override
    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
        LOGGER.info("removeAuthorizedClient - do nothing");
    }

}