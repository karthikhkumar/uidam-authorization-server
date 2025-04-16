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


import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * The UserRepositoryOauth2UserHandler class implements the Consumer interface with OAuth2User as the parameter.
 * This class is used to handle OAuth2User objects, specifically to save first-time users to a local data store.
 * It contains a UserRepository which is a simple in-memory data store for OAuth2User objects.
 */
public final class UserRepositoryOauth2UserHandler implements Consumer<OAuth2User> {

    private final UserRepository userRepository = new UserRepository();

    /**
     * This method is an override of the accept method in the Consumer interface.
     * It accepts an OAuth2User object and checks if the user already exists in the UserRepository.
     * If the user does not exist, it saves the user to the UserRepository.
     *
     * @param user the OAuth2User to be processed
     */
    @Override
    public void accept(OAuth2User user) {
        // Capture user in local data store on first authentication
        if (this.userRepository.findByName(user.getName()) == null) {
            this.userRepository.save(user);
        }
    }

    /**
     * UserRepository is a static inner class.
     * It serves as a simple in-memory data store for OAuth2User objects.
     * It contains a ConcurrentHashMap named userCache to store the OAuth2User objects.
     */
    static class UserRepository {

        private final Map<String, OAuth2User> userCache = new ConcurrentHashMap<>();

        /**
         * This method retrieves an OAuth2User from the userCache based on the user's name.
         * The user's name is used as the key to retrieve the corresponding OAuth2User from the ConcurrentHashMap.
         *
         * @param name the name of the OAuth2User to be retrieved
         * @return the OAuth2User object corresponding to the provided name, or null if no such user exists
         */
        public OAuth2User findByName(String name) {
            return this.userCache.get(name);
        }

        /**
         * This method saves an OAuth2User to the userCache.
         * The user's name is used as the key, and the OAuth2User object itself is the value.
         * If a user with the same name already exists in the userCache, it is replaced.
         *
         * @param oauth2User the OAuth2User to be saved
         */
        public void save(OAuth2User oauth2User) {
            this.userCache.put(oauth2User.getName(), oauth2User);
        }

    }

}
