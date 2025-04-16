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

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.CookieRequestCache;

import java.io.IOException;
import java.util.function.Consumer;

/**
 * The FederatedIdentityAuthenticationSuccessHandler implements the AuthenticationSuccessHandler interface. This class
 * is used to handle successful authentication events in a Spring Security context.
 */
public final class FederatedIdentityAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final SavedRequestAwareAuthenticationSuccessHandler delegate =
            new SavedRequestAwareAuthenticationSuccessHandler();

    private Consumer<OAuth2User> oauth2UserHandler = user -> {
    };

    /**
     * This method is an override of the onAuthenticationSuccess method in the AuthenticationSuccessHandler interface.
     * It is called when a user has been successfully authenticated.
     * The method retrieves the authenticated OAuth2User, processes the user using the oauth2UserHandler, and then
     * delegates the handling of the successful authentication event.
     *
     * @param request the HttpServletRequest associated with the authentication event
     * @param response the HttpServletResponse associated with the authentication event
     * @param authentication the Authentication object containing the details of the authenticated user
     * @throws IOException if an input or output exception occurred
     * @throws ServletException if the request for the GET/POST could not be handled
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException,
            ServletException {
        OAuth2AuthenticationToken oauth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oauth2User = oauth2AuthenticationToken.getPrincipal();
        // OidcUser in case of Google, Cognito, Azure
        // OAuth2User in case of GitHub
        this.oauth2UserHandler.accept(oauth2User);
        this.delegate.setRequestCache(new CookieRequestCache());
        this.delegate.onAuthenticationSuccess(request, response, authentication);
    }

}
