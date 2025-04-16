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
import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.service.DatabaseSecurityContextRepository;
import org.eclipse.ecsp.oauth2.server.core.utils.SecureUriUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.HashMap;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.ERROR_WHILE_BUILDING_REDIRECT_URI;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CODE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.STATE;

/**
 * The CustomAuthCodeSuccessHandler class implements the AuthenticationSuccessHandler interface.
 * This class is used to handle successful authentication events in a Spring Security context.
 */
public class CustomAuthCodeSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomAuthCodeSuccessHandler.class);

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    private final DatabaseSecurityContextRepository databaseSecurityContextRepository;

    private final boolean forceLogin;

    /**
     * This is a parameterized constructor for the CustomAuthCodeSuccessHandler class.
     * It initializes the DatabaseSecurityContextRepository instance and sets the forceLogin variable.
     *
     * @param databaseSecurityContextRepository an instance of DatabaseSecurityContextRepository, used to interact with
     *                                          the security context stored in the database
     * @param forceLogin a boolean value that determines whether to force a login or not
     */
    public CustomAuthCodeSuccessHandler(DatabaseSecurityContextRepository databaseSecurityContextRepository,
                                        boolean forceLogin) {
        Assert.notNull(databaseSecurityContextRepository, "databaseSecurityContextRepository cannot be null");
        this.databaseSecurityContextRepository = databaseSecurityContextRepository;
        this.forceLogin = forceLogin;
    }

    /**
     * This method is an override of the onAuthenticationSuccess method in the AuthenticationSuccessHandler interface.
     * It is called when a user has been successfully authenticated.
     * The method retrieves the authenticated OAuth2AuthorizationCodeRequestAuthenticationToken, checks if the redirect
     * URI or Authorization Code is not found, and if found, builds the redirect URI with the authorization code and
     * state (if present).
     * If forceLogin is true, it unauthenticates the context in the database.
     * Finally, it redirects the response to the built redirect URI.
     *
     * @param request the HttpServletRequest associated with the authentication event
     * @param response the HttpServletResponse associated with the authentication event
     * @param authentication the Authentication object containing the details of the authenticated user
     * @throws IOException if an input or output exception occurred
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        LOGGER.debug("## onAuthenticationSuccess - START");
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
            (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

        if (authorizationCodeRequestAuthentication == null
            || !StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())
            || authorizationCodeRequestAuthentication.getAuthorizationCode() == null) {
            LOGGER.debug("Authorization Code Request Authentication is null "
                + "OR Redirect URI OR Authorization Code not found");
            return;
        }

        HashMap<String, String> urlQueryParamsToBeSanitized = new HashMap<>();
        urlQueryParamsToBeSanitized.put(CODE,
            authorizationCodeRequestAuthentication.getAuthorizationCode().getTokenValue());
        String uri;
        try {
            if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
                urlQueryParamsToBeSanitized.put(STATE, authorizationCodeRequestAuthentication.getState());
            }

            uri = SecureUriUtils.buildRedirectUri(authorizationCodeRequestAuthentication.getRedirectUri(),
                urlQueryParamsToBeSanitized);
        } catch (Exception e) {
            LOGGER.error(ERROR_WHILE_BUILDING_REDIRECT_URI, e);
            return;
        }

        UriComponentsBuilder uriBuilder = UriComponentsBuilder
            .fromUriString(uri);
        if (forceLogin) {
            LOGGER.debug("forceLogin: {}", forceLogin);
            AbstractAuthenticationToken abstractAuthenticationToken = (AbstractAuthenticationToken)
                authentication.getPrincipal();
            if (abstractAuthenticationToken instanceof CustomUserPwdAuthenticationToken
                customUserPwdAuthenticationToken) {
                WebAuthenticationDetails webAuthenticationDetails = (WebAuthenticationDetails)
                    customUserPwdAuthenticationToken.getDetails();
                // Authenticated flag false after auth code generation
                this.databaseSecurityContextRepository.unauthenticatedContextInDb(
                    webAuthenticationDetails.getSessionId());
            }
            if (abstractAuthenticationToken instanceof OAuth2AuthenticationToken oauth2AuthenticationToken) {
                WebAuthenticationDetails webAuthenticationDetails = (WebAuthenticationDetails)
                    oauth2AuthenticationToken.getDetails();
                // Authenticated flag false after auth code generation
                this.databaseSecurityContextRepository.unauthenticatedContextInDb(
                    webAuthenticationDetails.getSessionId());
            }
        }

        String redirectUri = uriBuilder.build(true).toUriString();
        // build(true) -> Components are explicitly encoded
        this.redirectStrategy.sendRedirect(request, response, redirectUri);
        LOGGER.debug("## onAuthenticationSuccess - END");
    }

}