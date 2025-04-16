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
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.ecsp.oauth2.server.core.common.CustomOauth2ErrorResponse;
import org.eclipse.ecsp.oauth2.server.core.utils.SecureUriUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.HashMap;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.ERROR_WHILE_BUILDING_REDIRECT_URI;
import static org.eclipse.ecsp.oauth2.server.core.utils.CustomOauth2ErrorMessage.setCustomErrorMessage;

/**
 * The CustomAuthCodeFailureHandler class implements the AuthenticationFailureHandler interface.
 * This class is responsible for handling authentication failure events in a Spring Security context.
 */
@Component
public class CustomAuthCodeFailureHandler implements AuthenticationFailureHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomAuthCodeFailureHandler.class);

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * This method is an override of the onAuthenticationFailure method in the AuthenticationFailureHandler interface.
     * It is called when a user's authentication attempt has failed.
     * The method retrieves the failed OAuth2AuthorizationCodeRequestAuthenticationToken, checks if the redirect URI or
     * Authorization Code is not found, and if found, builds the redirect URI with the error details and state (if
     * present).
     * It then redirects the response to the built redirect URI.
     *
     * @param request the HttpServletRequest associated with the authentication event
     * @param response the HttpServletResponse associated with the authentication event
     * @param exception the AuthenticationException object containing the details of the authentication failure
     * @throws IOException if an input or output exception occurred
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        LOGGER.debug("## onAuthenticationFailure - START");
        OAuth2AuthorizationCodeRequestAuthenticationException authorizationCodeRequestAuthenticationException =
            (OAuth2AuthorizationCodeRequestAuthenticationException) exception;
        OAuth2Error error = authorizationCodeRequestAuthenticationException.getError();
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
            authorizationCodeRequestAuthenticationException.getAuthorizationCodeRequestAuthentication();

        if (authorizationCodeRequestAuthentication == null
            || !StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())) {
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.setHeader("X-Content-Type-Options", "nosniff");
            CustomOauth2ErrorResponse customOauth2ErrorResponse = setCustomErrorMessage(
                    authorizationCodeRequestAuthenticationException, response);
            response.getOutputStream().println(objectMapper.writeValueAsString(customOauth2ErrorResponse));
            return;
        }

        // Existing code for redirecting to client with error
        LOGGER.info("Redirecting to client with error {}", error.getDescription());
        HashMap<String, String> urlQueryParamsToBeSanitized = new HashMap<>();

        urlQueryParamsToBeSanitized.put(OAuth2ParameterNames.ERROR, error.getErrorCode());
        String uri;
        try {
            if (StringUtils.hasText(error.getDescription())) {
                urlQueryParamsToBeSanitized.put(OAuth2ParameterNames.ERROR_DESCRIPTION,
                    error.getDescription());
            }
            if (StringUtils.hasText(error.getUri())) {
                urlQueryParamsToBeSanitized.put(OAuth2ParameterNames.ERROR_URI, error.getUri());
            }
            if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
                urlQueryParamsToBeSanitized.put(OAuth2ParameterNames.STATE,
                    authorizationCodeRequestAuthentication.getState());
            }

            uri = SecureUriUtils.buildRedirectUri(authorizationCodeRequestAuthentication.getRedirectUri(),
                urlQueryParamsToBeSanitized);
        } catch (Exception e) {
            LOGGER.error(ERROR_WHILE_BUILDING_REDIRECT_URI, e);
            return;
        }

        UriComponentsBuilder uriBuilder = UriComponentsBuilder
            .fromUriString(uri);
        String redirectUri = uriBuilder.build(true).toUriString();
        this.redirectStrategy.sendRedirect(request, response, redirectUri);
        LOGGER.debug("## onAuthenticationFailure - END");
    }

}