/********************************************************************************
 * Copyright (c) 2023-24 Harman International 
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0  
 *  
 * <p>Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.ecsp.oauth2.server.core.authentication.handlers.LogoutHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.ui.Model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * Comprehensive unit tests for LogoutController. Tests all endpoints and scenarios including success cases, error
 * cases.
 */
@ExtendWith(MockitoExtension.class)
class LogoutControllerTest {

    private static final int INT_1000 = 1000;

    private static final int INT_500 = 500;

    private static final int INT_2048 = 2048;

    private static final int INT_3 = 3;

    @Mock
    private LogoutHandler logoutHandler;

    @Mock
    private Authentication authentication;

    @Mock
    private SecurityContext securityContext;

    @Mock
    private Model model;

    @InjectMocks
    private LogoutController logoutController;

    private MockMvc mockMvc; // Test constants
    private static final String VALID_ID_TOKEN_HINT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
            + ".eyJzdWIiOiJ0ZXN0VXNlciIsImF1ZCI6WyJ0ZXN0Q2xpZW50Il0sImV4cCI6MTcwMDAwMDAwMH0.signature";
    private static final String VALID_CLIENT_ID = "testClient";
    private static final String VALID_POST_LOGOUT_REDIRECT_URI = "https://example.com/logout-success";
    private static final String VALID_STATE = "state123";

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(logoutController).build();
        SecurityContextHolder.setContext(securityContext);
    }

    // ================== POST /oauth2/logout Tests ==================

    @Test
    void shouldProcessValidOidcLogoutPostWithRequiredParametersOnly() throws Exception {
        // Arrange
        when(securityContext.getAuthentication()).thenReturn(authentication);
        doNothing().when(logoutHandler).onLogoutSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
                eq(authentication), eq(VALID_ID_TOKEN_HINT), eq(VALID_CLIENT_ID), isNull(), isNull());

        // Act
        mockMvc.perform(
                post("/oauth2/logout").param("id_token_hint", VALID_ID_TOKEN_HINT).param("client_id", VALID_CLIENT_ID))
                .andExpect(status().isOk());

        // Assert
        verify(logoutHandler, times(1)).onLogoutSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
                eq(authentication), eq(VALID_ID_TOKEN_HINT), eq(VALID_CLIENT_ID), isNull(), isNull());
    }

    @Test
    void shouldProcessOidcLogoutPostWithEmptyOptionalParameters() throws Exception {
        // Arrange
        when(securityContext.getAuthentication()).thenReturn(authentication);
        doNothing().when(logoutHandler).onLogoutSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
                eq(authentication), eq(VALID_ID_TOKEN_HINT), eq(VALID_CLIENT_ID), isNull(), eq(""));

        // Act
        mockMvc.perform(
                post("/oauth2/logout").param("id_token_hint", VALID_ID_TOKEN_HINT).param("client_id", VALID_CLIENT_ID)
                        .param("post_logout_redirect_uri", "").param("state", "").param("logout_hint", ""))
                .andExpect(status().isOk());

        // Assert
        verify(logoutHandler, times(1)).onLogoutSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
                eq(authentication), eq(VALID_ID_TOKEN_HINT), eq(VALID_CLIENT_ID), isNull(), eq(""));
    }

    @Test
    void shouldReturnBadRequestWhenIdTokenHintIsMissing() throws Exception {
        mockMvc.perform(post("/oauth2/logout").param("client_id", VALID_CLIENT_ID)).andExpect(status().isBadRequest());

        verify(logoutHandler, never()).onLogoutSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
                any(Authentication.class), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void shouldReturnBadRequestWhenClientIdIsMissing() throws Exception {
        mockMvc.perform(post("/oauth2/logout").param("id_token_hint", VALID_ID_TOKEN_HINT))
                .andExpect(status().isBadRequest());

        verify(logoutHandler, never()).onLogoutSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
                any(Authentication.class), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void shouldReturnBadRequestWhenBothRequiredParametersAreMissing() throws Exception {
        mockMvc.perform(post("/oauth2/logout")).andExpect(status().isBadRequest());

        verify(logoutHandler, never()).onLogoutSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
                any(Authentication.class), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void shouldPassCorrectAuthenticationToLogoutHandler() throws Exception {
        // Arrange
        when(securityContext.getAuthentication()).thenReturn(authentication);
        ArgumentCaptor<Authentication> authCaptor = ArgumentCaptor.forClass(Authentication.class);

        // Act
        mockMvc.perform(
                post("/oauth2/logout").param("id_token_hint", VALID_ID_TOKEN_HINT).param("client_id", VALID_CLIENT_ID))
                .andExpect(status().isOk());

        // Assert
        verify(logoutHandler).onLogoutSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
                authCaptor.capture(), eq(VALID_ID_TOKEN_HINT), eq(VALID_CLIENT_ID), isNull(), isNull());

        assertEquals(authentication, authCaptor.getValue());
    }

    @Test
    void shouldHandleSpecialCharactersInParameters() throws Exception {
        // Arrange
        when(securityContext.getAuthentication()).thenReturn(authentication);
        String specialState = "state with spaces & symbols!@#$%";
        String specialRedirectUri = "https://example.com/logout?param=value&other=test";

        doNothing().when(logoutHandler).onLogoutSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
                eq(authentication), eq(VALID_ID_TOKEN_HINT), eq(VALID_CLIENT_ID), eq(specialRedirectUri),
                eq(specialState));

        // Act & Assert
        mockMvc.perform(
                post("/oauth2/logout").param("id_token_hint", VALID_ID_TOKEN_HINT).param("client_id", VALID_CLIENT_ID)
                        .param("post_logout_redirect_uri", specialRedirectUri).param("state", specialState))
                .andExpect(status().isOk());

        verify(logoutHandler, times(1)).onLogoutSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
                eq(authentication), eq(VALID_ID_TOKEN_HINT), eq(VALID_CLIENT_ID), eq(specialRedirectUri),
                eq(specialState));
    }

    // ================== GET /oauth2/logout/success Tests ==================

    @Test
    void shouldReturnLogoutSuccessPage() throws Exception {
        mockMvc.perform(get("/oauth2/logout/success")).andExpect(status().isOk())
                .andExpect(view().name("logout-success"));
    }

    @Test
    void shouldHandleMultipleSuccessPageRequests() throws Exception {
        // Test that multiple requests to success page work correctly
        for (int i = 0; i < INT_3; i++) {
            mockMvc.perform(get("/oauth2/logout/success")).andExpect(status().isOk())
                    .andExpect(view().name("logout-success"));
        }
    } // ================== GET /oauth2/logout/error Tests ==================

    @Test
    void shouldReturnLogoutErrorPageWithoutErrorParameter() throws Exception {
        mockMvc.perform(get("/oauth2/logout/error")).andExpect(status().isOk()).andExpect(view().name("logout-error"))
                .andExpect(model().attributeDoesNotExist("errorMessage"));
    }

    @Test
    void shouldReturnLogoutErrorPageWithInvalidTokenError() throws Exception {
        mockMvc.perform(get("/oauth2/logout/error").param("error", OAuth2ErrorCodes.INVALID_TOKEN))
                .andExpect(status().isOk()).andExpect(view().name("logout-error"))
                .andExpect(model().attribute("errorMessage", "The provided token is invalid or expired."));
    }

    @Test
    void shouldReturnLogoutErrorPageWithInvalidClientError() throws Exception {
        mockMvc.perform(get("/oauth2/logout/error").param("error", OAuth2ErrorCodes.INVALID_CLIENT))
                .andExpect(status().isOk()).andExpect(view().name("logout-error"))
                .andExpect(model().attribute("errorMessage", "The client is not recognized or not authorized."));
    }

    @Test
    void shouldReturnLogoutErrorPageWithInvalidRequestError() throws Exception {
        mockMvc.perform(get("/oauth2/logout/error").param("error", OAuth2ErrorCodes.INVALID_REQUEST))
                .andExpect(status().isOk()).andExpect(view().name("logout-error"))
                .andExpect(model().attribute("errorMessage", "The logout request is malformed or invalid."));
    }

    @Test
    void shouldReturnLogoutErrorPageWithUnauthorizedClientError() throws Exception {
        mockMvc.perform(get("/oauth2/logout/error").param("error", OAuth2ErrorCodes.UNAUTHORIZED_CLIENT))
                .andExpect(status().isOk()).andExpect(view().name("logout-error")).andExpect(model()
                        .attribute("errorMessage", "The client is not authorized to perform the logout operation."));
    }

    @Test
    void shouldReturnLogoutErrorPageWithAccessDeniedError() throws Exception {
        mockMvc.perform(get("/oauth2/logout/error").param("error", OAuth2ErrorCodes.ACCESS_DENIED))
                .andExpect(status().isOk()).andExpect(view().name("logout-error"))
                .andExpect(model().attribute("errorMessage", "Access to the logout operation was denied."));
    }

    @Test
    void shouldReturnLogoutErrorPageWithServerError() throws Exception {
        mockMvc.perform(get("/oauth2/logout/error").param("error", OAuth2ErrorCodes.SERVER_ERROR))
                .andExpect(status().isOk()).andExpect(view().name("logout-error"))
                .andExpect(model().attribute("errorMessage", "An internal server error occurred during logout."));
    }

    @Test
    void shouldReturnLogoutErrorPageWithTemporarilyUnavailableError() throws Exception {
        mockMvc.perform(get("/oauth2/logout/error").param("error", OAuth2ErrorCodes.TEMPORARILY_UNAVAILABLE))
                .andExpect(status().isOk()).andExpect(view().name("logout-error")).andExpect(model().attribute(
                        "errorMessage", "The logout service is temporarily unavailable. Please try again later."));
    }

    @Test
    void shouldReturnLogoutErrorPageWithUnknownError() throws Exception {
        mockMvc.perform(get("/oauth2/logout/error").param("error", "unknown_error")).andExpect(status().isOk())
                .andExpect(view().name("logout-error"))
                .andExpect(model().attribute("errorMessage", "An unexpected error occurred during logout."));
    }

    @Test
    void shouldHandleEmptyErrorParameter() throws Exception {
        mockMvc.perform(get("/oauth2/logout/error").param("error", "")).andExpect(status().isOk())
                .andExpect(view().name("logout-error"))
                .andExpect(model().attribute("errorMessage", "An unexpected error occurred during logout."));
    }

    @Test
    void shouldHandleNullErrorParameterExplicitly() {
        // Test direct controller method call to verify null handling
        String result = logoutController.logoutError(model, null);

        assertEquals("logout-error", result);
        verify(model, never()).addAttribute(eq("errorMessage"), anyString());
    }

    @Test
    void shouldHandleMultipleErrorParameters() throws Exception {
        // When multiple error parameters are provided, Spring MVC behavior may vary
        // In this case, it appears to result in an unexpected error message
        mockMvc.perform(get("/oauth2/logout/error").param("error", OAuth2ErrorCodes.INVALID_TOKEN).param("error",
                OAuth2ErrorCodes.INVALID_CLIENT)).andExpect(status().isOk()).andExpect(view().name("logout-error"))
                .andExpect(model().attribute("errorMessage", "An unexpected error occurred during logout."));
    }

    // ================== Error Message Mapping Tests ==================
    @Test
    void shouldMapAllOauth2ErrorCodesToCorrectMessages() {
        // Test all OAuth2 error codes through the error endpoint
        String[] errorCodes = { OAuth2ErrorCodes.INVALID_TOKEN, OAuth2ErrorCodes.INVALID_CLIENT,
            OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, OAuth2ErrorCodes.ACCESS_DENIED,
            OAuth2ErrorCodes.SERVER_ERROR, OAuth2ErrorCodes.TEMPORARILY_UNAVAILABLE };

        String[] expectedMessages = { "The provided token is invalid or expired.",
            "The client is not recognized or not authorized.", "The logout request is malformed or invalid.",
            "The client is not authorized to perform the logout operation.",
            "Access to the logout operation was denied.", "An internal server error occurred during logout.",
            "The logout service is temporarily unavailable. Please try again later." };

        for (int i = 0; i < errorCodes.length; i++) {
            String result = logoutController.logoutError(model, errorCodes[i]);
            assertEquals("logout-error", result);

            verify(model).addAttribute("errorMessage", expectedMessages[i]);
        }
    }

    // ================== Integration and Edge Case Tests ==================

    @Test
    void shouldHandleNullAuthentication() throws Exception {
        // Arrange
        when(securityContext.getAuthentication()).thenReturn(null);

        // Act & Assert
        mockMvc.perform(
                post("/oauth2/logout").param("id_token_hint", VALID_ID_TOKEN_HINT).param("client_id", VALID_CLIENT_ID))
                .andExpect(status().isOk());

        verify(logoutHandler, times(1)).onLogoutSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
                isNull(), eq(VALID_ID_TOKEN_HINT), eq(VALID_CLIENT_ID), isNull(), isNull());
    }

    @Test
    void shouldHandleLongParameterValues() throws Exception {
        // Test with very long parameter values
        when(securityContext.getAuthentication()).thenReturn(authentication);
        String longToken = "a".repeat(INT_2048);
        String longClientId = "b".repeat(INT_500);
        String longState = "c".repeat(INT_1000);
        String longRedirectUri = "https://example.com/" + "d".repeat(INT_1000);

        doNothing().when(logoutHandler).onLogoutSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
                eq(authentication), eq(longToken), eq(longClientId), eq(longRedirectUri), eq(longState));

        mockMvc.perform(post("/oauth2/logout").param("id_token_hint", longToken).param("client_id", longClientId)
                .param("post_logout_redirect_uri", longRedirectUri).param("state", longState))
                .andExpect(status().isOk());
    }

    @Test
    void shouldHandleControllerLogging() throws Exception {
        // This test verifies that the controller processes requests without errors
        // The actual logging verification would require additional setup with logback test appenders
        when(securityContext.getAuthentication()).thenReturn(authentication);

        mockMvc.perform(
                post("/oauth2/logout").param("id_token_hint", VALID_ID_TOKEN_HINT).param("client_id", VALID_CLIENT_ID)
                        .param("post_logout_redirect_uri", VALID_POST_LOGOUT_REDIRECT_URI).param("state", VALID_STATE))
                .andExpect(status().isOk());

        // Verify that the request was processed successfully
        verify(logoutHandler, times(1)).onLogoutSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
                eq(authentication), eq(VALID_ID_TOKEN_HINT), eq(VALID_CLIENT_ID), eq(VALID_POST_LOGOUT_REDIRECT_URI),
                eq(VALID_STATE));
    }

    @Test
    void shouldVerifyConstructorDependencyInjection() {
        // Test that the controller is properly constructed with the logout handler
        assertNotNull(logoutController);

        // Verify that the LogoutHandler dependency is properly injected
        // This is implicitly tested through all other tests, but we can verify construction
        LogoutController testController = new LogoutController(logoutHandler);
        assertNotNull(testController);
    }

    @Test
    void shouldAllowRelativePathRedirectUri() throws Exception {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        String relativeUri = "/logout-success";
        doNothing().when(logoutHandler).onLogoutSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
                eq(authentication), eq(VALID_ID_TOKEN_HINT), eq(VALID_CLIENT_ID), eq(relativeUri), isNull());

        mockMvc.perform(post("/oauth2/logout")
                .param("id_token_hint", VALID_ID_TOKEN_HINT)
                .param("client_id", VALID_CLIENT_ID)
                .param("post_logout_redirect_uri", relativeUri))
                .andExpect(status().isOk());

        verify(logoutHandler, times(1)).onLogoutSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
                eq(authentication), eq(VALID_ID_TOKEN_HINT), eq(VALID_CLIENT_ID), eq(relativeUri), isNull());
    }

    @Test
    void shouldBlockNonHttpsAndNonRelativeRedirectUri() throws Exception {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        String badUri = "http://malicious.com";
        doNothing().when(logoutHandler).onLogoutSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
                eq(authentication), eq(VALID_ID_TOKEN_HINT), eq(VALID_CLIENT_ID), isNull(), isNull());

        mockMvc.perform(post("/oauth2/logout")
                .param("id_token_hint", VALID_ID_TOKEN_HINT)
                .param("client_id", VALID_CLIENT_ID)
                .param("post_logout_redirect_uri", badUri))
                .andExpect(status().isOk());

        verify(logoutHandler, times(1)).onLogoutSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
                eq(authentication), eq(VALID_ID_TOKEN_HINT), eq(VALID_CLIENT_ID), isNull(), isNull());
    }
}
