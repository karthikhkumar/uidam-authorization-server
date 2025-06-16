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

package org.eclipse.ecsp.oauth2.server.core.controller;

import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.common.UpdatePasswordData;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.CaptchaProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.exception.ExceptionControllerAdvice;
import org.eclipse.ecsp.oauth2.server.core.exception.PasswordRecoveryException;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.eclipse.ecsp.oauth2.server.core.service.PasswordPolicyService;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.service.impl.CaptchaServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.ui.Model;
import java.lang.reflect.Field;
import java.util.Base64;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * This class tests the functionality of the PasswordRecoveryController.
 */
class PasswordRecoveryControllerTest {

    private static final int INTEGER_EIGHT = 8;

    @Mock
    private UserManagementClient userManagementClient;

    @Mock
    private CaptchaServiceImpl captchaServiceImpl;

    @Mock
    private PasswordPolicyService passwordPolicyService;

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    private PasswordRecoveryController passwordRecoveryController;

    private MockMvc mockMvc;

    /**
     * This method sets up the test environment before each test. It initializes the MockMvc instance.
     */
    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);
        // Mock tenant properties and captcha
        TenantProperties tenantProperties = new TenantProperties();
        CaptchaProperties captcha = new CaptchaProperties();
        captcha.setRecaptchaKeySite("dummy-site-key");
        tenantProperties.setCaptcha(captcha);
        Mockito.when(tenantConfigurationService.getTenantProperties("UIDAM")).thenReturn(tenantProperties);
        passwordRecoveryController = new PasswordRecoveryController(tenantConfigurationService, passwordPolicyService);
        // Inject mocks for @Autowired fields and tenantProperties
        try {
            Field userManagementClientField = passwordRecoveryController.getClass()
                    .getDeclaredField("userManagementClient");
            userManagementClientField.setAccessible(true);
            userManagementClientField.set(passwordRecoveryController, userManagementClient);
            Field captchaServiceImplField = passwordRecoveryController.getClass()
                    .getDeclaredField("captchaServiceImpl");
            captchaServiceImplField.setAccessible(true);
            captchaServiceImplField.set(passwordRecoveryController, captchaServiceImpl);
            Field tenantPropertiesField = passwordRecoveryController.getClass().getDeclaredField("tenantProperties");
            tenantPropertiesField.setAccessible(true);
            tenantPropertiesField.set(passwordRecoveryController, tenantProperties);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        ExceptionControllerAdvice exceptionControllerAdvice = new ExceptionControllerAdvice(tenantConfigurationService);
        // Inject tenantProperties into ExceptionControllerAdvice
        try {
            Field tenantPropertiesField = exceptionControllerAdvice.getClass().getDeclaredField("tenantProperties");
            tenantPropertiesField.setAccessible(true);
            tenantPropertiesField.set(exceptionControllerAdvice, tenantProperties);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        this.mockMvc = MockMvcBuilders.standaloneSetup(passwordRecoveryController)
                .setControllerAdvice(exceptionControllerAdvice).build();
        // Default mock for password policy setup
        Mockito.doAnswer(invocation -> {
            Model model = invocation.getArgument(0);
            model.addAttribute("passwordPolicyMessages", java.util.Collections.emptyList());
            model.addAttribute("passwordPolicyMinLength", INTEGER_EIGHT);
            return null;
        }).when(passwordPolicyService).setupPasswordPolicy(Mockito.any(Model.class), any(Boolean.class));
    }

    /**
     * This test method tests the scenario where the initial password recovery request is successful. It performs a GET
     * request to the /recovery endpoint. The test asserts that the returned status is HttpStatus.OK, the view name is
     * "recovery/forgot-password", and the "isCaptchaFieldEnabled" model attribute exists.
     */
    @Test
    void testForgotPasswordInit() throws Exception {
        this.mockMvc.perform(get("/recovery")).andExpect(status().isOk())
                .andExpect(view().name("recovery/forgot-password"))
                .andExpect(model().attributeExists("isCaptchaFieldEnabled"));
    }

    /**
     * This test method tests the scenario where the password recovery request is successful. It sets up the necessary
     * parameters and then calls the forgotPassword method. The test asserts that the returned status is HttpStatus.OK,
     * the view name is "recovery/email-sent", and the "message" model attribute exists.
     */
    @Test
    void testForgotPassword() throws Exception {
        UserDetailsResponse userDetailResponse = new UserDetailsResponse();
        userDetailResponse.setId("id");
        userDetailResponse.setUserName("username");
        userDetailResponse.setEmail("email");
        when(userManagementClient.getUserDetailsByUsername("username", "ignite")).thenReturn(userDetailResponse);
        this.mockMvc
                .perform(post("/recovery/forgotPassword").param("username", "username").param("accountName", "ignite"))
                .andExpect(status().isOk()).andExpect(view().name("recovery/email-sent"))
                .andExpect(model().attributeExists("message"));
    }

    /**
     * This test method tests the scenario where the user details are not found during password recovery. It sets up the
     * necessary parameters and then calls the forgotPassword method. The test asserts that the returned status is
     * HttpStatus.OK, the view name is "recovery/forgot-password", and the "error" model attribute exists.
     */
    @Test
    void testForgotPasswordUserDetailsNotFound() throws Exception {
        doThrow(new PasswordRecoveryException("User not found")).when(userManagementClient)
                .sendUserResetPasswordNotification("username", "ignite");
        this.mockMvc
                .perform(post("/recovery/forgotPassword").param("username", "username").param("accountName", "ignite"))
                .andExpect(status().isOk()).andExpect(view().name("recovery/forgot-password"))
                .andExpect(model().attributeExists("error"));
    }

    /**
     * This test method tests the scenario where an exception is thrown during password recovery. It sets up the
     * necessary parameters and then calls the forgotPassword method. The test asserts that the returned status is
     * HttpStatus.OK, the view name is "recovery/forgot-password", and the "error" model attribute exists.
     */
    @Test
    void testForgotPasswordUserException() throws Exception {
        doThrow(new PasswordRecoveryException("Some error")).when(userManagementClient)
                .sendUserResetPasswordNotification("username", "ignite");
        this.mockMvc
                .perform(post("/recovery/forgotPassword").param("username", "username").param("accountName", "ignite"))
                .andExpect(status().isOk()).andExpect(view().name("recovery/forgot-password"))
                .andExpect(model().attributeExists("error"));
    }

    /**
     * This test method tests the scenario where the password reset initialization is successful. It sets up the
     * necessary parameters and then calls the reset method. The test asserts that the returned status is HttpStatus.OK,
     * the view name is "recovery/change-password", and the "secret" model attribute matches the provided secret.
     */
    @Test
    void testForgotPasswordResetInit() throws Exception {
        String secret = "secret";
        String nonce = "nonce";
        String encodedParams = Base64.getEncoder().encodeToString(("secret=" + secret + "&nonce=" + nonce).getBytes());
        this.mockMvc.perform(get("/recovery/reset/" + encodedParams)).andDo(print()).andExpect(status().isOk())
                .andExpect(view().name("recovery/change-password")).andExpect(model().attribute("secret", secret));
    }

    /**
     * This test method tests the scenario where an invalid secret is provided during password reset. It sets up the
     * necessary parameters and then calls the reset method. The test asserts that the returned status is HttpStatus.OK
     * and the view name is "recovery/invalid-secret-provided".
     */
    @Test
    void testForgotPasswordResetInavlidSecret() throws Exception {
        String secret = "";
        String nonce = "nonce";
        String encodedParams = Base64.getEncoder().encodeToString(("secret=" + secret + "&nonce=" + nonce).getBytes());
        this.mockMvc.perform(get("/recovery/reset/" + encodedParams)).andDo(print()).andExpect(status().isOk())
                .andExpect(view().name("recovery/invalid-secret-provided"));
    }

    /**
     * This test method tests the scenario where an exception is thrown due to an invalid secret during password reset.
     * It sets up the necessary parameters and then calls the reset method. The test asserts that the returned status is
     * HttpStatus.OK and the view name is "recovery/invalid-secret-provided".
     */
    @Test
    void testForgotPasswordResetInavlidSecretException() throws Exception {
        String secret = "";
        String nonce = "nonce";
        String encodedParams = Base64.getEncoder().encodeToString(("secret=" + secret + "&nonce=" + nonce).getBytes());
        this.mockMvc.perform(get("/recovery/reset/" + encodedParams + "123")).andDo(print()).andExpect(status().isOk())
                .andExpect(view().name("recovery/invalid-secret-provided"));
    }

    /**
     * This test method tests the scenario where an exception is thrown during password reset. It sets up the necessary
     * parameters and then calls the reset method. The test asserts that the returned status is HttpStatus.OK, the view
     * name is "recovery/password-changed", and the "message" model attribute exists.
     */
    @Test
    void testPasswordResetException() throws Exception {
        when(userManagementClient.updateUserPasswordUsingRecoverySecret(UpdatePasswordData.of("secret", "password")))
                .thenReturn("");
        this.mockMvc
                .perform(post("/recovery/reset").param("password", "password").param("confirmPassword", "password")
                        .param("secret", "secret"))
                .andExpect(status().isOk()).andExpect(view().name("recovery/password-changed"))
                .andExpect(model().attributeExists("message"));
    }

    /**
     * This test method tests the scenario where the provided passwords do not match during password reset. It sets up
     * the necessary parameters and then calls the reset method. The test asserts that the returned status is
     * HttpStatus.OK, the view name is "recovery/change-password", and the "error" model attribute exists.
     */
    @Test
    void testPasswordResetPasswordNotMatchedException() throws Exception {
        when(userManagementClient.updateUserPasswordUsingRecoverySecret(UpdatePasswordData.of("secret", "password")))
                .thenReturn("");
        this.mockMvc
                .perform(post("/recovery/reset").param("password", "password").param("confirmPassword", "ignite")
                        .param("secret", "secret"))
                .andExpect(status().isOk()).andExpect(view().name("recovery/change-password"))
                .andExpect(model().attributeExists("error"));
    }

    /**
     * This test method tests the scenario where the UserManagementClient throws an exception during password reset. It
     * sets up the necessary parameters and then calls the reset method. The test asserts that the returned status is
     * HttpStatus.OK and the view name is "recovery/forgot-password".
     */
    @Test
    void testPasswordResetUserMgmtClientException() throws Exception {
        when(userManagementClient.updateUserPasswordUsingRecoverySecret(UpdatePasswordData.of("secret", "password")))
                .thenThrow(new RuntimeException("failed to process request"));
        this.mockMvc
                .perform(post("/recovery/reset").param("password", "password").param("confirmPassword", "password")
                        .param("secret", "secret"))
                .andExpect(status().isOk()).andExpect(view().name("recovery/forgot-password"));
    }

    /**
     * This test method tests the scenario where an empty secret is provided during password reset. It sets up the
     * necessary parameters and then calls the reset method. The test asserts that the returned status is HttpStatus.OK,
     * the view name is "recovery/invalid-secret-provided", and the "error" model attribute exists.
     */
    @Test
    void testPasswordResetEmptySecretException() throws Exception {
        this.mockMvc
                .perform(post("/recovery/reset").param("password", "password").param("confirmPassword", "password")
                        .param("secret", ""))
                .andExpect(status().isOk()).andExpect(view().name("recovery/invalid-secret-provided"))
                .andExpect(model().attributeExists("error"));
    }

    @Test
    void testPasswordForgotValidAccountName() throws Exception {
        UserDetailsResponse userDetailResponse = new UserDetailsResponse();
        userDetailResponse.setId("id");
        userDetailResponse.setUserName("username");
        userDetailResponse.setEmail("email");
        when(userManagementClient.getUserDetailsByUsername("username", "ignite")).thenReturn(userDetailResponse);
        this.mockMvc
                .perform(post("/recovery/forgotPassword").param("username", "username").param("accountName",
                        "validAccountName123"))
                .andExpect(status().isOk()).andExpect(view().name("recovery/email-sent"))
                .andExpect(model().attributeExists("message"));
    }

    @Test
    void testPasswordForgotInvalidAccountName() throws Exception {
        // The controller throws PatternMismatchException for invalid account name, which is handled by
        // ExceptionControllerAdvice
        this.mockMvc
                .perform(post("/recovery/forgotPassword")
                        .param("username", "username")
                        .param("accountName", "Invalid acc"))
                .andExpect(status().isOk())
                .andExpect(view().name("recovery/forgot-password"))
                .andExpect(model().attribute("error", "Invalid Account Name format.")); // ACC_NAME_FORMAT_ERROR
    }

    @Test
    void testPasswordForgotEmptyAccountName() throws Exception {
        this.mockMvc.perform(post("/recovery/forgotPassword").param("username", "username").param("accountName", ""))
                .andExpect(status().isOk());
    }

}
