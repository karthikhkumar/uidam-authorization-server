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

import jakarta.servlet.http.HttpServletRequest;
import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.CaptchaProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.request.dto.UserDto;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.eclipse.ecsp.oauth2.server.core.response.dto.PasswordPolicyResponseDto;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.service.impl.CaptchaServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.DEFAULT_PWD_MAX_LENGTH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.DEFAULT_PWD_MIN_LENGTH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.DEFAULT_PWD_REGEX;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.PRIVACY_AGREEMENT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.REDIRECT_LITERAL;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.SELF_SIGN_UP;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.USER_CREATED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CAPTCHA_FIELD_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CAPTCHA_SITE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.ERROR_LITERAL;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.IS_SIGN_UP_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MSG_LITERAL;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.PASSWORD_REGEX;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.PWD_MAX_LENGTH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.PWD_MIN_LENGTH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.PWD_NOTE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ActiveProfiles("test")
@TestPropertySource("classpath:application-test.properties")
@WebMvcTest(SignUpController.class)
@ContextConfiguration(classes = { SignUpController.class,
                                    UserManagementClient.class,
                                    TenantConfigurationService.class })
@EnableConfigurationProperties(value = TenantProperties.class)
class SignUpControllerTest {

    @Mock
    UserManagementClient userManagementClient;

    @MockitoBean
    CaptchaServiceImpl captchaService;

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    @Mock
    private TenantProperties tenantProperties;

    @InjectMocks
    private SignUpController signUpController;

    private int minLength = 10;

    @BeforeEach
    void setUp() {
        signUpController = new SignUpController(tenantConfigurationService);
        MockitoAnnotations.openMocks(this);
        when(tenantConfigurationService.getTenantProperties(any())).thenReturn(tenantProperties);
        when(userManagementClient.getPasswordPolicy()).thenReturn(getPasswordPolicyDto());

    }

    private CaptchaProperties defaultCaptchaProperties() {
        CaptchaProperties captchaProperties = new CaptchaProperties();
        captchaProperties.setRecaptchaKeySite("defaultSiteKey");
        captchaProperties.setRecaptchaKeySecret("defaultSecretKey");
        return captchaProperties;
    }


    @Test
    void selfSignUpInit_Success() {
        Model model = new ExtendedModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(false);
        String viewName = signUpController.selfSignUpInit(model);
        assertEquals(SELF_SIGN_UP, viewName);
        assertTrue(model.containsAttribute(IS_SIGN_UP_ENABLED));
        assertTrue(model.containsAttribute(MSG_LITERAL));
    }

    @Test
    void userCreated_Success() {
        Model model = new ExtendedModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(false);
        String viewName = signUpController.userCreated(model);
        assertEquals(USER_CREATED, viewName);
    }

    @Test
    void getPrivacyAgreementPage_Success() {
        Model model = new ExtendedModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(false);
        String viewName = signUpController.getPrivacyAgreementPage(model);
        assertEquals(PRIVACY_AGREEMENT, viewName);
    }

    @Test
    void addSelfUser_Success() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");
        HttpServletRequest request = new MockHttpServletRequest();
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(userManagementClient.selfCreateUser(any(UserDto.class), any(HttpServletRequest.class)))
                .thenReturn(getUserDetailsResponse());

        ModelAndView modelAndView = signUpController.addSelfUser(userDto, request, redirectAttributes);
        assertEquals(REDIRECT_LITERAL + SELF_SIGN_UP, modelAndView.getViewName());
    }

    @Test
    void addSelfUser_Success_ver_mail() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");
        HttpServletRequest request = new MockHttpServletRequest();
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(userManagementClient.selfCreateUser(any(UserDto.class), any(HttpServletRequest.class)))
                .thenReturn(getUserDetailsResponse1());

        ModelAndView modelAndView = signUpController.addSelfUser(userDto, request, redirectAttributes);
        assertEquals(REDIRECT_LITERAL + SELF_SIGN_UP, modelAndView.getViewName());
    }


    @Test
    void addSelfUserSignUpNotEnabled_Failure() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");
        HttpServletRequest request = new MockHttpServletRequest();
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

        when(userManagementClient.selfCreateUser(any(UserDto.class), any(HttpServletRequest.class)))
                .thenReturn(null);

        ModelAndView modelAndView = signUpController.addSelfUser(userDto, request, redirectAttributes);
        assertEquals(REDIRECT_LITERAL + SELF_SIGN_UP, modelAndView.getViewName());
        assertTrue(redirectAttributes.getFlashAttributes().containsKey(ERROR_LITERAL));
    }

    @Test
    void addSelfUser_Exception() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");
        HttpServletRequest request = new MockHttpServletRequest();
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(userManagementClient.selfCreateUser(any(UserDto.class), any(HttpServletRequest.class)))
                .thenThrow(new RuntimeException("Exception message"));

        ModelAndView modelAndView = signUpController.addSelfUser(userDto, request, redirectAttributes);
        assertEquals(REDIRECT_LITERAL + SELF_SIGN_UP, modelAndView.getViewName());
        assertTrue(redirectAttributes.getFlashAttributes().containsKey(ERROR_LITERAL));
    }

    @Test
    void selfSignUpInit_SignUpEnabled() {
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(tenantProperties.getCaptcha()).thenReturn(defaultCaptchaProperties());
        when(userManagementClient.getPasswordPolicy()).thenReturn(getPasswordPolicyDto());
        Model model = new ExtendedModelMap();
        String viewName = signUpController.selfSignUpInit(model);

        assertEquals(SELF_SIGN_UP, viewName);
        assertTrue(model.containsAttribute(IS_SIGN_UP_ENABLED));
        assertTrue(model.containsAttribute(CAPTCHA_FIELD_ENABLED));
        assertTrue(model.containsAttribute(CAPTCHA_SITE));
        assertTrue(model.containsAttribute(ERROR_LITERAL));
        assertTrue(model.containsAttribute(MSG_LITERAL));
        assertTrue(model.containsAttribute(PWD_NOTE));
        assertTrue(model.containsAttribute(PWD_MIN_LENGTH));
        assertTrue(model.containsAttribute(PWD_MAX_LENGTH));
        assertTrue(model.containsAttribute(PASSWORD_REGEX));
    }

    @Test
    void selfSignUpInit_SignUpEnabled2() {
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(tenantProperties.getCaptcha()).thenReturn(defaultCaptchaProperties());
        when(userManagementClient.getPasswordPolicy()).thenReturn(getPasswordPolicyDto());
        Model model = new ExtendedModelMap();
        model.addAttribute(ERROR_LITERAL, "error");
        String viewName = signUpController.selfSignUpInit(model);

        assertEquals(SELF_SIGN_UP, viewName);
        assertTrue(model.containsAttribute(IS_SIGN_UP_ENABLED));
        assertTrue(model.containsAttribute(CAPTCHA_FIELD_ENABLED));
        assertTrue(model.containsAttribute(CAPTCHA_SITE));
        assertTrue(model.containsAttribute(ERROR_LITERAL));
        assertTrue(model.containsAttribute(MSG_LITERAL));
        assertTrue(model.containsAttribute(PWD_NOTE));
        assertTrue(model.containsAttribute(PWD_MIN_LENGTH));
        assertTrue(model.containsAttribute(PWD_MAX_LENGTH));
        assertTrue(model.containsAttribute(PASSWORD_REGEX));
    }

    @Test
    void selfSignUpInit_SignUpEnabledTestForZeroLengthPassword() {
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(tenantProperties.getCaptcha()).thenReturn(defaultCaptchaProperties());
        when(userManagementClient.getPasswordPolicy()).thenReturn(getPasswordPolicyDtoForMinLengthZero());
        Model model = new ExtendedModelMap();
        model.addAttribute(ERROR_LITERAL, "error");
        signUpController.selfSignUpInit(model);
        assertEquals(model.getAttribute(PWD_MIN_LENGTH), minLength);
    }

    @Test
    void selfSignUpInit_SignUpDisabled() {
        when(tenantProperties.isSignUpEnabled()).thenReturn(false);

        Model model = new ExtendedModelMap();
        String viewName = signUpController.selfSignUpInit(model);

        assertEquals(SELF_SIGN_UP, viewName);
        assertTrue(model.containsAttribute(IS_SIGN_UP_ENABLED));
        assertEquals(AuthorizationServerConstants.SIGN_UP_NOT_ENABLED, model.getAttribute(MSG_LITERAL));
    }

    @Test
    void selfSignUpInit_NoPasswordPolicy() {
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(tenantProperties.getCaptcha()).thenReturn(defaultCaptchaProperties());
        when(userManagementClient.getPasswordPolicy()).thenReturn(null);

        Model model = new ExtendedModelMap();
        String viewName = signUpController.selfSignUpInit(model);

        assertEquals(SELF_SIGN_UP, viewName);
        assertTrue(model.containsAttribute(IS_SIGN_UP_ENABLED));
        assertTrue(model.containsAttribute(CAPTCHA_FIELD_ENABLED));
        assertTrue(model.containsAttribute(CAPTCHA_SITE));
        assertTrue(model.containsAttribute(ERROR_LITERAL));
        assertTrue(model.containsAttribute(MSG_LITERAL));
        assertTrue(model.containsAttribute(PWD_NOTE));
        assertEquals(DEFAULT_PWD_MIN_LENGTH, model.getAttribute(PWD_MIN_LENGTH));
        assertEquals(DEFAULT_PWD_MAX_LENGTH, model.getAttribute(PWD_MAX_LENGTH));
        assertEquals(DEFAULT_PWD_REGEX, model.getAttribute(PASSWORD_REGEX));
    }

    private PasswordPolicyResponseDto getPasswordPolicyDto() {
        PasswordPolicyResponseDto passwordPolicyResponseDto = new PasswordPolicyResponseDto();
        passwordPolicyResponseDto.setMinLength(DEFAULT_PWD_MIN_LENGTH);
        passwordPolicyResponseDto.setMaxLength(DEFAULT_PWD_MAX_LENGTH);
        passwordPolicyResponseDto.setPasswordRegex(DEFAULT_PWD_REGEX);
        return passwordPolicyResponseDto;
    }

    private PasswordPolicyResponseDto getPasswordPolicyDtoForMinLengthZero() {
        PasswordPolicyResponseDto passwordPolicyResponseDto = new PasswordPolicyResponseDto();
        passwordPolicyResponseDto.setMinLength(0);
        return passwordPolicyResponseDto;
    }

    private UserDetailsResponse getUserDetailsResponse() {
        UserDetailsResponse userDetailsResponse = new UserDetailsResponse();
        userDetailsResponse.setEmail("test@example.com");
        userDetailsResponse.setVerificationEmailSent(true);
        // Set other necessary fields...
        return userDetailsResponse;
    }

    private UserDetailsResponse getUserDetailsResponse1() {
        UserDetailsResponse userDetailsResponse = new UserDetailsResponse();
        userDetailsResponse.setEmail("test@example.com");
        userDetailsResponse.setVerificationEmailSent(false);
        // Set other necessary fields...
        return userDetailsResponse;
    }
}