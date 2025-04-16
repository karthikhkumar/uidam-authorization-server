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
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.request.dto.UserDto;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.eclipse.ecsp.oauth2.server.core.response.dto.PasswordPolicyResponseDto;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.validation.Valid;
import java.util.ArrayList;
import java.util.List;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.ADD_REQ_PAR;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.DEFAULT_PWD_MAX_LENGTH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.DEFAULT_PWD_MIN_LENGTH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.DEFAULT_PWD_REGEX;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.EMAIL_SENT_SUFFIX;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.FAILED_TO_CREATE_USER_WITH_USERNAME;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.PRIVACY_AGREEMENT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.REDIRECT_LITERAL;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.SELF_SIGN_UP;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.SIGN_UP_NOT_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.SLASH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TERMS_OF_USE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.UIDAM;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.UNEXPECTED_ERROR;
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
import static org.eclipse.ecsp.oauth2.server.core.utils.CommonMethodsUtils.obtainRecaptchaResponse;

/**
 * Controller class for handling self user sign-up operations.
 */
@Controller
@RequestMapping
public class SignUpController {

    private static final Logger LOGGER = LoggerFactory.getLogger(SignUpController.class);

    @Autowired
    UserManagementClient userManagementClient;

    private TenantProperties tenantProperties;

    /**
     * Constructor for SelfUserController.
     *
     * @param tenantConfigurationService the service to get tenant properties
     */
    @Autowired
    public SignUpController(TenantConfigurationService tenantConfigurationService) {
        tenantProperties = tenantConfigurationService.getTenantProperties(UIDAM);
    }

    /**
     * Initializes the self sign-up page.
     *
     * @param model the model to add attributes to
     * @return the name of the sign-up view
     */
    @GetMapping(SLASH + SELF_SIGN_UP)
    public String selfSignUpInit(Model model) {
        model.addAttribute(IS_SIGN_UP_ENABLED, tenantProperties.isSignUpEnabled());
        if (tenantProperties.isSignUpEnabled()) {
            setupCaptcha(model);
            setupPasswordPolicy(model);
        } else {
            model.addAttribute(MSG_LITERAL, SIGN_UP_NOT_ENABLED);
        }
        return SELF_SIGN_UP;
    }

    private void setupCaptcha(Model model) {
        model.addAttribute(CAPTCHA_FIELD_ENABLED, true);
        model.addAttribute(CAPTCHA_SITE, tenantProperties.getCaptcha().getRecaptchaKeySite());
        if (!model.containsAttribute(ERROR_LITERAL)) {
            model.addAttribute(ERROR_LITERAL, "");
        }
        model.addAttribute(MSG_LITERAL, "");
    }

    private void setupPasswordPolicy(Model model) {
        PasswordPolicyResponseDto passwordPolicy = userManagementClient.getPasswordPolicy();
        if (passwordPolicy != null) {
            model.addAttribute(PWD_MIN_LENGTH, passwordPolicy.getMinLength() > 0 ? passwordPolicy.getMinLength()
                    : DEFAULT_PWD_MIN_LENGTH);
            model.addAttribute(PWD_MAX_LENGTH, passwordPolicy.getMaxLength() > 0 ? passwordPolicy.getMaxLength()
                    : DEFAULT_PWD_MAX_LENGTH);
            model.addAttribute(PASSWORD_REGEX, passwordPolicy.getPasswordRegex() != null
                    ? passwordPolicy.getPasswordRegex() : DEFAULT_PWD_REGEX);
        } else {
            LOGGER.debug("No password policy received from user management service. Adding defaults...");
            passwordPolicy = addDefaultPwdPolicy(model);
        }
        model.addAttribute(PWD_NOTE, getPasswordPolicyMessages(passwordPolicy));
    }
    /**
     * Initializes the user created page.
     *
     * @param model the model to add attributes to
     * @return the name of the user-created UI view
     */

    @GetMapping(SLASH + USER_CREATED)
    public String userCreated(Model model) {
        return USER_CREATED;
    }

    /**
     * Initializes the terms of policy page.
     *
     * @return the name of the user-created UI view
     */
    @GetMapping(SLASH + TERMS_OF_USE)
    public String getTermsOfUsePage(Model model) {
        return TERMS_OF_USE;
    }

    /**
     * Initializes the privacy agreement page.
     *
     * @return the name of the user-created UI view
     */
    @GetMapping(SLASH + PRIVACY_AGREEMENT)
    public String getPrivacyAgreementPage(Model model) {
        return PRIVACY_AGREEMENT;
    }


    /**
     * Handles the submission of the self sign-up form.
     *
     * @param userDto the user data transfer object containing user details
     * @param request the HTTP servlet request
     * @param redirectAttributes the redirect attributes to add flash attributes
     * @return a ModelAndView object to redirect to the appropriate view
     */
    @PostMapping(value = SLASH + SELF_SIGN_UP, consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public ModelAndView addSelfUser(@ModelAttribute @Valid UserDto userDto, HttpServletRequest request,
                                    RedirectAttributes redirectAttributes) {
        LOGGER.info("## addSelfUser - START");
        boolean reqParametersPresent = checkForReqParameters(userDto, obtainRecaptchaResponse(request));
        if (!reqParametersPresent) {
            LOGGER.error("Required parameters are missing");
            redirectAttributes.addFlashAttribute(ERROR_LITERAL, ADD_REQ_PAR);
            return new ModelAndView(REDIRECT_LITERAL + SELF_SIGN_UP);
        }
        LOGGER.debug("Adding self user with username: {}", userDto.getFirstName());
        if (tenantProperties.isSignUpEnabled()) {
            try {
                UserDetailsResponse userDetailsResponse = userManagementClient.selfCreateUser(userDto, request);
                if (userDetailsResponse == null) {
                    LOGGER.error(FAILED_TO_CREATE_USER_WITH_USERNAME, userDto.getUserName());
                    redirectAttributes.addFlashAttribute(ERROR_LITERAL, UNEXPECTED_ERROR);
                    return new ModelAndView(REDIRECT_LITERAL + SELF_SIGN_UP);
                } else {
                    LOGGER.info("User created successfully with username: {}", userDto.getUserName());
                    if (!userDetailsResponse.isVerificationEmailSent()) {
                        redirectAttributes.addFlashAttribute(MSG_LITERAL,
                                AuthorizationServerConstants.USER_CREATED_SUCCESSFULLY);
                    } else {
                        redirectAttributes.addFlashAttribute(MSG_LITERAL,
                                AuthorizationServerConstants.EMAIL_SENT_PREFIX
                                        + userDetailsResponse.getEmail()
                                        +
                                        "\n"
                                        +
                                        EMAIL_SENT_SUFFIX);
                    }
                    return new ModelAndView(REDIRECT_LITERAL + USER_CREATED);
                }
            } catch (Exception e) {
                LOGGER.error(FAILED_TO_CREATE_USER_WITH_USERNAME, userDto.getEmail());
                redirectAttributes.addFlashAttribute(ERROR_LITERAL, e.getMessage());
                return new ModelAndView(REDIRECT_LITERAL + SELF_SIGN_UP);
            }
        } else {
            LOGGER.debug(SIGN_UP_NOT_ENABLED);
            redirectAttributes.addFlashAttribute(MSG_LITERAL, SIGN_UP_NOT_ENABLED);
            return new ModelAndView(REDIRECT_LITERAL + SELF_SIGN_UP);
        }
    }


    /**
     * Constructs a list of message strings describing the password policy.
     *
     * @return a list of strings with the password policy details
     */
    public List<String> getPasswordPolicyMessages(PasswordPolicyResponseDto passwordPolicyResponseDto) {
        LOGGER.info("Creating Password Policy message for UI");
        List<String> messages = new ArrayList<>();
        if (passwordPolicyResponseDto != null) {
            messages.add("Password must not contain email/username");
            if (passwordPolicyResponseDto.getMinLength() > 0) {
                messages.add("Password should contain atleast " + passwordPolicyResponseDto.getMinLength() 
                        + " characters minimum");
            }
            if (StringUtils.hasLength(passwordPolicyResponseDto.getPasswordRegex())) {
                messages.add("Password should contain atleast one Uppercase");
            }
            if (StringUtils.hasLength(passwordPolicyResponseDto.getPasswordRegex())) {
                messages.add("Password should contain atleast one Lowercase");
            }
            if (StringUtils.hasLength(passwordPolicyResponseDto.getPasswordRegex())) {
                messages.add("Password should contain atleast one Number");
            }
            if (StringUtils.hasLength(passwordPolicyResponseDto.getPasswordRegex())) {
                messages.add("Password should contain atleast one special character and should not contain space");
            }
        }
        return messages;
    }


    private PasswordPolicyResponseDto addDefaultPwdPolicy(Model model) {
        LOGGER.info("Creating Default Password Policy and message for UI");
        PasswordPolicyResponseDto passwordPolicyResponseDto = new PasswordPolicyResponseDto();
        passwordPolicyResponseDto.setMinLength(DEFAULT_PWD_MIN_LENGTH);
        passwordPolicyResponseDto.setMaxLength(DEFAULT_PWD_MAX_LENGTH);
        passwordPolicyResponseDto.setPasswordRegex(DEFAULT_PWD_REGEX);
        model.addAttribute(PWD_MIN_LENGTH, DEFAULT_PWD_MIN_LENGTH);
        model.addAttribute(PWD_MAX_LENGTH, DEFAULT_PWD_MAX_LENGTH);
        model.addAttribute(PASSWORD_REGEX, DEFAULT_PWD_REGEX);
        return passwordPolicyResponseDto;
    }

    private boolean checkForReqParameters(UserDto userDto, String recaptchaResp) {
        return StringUtils.hasText(userDto.getFirstName())
                && StringUtils.hasText(userDto.getEmail())
                && StringUtils.hasText(userDto.getPassword())
                && StringUtils.hasText(recaptchaResp);
    }
}

