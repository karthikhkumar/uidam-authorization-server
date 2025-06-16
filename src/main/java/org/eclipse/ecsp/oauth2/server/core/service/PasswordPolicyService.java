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

import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.response.dto.PasswordPolicyResponseDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.DEFAULT_ALLOWEDSPECIALCHARS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.DEFAULT_EXCLUDEDSPECIALCHARS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.DEFAULT_MAX_LENGTH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.DEFAULT_MIN_LENGTH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.ALLOWED_SPECIALCHARS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.EXCLUDED_SPECIALCHARS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MAX_LENGTH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MIN_CON_LETTERS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MIN_DIGITS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MIN_LENGTH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MIN_LOWERCASE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MIN_SPECIALCHARS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MIN_UPPERCASE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.PWD_NOTE;



/**
 * The PasswordPolicyService class is responsible for managing password policies. It retrieves the password policy from
 * the user management client and sets it up in the model. If no password policy is received, it adds default values.
 */
@Service
public class PasswordPolicyService {
    private static final String PASSWORD_SHOULD_CONTAIN_ATLEAST = "Password should contain atleast ";

    private static final Logger LOGGER = LoggerFactory.getLogger(PasswordPolicyService.class);

    private UserManagementClient userManagementClient;

    /**
     * Default constructor for PasswordPolicyService. This constructor is used by the Spring framework to create an
     * instance of this service.
     */
    public PasswordPolicyService(UserManagementClient userManagementClient) {
        this.userManagementClient = userManagementClient;
    }

    /**
     * This method sets up the password policy in the model. It retrieves the password policy from the user management
     * client and adds the relevant attributes to the model. If no password policy is received, it adds default values.
     *
     * @param model the model to which password policy attributes will be added
     * @param ignoreConsecutiveLetters whether to ignore consecutive letters in the password policy
     */
    public void setupPasswordPolicy(Model model, boolean ignoreConsecutiveLetters) {
        PasswordPolicyResponseDto passwordPolicy = userManagementClient.getPasswordPolicy();
        if (passwordPolicy != null) {
            model.addAttribute(MIN_LENGTH,
                    passwordPolicy.getMinLength() > 0 ? passwordPolicy.getMinLength() : DEFAULT_MIN_LENGTH);
            model.addAttribute(MAX_LENGTH,
                    passwordPolicy.getMaxLength() > 0 ? passwordPolicy.getMaxLength() : DEFAULT_MAX_LENGTH);
            if (!ignoreConsecutiveLetters) {
                model.addAttribute(MIN_CON_LETTERS, passwordPolicy.getMinConsecutiveLettersLength());
            }
            model.addAttribute(MIN_SPECIALCHARS, passwordPolicy.getMinSpecialChars());
            model.addAttribute(ALLOWED_SPECIALCHARS, passwordPolicy.getAllowedSpecialChars());
            model.addAttribute(EXCLUDED_SPECIALCHARS, passwordPolicy.getExcludedSpecialChars());
            model.addAttribute(MIN_UPPERCASE, passwordPolicy.getMinUppercase());
            model.addAttribute(MIN_LOWERCASE, passwordPolicy.getMinLowercase());
            model.addAttribute(MIN_DIGITS, passwordPolicy.getMinDigits());
            model.addAttribute(PWD_NOTE, getPasswordPolicyMessages(passwordPolicy, ignoreConsecutiveLetters));
        } else {
            LOGGER.debug("No password policy received from user management service. Adding defaults...");
            passwordPolicy = addDefaultPwdPolicy(model, ignoreConsecutiveLetters);
        }
        model.addAttribute(PWD_NOTE, getPasswordPolicyMessages(passwordPolicy, ignoreConsecutiveLetters));
    }

    /**
     * This method generates a list of messages based on the password policy. It checks each policy attribute and adds
     * corresponding messages to the list if the attribute is positive.
     *
     * @param policy the password policy response DTO
     * @param ignoreConsecutiveLetters whether to ignore consecutive letters in the password policy
     * @return a list of messages describing the password policy
     */
    public List<String> getPasswordPolicyMessages(PasswordPolicyResponseDto policy, boolean ignoreConsecutiveLetters) {
        LOGGER.info("Creating Password Policy message for UI");
        List<String> messages = new ArrayList<>();
        if (policy == null) {
            return messages;
        }
        addIfPositive(messages, policy.getMinLength(),
                v -> PASSWORD_SHOULD_CONTAIN_ATLEAST + v + " characters minimum");
        addIfPositive(messages, policy.getMaxLength(), v -> "Password should contain " + v + " characters maximum");
        addIfPositive(messages, policy.getMinUppercase(), v -> PASSWORD_SHOULD_CONTAIN_ATLEAST + v + " Uppercase");
        addIfPositive(messages, policy.getMinLowercase(), v -> PASSWORD_SHOULD_CONTAIN_ATLEAST + v + "  Lowercase");
        addIfPositive(messages, policy.getMinDigits(), v -> PASSWORD_SHOULD_CONTAIN_ATLEAST + v + " Number");
        if (StringUtils.hasText(policy.getAllowedSpecialChars())) {
            addIfPositive(messages, policy.getMinSpecialChars(),
                    v -> "Password should contain  " + v + " special character and should not contain space.");
        }

        if (!ignoreConsecutiveLetters) {
            messages.add("Password must not contain email/username");
            addIfPositive(messages, policy.getMinConsecutiveLettersLength(),
                    v -> "Password must not contain a sequence of " + v + " characters from the username ");
        }

        if (StringUtils.hasText(policy.getExcludedSpecialChars())) {
            messages.add("Password should not contain special characters: " + policy.getExcludedSpecialChars());
        }
        return messages;
    }

    /**
     * Helper method to add a message to the list if the value is positive. Uses IntFunction for better type safety and
     * clarity.
     *
     * @param messages the list to add to
     * @param value the integer value to check
     * @param msg the message generator function
     */
    private void addIfPositive(List<String> messages, int value, java.util.function.IntFunction<String> msg) {
        if (value > 0) {
            messages.add(msg.apply(value));
        }
    }



    /**
     * This method adds default password policy values to the model and returns a PasswordPolicyResponseDto with those
     * default values.
     *
     * @param model the model to which default password policy attributes will be added
     * @return a PasswordPolicyResponseDto with default password policy values
     */
    private PasswordPolicyResponseDto addDefaultPwdPolicy(Model model, boolean ignoreConsecutiveLetters) {
        LOGGER.info("Creating Default Password Policy and message for UI");
        PasswordPolicyResponseDto passwordPolicyResponseDto = new PasswordPolicyResponseDto();
        passwordPolicyResponseDto.setMinLength(DEFAULT_MIN_LENGTH);
        passwordPolicyResponseDto.setMaxLength(DEFAULT_MAX_LENGTH);
        passwordPolicyResponseDto.setMinConsecutiveLettersLength(0);
        passwordPolicyResponseDto.setMinSpecialChars(0);
        passwordPolicyResponseDto.setAllowedSpecialChars(null);
        passwordPolicyResponseDto.setExcludedSpecialChars(null);
        passwordPolicyResponseDto.setMinUppercase(0);
        passwordPolicyResponseDto.setMinLowercase(0);
        passwordPolicyResponseDto.setMinDigits(0);
        model.addAttribute(MIN_LENGTH, DEFAULT_MIN_LENGTH);
        model.addAttribute(MAX_LENGTH, DEFAULT_MAX_LENGTH);
        if (!ignoreConsecutiveLetters) {
            model.addAttribute(MIN_CON_LETTERS, 1);
        } 
        model.addAttribute(MIN_SPECIALCHARS, 1);
        model.addAttribute(ALLOWED_SPECIALCHARS, DEFAULT_ALLOWEDSPECIALCHARS);
        model.addAttribute(EXCLUDED_SPECIALCHARS, DEFAULT_EXCLUDEDSPECIALCHARS);
        model.addAttribute(MIN_UPPERCASE, 1);
        model.addAttribute(MIN_LOWERCASE, 1);
        model.addAttribute(MIN_DIGITS, 1);
        model.addAttribute(PWD_NOTE, getPasswordPolicyMessages(passwordPolicyResponseDto, ignoreConsecutiveLetters));
        model.addAttribute(MIN_LENGTH, DEFAULT_MIN_LENGTH);
        model.addAttribute(MAX_LENGTH, DEFAULT_MAX_LENGTH);
        return passwordPolicyResponseDto;
    }
}
