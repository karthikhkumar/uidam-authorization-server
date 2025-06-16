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

package org.eclipse.ecsp.oauth2.server.core.response.dto;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

/**
 * The PasswordPolicyResponseDto class represents the password policy settings.
 * It includes the minimum and maximum length requirements for passwords.
 * Additional requirements such as uppercase, lowercase, digit, and special character
 * constraints can be added as needed.
 */
@Getter
@Setter
public class PasswordPolicyResponseDto implements Serializable {

    private static final long serialVersionUID = 3558606548747012883L;
    private int minLength;
    private int maxLength;
    private int minConsecutiveLettersLength;
    private int minSpecialChars;
    private String allowedSpecialChars;
    private String excludedSpecialChars;
    private int minUppercase;
    private int minLowercase;
    private int minDigits;

}
