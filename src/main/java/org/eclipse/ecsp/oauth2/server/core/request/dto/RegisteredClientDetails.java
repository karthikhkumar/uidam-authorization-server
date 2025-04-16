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

package org.eclipse.ecsp.oauth2.server.core.request.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import lombok.Getter;
import lombok.Setter;
import org.eclipse.ecsp.oauth2.server.core.response.BaseResponse;

import java.util.List;
import java.util.Set;

/**
 * The RegisteredClientDetails class represents the details of a registered client received from UIDAM Auth Management.
 */
@Getter
@Setter
@JsonInclude(Include.NON_NULL)
public class RegisteredClientDetails extends BaseResponse {

    private String clientId;
    private String clientSecret;
    private String secretEncoder;
    private String clientName;
    private String tenantId;
    private List<String> clientAuthenticationMethods;
    private List<String> authorizationGrantTypes;
    private List<String> redirectUris;
    private Set<String> scopes;
    private long  accessTokenValidity;
    private long  refreshTokenValidity;
    private long  authorizationCodeValidity;
    private String additionalInformation;
    private boolean requireAuthorizationConsent;
    private boolean requireProofKey;

    private String clientType;
    private String accountType;
    private String accountName;
    private String accountId;


}
