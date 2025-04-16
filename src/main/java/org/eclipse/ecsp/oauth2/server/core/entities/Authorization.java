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

package org.eclipse.ecsp.oauth2.server.core.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.time.Instant;

/**
 * The Authorization class represents an OAuth 2.0 Authorization entity in the database.
 * It holds state related to the authorization granted.
 */
@Getter
@Setter
@Entity
@ToString
@Table(name = "`authorization`")
public class Authorization {
    @Id
    private String id;
    @Column(name = "REGISTERED_CLIENT_ID")
    private String registeredClientId;
    @Column(name = "PRINCIPAL_NAME")
    private String principalName;
    @Column(name = "AUTHORIZATION_GRANT_TYPE")
    private String authorizationGrantType;
    @Column(name = "AUTHORIZED_SCOPES", length = 1000)
    private String authorizedScopes;
    @Column(length = 20000)
    private String attributes;
    @Column(length = 500)
    private String state;

    @Column(name = "AUTHORIZATION_CODE_VALUE", length = 8000)
    private String authorizationCodeValue;
    @Column(name = "AUTHORIZATION_CODE_ISSUED_AT")
    private Instant authorizationCodeIssuedAt;
    @Column(name = "AUTHORIZATION_CODE_EXPIRES_AT")
    private Instant authorizationCodeExpiresAt;
    @Column(name = "AUTHORIZATION_CODE_METADATA")
    private String authorizationCodeMetadata;

    @Column(name = "ACCESS_TOKEN_VALUE", length = 8000)
    private String accessTokenValue;
    @Column(name = "ACCESS_TOKEN_ISSUED_AT")
    private Instant accessTokenIssuedAt;
    @Column(name = "ACCESS_TOKEN_EXPIRES_AT")
    private Instant accessTokenExpiresAt;
    @Column(name = "ACCESS_TOKEN_METADATA", length = 4192)
    private String accessTokenMetadata;
    @Column(name = "ACCESS_TOKEN_TYPE")
    private String accessTokenType;
    @Column(name = "ACCESS_TOKEN_SCOPES", length = 1000)
    private String accessTokenScopes;

    @Column(name = "REFRESH_TOKEN_VALUE", length = 8000)
    private String refreshTokenValue;
    @Column(name = "REFRESH_TOKEN_ISSUED_AT")
    private Instant refreshTokenIssuedAt;
    @Column(name = "REFRESH_TOKEN_EXPIRES_AT")
    private Instant refreshTokenExpiresAt;
    @Column(name = "REFRESH_TOKEN_METADATA", length = 4192)
    private String refreshTokenMetadata;

    @Column(name = "OIDC_ID_TOKEN_VALUE", length = 8000)
    private String oidcIdTokenValue;
    @Column(name = "OIDC_ID_TOKEN_ISSUED_AT")
    private Instant oidcIdTokenIssuedAt;
    @Column(name = "OIDC_ID_TOKEN_EXPIRES_AT")
    private Instant oidcIdTokenExpiresAt;
    @Column(name = "OIDC_ID_TOKEN_METADATA", length = 2000)
    private String oidcIdTokenMetadata;
    @Column(name = "OIDC_ID_TOKEN_CLAIMS", length = 2000)
    private String oidcIdTokenClaims;

    @Column(name = "USER_CODE_VALUE", length = 8000)
    private String userCodeValue;
    @Column(name = "USER_CODE_ISSUED_AT")
    private Instant userCodeIssuedAt;
    @Column(name = "USER_CODE_EXPIRES_AT")
    private Instant userCodeExpiresAt;
    @Column(name = "USER_CODE_METADATA", length = 2000)
    private String userCodeMetadata;

    @Column(name = "DEVICE_CODE_VALUE", length = 8000)
    private String deviceCodeValue;
    @Column(name = "DEVICE_CODE_ISSUED_AT")
    private Instant deviceCodeIssuedAt;
    @Column(name = "DEVICE_CODE_EXPIRES_AT")
    private Instant deviceCodeExpiresAt;
    @Column(name = "DEVICE_CODE_METADATA", length = 2000)
    private String deviceCodeMetadata;
}

