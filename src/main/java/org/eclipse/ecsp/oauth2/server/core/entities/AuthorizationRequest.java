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
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.math.BigInteger;
import java.sql.Timestamp;

/**
 * The AuthorizationRequest class represents an OAuth2 authorization request in the system.
 * This class holds state of the authorization request.
 */
@Getter
@Setter
@Entity
@ToString
@Table(name = "`authorization_request`")
public class AuthorizationRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false, updatable = false, columnDefinition = "NUMERIC(38) DEFAULT get_uuid()")
    private BigInteger id;
    @Column(name = "STATE")
    private String state;
    @Column(name = "ADDITIONAL_PARAMETERS")
    private String additionalParameters;
    @Column(name = "AUTHORIZATION_REQUEST_URI", nullable = false)
    private String authorizationRequestUri;
    @Column(name = "ATTRIBUTES", nullable = false)
    private String attributes;
    @Column(name = "SESSION_ID", nullable = false)
    private String sessionId;
    @Column(name = "CREATED_DATE", nullable = false)
    private Timestamp createdDate;
    @Column(name = "UPDATED_DATE")
    private Timestamp updatedDate;

}