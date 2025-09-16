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

package org.eclipse.ecsp.oauth2.server.core.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception thrown when tenant resolution fails in multi-tenant OAuth2 flows. This exception indicates that no valid
 * tenant could be resolved from any available source (ThreadLocal, SecurityContext, Session, or Database) for the
 * current request.
 */
public class TenantResolutionException extends UidamApplicationException {

    private static final long serialVersionUID = -6292067140968396185L;
    
    private static final String TENANT_RESOLUTION_FAILED = "TENANT_RESOLUTION_FAILED";
    private static final String TENANT_NOT_FOUND_IN_REQUEST = "TENANT_NOT_FOUND_IN_REQUEST";

    /**
     * Constructor for general tenant resolution failure.
     *
     * @param sessionId the session ID for which tenant resolution failed
     */
    public TenantResolutionException(String sessionId) {
        super(TENANT_RESOLUTION_FAILED, HttpStatus.BAD_REQUEST, sessionId);
    }

    /**
     * Constructor for tenant not found in request.
     *
     * @param requestUri the request URI that lacks tenant information
     */
    public static TenantResolutionException tenantNotFoundInRequest(String requestUri) {
        return new TenantResolutionException(TENANT_NOT_FOUND_IN_REQUEST, HttpStatus.BAD_REQUEST, requestUri);
    }

    /**
     * Constructor for invalid tenant configuration.
     *
     * @param tenantId the invalid tenant ID
     * @param requestUri the request URI with the invalid tenant
     */
    public static TenantResolutionException invalidTenant(String tenantId, String requestUri) {
        return new TenantResolutionException(TENANT_RESOLUTION_FAILED, HttpStatus.BAD_REQUEST, tenantId, requestUri);
    }

    /**
     * Private constructor for specific error types.
     */
    private TenantResolutionException(String key, HttpStatus httpStatus, String... values) {
        super(key, httpStatus, values);
    }

}
