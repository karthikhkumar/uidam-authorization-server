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

package org.eclipse.ecsp.oauth2.server.core.exception;

import org.eclipse.ecsp.oauth2.server.core.common.CustomOauth2TokenGenErrorCodes;

/**
 * CustomOauth2AuthorizationException is a custom exception class that extends RuntimeException.
 * This class is used to handle OAuth2 Authorization exceptions in the application.
 */
public class CustomOauth2AuthorizationException extends RuntimeException {

    private static final long serialVersionUID = 4122354761010744667L;

    private final String id;
    private final int statusCode;

    /**
     * Constructs a new CustomOauth2AuthorizationException with the specified CustomOauth2TokenGenErrorCodes.
     * The error code is used to set the id and statusCode fields of the exception.
     * The id field represents the error code and the statusCode field represents the HTTP status code associated with
     * the error.
     *
     * @param sp the CustomOauth2TokenGenErrorCodes object representing the error code
     */
    public CustomOauth2AuthorizationException(CustomOauth2TokenGenErrorCodes sp) {
        super(sp.getDescription());
        this.id = sp.getCode();
        this.statusCode = sp.getStatus();
    }

    /**
     * Returns the error code of this CustomOauth2AuthorizationException.
     *
     * @return the error code
     */
    public String getId() {
        return id;
    }

    /**
     * Returns the HTTP status code of this CustomOauth2AuthorizationException.
     *
     * @return the HTTP status code
     */
    public int getStatusCode() {
        return statusCode;
    }

}
