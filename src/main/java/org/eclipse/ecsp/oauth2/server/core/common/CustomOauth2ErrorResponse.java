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

package org.eclipse.ecsp.oauth2.server.core.common;

import lombok.Builder;

/**
 * CustomOauth2ErrorResponse is a record class that encapsulates information about an OAuth2 error response.
 *
 * @param error The error message associated with the OAuth2 error response.
 * @param errorDescription A detailed description of the error.
 * @param errorCode The code associated with the error.
 * @param timestamp The timestamp when the error was received.
 */
@Builder
public record CustomOauth2ErrorResponse(String error,
                                        String errorDescription,
                                        String errorCode,
                                        String timestamp){}
