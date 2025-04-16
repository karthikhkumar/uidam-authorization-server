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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The KeyGenerationException class extends the RuntimeException class.
 * This class represents a custom exception that is thrown when there is an error while generating an RSA key.
 */
public class KeyGenerationException extends RuntimeException {
    private static final Logger LOGGER = LoggerFactory.getLogger(KeyGenerationException.class);

    /**
     * This is a parameterized constructor for the KeyGenerationException class.
     * It initializes the superclass with the provided exception.
     *
     * @param exception an Exception instance representing the key generation exception
     */
    public KeyGenerationException(Exception exception) {
        super(exception);
        LOGGER.error(exception.getMessage());
    }
}
