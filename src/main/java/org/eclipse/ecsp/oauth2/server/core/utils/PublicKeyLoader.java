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

package org.eclipse.ecsp.oauth2.server.core.utils;

import org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Utility class for loading a public key from an input stream.
 */
public class PublicKeyLoader {

    private static final Logger LOGGER = LoggerFactory.getLogger(PublicKeyLoader.class);

    private PublicKeyLoader() {
    }

    /**
     * Loads a public key from the provided input stream.
     *
     * @param inputStream the input stream containing the public key data
     * @return the loaded public key
     * @throws Exception if an error occurs while loading the public key
     */
    public static PublicKey loadPublicKey(InputStream inputStream) throws Exception {
        LOGGER.info("## loadPublicKey - START");

        // Read all bytes from the input stream
        byte[] keyBytes = inputStream.readAllBytes();

        // Convert the byte array to a string
        String keyString = new String(keyBytes);

        // Remove the BEGIN and END markers and any whitespace
        keyString = keyString
                .replaceAll(AuthorizationServerConstants.BEGIN_PUBLIC_KEY, "")
                .replaceAll(AuthorizationServerConstants.END_PUBLIC_KEY, "")
                .replaceAll("\\s", "");

        // Decode the base64 encoded key string
        byte[] decodedKey = Base64.getDecoder().decode(keyString);

        // Create a specification for the public key
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedKey);

        // Get an RSA key factory
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // Generate the public key from the specification
        PublicKey publicKey = keyFactory.generatePublic(spec);

        LOGGER.info("## loadPublicKey - END");
        return publicKey;
    }
}