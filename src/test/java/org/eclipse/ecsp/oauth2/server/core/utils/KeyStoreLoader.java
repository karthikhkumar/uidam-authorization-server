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

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;

/**
 * Utility class for loading private keys from a keystore.
 */
public class KeyStoreLoader {

    private KeyStoreLoader() {
    }

    /**
     * Loads a private key from the specified keystore file.
     *
     * @param keystoreFile the name of the keystore file
     * @param alias the alias of the key in the keystore
     * @param keystorePassword the password of the keystore
     * @param keyPassword the password of the key
     * @return the private key
     * @throws Exception if an error occurs while loading the key
     */
    public static PrivateKey loadPrivateKey(String keystoreFile, String alias, String keystorePassword,
                                            String keyPassword) throws Exception {
        try (InputStream inputStream = KeyStoreLoader.class.getClassLoader().getResourceAsStream(keystoreFile)) {
            if (inputStream == null) {
                throw new FileNotFoundException("Keystore file not found: " + keystoreFile);
            }
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(inputStream, keystorePassword.toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(keyPassword.toCharArray());
            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, protParam);
            return pkEntry.getPrivateKey();
        }
    }
}