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

package org.eclipse.ecsp.oauth2.server.core.config;

import com.nimbusds.jose.jwk.RSAKey;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.exception.KeyGenerationException;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * The KeyStoreConfigByPubPvtKey class is a configuration class that uses a public/private key pair for generating RSA
 * keys.
 */
@Configuration
public class KeyStoreConfigByPubPvtKey {
    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreConfigByPubPvtKey.class);

    private final TenantConfigurationService tenantConfigurationService;

    /**
     * Constructor for KeyStoreConfigByPubPvtKey.
     * Uses TenantConfigurationService for tenant-aware operations during request processing.
     *
     * @param tenantConfigurationService Service for tenant-aware configuration operations
     */
    public KeyStoreConfigByPubPvtKey(TenantConfigurationService tenantConfigurationService) {
        this.tenantConfigurationService = tenantConfigurationService;
        LOGGER.info("Initialized KeyStoreConfigByPubPvtKey with TenantConfigurationService");
    }

    /**
     * Generate RSA Key for current tenant by reading PEM files.
     * This method is called during request processing when tenant context is available.
     *
     * @return RSAKey for current tenant (from PEM files)
     */
    public RSAKey generateRsaKey() {
        LOGGER.debug("Generating RSA Key for current tenant using PEM files");
        
        try {
            // Get tenant properties for current tenant context
            TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
            
            // Generate public and private keys from PEM files
            RSAPublicKey publicKey = generatePublicKey(tenantProperties);
            RSAPrivateKey privateKey = generatePrivateKey(tenantProperties);
            
            // Get key ID from tenant properties
            String keyId = tenantProperties.getCert().get("tenant-jwt-key-id");
            
            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(keyId != null ? keyId : "default-key-id")
                    .build();
            
        } catch (Exception e) {
            LOGGER.error("Failed to generate RSA key for current tenant: {}", e.getMessage(), e);
            throw new KeyGenerationException(e);
        }
    }

    /**
     * Generate RSA Public Key from PEM file for tenant.
     *
     * @param tenantProperties Tenant properties containing certificate configuration
     * @return RSAPublicKey generated from PEM file
     */
    private RSAPublicKey generatePublicKey(TenantProperties tenantProperties) {
        LOGGER.debug("## generatePublicKey - START");
        RSAPublicKey rsaPublicKey;
        try {
            String key = getFile(tenantProperties.getCert().get("tenant-jwt-public-key"));
            String publicKeyPem = key.replace("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PUBLIC KEY-----", "");
            byte[] decoded = Base64.getDecoder().decode(publicKeyPem);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
            rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception exception) {
            throw new KeyGenerationException(exception);
        }
        LOGGER.debug("## generatePublicKey - END");
        return rsaPublicKey;
    }

    /**
     * Generate RSA Private Key from PEM file for tenant.
     *
     * @param tenantProperties Tenant properties containing certificate configuration
     * @return RSAPrivateKey generated from PEM file
     */
    private RSAPrivateKey generatePrivateKey(TenantProperties tenantProperties) {
        LOGGER.debug("## generatePrivateKey - START");
        RSAPrivateKey rsaPrivateKey;
        try {
            String key = getFile(tenantProperties.getCert().get("tenant-jwt-private-key"));
            String privateKeyPem = key.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PRIVATE KEY-----", "");
            byte[] decoded = Base64.getDecoder().decode(privateKeyPem);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
            rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception exception) {
            throw new KeyGenerationException(exception);
        }
        LOGGER.debug("## generatePrivateKey - END");
        return rsaPrivateKey;
    }

    /**
     * Read file content from classpath.
     *
     * @param fileName Name of file to read
     * @return File content as string
     */
    private String getFile(String fileName) {
        try {
            ClassPathResource resource = new ClassPathResource(fileName);
            StringBuilder content = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line).append(System.lineSeparator());
                }
            }
            return content.toString();
        } catch (Exception exception) {
            throw new KeyGenerationException(exception);
        }
    }
}
