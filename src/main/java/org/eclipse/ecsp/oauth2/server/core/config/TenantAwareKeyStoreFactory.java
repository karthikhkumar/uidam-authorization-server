package org.eclipse.ecsp.oauth2.server.core.config;

import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_JWT_PRIVATE_KEY;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_JWT_PUBLIC_KEY;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_KEYSTORE_ALIAS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_KEYSTORE_FILENAME;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_KEYSTORE_JKS_ENCODED_CONTENT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_KEYSTORE_PASS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_KEYSTORE_TYPE;

/**
 * Factory for creating tenant-aware KeyStore configurations. This factory provides lazy evaluation and caching of
 * KeyStore objects per tenant. Components are created only when needed during request processing with proper tenant
 * context.
 */
@Component
public class TenantAwareKeyStoreFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(TenantAwareKeyStoreFactory.class);

    private final TenantConfigurationService tenantConfigurationService;
    private final Map<String, KeyStore> keyStoreCache = new ConcurrentHashMap<>();
    private final Map<String, KeyPair> keyPairCache = new ConcurrentHashMap<>();

    public TenantAwareKeyStoreFactory(TenantConfigurationService tenantConfigurationService) {
        this.tenantConfigurationService = tenantConfigurationService;
    }

    /**
     * Get KeyStore for current tenant with lazy evaluation and caching. This method is called during request processing
     * when tenant context is available.
     *
     * @return KeyStore for current tenant
     */
    public KeyStore getKeyStoreForCurrentTenant() {
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        if (tenantProperties == null) {
            throw new IllegalStateException("No tenant properties available for current request");
        }
        String cacheKey = tenantProperties.getTenantId() + "-" 
            + tenantProperties.getKeyStore().get(TENANT_KEYSTORE_FILENAME);
        LOGGER.info("Cache key in getKeyStoreForCurrentTenant : {}", cacheKey);
        return keyStoreCache.computeIfAbsent(cacheKey, k -> createKeyStore(tenantProperties));
    }

    /**
     * Get RSA KeyPair for current tenant with lazy evaluation and caching. This method supports both Java KeyStore and
     * PEM file sources.
     *
     * @return RSA KeyPair for current tenant
     */
    public KeyPair getRsaKeyPairForCurrentTenant() {
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        if (tenantProperties == null) {
            throw new IllegalStateException("No tenant properties available for current request");
        }

        // Create cache key based on tenant's key configuration
        String cacheKey = tenantProperties.getTenantId() + "-" 
            + createKeyPairCacheKey(tenantProperties);
        return keyPairCache.computeIfAbsent(cacheKey, k -> createKeyPair(tenantProperties));
    }
    
    /**
     * Get Public Key from Java KeyStore.
     */
    public PublicKey getCurrentTenantPublicKey()
            throws KeyStoreException {
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        KeyStore keyStore = getKeyStoreForCurrentTenant();
        String keyAlias = tenantProperties.getKeyStore().get(TENANT_KEYSTORE_ALIAS);

        return keyStore.getCertificate(keyAlias).getPublicKey();
    }

    /**
     * Create KeyStore from Java KeyStore file for the given tenant.
     */
    private KeyStore createKeyStore(TenantProperties tenantProperties) {
        try {
            String keyStoreLocation = tenantProperties.getKeyStore().get(TENANT_KEYSTORE_FILENAME);
            String keyStoreJksEncodedContent = tenantProperties.getKeyStore().get(TENANT_KEYSTORE_JKS_ENCODED_CONTENT);
            String keyStorePassword = tenantProperties.getKeyStore().get(TENANT_KEYSTORE_PASS);
            String keyStoreType = tenantProperties.getKeyStore().get(TENANT_KEYSTORE_TYPE);

            LOGGER.info("Creating KeyStore for tenant from: Teannt {} KeystoreLocation {}", 
                    tenantProperties.getTenantId(), keyStoreLocation);

            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            if (keyStoreJksEncodedContent != null && !keyStoreJksEncodedContent.isEmpty()) {
                LOGGER.info("KeyStore loading from Encoded String");
                byte[] decodedBytes = Base64.getDecoder().decode(keyStoreJksEncodedContent);
                try (ByteArrayInputStream bais = new ByteArrayInputStream(decodedBytes)) {
                    keyStore.load(bais, keyStorePassword.toCharArray());
                }
            } else {
                LOGGER.info("KeyStore loading from PEM file");
                try (FileInputStream keyStoreData = new FileInputStream(keyStoreLocation)) {
                    keyStore.load(keyStoreData, keyStorePassword.toCharArray());
                }
            }

            LOGGER.info("Successfully loaded KeyStore for tenant");
            return keyStore;

        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            LOGGER.error("Failed to create KeyStore for tenant: {}", e.getMessage());
            throw new RuntimeException("Failed to create KeyStore for tenant", e);
        }
    }

    /**
     * Create RSA KeyPair from tenant properties (supports both KeyStore and PEM sources).
     */
    private KeyPair createKeyPair(TenantProperties tenantProperties) {
        try {
            // Check if using Java KeyStore approach
            if (tenantProperties.getKeyStore() != null
                    && tenantProperties.getKeyStore().get(TENANT_KEYSTORE_FILENAME) != null) {
                return createKeyPairFromKeyStore(tenantProperties);
            } else if (tenantProperties.getCert() != null
                    && tenantProperties.getCert().get(TENANT_JWT_PUBLIC_KEY) != null) {
                return createKeyPairFromPemFiles(tenantProperties);
            } else {
                throw new IllegalStateException("No valid key configuration found for tenant");
            }
        } catch (Exception e) {
            LOGGER.error("Failed to create RSA KeyPair for tenant: ", e);
            throw new RuntimeException("Failed to create RSA KeyPair for tenant", e);
        }
    }

    /**
     * Create RSA KeyPair from Java KeyStore.
     */
    private KeyPair createKeyPairFromKeyStore(TenantProperties tenantProperties)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {

        KeyStore keyStore = getKeyStoreForCurrentTenant();
        String keyAlias = tenantProperties.getKeyStore().get(TENANT_KEYSTORE_ALIAS);
        String keyPassword = tenantProperties.getKeyStore().get(TENANT_KEYSTORE_PASS);

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPassword.toCharArray());
        PublicKey publicKey = keyStore.getCertificate(keyAlias).getPublicKey();

        LOGGER.info("Successfully created RSA KeyPair from KeyStore for tenant");
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Create RSA KeyPair from PEM files.
     */
    private KeyPair createKeyPairFromPemFiles(TenantProperties tenantProperties) {
        // This would use the existing PEM file loading logic from KeyStoreConfigByPubPvtKey
        // Implementation details would be moved here from the original class
        throw new UnsupportedOperationException("PEM file loading to be implemented");
    }

    /**
     * Create cache key for KeyPair based on tenant's key configuration.
     */
    private String createKeyPairCacheKey(TenantProperties tenantProperties) {
        if (tenantProperties.getKeyStore() != null
                && tenantProperties.getKeyStore().get(TENANT_KEYSTORE_FILENAME) != null) {
            return "keystore:" + tenantProperties.getKeyStore().get(TENANT_KEYSTORE_FILENAME) + ":"
                    + tenantProperties.getKeyStore().get(TENANT_KEYSTORE_ALIAS);
        } else if (tenantProperties.getCert() != null
                && tenantProperties.getCert().get(TENANT_JWT_PUBLIC_KEY) != null) {
            return "pem:" + tenantProperties.getCert().get(TENANT_JWT_PUBLIC_KEY) + ":"
                    + tenantProperties.getCert().get(TENANT_JWT_PRIVATE_KEY);
        } else {
            throw new IllegalStateException("No valid key configuration for cache key generation");
        }
    }

    /**
     * Clear cache for testing or configuration reload.
     */
    public void clearCache() {
        keyStoreCache.clear();
        keyPairCache.clear();
        LOGGER.info("Cleared KeyStore and KeyPair caches");
    }

    /**
     * Get cache statistics for monitoring.
     */
    public String getCacheStats() {
        return String.format("KeyStore cache: %d entries, KeyPair cache: %d entries", keyStoreCache.size(),
                keyPairCache.size());
    }
}
