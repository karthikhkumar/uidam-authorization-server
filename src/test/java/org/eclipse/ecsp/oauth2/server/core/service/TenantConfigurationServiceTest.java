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

package org.eclipse.ecsp.oauth2.server.core.service;

import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_CONTACT_NAME;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EMAIL;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_IDP_CLIENT_ID;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_IDP_CLIENT_SECRET;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_CLIENT_BY_CLIENT_ID_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_USER_BY_USERNAME_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_KEYSTORE_ALIAS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_KEYSTORE_FILENAME;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_KEYSTORE_PASS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_PHONE_NUMBER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.UIDAM;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.ENFORCE_AFTER_FAILURE_COUNT;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * This class tests the functionality of the TenantConfigurationService.
 */
@ExtendWith(SpringExtension.class)
@EnableConfigurationProperties(value = TenantProperties.class)
@ContextConfiguration(classes = {TenantConfigurationService.class})
@TestPropertySource("classpath:application-test.properties")
class TenantConfigurationServiceTest {
    @Autowired
    private TenantConfigurationService tenantConfigurationService;

    /**
     * This test method tests the getTenantProperties method of the TenantConfigurationService.
     * It asserts that the returned TenantProperties object has the expected values for its properties.
     */
    @Test
    void getTenantPropertiesTest() {
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties(UIDAM);
        assertEquals("uidam", tenantProperties.getTenantId());
        assertEquals("uidam", tenantProperties.getTenantName());
        assertEquals("ecsp", tenantProperties.getAlias());
        assertEquals(1, tenantProperties.getClient().getAccessTokenTtl());
        assertEquals(1, tenantProperties.getClient().getIdTokenTtl());
        assertEquals(1, tenantProperties.getClient().getRefreshTokenTtl());
        assertEquals(1, tenantProperties.getClient().getAuthCodeTtl());
        assertEquals(false, tenantProperties.getClient().getReuseRefreshToken());
        assertEquals("ChangeMe", tenantProperties.getClient().getSecretEncryptionKey());
        assertEquals("ChangeMe", tenantProperties.getClient().getSecretEncryptionSalt());
        assertEquals("admin", tenantProperties.getContactDetails().get(TENANT_CONTACT_NAME));
        assertEquals("8888888888", tenantProperties.getContactDetails().get(TENANT_PHONE_NUMBER));
        assertEquals("john.doe@domain.com", tenantProperties.getContactDetails().get(TENANT_EMAIL));
        assertEquals(ENFORCE_AFTER_FAILURE_COUNT, tenantProperties.getUser().getCaptchaAfterInvalidFailures());
        assertEquals(Boolean.FALSE, tenantProperties.getUser().getCaptchaRequired());
        assertEquals("ecsp", tenantProperties.getAccount().getAccountId());
        assertEquals("ecsp", tenantProperties.getAccount().getAccountName());
        assertEquals("ecsp", tenantProperties.getAccount().getAccountType());
        assertEquals("ignite", tenantProperties.getExternalIdpDetails().get(TENANT_EXTERNAL_IDP_CLIENT_ID));
        assertEquals("secret", tenantProperties.getExternalIdpDetails().get(TENANT_EXTERNAL_IDP_CLIENT_SECRET));
        assertEquals("/v1/users/{userName}/byUserName", tenantProperties.getExternalUrls()
                .get(TENANT_EXTERNAL_URLS_USER_BY_USERNAME_ENDPOINT));
        assertEquals("/v1/oauth2/client/{clientId}", tenantProperties.getExternalUrls().get(
                TENANT_EXTERNAL_URLS_CLIENT_BY_CLIENT_ID_ENDPOINT));
        assertEquals("uidamauthserver.jks", tenantProperties.getKeyStore().get(TENANT_KEYSTORE_FILENAME));
        assertEquals("uidam-test-pwd", tenantProperties.getKeyStore().get(TENANT_KEYSTORE_PASS));
        assertEquals("uidam-dev", tenantProperties.getKeyStore().get(TENANT_KEYSTORE_ALIAS));
    }
}