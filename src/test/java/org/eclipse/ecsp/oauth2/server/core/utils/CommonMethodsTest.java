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

import org.junit.jupiter.api.Test;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MULTI_ROLE_CLIENT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.SINGLE_ROLE_CLIENT;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This class tests the functionality of the CommonMethodsUtils class.
 */
class CommonMethodsTest {

    /**
     * This test method tests the scenario where the client type is MULTI_ROLE_CLIENT and the tenant configuration
     * parameter for scope customization is true.
     * It asserts that the isUserScopeValidationRequired method returns false.
     */
    @Test
    void isUserScopeValidationRequiredWhenMultiRoleClient() {
        boolean isUserScopeValReq =
                CommonMethodsUtils.isUserScopeValidationRequired(MULTI_ROLE_CLIENT, true);
        assertFalse(isUserScopeValReq);
    }

    /**
     * This test method tests the scenario where the client type is SINGLE_ROLE_CLIENT and the tenant configuration
     * parameter for scope customization is true.
     * It asserts that the isUserScopeValidationRequired method returns true.
     */
    @Test
    void isUserScopeValidationRequiredWhenSingleRoleClient() {
        boolean isUserScopeValReq =
                CommonMethodsUtils.isUserScopeValidationRequired(SINGLE_ROLE_CLIENT, true);
        assertTrue(isUserScopeValReq);
    }

    /**
     * This test method tests the scenario where there is no client type and the tenant configuration parameter for
     * scope customization is true.
     * It asserts that the isUserScopeValidationRequired method returns false.
     */
    @Test
    void isUserScopeValidationRequiredWhenNoClientTypeAndTenantConfigParamScopeCustomizationReqTrue() {
        boolean isUserScopeValReq =
                CommonMethodsUtils.isUserScopeValidationRequired(null, true);
        assertFalse(isUserScopeValReq);
    }

    /**
     * This test method tests the scenario where there is no client type and the tenant configuration parameter for
     * scope customization is false.
     * It asserts that the isUserScopeValidationRequired method returns true.
     */
    @Test
    void isUserScopeValidationRequiredWhenNoClientTypeAndTenantConfigParamScopeCustomizationReqFalse() {
        boolean isUserScopeValReq =
                CommonMethodsUtils.isUserScopeValidationRequired(null, false);
        assertTrue(isUserScopeValReq);
    }

    /**
     * This test method tests the scenario where the client type is MULTI_ROLE_CLIENT and there is no tenant
     * configuration parameter for scope customization.
     * It asserts that the isUserScopeValidationRequired method returns false.
     */
    @Test
    void isUserScopeValidationRequiredWhenMultiRoleClientAndTenantPropEmpty() {
        boolean isUserScopeValReq =
                CommonMethodsUtils.isUserScopeValidationRequired(MULTI_ROLE_CLIENT, null);
        assertFalse(isUserScopeValReq);
    }

    /**
     * This test method tests the scenario where the client type is SINGLE_ROLE_CLIENT and there is no tenant
     * configuration parameter for scope customization.
     * It asserts that the isUserScopeValidationRequired method returns true.
     */
    @Test
    void isUserScopeValidationRequiredWhenSingleRoleClientAndTenantPropEmpty() {
        boolean isUserScopeValReq =
                CommonMethodsUtils.isUserScopeValidationRequired(SINGLE_ROLE_CLIENT, null);
        assertTrue(isUserScopeValReq);
    }

}