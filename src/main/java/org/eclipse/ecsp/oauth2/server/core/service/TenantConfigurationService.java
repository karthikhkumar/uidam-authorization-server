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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.UIDAM;

/**
 * This service class is used to manage tenant configurations.
 */
@Service
public class TenantConfigurationService {

    private Map<String, TenantProperties> propertiesHashMap = new ConcurrentHashMap<>();

    /**
     * Constructor for TenantConfigurationService.
     * It initializes the tenant properties map with the provided tenant properties, using the UIDAM constant as the
     * key.
     *
     * @param tenantProperties the tenant properties to be stored in the map
     */
    @Autowired
    public TenantConfigurationService(TenantProperties tenantProperties) {
        propertiesHashMap.put(UIDAM, tenantProperties);
    }

    /**
     * This method retrieves the tenant properties for a given tenant ID.
     * It returns the tenant properties from the map using the provided tenant ID as the key.
     *
     * @param tenantId the ID of the tenant whose properties are to be retrieved
     * @return the tenant properties for the given tenant ID
     */
    public TenantProperties getTenantProperties(String tenantId) {
        return propertiesHashMap.get(tenantId);
    }
}
