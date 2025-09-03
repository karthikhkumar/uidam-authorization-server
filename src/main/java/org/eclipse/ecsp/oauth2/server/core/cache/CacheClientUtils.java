/*
 * Copyright (c) 2023 - 2024 Harman International
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.eclipse.ecsp.oauth2.server.core.cache;

import org.apache.commons.lang3.StringUtils;
import org.eclipse.ecsp.oauth2.server.core.util.SessionTenantResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Service class for handling client cache details.
 */
@Service
public class CacheClientUtils {

    @Autowired
    CacheClientService cacheClientService;

    @Value("${cache.client.ids}")
    private String cacheClientIds;

    /**
     * Retrieves client details based on the provided client ID.
     * If caching is enabled for all clients, it fetches the details with synchronization.
     * Otherwise, it fetches the details without synchronization.
     * The current tenant is automatically resolved and included in the cache key.
     *
     * @param clientId the ID of the client to retrieve details for
     * @return the client cache details
     */
    public ClientCacheDetails getClientDetails(String clientId) {
        String tenantId = SessionTenantResolver.getCurrentTenant();
        if (StringUtils.isNotEmpty(cacheClientIds) && (cacheClientIds.equalsIgnoreCase("ALL"))) {
            return cacheClientService.getClientDetailsWithSync(clientId, tenantId);
        } else {
            return cacheClientService.getClientDetailsWithoutSync(clientId, tenantId);
        }
    }

}