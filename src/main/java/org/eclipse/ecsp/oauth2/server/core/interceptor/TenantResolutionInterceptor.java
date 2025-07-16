/********************************************************************************
 * Copyright (c) 2023-24 Harman International 
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0  
 *  
 * <p>Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.ecsp.oauth2.server.core.config.TenantContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Interceptor to resolve and set tenant context from HTTP request. Runs with highest precedence to ensure tenant
 * context is available to all subsequent components. Supports multiple tenant resolution strategies: 1. Header-based
 * (X-Tenant-ID) 2. Subdomain-based (tenant.domain.com) 3. Path-based (/tenant/{tenantId}/...) 4. Parameter-based
 * (?tenantId=...)
 */
@Component 
@Order(Ordered.HIGHEST_PRECEDENCE)
public class TenantResolutionInterceptor implements HandlerInterceptor {

    private static final int INTEGER_TWO = 2;

    private static final Logger LOGGER = LoggerFactory.getLogger(TenantResolutionInterceptor.class);

    private static final String TENANT_HEADER = "X-Tenant-ID";
    private static final String TENANT_PARAM = "tenantId";
    private static final String TENANT_PATH_PREFIX = "/tenant/";

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String tenantId = resolveTenantId(request);
        TenantContext.setCurrentTenant(tenantId);
        LOGGER.debug("Resolved tenant: {} for request: {}", tenantId, request.getRequestURI());
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler,
            Exception ex) {
        TenantContext.clear();
    }

    /**
     * Resolve tenant ID from request using multiple strategies:
     * 1. Header (X-Tenant-ID)
     * 2. Subdomain (tenant.domain.com)
     * 3. Path (/tenant/{tenantId}/...)
     * 4. Parameter (?tenantId=...)
     *
     * @param request HTTP request
     * @return Resolved tenant ID or null if not found
     */
    private String resolveTenantId(HttpServletRequest request) {
        // Strategy 1: Header-based resolution
        String tenantId = request.getHeader(TENANT_HEADER);
        if (StringUtils.hasText(tenantId)) {
            LOGGER.debug("Tenant resolved from header: {}", tenantId);
            return tenantId.trim();
        }

        // Strategy 2: Subdomain-based resolution
        tenantId = resolveFromSubdomain(request);
        if (StringUtils.hasText(tenantId)) {
            LOGGER.debug("Tenant resolved from subdomain: {}", tenantId);
            return tenantId;
        }

        // Strategy 3: Path-based resolution
        tenantId = resolveFromPath(request);
        if (StringUtils.hasText(tenantId)) {
            LOGGER.debug("Tenant resolved from path: {}", tenantId);
            return tenantId;
        }

        // Strategy 4: Parameter-based resolution
        tenantId = request.getParameter(TENANT_PARAM);
        if (StringUtils.hasText(tenantId)) {
            LOGGER.debug("Tenant resolved from parameter: {}", tenantId);
            return tenantId.trim();
        }

        LOGGER.debug("No tenant found in request, using default");
        return null; // Will use default tenant
    }


    /**
     * Resolve tenant from subdomain (e.g., tenant.domain.com).
     *
     * @param request request
     * @return tenant ID or null if not found
     */
    private String resolveFromSubdomain(HttpServletRequest request) {
        String serverName = request.getServerName();
        if (StringUtils.hasText(serverName)) {
            String[] parts = serverName.split("\\.");
            if (parts.length > INTEGER_TWO) {
                // Assume first part is tenant if it's not 'www'
                String potentialTenant = parts[0];
                if (!"www".equalsIgnoreCase(potentialTenant) && !"api".equalsIgnoreCase(potentialTenant)) {
                    return potentialTenant;
                }
            }
        }
        return null;
    }

    
    /**
     * Resolve tenant from path (e.g., /tenant/{tenantId}/...).
     *
     * @param request request
     * @return tenant ID or null if not found
     */
    private String resolveFromPath(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        if (requestUri.startsWith(TENANT_PATH_PREFIX)) {
            String remainingPath = requestUri.substring(TENANT_PATH_PREFIX.length());
            int nextSlash = remainingPath.indexOf('/');
            if (nextSlash > 0) {
                return remainingPath.substring(0, nextSlash);
            } else if (StringUtils.hasLength(remainingPath)) {
                return remainingPath;
            }
        }
        return null;
    }
}
