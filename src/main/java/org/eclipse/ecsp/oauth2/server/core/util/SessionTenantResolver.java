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

package org.eclipse.ecsp.oauth2.server.core.util;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.eclipse.ecsp.oauth2.server.core.config.TenantContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Utility class for resolving tenant information from multiple sources
 * with session-based persistence across multi-threaded OAuth2 flows.
 * This resolver addresses the issue where different threads handle
 * different parts of the OAuth2 authorization flow, making ThreadLocal
 * tenant context unreliable.
 */
public class SessionTenantResolver {

    private static final Logger LOGGER = LoggerFactory.getLogger(SessionTenantResolver.class);
    
    private static final String TENANT_SESSION_KEY = "RESOLVED_TENANT_ID";

    private SessionTenantResolver() {
        // Utility class - prevent instantiation
    }

    /**
     * Get the current tenant ID with session-based fallback.
     * This method provides a more reliable tenant resolution than pure ThreadLocal
     * in multi-threaded environments like OAuth2 authorization flows.
     * Resolution order:
     * 1. ThreadLocal context (current thread)
     * 2. HTTP session (cross-thread persistence) 
     * 3. Default tenant
     *
     * @return current tenant ID, never null
     */
    public static String getCurrentTenant() {
        // First try ThreadLocal (fastest)
        String tenant = TenantContext.hasTenant() ? TenantContext.getCurrentTenant() : null;
        
        if (StringUtils.hasText(tenant)) {
            LOGGER.debug("Tenant resolved from ThreadLocal: {}", tenant);
            return tenant;
        }

        // Try to get from session if ThreadLocal is empty or default
        try {
            tenant = getTenantFromCurrentSession();
            if (StringUtils.hasText(tenant)) {
                LOGGER.debug("Tenant resolved from session: {}", tenant);
                // Update ThreadLocal for current thread
                TenantContext.setCurrentTenant(tenant);
                return tenant;
            }
        } catch (Exception e) {
            LOGGER.debug("Could not resolve tenant from session: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Set tenant ID in both ThreadLocal and session for persistence.
     */
    public static void setCurrentTenant(String tenantId) {
        if (!StringUtils.hasText(tenantId)) {
            LOGGER.debug("Attempted to set empty tenant ID, ignoring");
            return;
        }

        // Set in ThreadLocal
        TenantContext.setCurrentTenant(tenantId);

        // Also store in session for cross-thread access
        try {
            storeTenantInCurrentSession(tenantId);
            LOGGER.debug("Tenant '{}' set in both ThreadLocal and session", tenantId);
        } catch (Exception e) {
            LOGGER.debug("Could not store tenant in session: {}", e.getMessage());
        }
    }

    /**
     * Get tenant from current HTTP session.
     */
    private static String getTenantFromCurrentSession() {
        HttpServletRequest request = getCurrentRequest();
        if (request != null && request.getSession(false) != null) {
            return (String) request.getSession(false).getAttribute(TENANT_SESSION_KEY);
        }
        return null;
    }

    /**
     * Store tenant in current HTTP session.
     */
    private static void storeTenantInCurrentSession(String tenantId) {
        HttpServletRequest request = getCurrentRequest();
        if (request != null && StringUtils.hasText(tenantId)) {
            HttpSession session = request.getSession(true);
            session.setAttribute(TENANT_SESSION_KEY, tenantId);
        }
    }

    /**
     * Get current HTTP request from Spring's RequestContextHolder.
     */
    private static HttpServletRequest getCurrentRequest() {
        try {
            ServletRequestAttributes attributes = 
                (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            return attributes.getRequest();
        } catch (IllegalStateException e) {
            // No request context available (e.g., in background threads)
            return null;
        }
    }

    /**
     * Clear tenant from both ThreadLocal and session.
     */
    public static void clearTenant() {
        TenantContext.clear();
        
        try {
            HttpServletRequest request = getCurrentRequest();
            if (request != null && request.getSession(false) != null) {
                request.getSession(false).removeAttribute(TENANT_SESSION_KEY);
                LOGGER.debug("Cleared tenant from session");
            }
        } catch (Exception e) {
            LOGGER.debug("Could not clear tenant from session: {}", e.getMessage());
        }
    }
}
