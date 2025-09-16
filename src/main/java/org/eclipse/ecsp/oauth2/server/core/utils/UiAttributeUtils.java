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

import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.springframework.stereotype.Component;
import org.springframework.ui.Model;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.TENANT_LOGO_PATH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.TENANT_STYLESHEET_PATH;

/**
 * Utility class for adding UI configuration attributes to models across controllers.
 * This centralizes the logic for handling tenant-specific UI properties like logos and stylesheets.
 */
@Component
public class UiAttributeUtils {

    private final TenantConfigurationService tenantConfigurationService;

    /**
     * Constructor for UiAttributeUtils.
     *
     * @param tenantConfigurationService the service to get tenant properties
     */
    public UiAttributeUtils(TenantConfigurationService tenantConfigurationService) {
        this.tenantConfigurationService = tenantConfigurationService;
    }

    /**
     * Adds UI configuration attributes to the model based on tenant properties.
     * This method checks if tenant-specific UI properties are configured and uses them,
     * otherwise falls back to default values.
     *
     * @param model the model to add attributes to
     * @param tenantId the tenant ID for fallback logo path
     */
    public void addUiAttributes(Model model, String tenantId) {
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        if (tenantProperties.getUi() != null) {
            model.addAttribute(TENANT_LOGO_PATH, tenantProperties.getUi().getLogoPath(tenantId));
            model.addAttribute(TENANT_STYLESHEET_PATH, tenantProperties.getUi().getStylesheetPath());
        } else {
            // Fallback to default values
            model.addAttribute(TENANT_LOGO_PATH, "/images/" + tenantId + "-logo.svg");
            model.addAttribute(TENANT_STYLESHEET_PATH, "/css/style.css");
        }
    }

    /**
     * Adds default UI configuration attributes to the model when no tenant context is available.
     * This is typically used for error pages or other non-tenant-specific pages.
     *
     * @param model the model to add attributes to
     */
    public void addDefaultUiAttributes(Model model) {
        model.addAttribute(TENANT_LOGO_PATH, "/images/logo.svg");
        model.addAttribute(TENANT_STYLESHEET_PATH, "/css/style.css");
    }
}
