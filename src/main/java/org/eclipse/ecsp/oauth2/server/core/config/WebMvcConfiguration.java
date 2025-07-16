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

package org.eclipse.ecsp.oauth2.server.core.config;

import org.eclipse.ecsp.oauth2.server.core.interceptor.TenantResolutionInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Web MVC configuration that registers interceptors and other web-related configurations.
 * This configuration class is responsible for setting up multi-tenant support by registering
 * the TenantResolutionInterceptor.
 */
@Configuration
public class WebMvcConfiguration implements WebMvcConfigurer {

    private final TenantResolutionInterceptor tenantResolutionInterceptor;

    /**
     * Constructor for WebMvcConfiguration.
     *
     * @param tenantResolutionInterceptor the interceptor for resolving tenant context
     */
    public WebMvcConfiguration(TenantResolutionInterceptor tenantResolutionInterceptor) {
        this.tenantResolutionInterceptor = tenantResolutionInterceptor;
    }

    /**
     * Add interceptors to the registry.
     * This method registers the TenantResolutionInterceptor to handle tenant resolution
     * for all incoming requests with highest precedence.
     *
     * @param registry the interceptor registry
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(tenantResolutionInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns("/actuator/**", "/error", "/favicon.ico", 
                        "/static/**", "/css/**", "/js/**", "/images/**")
                .order(Integer.MIN_VALUE); // Highest precedence - runs first
    }
}
