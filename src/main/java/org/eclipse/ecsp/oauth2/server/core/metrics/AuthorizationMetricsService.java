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

package org.eclipse.ecsp.oauth2.server.core.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_ID_TAG;

/**
 * Service for managing authorization metrics using Micrometer.
 * Provides methods to increment various authentication and authorization metrics.
 */
@Component
public class AuthorizationMetricsService {

    private final MeterRegistry meterRegistry;

    public AuthorizationMetricsService(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    /**
     * Increments metrics counter for the specified metric type.
     *
     * @param metricType the type of metric to increment
     * @param tags additional tags to associate with the metric
     */
    public void incrementMetrics(MetricType metricType, String... tags) {
        String description = metricType.getDescription();
        Counter.builder(metricType.getMetricName())
            .description(description)
            .tags(tags)
            .register(meterRegistry)
            .increment();
    }

    /**
     * Increments metrics for a specific tenant.
     *
     * @param tenantId the tenant identifier
     * @param metricTypes the metric types to increment
     */
    public void incrementMetricsForTenant(String tenantId, MetricType... metricTypes) {
        String[] tagArray = new String[]{ TENANT_ID_TAG, tenantId};
        for (MetricType metricType : metricTypes) {
            incrementMetrics(metricType, tagArray);
        }
    }

    /**
     * Increments metrics for a specific tenant and identity provider.
     *
     * @param tenantId the tenant identifier
     * @param idProvider the identity provider
     * @param metricTypes the metric types to increment
     */
    public void incrementMetricsForTenantAndIdp(String tenantId, String idProvider, MetricType... metricTypes) {
        String[] tagArray = new String[]{ TENANT_ID_TAG, tenantId, "id_provider", idProvider };
        for (MetricType metricType : metricTypes) {
            incrementMetrics(metricType, tagArray);
        }
    }

}
