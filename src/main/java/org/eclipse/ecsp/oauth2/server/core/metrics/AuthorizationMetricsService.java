/********************************************************************************
 * Copyright (c) 2023-24 Harman International 
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0  
 *  
 * <p> Unless required by applicable law or agreed to in writing, software
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

@Component
public class AuthorizationMetricsService {

    private final MeterRegistry meterRegistry;

    public AuthorizationMetricsService(MeterRegistry meterRegistry){
        this.meterRegistry = meterRegistry;
    }
    
    public void incrementMetrics(MetricInfo metricInfo) {
        MetricType metricType = metricInfo.getMetricType();
        String description = metricType.getDescription();

        Counter.builder(metricType.getMetricName())
            .description(description)
            .tags(metricInfo.getTags())
            .register(meterRegistry)
            .increment();
    }

    public void incrementMetricsForTenant(String tenantId, MetricType... metricTypes) {
        for (MetricType metricType : metricTypes) {
            MetricInfo metricInfo = MetricInfo.builder()
                                        .metricType(metricType)
                                        .tags(new String[]{ TENANT_ID_TAG, tenantId })
                                        .build();
            incrementMetrics(metricInfo);
        }
    }

}
