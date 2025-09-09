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
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_ID_TAG;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive test class for AuthorizationMetricsService.
 * Tests all functionality including metric registration, counter incrementation, 
 * tenant-specific metrics, error handling, and edge cases.
 */
class AuthorizationMetricsServiceTest {

    private AuthorizationMetricsService authorizationMetricsService;
    private SimpleMeterRegistry meterRegistry;

    @BeforeEach
    void setUp() {
        meterRegistry = new SimpleMeterRegistry();
        authorizationMetricsService = new AuthorizationMetricsService(meterRegistry);
    }

    @Test
    void testConstructor() {
        SimpleMeterRegistry testRegistry = new SimpleMeterRegistry();
        AuthorizationMetricsService service = new AuthorizationMetricsService(testRegistry);
        assertNotNull(service);
    }

    @Test
    void testIncrementMetrics_WithValidMetricInfo_ShouldIncrementCounter() {
        // Arrange
        MetricInfo metricInfo = MetricInfo.builder()
            .metricType(MetricType.LOGIN_ATTEMPTS)
            .tags(new String[]{"environment", "test", "region", "us-east"})
            .build();

        // Act
        authorizationMetricsService.incrementMetrics(metricInfo);

        // Assert
        Counter counter = meterRegistry.get(MetricType.LOGIN_ATTEMPTS.getMetricName())
            .tag("environment", "test")
            .tag("region", "us-east")
            .counter();
        assertEquals(1.0, counter.count());
    }

    @Test
    void testIncrementMetrics_WithSuccessLoginAttempts_ShouldUseCorrectMetricName() {
        // Arrange
        MetricInfo metricInfo = MetricInfo.builder()
            .metricType(MetricType.SUCCESS_LOGIN_ATTEMPTS)
            .tags(new String[]{"tenant", "test-tenant"})
            .build();

        // Act
        authorizationMetricsService.incrementMetrics(metricInfo);

        // Assert
        Counter counter = meterRegistry.get(MetricType.SUCCESS_LOGIN_ATTEMPTS.getMetricName())
            .tag("tenant", "test-tenant")
            .counter();
        assertEquals(1.0, counter.count());
        assertEquals("success.login.attempts", MetricType.SUCCESS_LOGIN_ATTEMPTS.getMetricName());
    }

    @Test
    void testIncrementMetrics_WithEmptyTags_ShouldNotThrowException() {
        // Arrange
        MetricInfo metricInfo = MetricInfo.builder()
            .metricType(MetricType.FAILURE_LOGIN_ATTEMPTS)
            .tags(new String[]{})
            .build();

        // Act & Assert
        assertDoesNotThrow(() -> authorizationMetricsService.incrementMetrics(metricInfo));
        
        Counter counter = meterRegistry.get(MetricType.FAILURE_LOGIN_ATTEMPTS.getMetricName()).counter();
        assertEquals(1.0, counter.count());
    }

    @Test
    void testIncrementMetrics_WithNullTags_ShouldNotThrowException() {
        // Arrange
        MetricInfo metricInfo = MetricInfo.builder()
            .metricType(MetricType.LOGIN_ATTEMPTS)
            .tags(null)
            .build();

        // Act & Assert
        assertDoesNotThrow(() -> authorizationMetricsService.incrementMetrics(metricInfo));
        
        Counter counter = meterRegistry.get(MetricType.LOGIN_ATTEMPTS.getMetricName()).counter();
        assertEquals(1.0, counter.count());
    }

    @Test
    void testIncrementMetrics_WithNullMetricInfo_ShouldThrowException() {
        // Act & Assert
        assertThrows(NullPointerException.class, () -> 
            authorizationMetricsService.incrementMetrics(null));
    }

    @Test
    void testIncrementMetrics_WithNullMetricType_ShouldThrowException() {
        // Arrange
        MetricInfo metricInfo = MetricInfo.builder()
            .metricType(null)
            .tags(new String[]{"tag1", "value1"})
            .build();

        // Act & Assert
        assertThrows(NullPointerException.class, () -> 
            authorizationMetricsService.incrementMetrics(metricInfo));
    }

    @Test
    void testIncrementMetricsForTenant_WithSingleMetricType_ShouldIncrementWithTenantTag() {
        // Arrange
        String tenantId = "test-tenant-123";
        MetricType metricType = MetricType.LOGIN_ATTEMPTS;

        // Act
        authorizationMetricsService.incrementMetricsForTenant(tenantId, metricType);

        // Assert
        Counter counter = meterRegistry.get(metricType.getMetricName())
            .tag(TENANT_ID_TAG, tenantId)
            .counter();
        assertEquals(1.0, counter.count());
    }

    @Test
    void testIncrementMetricsForTenant_WithMultipleMetricTypes_ShouldIncrementAllMetrics() {
        // Arrange
        String tenantId = "multi-tenant-456";
        MetricType[] metricTypes = {
            MetricType.LOGIN_ATTEMPTS,
            MetricType.SUCCESS_LOGIN_ATTEMPTS,
            MetricType.FAILURE_LOGIN_ATTEMPTS
        };

        // Act
        authorizationMetricsService.incrementMetricsForTenant(tenantId, metricTypes);

        // Assert
        for (MetricType metricType : metricTypes) {
            Counter counter = meterRegistry.get(metricType.getMetricName())
                .tag(TENANT_ID_TAG, tenantId)
                .counter();
            assertEquals(1.0, counter.count(), 
                "Counter for " + metricType.getMetricName() + " should be incremented once");
        }
    }

    @Test
    void testIncrementMetricsForTenant_WithEmptyMetricTypes_ShouldNotIncrementAnyMetrics() {
        // Arrange
        String tenantId = "empty-tenant";
        MetricType[] metricTypes = {};
        int initialMeterCount = meterRegistry.getMeters().size();

        // Act
        authorizationMetricsService.incrementMetricsForTenant(tenantId, metricTypes);

        // Assert
        assertEquals(initialMeterCount, meterRegistry.getMeters().size());
    }

    @Test
    void testIncrementMetricsForTenant_WithNullTenantId_ShouldThrowException() {
        // Arrange
        String tenantId = null;
        MetricType metricType = MetricType.FAILURE_LOGIN_CAPTCHA;

        // Act & Assert
        // Micrometer doesn't allow null tag values, so this should throw an exception
        assertThrows(NullPointerException.class, () -> 
            authorizationMetricsService.incrementMetricsForTenant(tenantId, metricType));
    }

    @Test
    void testIncrementMetricsForTenant_WithNullMetricTypes_ShouldThrowException() {
        // Arrange
        String tenantId = "test-tenant";
        MetricType[] metricTypes = null;

        // Act & Assert
        assertThrows(NullPointerException.class, () -> 
            authorizationMetricsService.incrementMetricsForTenant(tenantId, metricTypes));
    }

    @Test
    void testIncrementMetricsForTenant_WithVariousFailureMetrics_ShouldIncrementAllFailureTypes() {
        // Arrange
        String tenantId = "failure-test-tenant";
        MetricType[] failureMetrics = {
            MetricType.FAILURE_LOGIN_CAPTCHA,
            MetricType.FAILURE_LOGIN_WRONG_PASSWORD,
            MetricType.FAILURE_LOGIN_USER_NOT_FOUND,
            MetricType.FAILURE_LOGIN_ACCOUNT_NOT_FOUND,
            MetricType.FAILURE_LOGIN_USER_BLOCKED,
            MetricType.FAILURE_LOGIN_ACCOUNT_LOCKED
        };

        // Act
        authorizationMetricsService.incrementMetricsForTenant(tenantId, failureMetrics);

        // Assert
        for (MetricType metricType : failureMetrics) {
            Counter counter = meterRegistry.get(metricType.getMetricName())
                .tag(TENANT_ID_TAG, tenantId)
                .counter();
            assertEquals(1.0, counter.count(), 
                "Failure counter for " + metricType.getMetricName() + " should be incremented once");
        }
    }

    @Test
    void testIncrementMetricsForTenant_WithSuccessMetrics_ShouldIncrementAllSuccessTypes() {
        // Arrange
        String tenantId = "success-test-tenant";
        MetricType[] successMetrics = {
            MetricType.SUCCESS_LOGIN_ATTEMPTS,
            MetricType.SUCCESS_LOGIN_BY_INTERNAL_CREDENTIALS,
            MetricType.SUCCESS_LOGIN_BY_EXTERNAL_IDP_CREDENTIALS
        };

        // Act
        authorizationMetricsService.incrementMetricsForTenant(tenantId, successMetrics);

        // Assert
        for (MetricType metricType : successMetrics) {
            Counter counter = meterRegistry.get(metricType.getMetricName())
                .tag(TENANT_ID_TAG, tenantId)
                .counter();
            assertEquals(1.0, counter.count(), 
                "Success counter for " + metricType.getMetricName() + " should be incremented once");
        }
    }

    @Test
    void testCombinedMetricsOperations_ShouldWorkCorrectly() {
        // Arrange
        String tenantId = "integration-tenant";
        MetricInfo directMetricInfo = MetricInfo.builder()
            .metricType(MetricType.LOGIN_ATTEMPTS)
            .tags(new String[]{"custom", "tag"})
            .build();

        // Act
        authorizationMetricsService.incrementMetrics(directMetricInfo);
        authorizationMetricsService.incrementMetricsForTenant(tenantId, MetricType.SUCCESS_LOGIN_ATTEMPTS);

        // Assert
        Counter directCounter = meterRegistry.get(MetricType.LOGIN_ATTEMPTS.getMetricName())
            .tag("custom", "tag")
            .counter();
        assertEquals(1.0, directCounter.count());
        
        Counter tenantCounter = meterRegistry.get(MetricType.SUCCESS_LOGIN_ATTEMPTS.getMetricName())
            .tag(TENANT_ID_TAG, tenantId)
            .counter();
        assertEquals(1.0, tenantCounter.count());
    }

    @Test
    void testIncrementMetricsForTenant_WithManyMetrics_ShouldHandleEfficiently() {
        // Arrange
        String tenantId = "performance-tenant";
        MetricType[] manyMetrics = {
            MetricType.LOGIN_ATTEMPTS,
            MetricType.SUCCESS_LOGIN_ATTEMPTS,
            MetricType.SUCCESS_LOGIN_BY_INTERNAL_CREDENTIALS,
            MetricType.SUCCESS_LOGIN_BY_EXTERNAL_IDP_CREDENTIALS,
            MetricType.FAILURE_LOGIN_ATTEMPTS,
            MetricType.FAILURE_LOGIN_CAPTCHA,
            MetricType.FAILURE_LOGIN_WRONG_PASSWORD,
            MetricType.FAILURE_LOGIN_USER_NOT_FOUND,
            MetricType.FAILURE_LOGIN_ACCOUNT_NOT_FOUND,
            MetricType.FAILURE_LOGIN_USER_BLOCKED,
            MetricType.FAILURE_LOGIN_ACCOUNT_LOCKED
        };

        // Act & Assert
        assertDoesNotThrow(() -> 
            authorizationMetricsService.incrementMetricsForTenant(tenantId, manyMetrics));
        
        // Verify all metrics were created and incremented
        for (MetricType metricType : manyMetrics) {
            Counter counter = meterRegistry.get(metricType.getMetricName())
                .tag(TENANT_ID_TAG, tenantId)
                .counter();
            assertEquals(1.0, counter.count(), 
                "Counter for " + metricType.getMetricName() + " should be incremented");
        }
    }

    @Test
    void testIncrementMetrics_MultipleIncrements_ShouldAccumulate() {
        // Arrange
        MetricInfo metricInfo = MetricInfo.builder()
            .metricType(MetricType.LOGIN_ATTEMPTS)
            .tags(new String[]{"test", "accumulation"})
            .build();

        // Act
        authorizationMetricsService.incrementMetrics(metricInfo);
        authorizationMetricsService.incrementMetrics(metricInfo);
        authorizationMetricsService.incrementMetrics(metricInfo);

        // Assert
        Counter counter = meterRegistry.get(MetricType.LOGIN_ATTEMPTS.getMetricName())
            .tag("test", "accumulation")
            .counter();
        assertEquals(3.0, counter.count());
    }

    @Test
    void testIncrementMetrics_ShouldUseMetricTypeDescription() {
        // Arrange
        MetricInfo metricInfo = MetricInfo.builder()
            .metricType(MetricType.LOGIN_ATTEMPTS)
            .tags(new String[]{"test", "description"})
            .build();

        // Act
        authorizationMetricsService.incrementMetrics(metricInfo);

        // Assert
        Counter counter = meterRegistry.get(MetricType.LOGIN_ATTEMPTS.getMetricName())
            .tag("test", "description")
            .counter();
        assertNotNull(counter);
        assertEquals(1.0, counter.count());
        
        // Verify the MetricType has the expected description
        assertNotNull(MetricType.LOGIN_ATTEMPTS.getDescription());
        assertEquals("Total number of login attempts", MetricType.LOGIN_ATTEMPTS.getDescription());
    }

    @Test
    void testIncrementMetricsForTenant_DifferentTenants_ShouldCreateSeparateMetrics() {
        // Arrange
        String tenant1 = "tenant-1";
        String tenant2 = "tenant-2";
        MetricType metricType = MetricType.LOGIN_ATTEMPTS;

        // Act
        authorizationMetricsService.incrementMetricsForTenant(tenant1, metricType);
        authorizationMetricsService.incrementMetricsForTenant(tenant1, metricType);
        authorizationMetricsService.incrementMetricsForTenant(tenant2, metricType);

        // Assert
        Counter tenant1Counter = meterRegistry.get(metricType.getMetricName())
            .tag(TENANT_ID_TAG, tenant1)
            .counter();
        assertEquals(2.0, tenant1Counter.count());

        Counter tenant2Counter = meterRegistry.get(metricType.getMetricName())
            .tag(TENANT_ID_TAG, tenant2)
            .counter();
        assertEquals(1.0, tenant2Counter.count());
    }

    @Test
    void testIncrementMetrics_WithOddNumberOfTags_ShouldThrowException() {
        // Arrange
        MetricInfo metricInfo = MetricInfo.builder()
            .metricType(MetricType.LOGIN_ATTEMPTS)
            .tags(new String[]{"key1", "value1", "key2"}) // Odd number - missing value for key2
            .build();

        // Act & Assert
        // Micrometer requires even number of tag elements (key-value pairs)
        assertThrows(IllegalArgumentException.class, () -> 
            authorizationMetricsService.incrementMetrics(metricInfo));
    }

    @Test
    void testIncrementMetrics_WithDifferentTagCombinations_ShouldCreateSeparateCounters() {
        // Arrange
        MetricType metricType = MetricType.FAILURE_LOGIN_ATTEMPTS;
        
        MetricInfo metricInfo1 = MetricInfo.builder()
            .metricType(metricType)
            .tags(new String[]{"reason", "password"})
            .build();
            
        MetricInfo metricInfo2 = MetricInfo.builder()
            .metricType(metricType)
            .tags(new String[]{"reason", "captcha"})
            .build();

        // Act
        authorizationMetricsService.incrementMetrics(metricInfo1);
        authorizationMetricsService.incrementMetrics(metricInfo1);
        authorizationMetricsService.incrementMetrics(metricInfo2);

        // Assert
        Counter passwordCounter = meterRegistry.get(metricType.getMetricName())
            .tag("reason", "password")
            .counter();
        assertEquals(2.0, passwordCounter.count());
        
        Counter captchaCounter = meterRegistry.get(metricType.getMetricName())
            .tag("reason", "captcha")
            .counter();
        assertEquals(1.0, captchaCounter.count());
    }

    @Test
    void testIncrementMetricsForTenant_WithEmptyTenantId_ShouldNotThrowException() {
        // Arrange
        String tenantId = "";
        MetricType metricType = MetricType.SUCCESS_LOGIN_ATTEMPTS;

        // Act & Assert
        assertDoesNotThrow(() -> 
            authorizationMetricsService.incrementMetricsForTenant(tenantId, metricType));
        
        Counter counter = meterRegistry.get(metricType.getMetricName())
            .tag(TENANT_ID_TAG, tenantId)
            .counter();
        assertEquals(1.0, counter.count());
    }

    @Test
    void testAllMetricTypes_ShouldHaveValidNamesAndDescriptions() {
        // Test that all MetricType enum values have non-null names and descriptions
        for (MetricType metricType : MetricType.values()) {
            assertNotNull(metricType.getMetricName(), "MetricType " + metricType + " should have a non-null metric name");
            assertNotNull(metricType.getDescription(), "MetricType " + metricType + " should have a non-null description");
            assertFalse(metricType.getMetricName().trim().isEmpty(), "MetricType " + metricType + " should have a non-empty metric name");
            assertFalse(metricType.getDescription().trim().isEmpty(), "MetricType " + metricType + " should have a non-empty description");
        }
    }

    @Test
    void testIncrementMetrics_WithLongTenantId_ShouldNotThrowException() {
        // Arrange
        String longTenantId = "very-long-tenant-id-with-many-characters-that-might-cause-issues-if-not-handled-properly";
        MetricType metricType = MetricType.LOGIN_ATTEMPTS;

        // Act & Assert
        assertDoesNotThrow(() -> 
            authorizationMetricsService.incrementMetricsForTenant(longTenantId, metricType));
        
        Counter counter = meterRegistry.get(metricType.getMetricName())
            .tag(TENANT_ID_TAG, longTenantId)
            .counter();
        assertEquals(1.0, counter.count());
    }

    @Test
    void testIncrementMetrics_WithSpecialCharactersInTags_ShouldNotThrowException() {
        // Arrange
        MetricInfo metricInfo = MetricInfo.builder()
            .metricType(MetricType.LOGIN_ATTEMPTS)
            .tags(new String[]{"special-key", "value@#$%^&*()", "unicode", "测试"})
            .build();

        // Act & Assert
        assertDoesNotThrow(() -> authorizationMetricsService.incrementMetrics(metricInfo));
        
        Counter counter = meterRegistry.get(MetricType.LOGIN_ATTEMPTS.getMetricName())
            .tag("special-key", "value@#$%^&*()")
            .tag("unicode", "测试")
            .counter();
        assertEquals(1.0, counter.count());
    }
}
