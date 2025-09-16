package org.eclipse.ecsp.oauth2.server.core.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_ID_TAG;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

class AuthorizationMetricsServiceTest {

    private static final int EXPECTED_COUNT_AFTER_SINGLE_INCREMENT = 1;
    private static final int EXPECTED_COUNT_AFTER_DOUBLE_INCREMENT = 2;

    private SimpleMeterRegistry meterRegistry;
    private AuthorizationMetricsService metricsService;

    @BeforeEach
    void setUp() {
        meterRegistry = new SimpleMeterRegistry();
        metricsService = new AuthorizationMetricsService(meterRegistry);
    }

    @Test
    void testIncrementMetrics() {
        metricsService.incrementMetrics(MetricType.TOTAL_LOGIN_ATTEMPTS, "tag1", "value1");

        Counter counter = meterRegistry.find("total.login.attempts").tags("tag1", "value1").counter();
        assertNotNull(counter);
        assertEquals(EXPECTED_COUNT_AFTER_SINGLE_INCREMENT, counter.count());
    }

    @Test
    void testIncrementMetricsForTenant() {
        metricsService.incrementMetricsForTenant("tenantX",
                                                MetricType.SUCCESS_LOGIN_ATTEMPTS,
                                                MetricType.FAILURE_LOGIN_ATTEMPTS);

        Counter counter1 = meterRegistry.find("success.login.attempts").tags(TENANT_ID_TAG, "tenantX").counter();
        Counter counter2 = meterRegistry.find("failure.login.attempts").tags(TENANT_ID_TAG, "tenantX").counter();

        assertNotNull(counter1);
        assertNotNull(counter2);
        assertEquals(EXPECTED_COUNT_AFTER_SINGLE_INCREMENT, counter1.count());
        assertEquals(EXPECTED_COUNT_AFTER_SINGLE_INCREMENT, counter2.count());
    }

    @Test
    void testIncrementMetricsForTenantAndIdp() {
        metricsService.incrementMetricsForTenantAndIdp("tenantY",
                                            "idpZ",
                                                      MetricType.SUCCESS_LOGIN_BY_EXTERNAL_IDP_CREDENTIALS);

        Counter counter = meterRegistry.find("success.login.attempts.by.external.idp.credentials")
                .tags(TENANT_ID_TAG, "tenantY", "id_provider", "idpZ")
                .counter();

        assertNotNull(counter);
        assertEquals(EXPECTED_COUNT_AFTER_SINGLE_INCREMENT, counter.count());
    }

    @Test
    void testIncrementMetrics_MultipleCalls() {
        metricsService.incrementMetrics(MetricType.FAILURE_LOGIN_CAPTCHA, "tagA", "valueA");
        metricsService.incrementMetrics(MetricType.FAILURE_LOGIN_CAPTCHA, "tagA", "valueA");

        Counter counter = meterRegistry.find("failure.login.attempts.captcha").tags("tagA", "valueA").counter();
        assertNotNull(counter);
        assertEquals(EXPECTED_COUNT_AFTER_DOUBLE_INCREMENT, counter.count());
    }

    @Test
    void testIncrementMetricsForTenantAndIdp_MultipleMetrics() {
        metricsService.incrementMetricsForTenantAndIdp("tenantZ", "idpQ",
            MetricType.SUCCESS_LOGIN_BY_INTERNAL_CREDENTIALS, MetricType.FAILURE_LOGIN_WRONG_PASSWORD);

        Counter counter1 = meterRegistry.find("success.login.attempts.by.internal.credentials")
                .tags(TENANT_ID_TAG, "tenantZ", "id_provider", "idpQ")
                .counter();
        Counter counter2 = meterRegistry.find("failure.login.attempts.wrong.password")
                .tags(TENANT_ID_TAG, "tenantZ", "id_provider", "idpQ")
                .counter();

        assertNotNull(counter1);
        assertNotNull(counter2);
        assertEquals(EXPECTED_COUNT_AFTER_SINGLE_INCREMENT, counter1.count());
        assertEquals(EXPECTED_COUNT_AFTER_SINGLE_INCREMENT, counter2.count());
    }
}