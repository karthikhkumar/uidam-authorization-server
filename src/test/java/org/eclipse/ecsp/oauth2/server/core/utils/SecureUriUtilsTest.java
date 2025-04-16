package org.eclipse.ecsp.oauth2.server.core.utils;

import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;


class SecureUriUtilsTest {

    @Mock
    TenantProperties tenantProperties;

    @Test
    void buildRedirectUri_validBaseUriAndParams() {
        Map<String, String> params = new HashMap<>();
        params.put("param1", "value1");
        params.put("param2", "value2");

        String result = SecureUriUtils.buildRedirectUri("https://example.com", params);
        assertEquals("https://example.com?param1=value1&param2=value2", result);
    }

    @Test
    void buildRedirectUri_BaseUri() {
        Map<String, String> params = new HashMap<>();
        params.put("param1", "value1");

        String uri = SecureUriUtils.buildRedirectUri("valid_uri", params);
        assertEquals("valid_uri?param1=value1", uri);
    }

    @Test
    void buildRedirectUri_emptyParams() {
        Map<String, String> params = new HashMap<>();

        String result = SecureUriUtils.buildRedirectUri("https://example.com", params);
        assertEquals("https://example.com", result);
    }

    @Test
    void buildRedirectUri_nullParams() {
        String result = SecureUriUtils.buildRedirectUri("https://example.com", null);
        assertEquals("https://example.com", result);
    }

}