package org.eclipse.ecsp.sql.postgress.config;

import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.CaptchaProperties;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

class CaptchaPropertiesTest {

    @Test
    void recaptchaVerifyUrl_canBeSetAndRetrieved() {
        CaptchaProperties properties = new CaptchaProperties();
        properties.setRecaptchaVerifyUrl("https://example.com/verify");
        assertEquals("https://example.com/verify", properties.getRecaptchaVerifyUrl());
    }

    @Test
    void recaptchaKeySite_canBeSetAndRetrieved() {
        CaptchaProperties properties = new CaptchaProperties();
        properties.setRecaptchaKeySite("site-key");
        assertEquals("site-key", properties.getRecaptchaKeySite());
    }

    @Test
    void recaptchaKeySecret_canBeSetAndRetrieved() {
        CaptchaProperties properties = new CaptchaProperties();
        properties.setRecaptchaKeySecret("secret-key");
        assertEquals("secret-key", properties.getRecaptchaKeySecret());
    }

    @Test
    void recaptchaVerifyUrl_defaultIsNull() {
        CaptchaProperties properties = new CaptchaProperties();
        assertEquals(null, properties.getRecaptchaVerifyUrl());
    }

    @Test
    void recaptchaKeySite_defaultIsNull() {
        CaptchaProperties properties = new CaptchaProperties();
        assertEquals(null, properties.getRecaptchaKeySite());
    }

    @Test
    void recaptchaKeySecret_defaultIsNull() {
        CaptchaProperties properties = new CaptchaProperties();
        assertEquals(null, properties.getRecaptchaKeySecret());
    }
}