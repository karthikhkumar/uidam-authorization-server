package org.eclipse.ecsp.oauth2.server.core.request.transformer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class DefaultIdpTransformerTest {

    private static final double CONSTANT_3_14 = 3.14;
    private static final int CONSTANT_123 = 123;
    private DefaultIdpTransformer transformer;

    @BeforeEach
    void setUp() {
        transformer = new DefaultIdpTransformer();
    }

    @Test
    void transformUserName_ShouldConvertToString() {
        assertEquals("testUser", transformer.transformUserName("testUser"));
        assertEquals("123", transformer.transformUserName(CONSTANT_123));
        assertEquals("null", transformer.transformUserName(null));
    }

    @Test
    void transformEmail_ShouldConvertToString() {
        assertEquals("test@example.com", transformer.transformEmail("test@example.com"));
        assertEquals("null", transformer.transformEmail(null));
    }

    @Test
    void transformAud_ShouldConvertToString() {
        assertEquals("audience123", transformer.transformAud("audience123"));
        assertEquals("null", transformer.transformAud(null));
    }

    @Test
    void transformName_ShouldConvertToString() {
        assertEquals("John", transformer.transformFirstName("John"));
        assertEquals("Doe", transformer.transformLastName("Doe"));
        assertEquals("null", transformer.transformFirstName(null));
        assertEquals("null", transformer.transformLastName(null));
    }

    @Test
    void transformLocation_ShouldConvertToString() {
        assertEquals("USA", transformer.transformCountry("USA"));
        assertEquals("CA", transformer.transformState("CA"));
        assertNull(transformer.transformCity("SomeCity")); // Special case returns null
        assertEquals("null", transformer.transformCountry(null));
        assertEquals("null", transformer.transformState(null));
    }

    @Test
    void transformAddress_ShouldConvertToString() {
        assertEquals("123 Main St", transformer.transformAddress1("123 Main St"));
        assertEquals("Apt 4B", transformer.transformAddress2("Apt 4B"));
        assertEquals("12345", transformer.transformPostalCode("12345"));
        assertEquals("null", transformer.transformAddress1(null));
        assertEquals("null", transformer.transformAddress2(null));
        assertEquals("null", transformer.transformPostalCode(null));
    }

    @Test
    void transformContact_ShouldConvertToString() {
        assertEquals("1234567890", transformer.transformPhoneNumber("1234567890"));
        assertEquals("null", transformer.transformPhoneNumber(null));
    }

    @Test
    void transformGender_ShouldConvertToString() {
        assertEquals("M", transformer.transformGender("M"));
        assertEquals("null", transformer.transformGender(null));
    }

    @Test
    void transformWithDifferentTypes_ShouldConvertToString() {
        // Testing with different object types
        assertEquals("123", transformer.transformPhoneNumber(CONSTANT_123));
        assertEquals("true", transformer.transformGender(true));
        assertEquals("3.14", transformer.transformPostalCode(CONSTANT_3_14));
    }
}