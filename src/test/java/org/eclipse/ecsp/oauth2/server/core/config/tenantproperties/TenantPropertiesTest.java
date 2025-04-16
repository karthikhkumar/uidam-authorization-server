package org.eclipse.ecsp.oauth2.server.core.config.tenantproperties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TenantPropertiesTest {

    private TenantProperties tenantProperties;

    @BeforeEach
    void setUp() {
        tenantProperties = new TenantProperties();
    }

    @Test
    void testParseMappings() {
        // Arrange
        ExternalIdpRegisteredClient client1 = new ExternalIdpRegisteredClient();
        client1.setClaimMappings("firstName#given_name,lastName#family_name,email#email");

        ExternalIdpRegisteredClient client2 = new ExternalIdpRegisteredClient();
        client2.setClaimMappings("username#sub");

        tenantProperties.setExternalIdpRegisteredClientList(Arrays.asList(client1, client2));

        // Act
        tenantProperties.parseMappings();

        // Assert
        HashMap<String, String> expectedMappingsClient1 = new HashMap<>();
        expectedMappingsClient1.put("firstName", "given_name");
        expectedMappingsClient1.put("lastName", "family_name");
        expectedMappingsClient1.put("email", "email");

        HashMap<String, String> expectedMappingsClient2 = new HashMap<>();
        expectedMappingsClient2.put("username", "sub");

        assertEquals(expectedMappingsClient1, client1.getMappings());
        assertEquals(expectedMappingsClient2, client2.getMappings());
    }
}