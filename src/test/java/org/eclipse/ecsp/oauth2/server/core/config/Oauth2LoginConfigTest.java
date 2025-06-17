package org.eclipse.ecsp.oauth2.server.core.config;

import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ExternalIdpRegisteredClient;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link Oauth2LoginConfig}.
 */
class Oauth2LoginConfigTest {
    @Mock
    private TenantConfigurationService tenantConfigurationService;
    @Mock
    private TenantProperties tenantProperties;

    private Oauth2LoginConfig config;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(tenantConfigurationService.getTenantProperties(anyString())).thenReturn(tenantProperties);
        config = new Oauth2LoginConfig(tenantConfigurationService);
    }

    @Test
    void clientRegistrationRepository_withExternalIdp_returnsRegistration() {
        ExternalIdpRegisteredClient idp = mock(ExternalIdpRegisteredClient.class);
        when(idp.getRegistrationId()).thenReturn("testidp");
        when(idp.getClientId()).thenReturn("client");
        when(idp.getClientSecret()).thenReturn("secret");
        when(idp.getClientAuthMethod())
                .thenReturn(org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        when(idp.getScope()).thenReturn("openid,email");
        when(idp.getAuthorizationUri()).thenReturn("https://auth.example.com/auth");
        when(idp.getTokenUri()).thenReturn("https://auth.example.com/token");
        when(idp.getUserInfoUri()).thenReturn("https://auth.example.com/userinfo");
        when(idp.getUserNameAttributeName()).thenReturn("sub");
        when(idp.getJwkSetUri()).thenReturn("https://auth.example.com/jwks");
        when(idp.getClientName()).thenReturn("Test IDP");
        when(tenantProperties.getExternalIdpRegisteredClientList()).thenReturn(List.of(idp));
        ClientRegistrationRepository repo = config.clientRegistrationRepository();
        ClientRegistration reg = repo.findByRegistrationId("testidp");
        assertNotNull(reg);
        assertEquals("testidp", reg.getRegistrationId());
        assertEquals("client", reg.getClientId());
    }

    @Test
    void authorizedClientService_andRepository_beans() {
        // Provide at least one mock registration to avoid IllegalArgumentException
        ExternalIdpRegisteredClient idp = mock(ExternalIdpRegisteredClient.class);
        when(idp.getRegistrationId()).thenReturn("testidp");
        when(idp.getClientId()).thenReturn("client");
        when(idp.getClientSecret()).thenReturn("secret");
        when(idp.getClientAuthMethod())
                .thenReturn(org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        when(idp.getScope()).thenReturn("openid,email");
        when(idp.getAuthorizationUri()).thenReturn("https://auth.example.com/auth");
        when(idp.getTokenUri()).thenReturn("https://auth.example.com/token");
        when(idp.getUserInfoUri()).thenReturn("https://auth.example.com/userinfo");
        when(idp.getUserNameAttributeName()).thenReturn("sub");
        when(idp.getJwkSetUri()).thenReturn("https://auth.example.com/jwks");
        when(idp.getClientName()).thenReturn("Test IDP");
        when(tenantProperties.getExternalIdpRegisteredClientList()).thenReturn(List.of(idp));
        ClientRegistrationRepository repo = config.clientRegistrationRepository();
        OAuth2AuthorizedClientService service = config.authorizedClientService(repo);
        assertNotNull(service);
        OAuth2AuthorizedClientRepository repository = config.authorizedClientRepository(service);
        assertNotNull(repository);
    }
}
