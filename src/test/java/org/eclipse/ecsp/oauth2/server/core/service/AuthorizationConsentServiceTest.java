package org.eclipse.ecsp.oauth2.server.core.service;

import org.eclipse.ecsp.oauth2.server.core.entities.AuthorizationConsent;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationConsentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

class AuthorizationConsentServiceTest {

    @Mock
    AuthorizationConsentRepository authorizationConsentRepository;
    @Mock
    RegisteredClientRepository registeredClientRepository;

    AuthorizationConsentService authorizationConsentService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        authorizationConsentService = new AuthorizationConsentService(authorizationConsentRepository,
                registeredClientRepository);
    }

    @Test
    void findByIdReturnsNullWhenNotFound() {
        when(authorizationConsentRepository.findByRegisteredClientIdAndPrincipalName("client-id", "principal-name"))
            .thenReturn(Optional.empty());

        OAuth2AuthorizationConsent result = authorizationConsentService.findById("client-id", "principal-name");
        assertNull(result);
    }

    @Test
    void findByIdThrowsExceptionWhenRegisteredClientNotFound() {
        AuthorizationConsent authorizationConsent = new AuthorizationConsent();
        authorizationConsent.setRegisteredClientId("client-id");
        authorizationConsent.setPrincipalName("principal-name");
        when(authorizationConsentRepository.findByRegisteredClientIdAndPrincipalName("client-id",
                "principal-name"))
            .thenReturn(Optional.of(authorizationConsent));
        when(registeredClientRepository.findById("client-id")).thenReturn(null);

        assertThrows(DataRetrievalFailureException.class, () -> authorizationConsentService.findById(
                "client-id", "principal-name"));
    }
}