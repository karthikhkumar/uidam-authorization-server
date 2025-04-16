/********************************************************************************
 * Copyright (c) 2023-24 Harman International
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0  
 *  
 * <p> Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.test;

import org.eclipse.ecsp.oauth2.server.core.request.dto.RegisteredClientDetails;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_FIRST_NAME;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_LAST_NAME;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLIENT_CREDENTIALS_GRANT_TYPE;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.CODE_VALIDITY;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TOKEN_VALIDITY;

/**
 * This class provides static data for testing purposes.
 */
public class TestCommonStaticData {


    private TestCommonStaticData() {
    }

    /**
     * Creates a dummy instance of RegisteredClientDetails with predefined values.
     *
     * @return A dummy instance of RegisteredClientDetails.
     */
    public static RegisteredClientDetails getClient() {
        RegisteredClientDetails rc = new RegisteredClientDetails();
        rc.setClientId("testClientId");
        rc.setClientName("testClientName");
        List<String> redirectUrls = new ArrayList<>();
        redirectUrls.add("http://example.com/test");
        rc.setRedirectUris(redirectUrls);
        rc.setClientSecret("secret");
        List<String> grantTypes = new ArrayList<>();
        grantTypes.add(CLIENT_CREDENTIALS_GRANT_TYPE);
        rc.setAuthorizationGrantTypes(grantTypes);
        rc.setAuthorizationCodeValidity(CODE_VALIDITY);
        rc.setRefreshTokenValidity(CODE_VALIDITY);
        Set<String> scopes = new HashSet<>();
        scopes.add("SelfManage");
        rc.setScopes(scopes);
        rc.setAccessTokenValidity(TOKEN_VALIDITY);
        rc.setAdditionalInformation("abc");
        List<String> authMethods = new ArrayList<>();
        authMethods.add("client_secret_basic");
        rc.setClientAuthenticationMethods(authMethods);
        rc.setAdditionalInformation("abc");
        rc.setRequireAuthorizationConsent(false);
        rc.setRequireProofKey(false);
        rc.setAccountType("Root");
        rc.setAccountName("ignite");
        rc.setAccountId("456");
        rc.setTenantId("789");
        return rc;
    }

    /**
     * Creates a dummy instance of RegisteredClientDetails with predefined values and multiple roles.
     *
     * @return A dummy instance of RegisteredClientDetails with multiple roles.
     */
    public static RegisteredClientDetails getClientWithMultiRole() {
        RegisteredClientDetails rc = new RegisteredClientDetails();
        rc.setClientId("testClientId");
        rc.setClientName("testClientName");
        List<String> redirectUrls = new ArrayList<>();
        redirectUrls.add("http://example.com/test");
        rc.setRedirectUris(redirectUrls);
        rc.setClientSecret("secret");
        List<String> grantTypes = new ArrayList<>();
        grantTypes.add(CLIENT_CREDENTIALS_GRANT_TYPE);
        rc.setAuthorizationGrantTypes(grantTypes);
        rc.setAuthorizationCodeValidity(CODE_VALIDITY);
        rc.setRefreshTokenValidity(CODE_VALIDITY);
        Set<String> scopes = new HashSet<>();
        scopes.add("SelfManage");
        rc.setScopes(scopes);
        rc.setAccessTokenValidity(TOKEN_VALIDITY);
        rc.setAdditionalInformation("abc");
        List<String> authMethods = new ArrayList<>();
        authMethods.add("client_secret_basic");
        rc.setClientAuthenticationMethods(authMethods);
        rc.setAdditionalInformation("abc");
        rc.setRequireAuthorizationConsent(false);
        rc.setRequireProofKey(false);
        rc.setAccountType("Root");
        rc.setAccountName("ignite");
        rc.setAccountId("456");
        rc.setTenantId("789");
        rc.setClientType("multi_role");
        return rc;
    }

    /**
     * Creates a dummy instance of RegisteredClientDetails with predefined values and an empty scope.
     *
     * @return A dummy instance of RegisteredClientDetails with an empty scope.
     */
    public static RegisteredClientDetails getClientWithEmptyScope() {
        RegisteredClientDetails rc = new RegisteredClientDetails();
        rc.setClientId("testClientId");
        rc.setClientName("testClientName");
        List<String> redirectUrls = new ArrayList<>();
        redirectUrls.add("http://example.com/test");
        rc.setRedirectUris(redirectUrls);
        rc.setClientSecret("secret");
        List<String> grantTypes = new ArrayList<>();
        grantTypes.add(CLIENT_CREDENTIALS_GRANT_TYPE);
        rc.setAuthorizationGrantTypes(grantTypes);
        rc.setAuthorizationCodeValidity(CODE_VALIDITY);
        rc.setRefreshTokenValidity(CODE_VALIDITY);
        rc.setAccessTokenValidity(TOKEN_VALIDITY);
        rc.setAdditionalInformation("abc");
        List<String> authMethods = new ArrayList<>();
        authMethods.add("client_secret_basic");
        rc.setClientAuthenticationMethods(authMethods);
        rc.setAdditionalInformation("abc");
        rc.setRequireAuthorizationConsent(false);
        rc.setRequireProofKey(false);
        rc.setClientType("multi_role");
        return rc;
    }

    /**
     * Creates a dummy instance of RegisteredClientDetails with predefined values and a custom scope.
     *
     * @return A dummy instance of RegisteredClientDetails with a custom scope.
     */
    public static RegisteredClientDetails getClientWithCustomScope() {
        RegisteredClientDetails rc = new RegisteredClientDetails();
        rc.setClientId("testClientId");
        rc.setClientName("testClientName");
        List<String> redirectUrls = new ArrayList<>();
        redirectUrls.add("http://example.com/test");
        rc.setRedirectUris(redirectUrls);
        rc.setClientSecret("secret");
        List<String> grantTypes = new ArrayList<>();
        grantTypes.add(CLIENT_CREDENTIALS_GRANT_TYPE);
        rc.setAuthorizationGrantTypes(grantTypes);
        rc.setAuthorizationCodeValidity(CODE_VALIDITY);
        rc.setRefreshTokenValidity(CODE_VALIDITY);
        Set<String> scopes = new HashSet<>();
        scopes.add("SelfClientManage");
        scopes.add("SelfManage");
        rc.setScopes(scopes);
        rc.setAccessTokenValidity(TOKEN_VALIDITY);
        rc.setAdditionalInformation("abc");
        List<String> authMethods = new ArrayList<>();
        authMethods.add("client_secret_basic");
        rc.setClientAuthenticationMethods(authMethods);
        rc.setAdditionalInformation("abc");
        rc.setRequireAuthorizationConsent(false);
        rc.setRequireProofKey(false);
        return rc;
    }

    /**
     * Creates a dummy instance of UserDetailsResponse with predefined values.
     *
     * @return A dummy instance of UserDetailsResponse.
     */
    public static UserDetailsResponse getUser() {
        UserDetailsResponse userDetailsResponse = new UserDetailsResponse();
        userDetailsResponse.setId("123");
        userDetailsResponse.setUserName("testUser");
        userDetailsResponse.setPassword("43DnFsXBdlZfdw0zJe2iCTthbC03v/lhoNrvwZtJtW4=");
        userDetailsResponse.setPasswordEncoder("SHA-256");
        userDetailsResponse.setSalt("testSalt");
        userDetailsResponse.setFailureLoginAttempts(1);
        Set<String> scopes = new HashSet<>();
        scopes.add("SelfManage");
        scopes.add("SelfUserManage");
        userDetailsResponse.setScopes(scopes);
        userDetailsResponse.setLastSuccessfulLoginTime("2023-10-31T14:53:18Z");
        userDetailsResponse.setAccountId("456");
        userDetailsResponse.setTenantId("789");
        Map<String, Object> additionalAttributes = new HashMap<>();
        additionalAttributes.put(CLAIM_FIRST_NAME, "first");
        additionalAttributes.put(CLAIM_LAST_NAME, "last");
        userDetailsResponse.setAdditionalAttributes(additionalAttributes);
        return userDetailsResponse;
    }

    /**
     * Creates a dummy instance of UserDetailsResponse with predefined values and an empty scope.
     *
     * @return A dummy instance of UserDetailsResponse with an empty scope.
     */
    public static UserDetailsResponse getUserWithEmptyScope() {
        UserDetailsResponse userDetailsResponse = new UserDetailsResponse();
        userDetailsResponse.setId("123");
        userDetailsResponse.setUserName("testUser");
        userDetailsResponse.setPassword("43DnFsXBdlZfdw0zJe2iCTthbC03v/lhoNrvwZtJtW4=");
        userDetailsResponse.setPasswordEncoder("SHA-256");
        userDetailsResponse.setSalt("testSalt");
        userDetailsResponse.setFailureLoginAttempts(1);
        return userDetailsResponse;
    }

    /**
     * Creates a dummy instance of JwsHeader.Builder with predefined values.
     *
     * @return A dummy instance of JwsHeader.Builder.
     */
    public static JwsHeader.Builder jwsHeader() {
        Map<String, Object> rsaJwk = new HashMap<>();
        rsaJwk.put("kty", "RSA");
        rsaJwk.put("n", "modulus");
        rsaJwk.put("e", "exponent");
        return JwsHeader.with(SignatureAlgorithm.RS256)
            .jwkSetUrl("https://provider.com/oauth2/jwks")
            .jwk(rsaJwk)
            .keyId("keyId")
            .x509Url("https://provider.com/oauth2/x509")
            .x509CertificateChain(Arrays.asList("x509Cert1", "x509Cert2"))
            .x509SHA1Thumbprint("x509SHA1Thumbprint")
            .x509SHA256Thumbprint("x509SHA256Thumbprint")
            .type("JWT")
            .contentType("jwt-content-type")
            .header("custom-header-name", "custom-header-value");
    }

    /**
     * Creates a dummy instance of JwtClaimsSet.Builder with predefined values.
     *
     * @return A dummy instance of JwtClaimsSet.Builder.
     */
    public static JwtClaimsSet.Builder jwtClaimsSet() {
        String issuer = "https://provider.com";
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);
        return JwtClaimsSet.builder()
            .issuer(issuer)
            .subject("subject")
            .audience(Collections.singletonList("client-1"))
            .issuedAt(issuedAt)
            .notBefore(issuedAt)
            .expiresAt(expiresAt)
            .id("jti")
            .claim("custom-claim-name", "custom-claim-value");
    }

    /**
     * Creates a dummy instance of JwtClaimsSet.Builder with predefined values and a scope.
     *
     * @return A dummy instance of JwtClaimsSet.Builder with a scope.
     */
    public static JwtClaimsSet.Builder jwtClaimsSetWithScope() {
        String issuer = "https://provider.com";
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);
        Set<String> scopeSet = new HashSet<>();
        scopeSet.add("SelfManage");
        return JwtClaimsSet.builder()
                .issuer(issuer)
                .subject("subject")
                .audience(Collections.singletonList("client-1"))
                .issuedAt(issuedAt)
                .notBefore(issuedAt)
                .expiresAt(expiresAt)
                .id("jti")
                .claim("custom-claim-name", "custom-claim-value")
                .claim("scope", scopeSet);
    }

    /**
     * Creates a dummy instance of JwtClaimsSet.Builder with predefined values and a custom scope.
     *
     * @return A dummy instance of JwtClaimsSet.Builder with a custom scope.
     */
    public static JwtClaimsSet.Builder jwtClaimsSetWithCustomScope() {
        String issuer = "https://provider.com";
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);
        Set<String> scopeSet = new HashSet<>();
        scopeSet.add("SelfClientManage");
        return JwtClaimsSet.builder()
                .issuer(issuer)
                .subject("subject")
                .audience(Collections.singletonList("client-1"))
                .issuedAt(issuedAt)
                .notBefore(issuedAt)
                .expiresAt(expiresAt)
                .id("jti")
                .claim("custom-claim-name", "custom-claim-value")
                .claim("scope", scopeSet);
    }

}