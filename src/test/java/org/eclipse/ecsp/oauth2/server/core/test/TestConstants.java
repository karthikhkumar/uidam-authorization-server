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

/**
 * This class provides a set of constants that are used in test classes.
 */
public class TestConstants {
    protected TestConstants() {
    }

    public static final int RESPONSE_STATUS_CODE_UNAUTHORIZED = 401;
    public static final int BAD_REQUEST = 400;
    public static final int SECONDS_TO_ADD = 120;
    public static final int SECONDS_TO_ADD1 = 300;
    public static final int SECONDS_TO_ADD2 = 900;
    public static final long SECONDS_TO_ADD3 = 2000L;
    public static final int SECONDS_TO_SUB = 360;
    public static final String DUMMY_TOKEN = "eyJ4NXQjUzI1NiI6IlVQRHRwWW1LODZFVndzVUlHVWxXNS1FVV9pTkhRLW5"
        + "TTDNDYTU4dUFHNzAiLCJraWQiOiI2YzQ5NTkyYy0xZDA0LTQ1NjAtYjcyNC03ZTI4OWVkODc2Nzk"
        + "iLCJ0eXAiOiJhdCtqd3QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0Q2xpZW50QUsyIiwiYXV"
        + "kIjoidGVzdENsaWVudEFLMiIsImF1dCI6IkFQUExJQ0FUSU9OIiwibmJmIjoxNjk1NjQxMzc0LCJh"
        + "enAiOiJ0ZXN0Q2xpZW50QUsyIiwic2NvcGUiOlsiU2VsZk1hbmFnZSJdLCJpc3MiOiJodHRwOi8vb"
        + "G9jYWxob3N0OjkwMDAiLCJleHAiOjE2OTU2NDE2NzQsImlhdCI6MTY5NTY0MTM3NCwianRpIjoiOD"
        + "c1Yjk5ZTYtNDVjMC00NzE4LTkxZWUtY2Y5Yzg2YTdlMDgyIn0.WLv8fYE3gCVxYd1J3Wann0Iw73Kx"
        + "APfbKrWqibA7JVjqhVwfb5Uf9WIRaLE6YiMGYaL6Nxlsi-u_W7pKES2Gd-wSxHpzc_N1LZ4eakMOnJN"
        + "JZ0H5-uYgIRBGKsP3ivufTKH2Wtz2SSM6dqPzJji8s05nVB4_LFm72I45ZwXY3S673nY8cemUNI-0l_1"
        + "flgsNE8TMF77cOevjIgyHEMCGJg76Gsjx-vnS_VGMYcGCD9p5o_LnhYiLBNW-4QPnpJoGEGw3K-xcXL2V"
        + "m8xEvMHSUu-4E1wPjh1HdY0WuUiglrRw5wI2juhMisASB4Gt4XUtCklQpK1lmvDUemIgYeC7Rg";

    public static final String TOKEN_METADATA = "{\"@class\":\"java.util.Collections$UnmodifiableMap\","
        + "\"metadata.token.claims\":{\"@class\":\"java.util.Collections$UnmodifiableMap\","
        + "\"sub\":\"testClient\",\"aud\":[\"java.util.Collections$SingletonList\",[\"testClient\"]],"
        + "\"aut\":\"APPLICATION\",\"nbf\":[\"java.time.Instant\",1700460227.445355600],\"azp\":\"testClient\","
        + "\"scope\":[\"java.util.LinkedHashSet\",[\"IgniteSystem\",\"RevokeToken\",\"SelfManage\"]],"
        + "\"iss\":[\"java.net.URL\",\"https://localhost:9443\"],"
        + "\"exp\":[\"java.time.Instant\",1736460227.445355600],"
        + "\"iat\":[\"java.time.Instant\",1700460227.445355600],"
        + "\"jti\":\"31ddb09a-6cde-42de-a2e9-7a684ad1d120\"},\"metadata.token.invalidated\":false}";
    public static final int TOKEN_TIME_TO_LIVE = 200;
    public static final long CODE_VALIDITY = 100L;
    public static final long TOKEN_VALIDITY = 2000L;

    public static final int AMOUNT_TO_ADD = 5;
    public static final int AMOUNT_TO_ADD1 = 60;
    public static final int ENFORCE_AFTER_FAILURE_COUNT = 2;
    public static final int LOGIN_ATTEMPT = 2;

    public static final String USER_MGMT_BASE_URL = "http://uidam-user-management:8080";
    public static final String USER_BY_USERNAME_ENDPOINT = "/v1/users/{userName}/byUserName";
    public static final String USER_EVENT_ENDPOINT = "/v1/users/{id}/events";
    public static final String USER_RECOVERY_NOTIF_ENDPOINT = "/v1/users/{userName}/recovery/forgotpassword";
    public static final String USER_RESET_PASSWORD_ENDPOINT = "/v1/users/recovery/set-password";
    public static final String ACCOUNT_NAME = "accountName";

    public static final String ID = "id";
    public static final String PRINCIPAL_NAME = "testClientAK2";

    public static final String TEST_USER_NAME = "testUser";
    public static final String TEST_PASSWORD = "testPwd";
    public static final String TEST_ACCOUNT_NAME = "testAccount";
    public static final String TEST_ENCODER = "SHA-256";
    public static final String TEST_SALT = "testSalt";

    public static final String TEST_CLIENT_ID = "testClient";
    public static final String URI = "uri";
    public static final String VALID_URI = "https://oauth.pstmn.io/v1/callback";
    public static final String STATE = "state";
    public static final String INVALID_CLIENT = "INVALID_CLIENT";

    public static final String ATTRIBUTE_SUB = "sub";
    public static final String REGISTRATION_ID_GOOGLE = "google";

    public static final String REQUESTED_SESSION_ID = "1234567890";
    public static final String GRANTED_AUTORITIES = "USER,ADMIN";
    public static final int SECONDS_300 = 300;
    public static final String EXTERNAL_IDP_PRINCIPAL = "{\"@class\":\"java.util.HashMap\",\"principal\":{\"@class\":"
            + "\"org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser\",\"idToken\":{\"@class\":"
            + "\"org.springframework.security.oauth2.core.oidc.OidcIdToken\",\"tokenValue\":\"token\",\"claims\":"
            + "{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"sub\":\"sub\"}},\"nameAttributeKey\":\"sub\"}}";

    public static final String EXTERNAL_IDP_ADDITIONAL_PARAMETERS = "{\"@class\":"
        + "\"java.util.Collections$UnmodifiableMap\",\"nonce\":\"nonce\"}";
    public static final String EXTERNAL_IDP_ATTRIBUTES = "{\"@class\":\"java.util.Collections$UnmodifiableMap\","
        + "\"registration_id\":\"google\",\"nonce\":\"nonce\"}";

    public static final String RECAPTCHA_URL = "https://www.google.com/recaptcha/api/siteverify";

}