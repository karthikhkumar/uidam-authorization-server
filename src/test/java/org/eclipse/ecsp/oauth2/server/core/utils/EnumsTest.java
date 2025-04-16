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

package org.eclipse.ecsp.oauth2.server.core.utils;

import org.eclipse.ecsp.oauth2.server.core.common.CustomOauth2TokenGenErrorCodes;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.BAD_REQUEST;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * This class tests the functionality of the EnumUtils class.
 */
class EnumsTest {

    /**
     * This parameterized test method tests the findFromValueCaseInsensitive method of the EnumUtils class with
     * different error code values.
     * It asserts that the returned CustomOauth2TokenGenErrorCodes object has the expected code, description, and
     * status.
     *
     * @param errCodeValue The error code value to be passed to the findFromValueCaseInsensitive method.
     * @param codeExpected The expected code of the returned CustomOauth2TokenGenErrorCodes object.
     * @param descExpected The expected description of the returned CustomOauth2TokenGenErrorCodes object.
     */
    @ParameterizedTest
    @MethodSource("findFromValueCaseInsensitiveArguments")
    void testFindFromValueCaseInsensitive(String errCodeValue, String codeExpected, String descExpected) {
        CustomOauth2TokenGenErrorCodes
            customOauth2TokenGenErrorCodes = EnumUtils.findFromValueCaseInsensitive(
                CustomOauth2TokenGenErrorCodes.class, CustomOauth2TokenGenErrorCodes::name, errCodeValue)
                .orElse(CustomOauth2TokenGenErrorCodes.INVALID_REQUEST);
        assertEquals(codeExpected, customOauth2TokenGenErrorCodes.getCode());
        assertEquals(descExpected, customOauth2TokenGenErrorCodes.getDescription());
        assertEquals(BAD_REQUEST, customOauth2TokenGenErrorCodes.getStatus());
    }

    /**
     * This method provides the arguments for the testFindFromValueCaseInsensitive method.
     *
     * @return Stream of Arguments for the testFindFromValueCaseInsensitive method.
     */
    private static Stream<Arguments> findFromValueCaseInsensitiveArguments() {
        return Stream.of(
            Arguments.of("INVALID_SCOPE", "TG-001", "Requested Scope Is Invalid"),
            Arguments.of("INVALID_SCOPES", "TG-003", "Request is invalid"),
            Arguments.of(null, "TG-003", "Request is invalid")
        );
    }

}