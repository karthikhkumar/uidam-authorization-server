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

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * This class tests the functionality of the DateUtils class.
 */
class DateUtilsTest {

    /**
     * This test method tests the stringToTimestamp method of the DateUtils class with a valid timestamp string.
     * It asserts that the returned string is not null and matches the expected timestamp.
     */
    @Test
    void testStringToTimestampSuccess() {
        assertNotNull(DateUtils.stringToTimestamp("2023-10-31T14:53:18Z"));
        assertEquals("1698763998000", DateUtils.stringToTimestamp("2023-10-31T14:53:18Z"));
    }

    /**
     * This test method tests the stringToTimestamp method of the DateUtils class with an invalid timestamp string,
     * expecting an OAuth2AuthenticationException.
     * It asserts that an OAuth2AuthenticationException is thrown.
     */
    @Test
    void testStringToTimestampException() {
        assertThrows(OAuth2AuthenticationException.class,
                () -> DateUtils.stringToTimestamp("2023-10-31T14:53:18.000Z"));
    }

}