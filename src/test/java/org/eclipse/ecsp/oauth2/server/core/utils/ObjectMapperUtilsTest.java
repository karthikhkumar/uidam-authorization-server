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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * This class tests the functionality of the ObjectMapperUtils class.
 */
class ObjectMapperUtilsTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * This test method tests the parseMap method of the ObjectMapperUtils class with a valid JSON string.
     * It asserts that the returned map is not null.
     */
    @Test
    void testParseMapSuccess() {
        assertNotNull(ObjectMapperUtils.parseMap(objectMapper,
            "{\"@class\":\"java.util.HashMap\",\"principal\":\"principal\"}"));
    }

    /**
     * This test method tests the parseMap method of the ObjectMapperUtils class with an empty string, expecting an
     * IllegalArgumentException.
     * It asserts that an IllegalArgumentException is thrown.
     */
    @Test
    void testParseMapException() {
        assertThrows(IllegalArgumentException.class,
                () -> ObjectMapperUtils.parseMap(objectMapper, ""));
    }

    /**
     * This test method tests the writeMap method of the ObjectMapperUtils class with a valid map.
     * It asserts that the returned JSON string is not null.
     */
    @Test
    void testWriteMapSuccess() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("@class", "java.util.HashMap");
        metadata.put("principal", "principal");
        assertNotNull(ObjectMapperUtils.writeMap(objectMapper, metadata));
    }

}