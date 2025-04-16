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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;

/**
 * The ObjectMapperUtils class is a utility class that provides methods for converting data between Map and String
 * formats using the Jackson ObjectMapper.
 */
public class ObjectMapperUtils {

    protected ObjectMapperUtils() {
        // Prevent instantiation
    }

    /**
     * This method converts data in String format to a Map using the provided ObjectMapper.
     * It uses the ObjectMapper's readValue method to parse the String into a Map.
     * If an exception occurs during the conversion, it throws an IllegalArgumentException with the exception's message.
     *
     * @param objectMapper the ObjectMapper to use for the conversion.
     * @param data the data in String format to be converted.
     * @return the data converted to a Map.
     * @throws IllegalArgumentException if an exception occurs during the conversion.
     */
    public static Map<String, Object> parseMap(ObjectMapper objectMapper, String data) {
        try {
            return objectMapper.readValue(data, new TypeReference<>() {
            });
        } catch (Exception e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    /**
     * This method converts data in a Map to a String format using the provided ObjectMapper.
     * It uses the ObjectMapper's writeValueAsString method to convert the Map into a String.
     * If an exception occurs during the conversion, it throws an IllegalArgumentException with the exception's message.
     *
     * @param objectMapper the ObjectMapper to use for the conversion.
     * @param metadata the data in Map format to be converted.
     * @return the data converted to a String.
     * @throws IllegalArgumentException if an exception occurs during the conversion.
     */
    public static String writeMap(ObjectMapper objectMapper, Map<String, Object> metadata) {
        try {
            return objectMapper.writeValueAsString(metadata);
        } catch (Exception e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

}