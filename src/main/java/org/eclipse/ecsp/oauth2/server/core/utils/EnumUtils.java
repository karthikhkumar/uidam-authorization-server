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

import java.util.EnumSet;
import java.util.Optional;
import java.util.function.Function;

/**
 * The EnumUtils class is a utility class that provides methods for working with Enumerations.
 */
public final class EnumUtils {

    protected EnumUtils() {
      // Prevent instantiation
    }

    /**
     * This method finds an Enumeration instance based on a comparator function and a comparable value.
     * It uses the Java 8 Stream API to filter the Enumeration instances and find the first one that matches the
     * comparator.
     * The comparator function is applied to each Enumeration instance, and the result is compared to the provided value
     * in a case-insensitive manner.
     * If a match is found, it is returned wrapped in an Optional. If no match is found, an empty Optional is returned.
     *
     * @param <E> the type of the Enum
     * @param <T> the type of the value to compare to
     * @param enumType The class of the Enum
     * @param comparator the function that will be used to find the matching instance of the Enum.
     * @param value the value to compare to in the function
     * @return an Optional containing the matching Enum instance, or an empty Optional if no match is found
     */
    public static <E extends Enum<E>, T> Optional<E> findFromValueCaseInsensitive(
        final Class<E> enumType,
        final Function<E, T> comparator,
        final T value) {

        final String comparableValue = value != null ? value.toString() : null;

        // Filter out all enum that doesn't match the comparator and find the first one
        return EnumSet
            .allOf(enumType)
            .stream()
            .filter(e -> comparator.apply(e).toString().equalsIgnoreCase(comparableValue))
            .findFirst();
    }
}
