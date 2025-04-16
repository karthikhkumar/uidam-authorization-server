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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.text.ParseException;
import java.text.SimpleDateFormat;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.DATE_FORMAT;

/**
 * The DateUtils class is a utility class that provides methods for handling dates.
 */
public class DateUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(DateUtils.class);

    protected DateUtils() {
        // Prevent instantiation
    }

    /**
     * This method converts a date in String format to a timestamp.
     * If the date String cannot be parsed, and throws an OAuth2AuthenticationException with a server
     * error code.
     *
     * @param date the date in String format to be converted.
     * @return the date in Timestamp format returned as a String.
     * @throws OAuth2AuthenticationException if the date String cannot be parsed.
     */
    public static String stringToTimestamp(String date) {
        SimpleDateFormat formatter = new SimpleDateFormat(DATE_FORMAT);
        try {
            return formatter.parse(date).getTime() + "";
        } catch (ParseException e) {
            LOGGER.error("stringToTimestamp - {}", e.getMessage());
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "Unable to validate date format", null);
            throw new OAuth2AuthenticationException(error);
        }
    }

}