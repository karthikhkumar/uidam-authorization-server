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
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import reactor.core.publisher.Mono;

/**
 * The RequestResponseLogger class is a utility class used to log HTTP requests and responses.
 * It uses the SLF4J Logger to log the request method, URL, and response status code.
 */
public class RequestResponseLogger {

    private static final Logger LOGGER = LoggerFactory.getLogger(RequestResponseLogger.class);

    protected RequestResponseLogger() {
        // Prevent instantiation
    }

    /**
     * This method is used to log the request details.
     * It creates an ExchangeFilterFunction that logs the HTTP method and URL of the request.
     *
     * @return ExchangeFilterFunction that logs the request details.
     */
    public static ExchangeFilterFunction logRequest() {
        return ExchangeFilterFunction.ofRequestProcessor(request -> {
            LOGGER.debug("Request {} {}", request.method(), request.url());
            return Mono.just(request);
        });
    }

    /**
     * This method is used to log the response details.
     * It creates an ExchangeFilterFunction that logs the status code of the response.
     *
     * @return ExchangeFilterFunction that logs the response details.
     */
    public static ExchangeFilterFunction logResponse() {
        return ExchangeFilterFunction.ofResponseProcessor(response -> {
            LOGGER.info("Response status code {} ", response.statusCode());
            return Mono.just(response);
        });
    }

}