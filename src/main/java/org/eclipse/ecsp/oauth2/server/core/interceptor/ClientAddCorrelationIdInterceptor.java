/*
 * Copyright (c) 2023 - 2024 Harman International
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.eclipse.ecsp.oauth2.server.core.interceptor;

import org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants;
import org.slf4j.MDC;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;

/**
 * The ClientAddCorrelationIdInterceptor class is a utility class that provides a method to add a 'correlationId' header
 * to a WebClient request.
 */
public class ClientAddCorrelationIdInterceptor {
    private ClientAddCorrelationIdInterceptor() {

    }
    
    /**
     * This method is an interceptor that checks if the clientRequest has a 'correlationId' in its headers.
     * If not, it adds the 'correlationId' to the headers of the clientRequest.
     * The 'correlationId' is retrieved from the Mapped Diagnostic Context (MDC).
     * The method returns an ExchangeFilterFunction, which is a function that transforms a ClientRequest into a
     * ResponseSpec.
     *
     * @return an ExchangeFilterFunction that adds the 'correlationId' to the headers of the clientRequest.
     */
    public static ExchangeFilterFunction addCorrelationIdAndContentType() {
        return (clientRequest, next) -> {
            String correlationId = MDC.get(IgniteOauth2CoreConstants.CORRELATION_ID);
            ClientRequest modifiedClientRequest = ClientRequest.from(clientRequest)
                .header(IgniteOauth2CoreConstants.CORRELATION_ID, correlationId)
                .build();
            return next.exchange(modifiedClientRequest);
        };
    }
}
