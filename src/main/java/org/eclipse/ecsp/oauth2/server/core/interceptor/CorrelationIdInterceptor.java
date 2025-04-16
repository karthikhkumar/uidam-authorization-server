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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants;
import org.slf4j.MDC;
import org.springframework.web.servlet.AsyncHandlerInterceptor;

/**
 * The CorrelationIdInterceptor class is an implementation of the AsyncHandlerInterceptor interface.
 * It is used to intercept incoming HTTP requests and validate the presence of a correlation id in the request headers.
 * The correlation id is then stored in the Mapped Diagnostic Context (MDC) for later use.
 * After the request is handled, the correlation id is removed from the MDC.
 */
public class CorrelationIdInterceptor implements AsyncHandlerInterceptor {
    
    /**
     * The preHandle method is overridden from the AsyncHandlerInterceptor interface.
     * It is called before the actual handler is executed.
     * The method checks if the incoming HTTP request contains a correlation id in its headers.
     * If a correlation id is present, it is stored in the MDC.
     * If a correlation id is not present, an exception is thrown.
     *
     * @param request the current HTTP request.
     * @param response the current HTTP response.
     * @param handler the chosen handler to execute.
     * @return true if a correlation id is present in the request headers, false otherwise.
     * @throws Exception if a correlation id is not present in the request headers.
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        String correlationId = request.getHeader(IgniteOauth2CoreConstants.CORRELATION_ID);
        if (correlationId != null) {
            MDC.put(IgniteOauth2CoreConstants.CORRELATION_ID, correlationId);
        }
        return true;
    }

    /**
     * The afterCompletion method is overridden from the AsyncHandlerInterceptor interface.
     * It is called after the handler is executed and the view is rendered.
     * The method removes the correlation id from the MDC.
     *
     * @param request the current HTTP request.
     * @param response the current HTTP response.
     * @param handler the handler (or HandlerMethod) that started asynchronous execution.
     * @param ex any exception thrown on handler execution, if any. This does not include exceptions that have been
     *           handled through an exception resolver.
     * @throws Exception if an error occurs during the removal of the correlation id from the MDC.
     */
    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex)
            throws Exception {
        MDC.remove(IgniteOauth2CoreConstants.CORRELATION_ID);
    }

}
