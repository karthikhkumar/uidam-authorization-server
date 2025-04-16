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

package org.eclipse.ecsp.oauth2.server.core.service.impl;


import jakarta.servlet.http.HttpServletRequest;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.exception.ReCaptchaInvalidException;
import org.eclipse.ecsp.oauth2.server.core.exception.ReCaptchaUnavailableException;
import org.eclipse.ecsp.oauth2.server.core.response.GoogleResponse;
import org.eclipse.ecsp.oauth2.server.core.service.CaptchaService;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.reactive.function.client.WebClient;

import java.net.URI;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.UIDAM;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.LOGIN_ATTEMPT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.RECAPTCHA_URL_TEMPLATE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.RESPONSE_PATTERN;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.SESSION_USER_RESPONSE_CAPTCHA_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.SESSION_USER_RESPONSE_ENFORCE_AFTER_NO_OF_FAILURES;
import static org.eclipse.ecsp.oauth2.server.core.utils.RequestResponseLogger.logRequest;
import static org.eclipse.ecsp.oauth2.server.core.utils.RequestResponseLogger.logResponse;

/**
 * The CaptchaServiceImpl class is an implementation of the CaptchaService interface.
 */
@Service("captchaService")
public class CaptchaServiceImpl implements CaptchaService {

    private static final Logger LOGGER = LoggerFactory.getLogger(CaptchaServiceImpl.class);

    private TenantProperties tenantProperties;

    /**
     * Constructor that initializes the tenantProperties object.
     *
     * @param tenantConfigurationService the service to retrieve tenant properties.
     */
    public CaptchaServiceImpl(TenantConfigurationService tenantConfigurationService) {
        tenantProperties = tenantConfigurationService.getTenantProperties(UIDAM);
    }

    /**
     * Processes the response from the reCAPTCHA service.
     * It performs a security check on the response, sends a verification request to the reCAPTCHA service,
     * and handles the GoogleResponse from the service.
     *
     * @param response the response from the reCAPTCHA service.
     * @param request the HttpServletRequest object.
     */
    @Override
    public void processResponse(final String response, HttpServletRequest request) {
        LOGGER.info("## processResponse - START");
        securityCheck(response);
        String recaptchaVerifyUrl = tenantProperties.getCaptcha().getRecaptchaVerifyUrl() + RECAPTCHA_URL_TEMPLATE;
        final URI verifyUri = URI.create(String.format(recaptchaVerifyUrl, getReCaptchaSecret(), response,
            getClientIp(request)));
        WebClient webClient = WebClient.builder().baseUrl(String.valueOf(verifyUri))
                .filter(logRequest()).filter(logResponse())
                .build();
        try {
            final GoogleResponse googleResponse = webClient.method(HttpMethod.GET)
                    .uri(verifyUri)
                    .accept(MediaType.APPLICATION_JSON).retrieve()
                    .bodyToMono(GoogleResponse.class).block();

            if (null != googleResponse) {
                LOGGER.debug("Google's response: {} ", googleResponse);

                if (!googleResponse.isSuccess()) {
                    if (googleResponse.hasClientError()) {
                        LOGGER.debug("Recaptcha client error");
                    }
                    throw new ReCaptchaInvalidException("reCaptcha was not successfully validated");
                }
            }
        } catch (RestClientException rce) {
            throw new ReCaptchaUnavailableException("ReCaptcha service unavailable at this time. "
                + "Please try again later.", rce);
        } finally {
            if (null != request.getSession()) {
                request.getSession().removeAttribute(LOGIN_ATTEMPT);
                request.getSession().removeAttribute(SESSION_USER_RESPONSE_CAPTCHA_ENABLED);
                request.getSession().removeAttribute(SESSION_USER_RESPONSE_ENFORCE_AFTER_NO_OF_FAILURES);
            }
        }
        LOGGER.info("## processResponse - END");
    }

    /**
     * Returns the reCAPTCHA site key.
     *
     * @return the reCAPTCHA site key.
     */
    @Override
    public String getReCaptchaSite() {
        return this.tenantProperties.getCaptcha().getRecaptchaKeySite();
    }

    /**
     * Returns the reCAPTCHA secret key.
     *
     * @return the reCAPTCHA secret key.
     */
    @Override
    public String getReCaptchaSecret() {
        return this.tenantProperties.getCaptcha().getRecaptchaKeySecret();
    }

    /**
     * Performs a security check on the response from the reCAPTCHA service.
     * It throws a ReCaptchaInvalidException if the response contains invalid characters.
     *
     * @param response the response from the reCAPTCHA service.
     */
    protected void securityCheck(final String response) {
        LOGGER.debug("Attempting to validate recaptcha response");
        if (!responseSanityCheck(response)) {
            throw new ReCaptchaInvalidException("Response contains invalid characters");
        }
        LOGGER.debug("Recaptcha response validated");
    }

    /**
     * Checks if the response from the reCAPTCHA service is valid.
     *
     * @param response the response from the reCAPTCHA service.
     * @return true if the response is valid, false otherwise.
     */
    protected boolean responseSanityCheck(final String response) {
        return StringUtils.hasLength(response) && RESPONSE_PATTERN.matcher(response).matches();
    }

    /**
     * Returns the client's IP address.
     * It checks the "X-Forwarded-For" header first. If the header is not present or does not contain the client's IP
     * address, it returns the IP address from the HttpServletRequest object.
     *
     * @param request the HttpServletRequest object.
     * @return the client's IP address.
     */
    protected String getClientIp(HttpServletRequest request) {
        final String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty() || !xfHeader.contains(request.getRemoteAddr())) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}