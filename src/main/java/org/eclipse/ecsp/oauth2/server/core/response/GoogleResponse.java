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

package org.eclipse.ecsp.oauth2.server.core.response;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.eclipse.ecsp.oauth2.server.core.response.GoogleResponse.ErrorCode.BAD_REQUEST;
import static org.eclipse.ecsp.oauth2.server.core.response.GoogleResponse.ErrorCode.INVALID_RESPONSE;
import static org.eclipse.ecsp.oauth2.server.core.response.GoogleResponse.ErrorCode.MISSING_RESPONSE;

/**
 * The GoogleResponse class represents the response from Google's reCAPTCHA service.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonPropertyOrder({ "success", "score", "action", "challenge_ts", "hostname", "error-codes" })
public class GoogleResponse {

    @JsonProperty("success")
    private boolean success;
    @JsonProperty("challenge_ts")
    private String challengeTimeStamp;
    @JsonProperty("hostname")
    private String hostname;
    @JsonProperty("score")
    private float score;
    @JsonProperty("action")
    private String action;
    @JsonProperty("error-codes")
    private ErrorCode[] errorCodes;

    /**
     * The ErrorCode enum represents possible error codes returned by the reCAPTCHA service.
     */
    enum ErrorCode {
        MISSING_SECRET, INVALID_SECRET, MISSING_RESPONSE, INVALID_RESPONSE, BAD_REQUEST, TIMEOUT_OR_DUPLICATE;

        public static final int INITIAL_CAPACITY = 6;
        private static Map<String, ErrorCode> errorsMap = new HashMap<>(INITIAL_CAPACITY);

        static {
            errorsMap.put("missing-input-secret", MISSING_SECRET);
            errorsMap.put("invalid-input-secret", INVALID_SECRET);
            errorsMap.put("missing-input-response", MISSING_RESPONSE);
            errorsMap.put("invalid-input-response", INVALID_RESPONSE);
            errorsMap.put("bad-request", BAD_REQUEST);
            errorsMap.put("timeout-or-duplicate", TIMEOUT_OR_DUPLICATE);
        }

        /**
         * Returns the ErrorCode associated with the given string value.
         *
         * @param value the string error code
         * @return the associated ErrorCode
         */
        @JsonCreator
        public static ErrorCode forValue(final String value) {
            return errorsMap.get(value.toLowerCase());
        }
    }

    /**
     * Checks the success status of the Google reCAPTCHA response.
     *
     * @return true if the reCAPTCHA was successful, false otherwise
     */
    @JsonProperty("success")
    public boolean isSuccess() {
        return success;
    }

    /**
     * Sets the success status of the Google reCAPTCHA response.
     *
     * @param success the success status to set
     */
    @JsonProperty("success")
    public void setSuccess(boolean success) {
        this.success = success;
    }

    /**
     * Retrieves the challenge timestamp of the Google reCAPTCHA response.
     *
     * @return the challenge timestamp
     */
    @JsonProperty("challenge_ts")
    public String getChallengeTimeStamp() {
        return challengeTimeStamp;
    }

    /**
     * Sets the challenge timestamp of the Google reCAPTCHA response.
     *
     * @param challengeTimeStamp the challenge timestamp to set
     */
    @JsonProperty("challenge_ts")
    public void setChallengeTimeStamp(String challengeTimeStamp) {
        this.challengeTimeStamp = challengeTimeStamp;
    }

    /**
     * Retrieves the hostname of the Google reCAPTCHA response.
     *
     * @return the hostname
     */
    @JsonProperty("hostname")
    public String getHostname() {
        return hostname;
    }

    /**
     * Sets the hostname of the Google reCAPTCHA response.
     *
     * @param hostname the hostname to set
     */
    @JsonProperty("hostname")
    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    /**
     * Sets the error codes of the Google reCAPTCHA response.
     *
     * @param errorCodes the error codes to set
     */
    @JsonProperty("error-codes")
    public void setErrorCodes(ErrorCode[] errorCodes) {
        this.errorCodes = errorCodes;
    }

    /**
     * Retrieves the error codes of the Google reCAPTCHA response.
     *
     * @return the error codes
     */
    @JsonProperty("error-codes")
    public ErrorCode[] getErrorCodes() {
        return errorCodes;
    }

    /**
     * Retrieves the score of the Google reCAPTCHA response.
     *
     * @return the score
     */
    @JsonProperty("score")
    public float getScore() {
        return score;
    }

    /**
     * Sets the score of the Google reCAPTCHA response.
     *
     * @param score the score to set
     */
    @JsonProperty("score")
    public void setScore(float score) {
        this.score = score;
    }

    /**
     * Retrieves the action of the Google reCAPTCHA response.
     *
     * @return the action
     */
    @JsonProperty("action")
    public String getAction() {
        return action;
    }

    /**
     * Sets the action of the Google reCAPTCHA response.
     *
     * @param action the action to set
     */
    @JsonProperty("action")
    public void setAction(String action) {
        this.action = action;
    }

    /**
     * Checks if the response contains a client error.
     *
     * @return true if a client error is present, false otherwise
     */
    @JsonIgnore
    public boolean hasClientError() {
        final ErrorCode[] errors = getErrorCodes();
        if (errors == null) {
            return false;
        }
        for (final ErrorCode error : errors) {
            if (error == INVALID_RESPONSE || error == MISSING_RESPONSE || error == BAD_REQUEST) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns a string representation of the GoogleResponse.
     *
     * @return a string representation of the GoogleResponse
     */
    @Override
    public String toString() {
        return "GoogleResponse{" + "success=" + success + ", challengeTs='" + challengeTimeStamp + '\''
            + ", hostname='" + hostname + '\'' + ", score='" + score + '\'' + ", action='" + action + '\''
            + ", errorCodes=" + Arrays.toString(errorCodes) + '}';
    }
}