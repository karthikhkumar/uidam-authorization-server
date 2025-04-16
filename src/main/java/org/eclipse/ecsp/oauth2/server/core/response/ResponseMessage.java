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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.INITIAL_ODD_NUMBER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MULTIPLIER_ODD_NUMBER;

/**
 * The ResponseMessage class represents a response message in the application.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ResponseMessage {
    private String key;

    private List<Object> parameters = new ArrayList<>();

    public ResponseMessage() {

    }

    /**
     * Constructor that initializes the key with the provided string.
     *
     * @param key a string representing the key of the response message.
     */
    public ResponseMessage(String key) {
        this.key = key;
    }

    /**
     * Constructor that initializes the key with the provided string and adds the provided parameters to the parameters
     * list.
     *
     * @param key a string representing the key of the response message.
     * @param parameters an array of objects representing the parameters of the response message.
     */
    public ResponseMessage(String key, Object... parameters) {
        this.key = key;
        Collections.addAll(this.parameters, parameters);
    }

    /**
     * Constructor that initializes the key and parameters list with the provided string and list.
     *
     * @param key a string representing the key of the response message.
     * @param parameters a list of objects representing the parameters of the response message.
     */
    public ResponseMessage(String key, List<Object> parameters) {
        this.key = key;
        this.parameters = parameters;
    }

    /**
     * Getter for the key.
     *
     * @return a string representing the key of the response message.
     */
    public String getKey() {
        return key;
    }

    /**
     * Setter for the key.
     *
     * @param key a string representing the key of the response message.
     */
    public void setKey(String key) {
        this.key = key;
    }

    /**
     * Getter for the parameters list.
     *
     * @return a list of objects representing the parameters of the response message.
     */
    public List<Object> getParameters() {
        return parameters;
    }

    /**
     * Setter for the parameters list.
     *
     * @param parameters a list of objects representing the parameters of the response message.
     */
    public void setParameters(List<Object> parameters) {
        this.parameters = parameters;
    }

    /**
     * Overrides the equals() method from the Object class.
     * Two ResponseMessage objects are equal if their keys and parameters lists are equal.
     *
     * @param o an object to compare with this ResponseMessage.
     * @return true if the objects are equal, false otherwise.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        ResponseMessage that = (ResponseMessage) o;

        return new EqualsBuilder()
            .append(key, that.key)
            .append(parameters, that.parameters)
            .isEquals();
    }

    /**
     * Overrides the hashCode() method from the Object class.
     * The hash code is calculated based on the key and parameters list.
     *
     * @return the hash code of this ResponseMessage.
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(INITIAL_ODD_NUMBER, MULTIPLIER_ODD_NUMBER)
            .append(key)
            .append(parameters)
            .toHashCode();
    }

    /**
     * Overrides the toString() method from the Object class.
     * The string representation includes the key and parameters list.
     *
     * @return a string representation of this ResponseMessage.
     */
    @Override
    public String toString() {
        return "ResponseMessage{" + "key='" + key + '\'' + ", parameters=" + parameters + '}';
    }
}
