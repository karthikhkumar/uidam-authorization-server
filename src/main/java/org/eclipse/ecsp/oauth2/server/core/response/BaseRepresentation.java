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

import com.fasterxml.jackson.annotation.JsonFormat;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.List;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.INITIAL_ODD_NUMBER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MULTIPLIER_ODD_NUMBER;

/**
 * The BaseRepresentation class is a base class for all response representations.
 */
public class BaseRepresentation {

    @JsonFormat(with = JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY)
    protected List<ResponseMessage> messages;


    public BaseRepresentation() {
    }

    /**
     * Constructor that initializes the messages list with the provided list.
     *
     * @param messages a list of ResponseMessage objects.
     */
    public BaseRepresentation(List<ResponseMessage> messages) {
        this.messages = messages;
    }

    /**
     * Getter for the messages list.
     * If the list is empty, it initializes a new ArrayList.
     *
     * @return a list of ResponseMessage objects.
     */
    public List<ResponseMessage> getMessages() {
        if (CollectionUtils.isEmpty(messages)) {
            messages = new ArrayList<>();
        }
        return messages;
    }

    /**
     * Setter for the messages list.
     *
     * @param messages a list of ResponseMessage objects.
     */
    public void setMessages(List<ResponseMessage> messages) {
        this.messages = messages;
    }

    /**
     * Adds a ResponseMessage object to the messages list.
     *
     * @param message a ResponseMessage object.
     */
    public void addMessage(ResponseMessage message) {
        this.getMessages();
        this.messages.add(message);
    }

    /**
     * Overrides the equals() method from the Object class.
     * Two BaseRepresentation objects are equal if their messages lists are equal.
     *
     * @param o an object to compare with this BaseRepresentation.
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

        BaseRepresentation that = (BaseRepresentation) o;

        return new EqualsBuilder()
            .append(messages, that.messages)
            .isEquals();
    }

    /**
     * Overrides the hashCode() method from the Object class.
     * The hash code is calculated based on the messages list.
     *
     * @return the hash code of this BaseRepresentation.
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(INITIAL_ODD_NUMBER, MULTIPLIER_ODD_NUMBER)
                .append(messages)
                .toHashCode();
    }

    /**
     * Overrides the toString() method from the Object class.
     * The string representation includes the messages list.
     *
     * @return a string representation of this BaseRepresentation.
     */
    @Override
    public String toString() {
        return "BaseRepresentation{" + "messages=" + messages + '}';
    }
}
