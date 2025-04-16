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

package org.eclipse.ecsp.oauth2.server.core.entities;


import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.Objects;

/**
 * The AuthorizationConsent class represents an OAuth 2.0 "consent" to an Authorization request.
 * This class holds state related to the set of authorities granted to a client by the resource owner.
 */
@Getter
@Setter
@Entity
@Table(name = "`authorization_consent`")
@IdClass(AuthorizationConsent.AuthorizationConsentId.class)
public class AuthorizationConsent {
    @Id
    @Column(name = "REGISTERED_CLIENT_ID")
    private String registeredClientId;
    @Id
    @Column(name = "PRINCIPAL_NAME")
    private String principalName;
    @Column(length = 1000)
    private String authorities;

    /**
     * The AuthorizationConsentId class represents the composite primary key for the AuthorizationConsent entity.
     */
    public static class AuthorizationConsentId implements Serializable {
        private String registeredClientId;
        private String principalName;

        /**
         * Constructs a new AuthorizationConsentId with the specified registeredClientId and principalName.
         *
         * @param registeredClientId the registered client id
         * @param principalName the principal name
         */
        public AuthorizationConsentId(String registeredClientId, String principalName) {
            this.registeredClientId = registeredClientId;
            this.principalName = principalName;
        }

        /**
         * Indicates whether some other object is "equal to" this one.
         *
         * @param o the reference object with which to compare
         * @return true if this object is the same as the obj argument; false otherwise
         */
        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            AuthorizationConsentId that = (AuthorizationConsentId) o;
            return registeredClientId.equals(that.registeredClientId) && principalName.equals(that.principalName);
        }

        /**
         * Returns a hash code value for the object.
         *
         * @return a hash code value for this object
         */
        @Override
        public int hashCode() {
            return Objects.hash(registeredClientId, principalName);
        }
    }
}

