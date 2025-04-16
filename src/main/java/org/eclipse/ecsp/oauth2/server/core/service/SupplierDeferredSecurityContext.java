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

package org.eclipse.ecsp.oauth2.server.core.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

import java.util.function.Supplier;

/**
 * This is an implementation of the DeferredSecurityContext interface that allows delayed access to a SecurityContext
 * that may be generated. It uses a Supplier to generate the SecurityContext when needed.
 * It also uses a SecurityContextHolderStrategy to create an empty SecurityContext if the Supplier does not provide one.
 */
final class SupplierDeferredSecurityContext implements DeferredSecurityContext {

    private static final Logger LOGGER = LoggerFactory.getLogger(SupplierDeferredSecurityContext.class);

    private final Supplier<SecurityContext> supplier;

    private final SecurityContextHolderStrategy strategy;

    private SecurityContext securityContext;

    private boolean missingContext;

    /**
     * Constructor for SupplierDeferredSecurityContext. It initializes the supplier and strategy.
     *
     * @param supplier the Supplier that provides the SecurityContext
     * @param strategy the SecurityContextHolderStrategy used to create an empty SecurityContext
     */
    SupplierDeferredSecurityContext(Supplier<SecurityContext> supplier, SecurityContextHolderStrategy strategy) {
        this.supplier = supplier;
        this.strategy = strategy;
    }

    /**
     * This method retrieves the SecurityContext.
     * If the SecurityContext has not been initialized yet, it initializes it.
     *
     * @return the SecurityContext
     */
    @Override
    public SecurityContext get() {
        init();
        return this.securityContext;
    }

    /**
     * This method checks if the SecurityContext was generated (i.e., not provided by the Supplier).
     * If the SecurityContext has not been initialized yet, it initializes it.
     *
     * @return true if the SecurityContext was generated, false otherwise
     */
    @Override
    public boolean isGenerated() {
        init();
        return this.missingContext;
    }

    /**
     * This method initializes the SecurityContext. If the SecurityContext has already been initialized, it does
     * nothing.
     * It first tries to get the SecurityContext from the Supplier. If the Supplier does not provide a SecurityContext,
     * it creates an empty SecurityContext using the SecurityContextHolderStrategy and sets the missingContext flag to
     * true.
     */
    private void init() {
        if (this.securityContext != null) {
            return;
        }

        this.securityContext = this.supplier.get();
        this.missingContext = (this.securityContext == null);
        if (this.missingContext) {
            this.securityContext = this.strategy.createEmptyContext();
            LOGGER.trace("Created {}", this.securityContext);
        }
    }

}