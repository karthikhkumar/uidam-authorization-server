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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * This class tests the functionality of the DatabaseAuthorizedClientService.
 */
class DatabaseAuthorizedClientServiceTest {

    DatabaseAuthorizedClientService databaseAuthorizedClientService;

    /**
     * This method sets up the test environment before each test.
     */
    @BeforeEach
    void setUp() {
        databaseAuthorizedClientService = new DatabaseAuthorizedClientService();
    }

    /**
     * This test method tests the loadAuthorizedClient method of the DatabaseAuthorizedClientService.
     * It asserts that no exception is thrown.
     */
    @Test
    void loadAuthorizedClientTest() {
        assertDoesNotThrow(() -> databaseAuthorizedClientService.loadAuthorizedClient(null, null));
    }

    /**
     * This test method tests the saveAuthorizedClient method of the DatabaseAuthorizedClientService.
     * It asserts that no exception is thrown.
     */
    @Test
    void saveAuthorizedClientTest() {
        assertDoesNotThrow(() -> databaseAuthorizedClientService.saveAuthorizedClient(null, null));
    }

    /**
     * This test method tests the removeAuthorizedClient method of the DatabaseAuthorizedClientService.
     * It asserts that no exception is thrown.
     */
    @Test
    void removeAuthorizedClientTest() {
        assertDoesNotThrow(() -> databaseAuthorizedClientService.removeAuthorizedClient(null, null));
    }

}