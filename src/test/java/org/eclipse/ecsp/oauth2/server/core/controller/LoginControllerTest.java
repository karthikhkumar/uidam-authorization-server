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

package org.eclipse.ecsp.oauth2.server.core.controller;

import lombok.extern.slf4j.Slf4j;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.service.LoginService;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * This class tests the functionality of the LoginController.
 */
@Slf4j
@WebMvcTest(LoginController.class)
@ContextConfiguration(classes = {LoginController.class, TenantConfigurationService.class})
@EnableConfigurationProperties(value = TenantProperties.class)
@TestPropertySource("classpath:application-test.properties")
@TestPropertySource("classpath:external-idp-application.properties")
class LoginControllerTest {

    @Autowired
    private WebApplicationContext wac;

    @MockitoBean
    LoginService loginService;

    private MockMvc mockMvc;

    /**
     * This method sets up the test environment before each test.
     * It initializes the MockMvc instance.
     */
    @BeforeEach
    void setup() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
    }

    /**
     * This test method tests the scenario where an anonymous user can access the login page.
     * It performs a GET request to the /login endpoint.
     * The test asserts that the returned status is HttpStatus.OK, the view name is "login", and the
     * "isAccountFieldEnabled" model attribute exists.
     */
    @Test
    void shouldAllowLoginPageAccessForAnonymousUser() throws Exception {
        this.mockMvc
            .perform(get("/login"))
            .andExpect(status().isOk())
            .andExpect(view().name("login"))
            .andExpect(model().attributeExists("isAccountFieldEnabled"));
    }

    /**
     * This test method tests the scenario where an anonymous user can access the error page.
     * It performs a GET request to the /error endpoint.
     * The test asserts that the returned status is HttpStatus.OK and the view name is "error".
     */
    @Test
    void shouldAllowErrorPageAccessForAnonymousUser() throws Exception {
        this.mockMvc
            .perform(get("/error"))
            .andExpect(status().isOk())
            .andExpect(view().name("error"));
    }
}