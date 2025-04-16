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

package org.eclipse.ecsp.oauth2.server.core.job;

import org.eclipse.ecsp.oauth2.server.core.exception.CleanupJobException;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationRepository;
import org.eclipse.ecsp.oauth2.server.core.repositories.CleanupJobAuditRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.context.ActiveProfiles;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Token cleanup job Test.
 *
 */

@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
class CleanupJobTest {

    @Mock
    AuthorizationRepository authorizationRepository;

    @Mock
    CleanupJobAuditRepository cleanupJobAuditRepository;

    @InjectMocks
    CleanupJob cleanupJob;

    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testTokenCleanupJob() {
        when(authorizationRepository.count()).thenReturn(1L);
        List<String> ids = List.of("ids");
        when(authorizationRepository.findByTokenOrCodeExpiresBefore(any(Instant.class), anyInt()))
        .thenReturn(ids).thenReturn(Collections.emptyList());
        cleanupJob.executeCleanupTasks();
        verify(authorizationRepository, times(1 + 1)).findByTokenOrCodeExpiresBefore(any(Instant.class), anyInt());
        verify(authorizationRepository, times(1)).deleteAllById(ids);

    }

    @Test
    void testTokenCleanupJobNoTokens() {
        when(authorizationRepository.count()).thenReturn(1L);
        List<String> ids = Collections.emptyList();
        when(authorizationRepository.findByTokenOrCodeExpiresBefore(any(Instant.class), anyInt())).thenReturn(ids);
        cleanupJob.executeCleanupTasks();
        verify(authorizationRepository, times(1)).findByTokenOrCodeExpiresBefore(any(Instant.class), anyInt());
        verify(authorizationRepository, times(0)).deleteAllById(ids);

    }

    @Test
    void testTokenCleanupJobExceptionCase() throws InterruptedException {
        when(authorizationRepository.count()).thenReturn(1L);
        when(authorizationRepository.findByTokenOrCodeExpiresBefore(any(Instant.class), anyInt()))
            .thenThrow(new RuntimeException());
        assertThrowsExactly(CleanupJobException.class, () -> cleanupJob.executeCleanupTasks());
        verify(authorizationRepository, times(1)).findByTokenOrCodeExpiresBefore(any(Instant.class), anyInt());

    }

}
