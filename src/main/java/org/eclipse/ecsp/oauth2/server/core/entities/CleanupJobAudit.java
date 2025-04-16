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
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.time.Instant;

/**
 * Token cleanup audit entity.
 *
 */

@Getter
@Setter
@Entity
@ToString
@Table(name = "`cleanup_job_audit`")
public class CleanupJobAudit {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "cleanupJobAuditSequence")
    @SequenceGenerator(name = "cleanupJobAuditSequence", sequenceName = "cleanup_job_audit_id_seq", 
         allocationSize = 1)
    private Long id;
    @Column(name = "job_started_at")
    private Instant cleanupJobStartedAt;
    @Column(name = "job_completed_at")
    private Instant cleanupJobCompletedAt;
    @Column(name = "total_existing_records")
    private long totalExistingRecords;
    @Column(name = "total_deleted_records")
    private long totalDeletedRecords;
    @Column(name = "records_table_name")
    private String recordsTableName;
    @Column(name = "job_completed")
    private boolean jobCompleted;

}
