# File: commvaultcloud_consts.py
#
# Copyright (c) Commvault Systems, 2024
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

EVENT_ID = "event_id"
EVENT_TIME = "event_time"
ANOMALY_SUB_TYPE = "anomaly_sub_type"
ORIGINATING_CLIENT = "originating_client"
ORIGINATING_PROGRAM = "originating_program"
JOB = "job"
JOB_ID = "job_id"
AFFECTED_FILES_COUNT = "affected_files_count"
MODIFIED_FILES_COUNT = "modified_files_count"
DELETED_FILES_COUNT = "deleted_files_count"
RENAMED_FILES_COUNT = "renamed_files_count"
CREATED_FILES_COUNT = "created_files_count"
FACILITY = "Commvault"
DESCRIPTION = "description"
SEVERITY = 'severity'
# Splunk container specific constants
CONTAINER_LABEL = 'events'
CONTAINER_STATUS_OPEN = 'open'
SEVERITY_MEDIUM = "medium"
# Sensitivity amber: confidential
SENSITIVITY_AMBER = "amber"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters."

# SUPPORTED_EVENT_CODES = ['7:211', '7:212', '7:293', '
# 7:269', '14:337', '14:338', '69:59', '7:333', '69:60','35:5575']
SUPPORTED_EVENT_CODES = ['69:59','17:193','69:60','14:337','14:338','7:349']
EVENT_CODE_TO_ANOMALY_TYPE = {
    '69:59': 'Threat Scan - Malware Detection',
    '17:193': 'Threat Scan - Malware Detection',
    '69:60': 'Threat Scan - Encryption Detection',
    '14:337': 'Threat Scan - Anomaly Detection',
    '14:338': 'Threat Scan - Anomaly Detection',
    '7:349': 'Threat Scan - Anomaly Detection'
}
EVENT_CODE_TO_SEVERITY = {
    '69:59': 'high',
    '17:193': 'high',
    '69:60': 'high',
    '14:337': 'medium',
    '14:338': 'medium',
    '7:349': 'medium'
}
PARTNER_ID = 5