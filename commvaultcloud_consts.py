# File: commvaultcloud_consts.py
#
# Copyright (c) Commvault Systems, 2024-2025
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
PATH_KEY = "path"
SOURCE_SYSLOG = "syslog"
SOURCE_WEBHOOK = "webhook"
SOURCE_FETCH_INCIDENTS = "fetch"
DESCRIPTION = "description"
SEVERITY = "severity"
# Splunk container specific constants
CONTAINER_LABEL = "events"
CONTAINER_STATUS_OPEN = "open"
CONTAINER_STATUS_NEW = "new"
CONTAINER_STATUS_CLOSE = "closed"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
# Sensitivity white: public, green: controller, amber: confidential, red: classified
SENSITIVITY_RED = "red"
SENSITIVITY_GREEN = "green"
SENSITIVITY_AMBER = "amber"
SENSITIVITY_WHITE = "white"
# Artifact constants
ARTIFACT_NAME = "Commvault SecurityIQ Artifact"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters."
# Anomaly types
ANOMALY_TYPE_1 = "File Activity"
ANOMALY_TYPE_2 = "File Type"
ANOMALY_TYPE_3 = "Threat Analysis"
ANOMALY_TYPE_UNDEFINED = "Undefined"
# SUPPORTED_EVENT_CODES = ['7:211', '7:212', '7:293', '
# 7:269', '14:337', '14:338', '69:59', '7:333', '69:60','35:5575']
SUPPORTED_EVENT_CODES = ["14:337"]
ANOMALY_TYPE_2_PAYLOAD = (
    "eyJvcFR5cGUiOiAxLCAiZW50aXR5IjogeyJfdHlwZV8iOiAwfSwgIm9wdGlvbnMiOiB7InJlc3RvcmVJbm"  # pragma: allowlist secret
    "RleCI6IHRydWV9LCAicXVlcmllcyI6IFt7InR5cGUiOiAwLCAicXVlcnlJZCI6ICJNaW1lRmlsZUxpc3Q"  # pragma: allowlist secret
    "iLCAid2hlcmVDbGF1c2UiOiBbeyJjcml0ZXJpYSI6IHsiZmllbGQiOiAzOCwgImRhdGFPcGVyYXRvci"  # pragma: allowlist secret
    "I6IDksICJ2YWx1ZXMiOiBbImZpbGUiXX19LCB7ImNyaXRlcmlhIjogeyJmaWVsZCI6IDE0NywgImRhdGFP"  # pragma: allowlist secret
    "cGVyYXRvciI6IDAsICJ2YWx1ZXMiOiBbIjIiXX19XSwgImRhdGFQYXJhbSI6IHsic29ydFBhcmFtIjogey"  # pragma: allowlist secret
    "Jhc2NlbmRpbmciOiB0cnVlLCAic29ydEJ5IjogWzBdfSwgInBhZ2luZyI6IHsiZmlyc3ROb2RlIjogMCwg"  # pragma: allowlist secret
    "InBhZ2VTaXplIjogLTEsICJza2lwTm9kZSI6IDB9fX0sIHsidHlwZSI6IDEsICJxdWVyeUlkIjogIk1pbWV"  # pragma: allowlist secret
    "GaWxlQ291bnQiLCAid2hlcmVDbGF1c2UiOiBbeyJjcml0ZXJpYSI6IHsiZmllbGQiOiAzOCwgImRhdGFPc"  # pragma: allowlist secret
    "GVyYXRvciI6IDksICJ2YWx1ZXMiOiBbImZpbGUiXX19LCB7ImNyaXRlcmlhIjogeyJmaWVsZCI6IDE0Ny"  # pragma: allowlist secret
    "wgImRhdGFPcGVyYXRvciI6IDAsICJ2YWx1ZXMiOiBbIjIiXX19XSwgImRhdGFQYXJhbSI6IHsic29ydF"  # pragma: allowlist secret
    "BhcmFtIjogeyJhc2NlbmRpbmciOiB0cnVlLCAic29ydEJ5IjogWzBdfSwgInBhZ2luZyI6IHsiZmlyc3R"  # pragma: allowlist secret
    "Ob2RlIjogMCwgInBhZ2VTaXplIjogLTEsICJza2lwTm9kZSI6IDB9fX1dLCAicGF0aHMiOiBbeyJwYX"  # pragma: allowlist secret
    "RoIjogIi8qKi8qIn1dLCAiYWR2T3B0aW9ucyI6IHsiYWR2Q29uZmlnIjogeyJicm93c2VBZHZhbmNlZENvbm"  # pragma: allowlist secret
    "ZpZ0Jyb3dzZUJ5Sm9iIjogeyJqb2JJZCI6ICJ7e2JhY2t1cGpvYmlkfX0ifX19fQ=="  # pragma: allowlist secret
)
ANOMALY_TYPE_3_PAYLOAD = (
    "eyJvcFR5cGUiOiAxLCAiZW50aXR5IjogeyJfdHlwZV8iOiAwfSwgIm9wdGlvbnMiOiB7InJlc3RvcmVJbmRle"  # pragma: allowlist secret
    "CI6IHRydWUsICJhbGxvd0luZmVjdGVkRmlsZXNSZXN0b3JlIjogdHJ1ZX0sICJxdWVyaWVzIjogW3sidHlwZ"  # pragma: allowlist secret
    "SI6IDAsICJxdWVyeUlkIjogIkluZmVjdGVkRmlsZUxpc3QiLCAid2hlcmVDbGF1c2UiOiBbeyJjcml0ZXJp"  # pragma: allowlist secret
    "YSI6IHsiZmllbGQiOiAxNTEsICJkYXRhT3BlcmF0b3IiOiAwLCAidmFsdWVzIjogWyIxIl19fV0sICJkYXRh"  # pragma: allowlist secret
    "UGFyYW0iOiB7InNvcnRQYXJhbSI6IHsiYXNjZW5kaW5nIjogdHJ1ZSwgInNvcnRCeSI6IFswXX0sICJwYW"  # pragma: allowlist secret
    "dpbmciOiB7ImZpcnN0Tm9kZSI6IDAsICJwYWdlU2l6ZSI6IC0xLCAic2tpcE5vZGUiOiAwfX19LCB7InR5cG"  # pragma: allowlist secret
    "UiOiAxLCAicXVlcnlJZCI6ICJJbmZlY3RlZEZpbGVDb3VudCIsICJ3aGVyZUNsYXVzZSI6IFt7ImNyaXRlcml"  # pragma: allowlist secret
    "hIjogeyJmaWVsZCI6IDE1MSwgImRhdGFPcGVyYXRvciI6IDAsICJ2YWx1ZXMiOiBbIjEiXX19XSwgImFnZ3J"  # pragma: allowlist secret
    "QYXJhbSI6IHsiZmllbGQiOiA4MCwgImFnZ3JUeXBlIjogNH19XSwgInBhdGhzIjogW3sicGF0aCI6ICIvKio"  # pragma: allowlist secret
    "vKiJ9XSwgImFkdk9wdGlvbnMiOiB7ImFkdkNvbmZpZyI6IHsiYnJvd3NlQWR2YW5jZWRDb25maWdCcm93c2V"  # pragma: allowlist secret
    "CeUpvYiI6IHsiam9iSWQiOiAie3tiYWNrdXBqb2JpZH19In19fX0="  # pragma: allowlist secret
)
