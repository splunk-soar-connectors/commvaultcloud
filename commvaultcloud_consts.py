class Constants:
    event_id: str = "event_id"
    event_time: str = "event_time"
    anomaly_sub_type: str = "anomaly_sub_type"
    originating_client: str = "originating_client"
    originating_program: str = "originating_program"
    job: str = "job"
    job_id: str = "job_id"
    affected_files_count: str = "affected_files_count"
    modified_files_count: str = "modified_files_count"
    deleted_files_count: str = "deleted_files_count"
    renamed_files_count: str = "renamed_files_count"
    created_files_count: str = "created_files_count"
    facility: str = "Commvault"
    path_key: str = "path"
    source_syslog: str = "syslog"
    source_webhook: str = "webhook"
    source_fetch_incidents: str = "fetch"
    description: str = "description"
    severity: str = 'severity'
    # Splunk container specific constants
    container_label = 'events'
    container_status_open: str = 'open'
    container_status_new: str = 'new'
    container_status_close: str = 'closed'
    severity_high: str = "high"
    severity_medium: str = "medium"
    severity_low: str = "low"
    # Sensitivity white: public, green: controller, amber: confidential, red: classified
    sensitivity_red: str = "red"
    sensitivity_green: str = "green"
    sensitivity_amber: str = "amber"
    sensitivity_white: str = "white"
    # Artifact constants
    artifact_name: str = 'Commvault SecurityIQ Artifact'
    ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters."
    # Anomaly types
    ANOMALY_TYPE_1 = 'File Activity'
    ANOMALY_TYPE_2 = 'File Type'
    ANOMALY_TYPE_3 = 'Threat Analysis'
    ANOMALY_TYPE_UNDEFINED = 'Undefined'
    # SUPPORTED_EVENT_CODES = ['7:211', '7:212', '7:293', '
    # 7:269', '14:337', '14:338', '69:59', '7:333', '69:60','35:5575']
    SUPPORTED_EVENT_CODES = ['14:337']
    ANOMALY_TYPE_2_PAYLOAD = 'eyJvcFR5cGUiOiAxLCAiZW50aXR5IjogeyJfdHlwZV8iOiAwfSwgIm9wdGlvbnMiOiB7InJlc3RvcmVJbm' \
                             'RleCI6IHRydWV9LCAicXVlcmllcyI6IFt7InR5cGUiOiAwLCAicXVlcnlJZCI6ICJNaW1lRmlsZUxpc3Q' \
                             'iLCAid2hlcmVDbGF1c2UiOiBbeyJjcml0ZXJpYSI6IHsiZmllbGQiOiAzOCwgImRhdGFPcGVyYXRvci' \
                             'I6IDksICJ2YWx1ZXMiOiBbImZpbGUiXX19LCB7ImNyaXRlcmlhIjogeyJmaWVsZCI6IDE0NywgImRhdGFP' \
                             'cGVyYXRvciI6IDAsICJ2YWx1ZXMiOiBbIjIiXX19XSwgImRhdGFQYXJhbSI6IHsic29ydFBhcmFtIjogey' \
                             'Jhc2NlbmRpbmciOiB0cnVlLCAic29ydEJ5IjogWzBdfSwgInBhZ2luZyI6IHsiZmlyc3ROb2RlIjogMCwg' \
                             'InBhZ2VTaXplIjogLTEsICJza2lwTm9kZSI6IDB9fX0sIHsidHlwZSI6IDEsICJxdWVyeUlkIjogIk1pbWV' \
                             'GaWxlQ291bnQiLCAid2hlcmVDbGF1c2UiOiBbeyJjcml0ZXJpYSI6IHsiZmllbGQiOiAzOCwgImRhdGFPc' \
                             'GVyYXRvciI6IDksICJ2YWx1ZXMiOiBbImZpbGUiXX19LCB7ImNyaXRlcmlhIjogeyJmaWVsZCI6IDE0Ny' \
                             'wgImRhdGFPcGVyYXRvciI6IDAsICJ2YWx1ZXMiOiBbIjIiXX19XSwgImRhdGFQYXJhbSI6IHsic29ydF' \
                             'BhcmFtIjogeyJhc2NlbmRpbmciOiB0cnVlLCAic29ydEJ5IjogWzBdfSwgInBhZ2luZyI6IHsiZmlyc3R' \
                             'Ob2RlIjogMCwgInBhZ2VTaXplIjogLTEsICJza2lwTm9kZSI6IDB9fX1dLCAicGF0aHMiOiBbeyJwYX' \
                             'RoIjogIi8qKi8qIn1dLCAiYWR2T3B0aW9ucyI6IHsiYWR2Q29uZmlnIjogeyJicm93c2VBZHZhbmNlZENvbm' \
                             'ZpZ0Jyb3dzZUJ5Sm9iIjogeyJqb2JJZCI6ICJ7e2JhY2t1cGpvYmlkfX0ifX19fQ=='
    ANOMALY_TYPE_3_PAYLOAD = 'eyJvcFR5cGUiOiAxLCAiZW50aXR5IjogeyJfdHlwZV8iOiAwfSwgIm9wdGlvbnMiOiB7InJlc3RvcmVJbmRle' \
                             'CI6IHRydWUsICJhbGxvd0luZmVjdGVkRmlsZXNSZXN0b3JlIjogdHJ1ZX0sICJxdWVyaWVzIjogW3sidHlwZ' \
                             'SI6IDAsICJxdWVyeUlkIjogIkluZmVjdGVkRmlsZUxpc3QiLCAid2hlcmVDbGF1c2UiOiBbeyJjcml0ZXJp' \
                             'YSI6IHsiZmllbGQiOiAxNTEsICJkYXRhT3BlcmF0b3IiOiAwLCAidmFsdWVzIjogWyIxIl19fV0sICJkYXRh' \
                             'UGFyYW0iOiB7InNvcnRQYXJhbSI6IHsiYXNjZW5kaW5nIjogdHJ1ZSwgInNvcnRCeSI6IFswXX0sICJwYW' \
                             'dpbmciOiB7ImZpcnN0Tm9kZSI6IDAsICJwYWdlU2l6ZSI6IC0xLCAic2tpcE5vZGUiOiAwfX19LCB7InR5cG' \
                             'UiOiAxLCAicXVlcnlJZCI6ICJJbmZlY3RlZEZpbGVDb3VudCIsICJ3aGVyZUNsYXVzZSI6IFt7ImNyaXRlcml' \
                             'hIjogeyJmaWVsZCI6IDE1MSwgImRhdGFPcGVyYXRvciI6IDAsICJ2YWx1ZXMiOiBbIjEiXX19XSwgImFnZ3J' \
                             'QYXJhbSI6IHsiZmllbGQiOiA4MCwgImFnZ3JUeXBlIjogNH19XSwgInBhdGhzIjogW3sicGF0aCI6ICIvKio' \
                             'vKiJ9XSwgImFkdk9wdGlvbnMiOiB7ImFkdkNvbmZpZyI6IHsiYnJvd3NlQWR2YW5jZWRDb25maWdCcm93c2V' \
                             'CeUpvYiI6IHsiam9iSWQiOiAie3tiYWNrdXBqb2JpZH19In19fX0='
