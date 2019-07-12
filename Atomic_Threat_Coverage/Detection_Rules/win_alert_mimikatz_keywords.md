| Title                | Mimikatz Use                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This method detects mimikatz keywords in different Eventlogs (some of them only appear in older Mimikatz version that are however still used by different threat groups)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0053_2100_pnp_or_power_operation_for_usb_device](../Data_Needed/DN_0053_2100_pnp_or_power_operation_for_usb_device.md)</li><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li><li>[DN_0006_2_windows_sysmon_process_changed_a_file_creation_time](../Data_Needed/DN_0006_2_windows_sysmon_process_changed_a_file_creation_time.md)</li><li>[DN_0012_8_windows_sysmon_CreateRemoteThread](../Data_Needed/DN_0012_8_windows_sysmon_CreateRemoteThread.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0066_4704_user_right_was_assigned](../Data_Needed/DN_0066_4704_user_right_was_assigned.md)</li><li>[DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account](../Data_Needed/DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account.md)</li><li>[DN_0062_4663_attempt_was_made_to_access_an_object](../Data_Needed/DN_0062_4663_attempt_was_made_to_access_an_object.md)</li><li>[DN_0019_15_windows_sysmon_FileCreateStreamHash](../Data_Needed/DN_0019_15_windows_sysmon_FileCreateStreamHash.md)</li><li>[DN_0052_2003_query_to_load_usb_drivers](../Data_Needed/DN_0052_2003_query_to_load_usb_drivers.md)</li><li>[DN_0058_4656_handle_to_an_object_was_requested](../Data_Needed/DN_0058_4656_handle_to_an_object_was_requested.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0045_1001_windows_error_reporting](../Data_Needed/DN_0045_1001_windows_error_reporting.md)</li><li>[DN_0010_6_windows_sysmon_driver_loaded](../Data_Needed/DN_0010_6_windows_sysmon_driver_loaded.md)</li><li>[DN_0076_4768_kerberos_authentication_ticket_was_requested](../Data_Needed/DN_0076_4768_kerberos_authentication_ticket_was_requested.md)</li><li>[DN_0023_20_windows_sysmon_WmiEvent](../Data_Needed/DN_0023_20_windows_sysmon_WmiEvent.md)</li><li>[DN_0046_1031_dhcp_service_callout_dll_file_has_caused_an_exception](../Data_Needed/DN_0046_1031_dhcp_service_callout_dll_file_has_caused_an_exception.md)</li><li>[DN_0048_1033_dhcp_service_successfully_loaded_callout_dlls](../Data_Needed/DN_0048_1033_dhcp_service_successfully_loaded_callout_dlls.md)</li><li>[DN_0038_1102_the_audit_log_was_cleared](../Data_Needed/DN_0038_1102_the_audit_log_was_cleared.md)</li><li>[DN_0085_22_windows_sysmon_DnsQuery](../Data_Needed/DN_0085_22_windows_sysmon_DnsQuery.md)</li><li>[DN_0083_16_access_history_in_hive_was_cleared](../Data_Needed/DN_0083_16_access_history_in_hive_was_cleared.md)</li><li>[DN_0022_19_windows_sysmon_WmiEvent](../Data_Needed/DN_0022_19_windows_sysmon_WmiEvent.md)</li><li>[DN_0029_4661_handle_to_an_object_was_requested](../Data_Needed/DN_0029_4661_handle_to_an_object_was_requested.md)</li><li>[DN_0035_106_task_scheduler_task_registered](../Data_Needed/DN_0035_106_task_scheduler_task_registered.md)</li><li>[DN_0026_5136_windows_directory_service_object_was_modified](../Data_Needed/DN_0026_5136_windows_directory_service_object_was_modified.md)</li><li>[DN_0073_4756_member_was_added_to_a_security_enabled_universal_group](../Data_Needed/DN_0073_4756_member_was_added_to_a_security_enabled_universal_group.md)</li><li>[DN_0036_150_dns_server_could_not_load_dll](../Data_Needed/DN_0036_150_dns_server_could_not_load_dll.md)</li><li>[DN_0018_14_windows_sysmon_RegistryEvent](../Data_Needed/DN_0018_14_windows_sysmon_RegistryEvent.md)</li><li>[DN_0049_1034_dhcp_service_failed_to_load_callout_dlls](../Data_Needed/DN_0049_1034_dhcp_service_failed_to_load_callout_dlls.md)</li><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li><li>[DN_0060_4658_handle_to_an_object_was_closed](../Data_Needed/DN_0060_4658_handle_to_an_object_was_closed.md)</li><li>[DN_0059_4657_registry_value_was_modified](../Data_Needed/DN_0059_4657_registry_value_was_modified.md)</li><li>[DN_0077_4769_kerberos_service_ticket_was_requested](../Data_Needed/DN_0077_4769_kerberos_service_ticket_was_requested.md)</li><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li><li>[DN_0030_4662_operation_was_performed_on_an_object](../Data_Needed/DN_0030_4662_operation_was_performed_on_an_object.md)</li><li>[DN_0057_4625_account_failed_to_logon](../Data_Needed/DN_0057_4625_account_failed_to_logon.md)</li><li>[DN_0072_4755_security_enabled_universal_group_was_changed](../Data_Needed/DN_0072_4755_security_enabled_universal_group_was_changed.md)</li><li>[DN_0082_8002_ntlm_server_blocked_audit](../Data_Needed/DN_0082_8002_ntlm_server_blocked_audit.md)</li><li>[DN_0063_4697_service_was_installed_in_the_system](../Data_Needed/DN_0063_4697_service_was_installed_in_the_system.md)</li><li>[DN_0061_4660_object_was_deleted](../Data_Needed/DN_0061_4660_object_was_deleted.md)</li><li>[DN_0020_17_windows_sysmon_PipeEvent](../Data_Needed/DN_0020_17_windows_sysmon_PipeEvent.md)</li><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li><li>[DN_0028_4794_directory_services_restore_mode_admin_password_set](../Data_Needed/DN_0028_4794_directory_services_restore_mode_admin_password_set.md)</li><li>[DN_0067_4719_system_audit_policy_was_changed](../Data_Needed/DN_0067_4719_system_audit_policy_was_changed.md)</li><li>[DN_0050_1102_audit_log_was_cleared](../Data_Needed/DN_0050_1102_audit_log_was_cleared.md)</li><li>[DN_0044_1000_application_crashed](../Data_Needed/DN_0044_1000_application_crashed.md)</li><li>[DN_0021_18_windows_sysmon_PipeEvent](../Data_Needed/DN_0021_18_windows_sysmon_PipeEvent.md)</li><li>[DN_0031_7036_service_started_stopped](../Data_Needed/DN_0031_7036_service_started_stopped.md)</li><li>[DN_0069_4732_member_was_added_to_security_enabled_local_group](../Data_Needed/DN_0069_4732_member_was_added_to_security_enabled_local_group.md)</li><li>[DN_0071_4737_security_enabled_global_group_was_changed](../Data_Needed/DN_0071_4737_security_enabled_global_group_was_changed.md)</li><li>[DN_0027_4738_user_account_was_changed](../Data_Needed/DN_0027_4738_user_account_was_changed.md)</li><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li><li>[DN_0068_4728_member_was_added_to_security_enabled_global_group](../Data_Needed/DN_0068_4728_member_was_added_to_security_enabled_global_group.md)</li><li>[DN_0080_5859_wmi_activity](../Data_Needed/DN_0080_5859_wmi_activity.md)</li><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li><li>[DN_0034_104_log_file_was_cleared](../Data_Needed/DN_0034_104_log_file_was_cleared.md)</li><li>[DN_0024_21_windows_sysmon_WmiEvent](../Data_Needed/DN_0024_21_windows_sysmon_WmiEvent.md)</li><li>[DN_0054_2102_pnp_or_power_operation_for_usb_device](../Data_Needed/DN_0054_2102_pnp_or_power_operation_for_usb_device.md)</li><li>[DN_0078_4771_kerberos_pre_authentication_failed](../Data_Needed/DN_0078_4771_kerberos_pre_authentication_failed.md)</li><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li><li>[DN_0033_5140_network_share_object_was_accessed](../Data_Needed/DN_0033_5140_network_share_object_was_accessed.md)</li><li>[DN_0014_10_windows_sysmon_ProcessAccess](../Data_Needed/DN_0014_10_windows_sysmon_ProcessAccess.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0009_5_windows_sysmon_process_terminated](../Data_Needed/DN_0009_5_windows_sysmon_process_terminated.md)</li><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li><li>[DN_0038_400_windows_powershell_engine_lifecycle](../Data_Needed/DN_0038_400_windows_powershell_engine_lifecycle.md)</li><li>[DN_0081_5861_wmi_activity](../Data_Needed/DN_0081_5861_wmi_activity.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0070_4735_security_enabled_local_group_was_changed](../Data_Needed/DN_0070_4735_security_enabled_local_group_was_changed.md)</li><li>[DN_0065_4701_scheduled_task_was_disabled](../Data_Needed/DN_0065_4701_scheduled_task_was_disabled.md)</li><li>[DN_0008_4_windows_sysmon_sysmon_service_state_changed](../Data_Needed/DN_0008_4_windows_sysmon_sysmon_service_state_changed.md)</li><li>[DN_0047_1032_dhcp_service_callout_dll_file_has_caused_an_exception](../Data_Needed/DN_0047_1032_dhcp_service_callout_dll_file_has_caused_an_exception.md)</li><li>[DN_0064_4698_scheduled_task_was_created](../Data_Needed/DN_0064_4698_scheduled_task_was_created.md)</li><li>[DN_0013_9_windows_sysmon_RawAccessRead](../Data_Needed/DN_0013_9_windows_sysmon_RawAccessRead.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Naughty administrators</li><li>Penetration test</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>attack.s0002</li><li>attack.s0002</li><li>car.2013-07-001</li><li>car.2013-07-001</li><li>car.2019-04-004</li><li>car.2019-04-004</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Mimikatz Use
description: This method detects mimikatz keywords in different Eventlogs (some of them only appear in older Mimikatz version that are however still used by different threat groups)
author: Florian Roth
tags:
    - attack.s0002
    - attack.t1003
    - attack.lateral_movement
    - attack.credential_access
    - car.2013-07-001
    - car.2019-04-004
logsource:
    product: windows
detection:
    keywords:
        - "* mimikatz *"
        - "* mimilib *"
        - "* <3 eo.oe *"
        - "* eo.oe.kiwi *"
        - "* privilege::debug *"
        - "* sekurlsa::logonpasswords *"
        - "* lsadump::sam *"
        - "* mimidrv.sys *"
    condition: keywords
falsepositives:
    - Naughty administrators
    - Penetration test
level: critical

```





### es-qs
    
```
(*\\ mimikatz\\ * OR *\\ mimilib\\ * OR *\\ 3\\ eo.oe\\ * OR *\\ eo.oe.kiwi\\ * OR *\\ privilege\\:\\:debug\\ * OR *\\ sekurlsa\\:\\:logonpasswords\\ * OR *\\ lsadump\\:\\:sam\\ * OR *\\ mimidrv.sys\\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Mimikatz-Use <<EOF\n{\n  "metadata": {\n    "title": "Mimikatz Use",\n    "description": "This method detects mimikatz keywords in different Eventlogs (some of them only appear in older Mimikatz version that are however still used by different threat groups)",\n    "tags": [\n      "attack.s0002",\n      "attack.t1003",\n      "attack.lateral_movement",\n      "attack.credential_access",\n      "car.2013-07-001",\n      "car.2019-04-004"\n    ],\n    "query": "(*\\\\ mimikatz\\\\ * OR *\\\\ mimilib\\\\ * OR *\\\\ 3\\\\ eo.oe\\\\ * OR *\\\\ eo.oe.kiwi\\\\ * OR *\\\\ privilege\\\\:\\\\:debug\\\\ * OR *\\\\ sekurlsa\\\\:\\\\:logonpasswords\\\\ * OR *\\\\ lsadump\\\\:\\\\:sam\\\\ * OR *\\\\ mimidrv.sys\\\\ *)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(*\\\\ mimikatz\\\\ * OR *\\\\ mimilib\\\\ * OR *\\\\ 3\\\\ eo.oe\\\\ * OR *\\\\ eo.oe.kiwi\\\\ * OR *\\\\ privilege\\\\:\\\\:debug\\\\ * OR *\\\\ sekurlsa\\\\:\\\\:logonpasswords\\\\ * OR *\\\\ lsadump\\\\:\\\\:sam\\\\ * OR *\\\\ mimidrv.sys\\\\ *)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Mimikatz Use\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
("* mimikatz *" OR "* mimilib *" OR "* <3 eo.oe *" OR "* eo.oe.kiwi *" OR "* privilege\\:\\:debug *" OR "* sekurlsa\\:\\:logonpasswords *" OR "* lsadump\\:\\:sam *" OR "* mimidrv.sys *")
```


### splunk
    
```
("* mimikatz *" OR "* mimilib *" OR "* <3 eo.oe *" OR "* eo.oe.kiwi *" OR "* privilege::debug *" OR "* sekurlsa::logonpasswords *" OR "* lsadump::sam *" OR "* mimidrv.sys *")
```


### logpoint
    
```
("* mimikatz *" OR "* mimilib *" OR "* <3 eo.oe *" OR "* eo.oe.kiwi *" OR "* privilege::debug *" OR "* sekurlsa::logonpasswords *" OR "* lsadump::sam *" OR "* mimidrv.sys *")
```


### grep
    
```
grep -P '^(?:.*(?:.*.* mimikatz .*|.*.* mimilib .*|.*.* <3 eo\\.oe .*|.*.* eo\\.oe\\.kiwi .*|.*.* privilege::debug .*|.*.* sekurlsa::logonpasswords .*|.*.* lsadump::sam .*|.*.* mimidrv\\.sys .*))'
```



