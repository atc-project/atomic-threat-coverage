| Title                | Default PowerSploit Schtasks Persistence                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the creation of a schtask via PowerSploit Default Configuration                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privelege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1053](https://attack.mitre.org/tactics/T1053)</li><li>[T1086](https://attack.mitre.org/tactics/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0024_21_windows_sysmon_WmiEvent](../Data_Needed/DN_0024_21_windows_sysmon_WmiEvent.md)</li><li>[DN_0009_5_windows_sysmon_process_terminated](../Data_Needed/DN_0009_5_windows_sysmon_process_terminated.md)</li><li>[DN_0010_6_windows_sysmon_driver_loaded](../Data_Needed/DN_0010_6_windows_sysmon_driver_loaded.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0012_8_windows_sysmon_CreateRemoteThread](../Data_Needed/DN_0012_8_windows_sysmon_CreateRemoteThread.md)</li><li>[DN_0014_10_windows_sysmon_ProcessAccess](../Data_Needed/DN_0014_10_windows_sysmon_ProcessAccess.md)</li><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li><li>[DN_0019_15_windows_sysmon_FileCreateStreamHash](../Data_Needed/DN_0019_15_windows_sysmon_FileCreateStreamHash.md)</li><li>[DN_0021_18_windows_sysmon_PipeEvent](../Data_Needed/DN_0021_18_windows_sysmon_PipeEvent.md)</li><li>[DN_0023_20_windows_sysmon_WmiEvent](../Data_Needed/DN_0023_20_windows_sysmon_WmiEvent.md)</li><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li><li>[DN_0006_2_windows_sysmon_process_changed_a_file_creation_time](../Data_Needed/DN_0006_2_windows_sysmon_process_changed_a_file_creation_time.md)</li><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0008_4_windows_sysmon_sysmon_service_state_changed](../Data_Needed/DN_0008_4_windows_sysmon_sysmon_service_state_changed.md)</li><li>[DN_0020_17_windows_sysmon_PipeEvent](../Data_Needed/DN_0020_17_windows_sysmon_PipeEvent.md)</li><li>[DN_0022_19_windows_sysmon_WmiEvent](../Data_Needed/DN_0022_19_windows_sysmon_WmiEvent.md)</li><li>[DN_0013_9_windows_sysmon_RawAccessRead](../Data_Needed/DN_0013_9_windows_sysmon_RawAccessRead.md)</li><li>[DN_0018_14_windows_sysmon_RegistryEvent](../Data_Needed/DN_0018_14_windows_sysmon_RegistryEvent.md)</li><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1053](../Triggering/T1053.md)</li><li>[T1086](../Triggering/T1086.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>False positives are possible, depends on organisation and processes</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://github.com/0xdeadbeefJERKY/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1](https://github.com/0xdeadbeefJERKY/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1)</li></ul>                                                          |
| Author               | Markus Neis                                                                                                                                                |
| Other Tags           | <ul><li>attack.s0111</li><li>attack.s0111</li><li>attack.g0022</li><li>attack.g0022</li><li>attack.g0060</li><li>attack.g0060</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Default PowerSploit Schtasks Persistence 
status: experimental
description: Detects the creation of a schtask via PowerSploit Default Configuration 
references:
    - https://github.com/0xdeadbeefJERKY/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1
author: Markus Neis
date: 2018/03/06
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        ParentImage:
            - '*\Powershell.exe'
        CommandLine:
            - '*\schtasks.exe*/Create*/RU*system*/SC*ONLOGON*'
            - '*\schtasks.exe*/Create*/RU*system*/SC*DAILY*'
            - '*\schtasks.exe*/Create*/RU*system*/SC*ONIDLE*'
            - '*\schtasks.exe*/Create*/RU*system*/SC*HOURLY*'
    condition: selection
tags:
    - attack.execution
    - attack.persistence
    - attack.privelege_escalation
    - attack.t1053
    - attack.t1086
    - attack.s0111
    - attack.g0022
    - attack.g0060
falsepositives:
    - False positives are possible, depends on organisation and processes
level: high

```





### Kibana query

```
(ParentImage:("*\\\\Powershell.exe") AND CommandLine:("*\\\\schtasks.exe*\\/Create*\\/RU*system*\\/SC*ONLOGON*" "*\\\\schtasks.exe*\\/Create*\\/RU*system*\\/SC*DAILY*" "*\\\\schtasks.exe*\\/Create*\\/RU*system*\\/SC*ONIDLE*" "*\\\\schtasks.exe*\\/Create*\\/RU*system*\\/SC*HOURLY*"))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Default-PowerSploit-Schtasks-Persistence <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(ParentImage:(\\"*\\\\\\\\Powershell.exe\\") AND CommandLine:(\\"*\\\\\\\\schtasks.exe*\\\\/Create*\\\\/RU*system*\\\\/SC*ONLOGON*\\" \\"*\\\\\\\\schtasks.exe*\\\\/Create*\\\\/RU*system*\\\\/SC*DAILY*\\" \\"*\\\\\\\\schtasks.exe*\\\\/Create*\\\\/RU*system*\\\\/SC*ONIDLE*\\" \\"*\\\\\\\\schtasks.exe*\\\\/Create*\\\\/RU*system*\\\\/SC*HOURLY*\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Default PowerSploit Schtasks Persistence\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(ParentImage:("*\\\\Powershell.exe") AND CommandLine:("*\\\\schtasks.exe*\\/Create*\\/RU*system*\\/SC*ONLOGON*" "*\\\\schtasks.exe*\\/Create*\\/RU*system*\\/SC*DAILY*" "*\\\\schtasks.exe*\\/Create*\\/RU*system*\\/SC*ONIDLE*" "*\\\\schtasks.exe*\\/Create*\\/RU*system*\\/SC*HOURLY*"))
```

