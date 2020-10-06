| Title                    | Grabbing Sensitive Hives via Reg Utility       |
|:-------------------------|:------------------|
| **Description**          | Dump sam, system or security hives using REG.exe utility |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003.002: Security Account Manager](https://attack.mitre.org/techniques/T1003/002)</li><li>[T1003.004: LSA Secrets](https://attack.mitre.org/techniques/T1003/004)</li><li>[T1003.005: Cached Domain Credentials](https://attack.mitre.org/techniques/T1003/005)</li><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003.002: Security Account Manager](../Triggers/T1003.002.md)</li><li>[T1003.004: LSA Secrets](../Triggers/T1003.004.md)</li><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Dumping hives for legitimate purpouse i.e. backup or forensic investigation</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/aed95fc6-5e3f-49dc-8b35-06508613f979.html](https://eqllib.readthedocs.io/en/latest/analytics/aed95fc6-5e3f-49dc-8b35-06508613f979.html)</li><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov, Endgame, JHasenbusch, Daniil Yugoslavskiy, oscd.community |
| Other Tags           | <ul><li>car.2013-07-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Grabbing Sensitive Hives via Reg Utility
id: fd877b94-9bb5-4191-bb25-d79cbd93c167
description: Dump sam, system or security hives using REG.exe utility
author: Teymur Kheirkhabarov, Endgame, JHasenbusch, Daniil Yugoslavskiy, oscd.community
date: 2019/10/22
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
    - https://eqllib.readthedocs.io/en/latest/analytics/aed95fc6-5e3f-49dc-8b35-06508613f979.html
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md
tags:
    - attack.credential_access
    - attack.t1003.002
    - attack.t1003.004
    - attack.t1003.005
    - attack.t1003  # an old one
    - car.2013-07-001
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image: '*\reg.exe'
        CommandLine|contains:
            - 'save'
            - 'export'
    selection_2:
        CommandLine|contains:
            - 'hklm'
            - 'hkey_local_machine'
    selection_3:
        CommandLine|endswith:
            - '\system'
            - '\sam'
            - '\security'
    condition: selection_1 and selection_2 and selection_3
falsepositives:
    - Dumping hives for legitimate purpouse i.e. backup or forensic investigation
level: medium
status: experimental

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\\\reg.exe" -and ($_.message -match "CommandLine.*.*save.*" -or $_.message -match "CommandLine.*.*export.*") -and ($_.message -match "CommandLine.*.*hklm.*" -or $_.message -match "CommandLine.*.*hkey_local_machine.*") -and ($_.message -match "CommandLine.*.*\\\\system" -or $_.message -match "CommandLine.*.*\\\\sam" -or $_.message -match "CommandLine.*.*\\\\security")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\\\reg.exe AND winlog.event_data.CommandLine.keyword:(*save* OR *export*) AND winlog.event_data.CommandLine.keyword:(*hklm* OR *hkey_local_machine*) AND winlog.event_data.CommandLine.keyword:(*\\\\system OR *\\\\sam OR *\\\\security))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/fd877b94-9bb5-4191-bb25-d79cbd93c167 <<EOF\n{\n  "metadata": {\n    "title": "Grabbing Sensitive Hives via Reg Utility",\n    "description": "Dump sam, system or security hives using REG.exe utility",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003.002",\n      "attack.t1003.004",\n      "attack.t1003.005",\n      "attack.t1003",\n      "car.2013-07-001"\n    ],\n    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\reg.exe AND winlog.event_data.CommandLine.keyword:(*save* OR *export*) AND winlog.event_data.CommandLine.keyword:(*hklm* OR *hkey_local_machine*) AND winlog.event_data.CommandLine.keyword:(*\\\\\\\\system OR *\\\\\\\\sam OR *\\\\\\\\security))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\reg.exe AND winlog.event_data.CommandLine.keyword:(*save* OR *export*) AND winlog.event_data.CommandLine.keyword:(*hklm* OR *hkey_local_machine*) AND winlog.event_data.CommandLine.keyword:(*\\\\\\\\system OR *\\\\\\\\sam OR *\\\\\\\\security))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Grabbing Sensitive Hives via Reg Utility\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\reg.exe AND CommandLine.keyword:(*save* *export*) AND CommandLine.keyword:(*hklm* *hkey_local_machine*) AND CommandLine.keyword:(*\\\\system *\\\\sam *\\\\security))
```


### splunk
    
```
(Image="*\\\\reg.exe" (CommandLine="*save*" OR CommandLine="*export*") (CommandLine="*hklm*" OR CommandLine="*hkey_local_machine*") (CommandLine="*\\\\system" OR CommandLine="*\\\\sam" OR CommandLine="*\\\\security"))
```


### logpoint
    
```
(Image="*\\\\reg.exe" CommandLine IN ["*save*", "*export*"] CommandLine IN ["*hklm*", "*hkey_local_machine*"] CommandLine IN ["*\\\\system", "*\\\\sam", "*\\\\security"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\reg\\.exe)(?=.*(?:.*.*save.*|.*.*export.*))(?=.*(?:.*.*hklm.*|.*.*hkey_local_machine.*))(?=.*(?:.*.*\\system|.*.*\\sam|.*.*\\security)))'
```



