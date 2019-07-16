| Title                | Logon Scripts (UserInitMprLogonScript)                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects creation or execution of UserInitMprLogonScript persistence method                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1037: Logon Scripts](https://attack.mitre.org/techniques/T1037)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0018_14_windows_sysmon_RegistryEvent](../Data_Needed/DN_0018_14_windows_sysmon_RegistryEvent.md)</li><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1037: Logon Scripts](../Triggers/T1037.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>exclude legitimate logon scripts</li><li>penetration tests, red teaming</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://attack.mitre.org/techniques/T1037/](https://attack.mitre.org/techniques/T1037/)</li></ul>  |
| Author               | Tom Ueltschi (@c_APT_ure) |


## Detection Rules

### Sigma rule

```
title: Logon Scripts (UserInitMprLogonScript)
status: experimental
description: Detects creation or execution of UserInitMprLogonScript persistence method
references:
    - https://attack.mitre.org/techniques/T1037/
tags:
    - attack.t1037
    - attack.persistence
    - attack.lateral_movement
author: Tom Ueltschi (@c_APT_ure)
logsource:
    product: windows
    service: sysmon
detection:
    exec_selection:
        EventID: 1 # Migration to process_creation requires multipart YAML
        ParentImage: '*\userinit.exe'
    exec_exclusion:
        Image: '*\explorer.exe'
        CommandLine: '*\netlogon.bat'
    create_selection:
        EventID:
            - 1
            - 11
            - 12
            - 13
            - 14
    create_keywords:
        - UserInitMprLogonScript
    condition: (exec_selection and not exec_exclusion) or (create_selection and create_keywords)
falsepositives:
    - exclude legitimate logon scripts
    - penetration tests, red teaming
level: high
```





### es-qs
    
```
(((EventID:"1" AND ParentImage.keyword:*\\\\userinit.exe) AND (NOT (Image.keyword:*\\\\explorer.exe AND CommandLine.keyword:*\\\\netlogon.bat))) OR (EventID:("1" "11" "12" "13" "14") AND "UserInitMprLogonScript"))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Logon-Scripts-UserInitMprLogonScript <<EOF\n{\n  "metadata": {\n    "title": "Logon Scripts (UserInitMprLogonScript)",\n    "description": "Detects creation or execution of UserInitMprLogonScript persistence method",\n    "tags": [\n      "attack.t1037",\n      "attack.persistence",\n      "attack.lateral_movement"\n    ],\n    "query": "(((EventID:\\"1\\" AND ParentImage.keyword:*\\\\\\\\userinit.exe) AND (NOT (Image.keyword:*\\\\\\\\explorer.exe AND CommandLine.keyword:*\\\\\\\\netlogon.bat))) OR (EventID:(\\"1\\" \\"11\\" \\"12\\" \\"13\\" \\"14\\") AND \\"UserInitMprLogonScript\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(((EventID:\\"1\\" AND ParentImage.keyword:*\\\\\\\\userinit.exe) AND (NOT (Image.keyword:*\\\\\\\\explorer.exe AND CommandLine.keyword:*\\\\\\\\netlogon.bat))) OR (EventID:(\\"1\\" \\"11\\" \\"12\\" \\"13\\" \\"14\\") AND \\"UserInitMprLogonScript\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Logon Scripts (UserInitMprLogonScript)\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(((EventID:"1" AND ParentImage:"*\\\\userinit.exe") AND NOT (Image:"*\\\\explorer.exe" AND CommandLine:"*\\\\netlogon.bat")) OR (EventID:("1" "11" "12" "13" "14") AND "UserInitMprLogonScript"))
```


### splunk
    
```
(((EventID="1" ParentImage="*\\\\userinit.exe") NOT (Image="*\\\\explorer.exe" CommandLine="*\\\\netlogon.bat")) OR ((EventID="1" OR EventID="11" OR EventID="12" OR EventID="13" OR EventID="14") "UserInitMprLogonScript"))
```


### logpoint
    
```
(((EventID="1" ParentImage="*\\\\userinit.exe")  -(Image="*\\\\explorer.exe" CommandLine="*\\\\netlogon.bat")) OR (EventID IN ["1", "11", "12", "13", "14"] "UserInitMprLogonScript"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*(?:.*(?=.*1)(?=.*.*\\userinit\\.exe)))(?=.*(?!.*(?:.*(?=.*.*\\explorer\\.exe)(?=.*.*\\netlogon\\.bat)))))|.*(?:.*(?=.*(?:.*1|.*11|.*12|.*13|.*14))(?=.*UserInitMprLogonScript))))'
```



