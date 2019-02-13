| Title                | Abusing impersonation. Service account –> SYSTEM                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detection of processes spawned under SYSTEM by processes started with Network or Local service accounts                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1134](https://attack.mitre.org/tactics/T1134)</li></ul>                             |
| Data Needed          | <ul><li>[[]](../Data_Needed/[].md)</li><li>[['DN_0003_1_windows_sysmon_process_creation']](../Data_Needed/['DN_0003_1_windows_sysmon_process_creation'].md)</li><li>[['DN_0003_1_windows_sysmon_process_creation']](../Data_Needed/['DN_0003_1_windows_sysmon_process_creation'].md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1134](../Triggering/T1134.md)</li></ul>  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>Todo</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-privilege-escalation-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)</li></ul>                                                          |
| Author               | Teymur Kheirkhabarov                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Abusing impersonation. Service account –> SYSTEM
description: Detection of processes spawned under SYSTEM by processes started with Network or Local service accounts
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1134
status: experimental
author: Teymur Kheirkhabarov
logsource:
    product: windows
    service: sysmon
detection:
    selection1:
        EventID: 1
        User: "NT AUTHORITY\\SYSTEM"
        ParentUser: 
          - "NT AUTHORITY\\NETWORK SERVICE" 
          - "NT AUTHORITY\\LOCAL SERVICE"
    selection2:
        CommandLine: 
            - "*rundll32*"
    selection3:
        CommandLine: 
            - "*DavSetCookie*"            
    condition: selection1 and not (selection2 and selection3)
falsepositives: 
    - Todo
level: critical
enrichment:
    - EN_0001_cache_sysmon_event_id_1_info
    - EN_0002_enrich_sysmon_event_id_1_with_parent_info

```





### Kibana query

```
((EventID:"1" AND User:"NT AUTHORITY\\\\SYSTEM" AND ParentUser:("NT AUTHORITY\\\\NETWORK SERVICE" "NT AUTHORITY\\\\LOCAL SERVICE")) AND NOT ((CommandLine:("*rundll32*") AND CommandLine:("*DavSetCookie*"))))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Abusing-impersonation.-Service-account-\xe2\x80\x93>-SYSTEM <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"1\\" AND User:\\"NT AUTHORITY\\\\\\\\SYSTEM\\" AND ParentUser:(\\"NT AUTHORITY\\\\\\\\NETWORK SERVICE\\" \\"NT AUTHORITY\\\\\\\\LOCAL SERVICE\\")) AND NOT ((CommandLine:(\\"*rundll32*\\") AND CommandLine:(\\"*DavSetCookie*\\"))))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Abusing impersonation. Service account \\u2013> SYSTEM\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
((EventID:"1" AND User:"NT AUTHORITY\\\\SYSTEM" AND ParentUser:("NT AUTHORITY\\\\NETWORK SERVICE" "NT AUTHORITY\\\\LOCAL SERVICE")) AND NOT ((CommandLine:("*rundll32*") AND CommandLine:("*DavSetCookie*"))))
```

