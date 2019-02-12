| Title                | NetNTLM Downgrade Attack                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects post exploitation using NetNTLM downgrade attacks                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1212](https://attack.mitre.org/tactics/T1212)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1212](../Triggers/T1212.md)</li></ul>  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
--- 
action: global
title: NetNTLM Downgrade Attack
description: Detects post exploitation using NetNTLM downgrade attacks
reference: 
    - https://www.optiv.com/blog/post-exploitation-using-netntlm-downgrade-attacks
author: Florian Roth
date: 2018/03/20
tags:
    - attack.credential_access
    - attack.t1212
detection:
    condition: 1 of them
falsepositives:
    - Unknown
level: critical
--- 
logsource:
    product: windows
    service: sysmon
detection:
    selection1:
        EventID: 13
        TargetObject: 
            - '*SYSTEM\*ControlSet*\Control\Lsa\lmcompatibilitylevel'
            - '*SYSTEM\*ControlSet*\Control\Lsa\NtlmMinClientSec'
            - '*SYSTEM\*ControlSet*\Control\Lsa\RestrictSendingNTLMTraffic'
---
# Windows Security Eventlog: Process Creation with Full Command Line
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Object Access > Audit Registry (Success)'
detection:
    selection2:
        EventID: 4657
        ObjectName: '\REGISTRY\MACHINE\SYSTEM\*ControlSet*\Control\Lsa'
        ObjectValueName: 
            - 'LmCompatibilityLevel'
            - 'NtlmMinClientSec'
            - 'RestrictSendingNTLMTraffic'

```





### Kibana query

```
(EventID:"13" AND TargetObject.keyword:(*SYSTEM\\*ControlSet*\\\\Control\\\\Lsa\\\\lmcompatibilitylevel *SYSTEM\\*ControlSet*\\\\Control\\\\Lsa\\\\NtlmMinClientSec *SYSTEM\\*ControlSet*\\\\Control\\\\Lsa\\\\RestrictSendingNTLMTraffic))\n(EventID:"4657" AND ObjectName.keyword:\\\\REGISTRY\\\\MACHINE\\\\SYSTEM\\*ControlSet*\\\\Control\\\\Lsa AND ObjectValueName:("LmCompatibilityLevel" "NtlmMinClientSec" "RestrictSendingNTLMTraffic"))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/NetNTLM-Downgrade-Attack <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"13\\" AND TargetObject.keyword:(*SYSTEM\\\\*ControlSet*\\\\\\\\Control\\\\\\\\Lsa\\\\\\\\lmcompatibilitylevel *SYSTEM\\\\*ControlSet*\\\\\\\\Control\\\\\\\\Lsa\\\\\\\\NtlmMinClientSec *SYSTEM\\\\*ControlSet*\\\\\\\\Control\\\\\\\\Lsa\\\\\\\\RestrictSendingNTLMTraffic))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'NetNTLM Downgrade Attack\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/NetNTLM-Downgrade-Attack-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4657\\" AND ObjectName.keyword:\\\\\\\\REGISTRY\\\\\\\\MACHINE\\\\\\\\SYSTEM\\\\*ControlSet*\\\\\\\\Control\\\\\\\\Lsa AND ObjectValueName:(\\"LmCompatibilityLevel\\" \\"NtlmMinClientSec\\" \\"RestrictSendingNTLMTraffic\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'NetNTLM Downgrade Attack\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"13" AND TargetObject:("*SYSTEM\\*ControlSet*\\\\Control\\\\Lsa\\\\lmcompatibilitylevel" "*SYSTEM\\*ControlSet*\\\\Control\\\\Lsa\\\\NtlmMinClientSec" "*SYSTEM\\*ControlSet*\\\\Control\\\\Lsa\\\\RestrictSendingNTLMTraffic"))\n(EventID:"4657" AND ObjectName:"\\\\REGISTRY\\\\MACHINE\\\\SYSTEM\\*ControlSet*\\\\Control\\\\Lsa" AND ObjectValueName:("LmCompatibilityLevel" "NtlmMinClientSec" "RestrictSendingNTLMTraffic"))
```

