| Title                | Mimikatz In-Memory                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects certain DLL loads when Mimikatz gets executed                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://securityriskadvisors.com/blog/post/detecting-in-memory-mimikatz/](https://securityriskadvisors.com/blog/post/detecting-in-memory-mimikatz/)</li></ul>                                                          |
| Author               |                                                                                                                                                 |
| Other Tags           | <ul><li>attack.s0002</li><li>attack.s0002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Mimikatz In-Memory
status: experimental
description: Detects certain DLL loads when Mimikatz gets executed
references:
    - https://securityriskadvisors.com/blog/post/detecting-in-memory-mimikatz/
tags:
    - attack.s0002
    - attack.lateral_movement
    - attack.credential_access
logsource:
    product: windows
    service: sysmon
detection:
    selector:
        EventID: 7
        Image: 'C:\Windows\System32\rundll32.exe'
    dllload1:
        ImageLoaded: '*\vaultcli.dll'
    dllload2:
        ImageLoaded: '*\wlanapi.dll'        
    exclusion:
        ImageLoaded:
            - 'ntdsapi.dll'
            - 'netapi32.dll'
            - 'imm32.dll'
            - 'samlib.dll'
            - 'combase.dll'
            - 'srvcli.dll'
            - 'shcore.dll'
            - 'ntasn1.dll'
            - 'cryptdll.dll'
            - 'logoncli.dll'
    timeframe: 30s
    condition: selector | near dllload1 and dllload2 and not exclusion
falsepositives:
    - unknown
level: medium

```








### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Mimikatz-In-Memory <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30s"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"7\\" AND Image:\\"C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\rundll32.exe\\")",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Mimikatz In-Memory\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```




