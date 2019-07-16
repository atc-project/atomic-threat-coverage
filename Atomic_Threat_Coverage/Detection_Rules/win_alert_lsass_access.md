| Title                | LSASS Access Detected via Attack Surface Reduction                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Access to LSASS Process                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Google Chrome GoogleUpdate.exe</li><li>Some Taskmgr.exe related activity</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard?WT.mc_id=twitter](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard?WT.mc_id=twitter)</li></ul>  |
| Author               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: LSASS Access Detected via Attack Surface Reduction
description: Detects Access to LSASS Process
status: experimental
references:
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard?WT.mc_id=twitter
author: Markus Neis
date: 2018/08/26
tags:
    - attack.credential_access
    - attack.t1003
# Defender Attack Surface Reduction
logsource:
    product: windows_defender
    definition: 'Requirements:Enabled Block credential stealing from the Windows local security authority subsystem (lsass.exe) from Attack Surface Reduction (GUID: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2)'
detection:
    selection:
        EventID: 1121
        Path: '*\lsass.exe'
    condition: selection
falsepositives:
    - Google Chrome GoogleUpdate.exe
    - Some Taskmgr.exe related activity
level: high

```





### es-qs
    
```
(EventID:"1121" AND Path.keyword:*\\\\lsass.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/LSASS-Access-Detected-via-Attack-Surface-Reduction <<EOF\n{\n  "metadata": {\n    "title": "LSASS Access Detected via Attack Surface Reduction",\n    "description": "Detects Access to LSASS Process",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003"\n    ],\n    "query": "(EventID:\\"1121\\" AND Path.keyword:*\\\\\\\\lsass.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"1121\\" AND Path.keyword:*\\\\\\\\lsass.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'LSASS Access Detected via Attack Surface Reduction\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"1121" AND Path:"*\\\\lsass.exe")
```


### splunk
    
```
(EventID="1121" Path="*\\\\lsass.exe")
```


### logpoint
    
```
(EventID="1121" Path="*\\\\lsass.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*1121)(?=.*.*\\lsass\\.exe))'
```



