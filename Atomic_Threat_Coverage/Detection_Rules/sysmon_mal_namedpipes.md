| Title                | Malicious Named Pipe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the creation of a named pipe used by known APT malware                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1055: Process Injection](https://attack.mitre.org/techniques/T1055)</li></ul>  |
| Data Needed          | <ul><li>[DN_0021_18_windows_sysmon_PipeEvent](../Data_Needed/DN_0021_18_windows_sysmon_PipeEvent.md)</li><li>[DN_0020_17_windows_sysmon_PipeEvent](../Data_Needed/DN_0020_17_windows_sysmon_PipeEvent.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1055: Process Injection](../Triggers/T1055.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unkown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[Various sources](Various sources)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Malicious Named Pipe
status: experimental
description: Detects the creation of a named pipe used by known APT malware
references:
    - Various sources
date: 2017/11/06
author: Florian Roth
logsource:
   product: windows
   service: sysmon
   definition: 'Note that you have to configure logging for PipeEvents in Symson config'
detection:
   selection:
      EventID: 
         - 17
         - 18
      PipeName: 
         - '\isapi_http'  # Uroburos Malware Named Pipe
         - '\isapi_dg'  # Uroburos Malware Named Pipe
         - '\isapi_dg2'  # Uroburos Malware Named Pipe
         - '\sdlrpc'  # Cobra Trojan Named Pipe http://goo.gl/8rOZUX
         - '\ahexec'  # Sofacy group malware
         - '\winsession'  # Wild Neutron APT malware https://goo.gl/pivRZJ
         - '\lsassw'  # Wild Neutron APT malware https://goo.gl/pivRZJ
         - '\46a676ab7f179e511e30dd2dc41bd388'  # Project Sauron https://goo.gl/eFoP4A
         - '\9f81f59bc58452127884ce513865ed20'  # Project Sauron https://goo.gl/eFoP4A
         - '\e710f28d59aa529d6792ca6ff0ca1b34'  # Project Sauron https://goo.gl/eFoP4A
         - '\rpchlp_3'  # Project Sauron https://goo.gl/eFoP4A - Technical Analysis Input
         - '\NamePipe_MoreWindows'  # Cloud Hopper Annex B https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf, US-CERT Alert - RedLeaves https://www.us-cert.gov/ncas/alerts/TA17-117A
         - '\pcheap_reuse'  # Pipe used by Equation Group malware 77486bb828dba77099785feda0ca1d4f33ad0d39b672190079c508b3feb21fb0
         - '\msagent_*'  # CS default named pipes https://github.com/Neo23x0/sigma/issues/253
         # - '\status_*'  # CS default named pipes https://github.com/Neo23x0/sigma/issues/253
   condition: selection
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1055
falsepositives:
   - Unkown
level: critical

```





### es-qs
    
```
(EventID:("17" "18") AND PipeName.keyword:(\\\\isapi_http \\\\isapi_dg \\\\isapi_dg2 \\\\sdlrpc \\\\ahexec \\\\winsession \\\\lsassw \\\\46a676ab7f179e511e30dd2dc41bd388 \\\\9f81f59bc58452127884ce513865ed20 \\\\e710f28d59aa529d6792ca6ff0ca1b34 \\\\rpchlp_3 \\\\NamePipe_MoreWindows \\\\pcheap_reuse \\\\msagent_*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Malicious-Named-Pipe <<EOF\n{\n  "metadata": {\n    "title": "Malicious Named Pipe",\n    "description": "Detects the creation of a named pipe used by known APT malware",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.privilege_escalation",\n      "attack.t1055"\n    ],\n    "query": "(EventID:(\\"17\\" \\"18\\") AND PipeName.keyword:(\\\\\\\\isapi_http \\\\\\\\isapi_dg \\\\\\\\isapi_dg2 \\\\\\\\sdlrpc \\\\\\\\ahexec \\\\\\\\winsession \\\\\\\\lsassw \\\\\\\\46a676ab7f179e511e30dd2dc41bd388 \\\\\\\\9f81f59bc58452127884ce513865ed20 \\\\\\\\e710f28d59aa529d6792ca6ff0ca1b34 \\\\\\\\rpchlp_3 \\\\\\\\NamePipe_MoreWindows \\\\\\\\pcheap_reuse \\\\\\\\msagent_*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:(\\"17\\" \\"18\\") AND PipeName.keyword:(\\\\\\\\isapi_http \\\\\\\\isapi_dg \\\\\\\\isapi_dg2 \\\\\\\\sdlrpc \\\\\\\\ahexec \\\\\\\\winsession \\\\\\\\lsassw \\\\\\\\46a676ab7f179e511e30dd2dc41bd388 \\\\\\\\9f81f59bc58452127884ce513865ed20 \\\\\\\\e710f28d59aa529d6792ca6ff0ca1b34 \\\\\\\\rpchlp_3 \\\\\\\\NamePipe_MoreWindows \\\\\\\\pcheap_reuse \\\\\\\\msagent_*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Malicious Named Pipe\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:("17" "18") AND PipeName:("\\\\isapi_http" "\\\\isapi_dg" "\\\\isapi_dg2" "\\\\sdlrpc" "\\\\ahexec" "\\\\winsession" "\\\\lsassw" "\\\\46a676ab7f179e511e30dd2dc41bd388" "\\\\9f81f59bc58452127884ce513865ed20" "\\\\e710f28d59aa529d6792ca6ff0ca1b34" "\\\\rpchlp_3" "\\\\NamePipe_MoreWindows" "\\\\pcheap_reuse" "\\\\msagent_*"))
```


### splunk
    
```
((EventID="17" OR EventID="18") (PipeName="\\\\isapi_http" OR PipeName="\\\\isapi_dg" OR PipeName="\\\\isapi_dg2" OR PipeName="\\\\sdlrpc" OR PipeName="\\\\ahexec" OR PipeName="\\\\winsession" OR PipeName="\\\\lsassw" OR PipeName="\\\\46a676ab7f179e511e30dd2dc41bd388" OR PipeName="\\\\9f81f59bc58452127884ce513865ed20" OR PipeName="\\\\e710f28d59aa529d6792ca6ff0ca1b34" OR PipeName="\\\\rpchlp_3" OR PipeName="\\\\NamePipe_MoreWindows" OR PipeName="\\\\pcheap_reuse" OR PipeName="\\\\msagent_*"))
```


### logpoint
    
```
(EventID IN ["17", "18"] PipeName IN ["\\\\isapi_http", "\\\\isapi_dg", "\\\\isapi_dg2", "\\\\sdlrpc", "\\\\ahexec", "\\\\winsession", "\\\\lsassw", "\\\\46a676ab7f179e511e30dd2dc41bd388", "\\\\9f81f59bc58452127884ce513865ed20", "\\\\e710f28d59aa529d6792ca6ff0ca1b34", "\\\\rpchlp_3", "\\\\NamePipe_MoreWindows", "\\\\pcheap_reuse", "\\\\msagent_*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*17|.*18))(?=.*(?:.*\\isapi_http|.*\\isapi_dg|.*\\isapi_dg2|.*\\sdlrpc|.*\\ahexec|.*\\winsession|.*\\lsassw|.*\\46a676ab7f179e511e30dd2dc41bd388|.*\\9f81f59bc58452127884ce513865ed20|.*\\e710f28d59aa529d6792ca6ff0ca1b34|.*\\rpchlp_3|.*\\NamePipe_MoreWindows|.*\\pcheap_reuse|.*\\msagent_.*)))'
```



