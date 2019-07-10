| Title                | Cmdkey Cached Credentials Recon                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects usage of cmdkey to look for cached credentials                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Legitimate administrative tasks.</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.peew.pw/blog/2017/11/26/exploring-cmdkey-an-edge-case-for-privilege-escalation](https://www.peew.pw/blog/2017/11/26/exploring-cmdkey-an-edge-case-for-privilege-escalation)</li><li>[https://technet.microsoft.com/en-us/library/cc754243(v=ws.11).aspx](https://technet.microsoft.com/en-us/library/cc754243(v=ws.11).aspx)</li></ul>  |
| Author               | jmallette |


## Detection Rules

### Sigma rule

```
title: Cmdkey Cached Credentials Recon
status: experimental
description: Detects usage of cmdkey to look for cached credentials
references:
    - https://www.peew.pw/blog/2017/11/26/exploring-cmdkey-an-edge-case-for-privilege-escalation
    - https://technet.microsoft.com/en-us/library/cc754243(v=ws.11).aspx
author: jmallette
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\cmdkey.exe'
        CommandLine: '* /list *'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
    - User
falsepositives:
    - Legitimate administrative tasks.
level: low

```





### es-qs
    
```
(Image.keyword:*\\\\cmdkey.exe AND CommandLine.keyword:*\\ \\/list\\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Cmdkey-Cached-Credentials-Recon <<EOF\n{\n  "metadata": {\n    "title": "Cmdkey Cached Credentials Recon",\n    "description": "Detects usage of cmdkey to look for cached credentials",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003"\n    ],\n    "query": "(Image.keyword:*\\\\\\\\cmdkey.exe AND CommandLine.keyword:*\\\\ \\\\/list\\\\ *)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:*\\\\\\\\cmdkey.exe AND CommandLine.keyword:*\\\\ \\\\/list\\\\ *)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Cmdkey Cached Credentials Recon\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}\\n             User = {{_source.User}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image:"*\\\\cmdkey.exe" AND CommandLine:"* \\/list *")
```


### splunk
    
```
(Image="*\\\\cmdkey.exe" CommandLine="* /list *") | table CommandLine,ParentCommandLine,User
```


### logpoint
    
```
(Image="*\\\\cmdkey.exe" CommandLine="* /list *")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\cmdkey\\.exe)(?=.*.* /list .*))'
```



