| Title                    | Mimikatz Command Line       |
|:-------------------------|:------------------|
| **Description**          | Detection well-known mimikatz command line arguments |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate Administrator using tool for password recovery</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov, oscd.community |


## Detection Rules

### Sigma rule

```
title: Mimikatz Command Line
id: a642964e-bead-4bed-8910-1bb4d63e3b4d
description: Detection well-known mimikatz command line arguments
author: Teymur Kheirkhabarov, oscd.community
date: 2019/10/22
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        CommandLine|contains:
            - DumpCreds
            - invoke-mimikatz
    selection_2:
        CommandLine|contains:
            - rpc
            - token
            - crypto
            - dpapi
            - sekurlsa
            - kerberos
            - lsadump
            - privilege
            - process
    selection_3:
        CommandLine|contains:
            - '::'
    condition: selection_1 or 
               selection_2 and selection_3
falsepositives:
    - Legitimate Administrator using tool for password recovery
level: medium
status: experimental

```





### es-qs
    
```
(CommandLine.keyword:(*DumpCreds* OR *invoke\\-mimikatz*) OR (CommandLine.keyword:(*rpc* OR *token* OR *crypto* OR *dpapi* OR *sekurlsa* OR *kerberos* OR *lsadump* OR *privilege* OR *process*) AND CommandLine.keyword:(*\\:\\:*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/a642964e-bead-4bed-8910-1bb4d63e3b4d <<EOF\n{\n  "metadata": {\n    "title": "Mimikatz Command Line",\n    "description": "Detection well-known mimikatz command line arguments",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003"\n    ],\n    "query": "(CommandLine.keyword:(*DumpCreds* OR *invoke\\\\-mimikatz*) OR (CommandLine.keyword:(*rpc* OR *token* OR *crypto* OR *dpapi* OR *sekurlsa* OR *kerberos* OR *lsadump* OR *privilege* OR *process*) AND CommandLine.keyword:(*\\\\:\\\\:*)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(CommandLine.keyword:(*DumpCreds* OR *invoke\\\\-mimikatz*) OR (CommandLine.keyword:(*rpc* OR *token* OR *crypto* OR *dpapi* OR *sekurlsa* OR *kerberos* OR *lsadump* OR *privilege* OR *process*) AND CommandLine.keyword:(*\\\\:\\\\:*)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Mimikatz Command Line\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:(*DumpCreds* *invoke\\-mimikatz*) OR (CommandLine.keyword:(*rpc* *token* *crypto* *dpapi* *sekurlsa* *kerberos* *lsadump* *privilege* *process*) AND CommandLine.keyword:(*\\:\\:*)))
```


### splunk
    
```
((CommandLine="*DumpCreds*" OR CommandLine="*invoke-mimikatz*") OR ((CommandLine="*rpc*" OR CommandLine="*token*" OR CommandLine="*crypto*" OR CommandLine="*dpapi*" OR CommandLine="*sekurlsa*" OR CommandLine="*kerberos*" OR CommandLine="*lsadump*" OR CommandLine="*privilege*" OR CommandLine="*process*") (CommandLine="*::*")))
```


### logpoint
    
```
(event_id="1" (CommandLine IN ["*DumpCreds*", "*invoke-mimikatz*"] OR (CommandLine IN ["*rpc*", "*token*", "*crypto*", "*dpapi*", "*sekurlsa*", "*kerberos*", "*lsadump*", "*privilege*", "*process*"] CommandLine IN ["*::*"])))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*.*DumpCreds.*|.*.*invoke-mimikatz.*)|.*(?:.*(?=.*(?:.*.*rpc.*|.*.*token.*|.*.*crypto.*|.*.*dpapi.*|.*.*sekurlsa.*|.*.*kerberos.*|.*.*lsadump.*|.*.*privilege.*|.*.*process.*))(?=.*(?:.*.*::.*)))))'
```



