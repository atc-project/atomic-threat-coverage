| Title                | Possible Privilege Escalation via Weak Service Permissions                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detection of sc.exe utility spawning by user with Medium integrity level to change service ImagePath or FailureCommand                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1134: Access Token Manipulation](https://attack.mitre.org/techniques/T1134)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Trigger              | <ul><li>[T1134: Access Token Manipulation](../Triggers/T1134.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment](https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)</li><li>[https://pentestlab.blog/2017/03/30/weak-service-permissions/](https://pentestlab.blog/2017/03/30/weak-service-permissions/)</li></ul>  |
| Author               | Teymur Kheirkhabarov |


## Detection Rules

### Sigma rule

```
title: Possible Privilege Escalation via Weak Service Permissions
id: d937b75f-a665-4480-88a5-2f20e9f9b22a
description: Detection of sc.exe utility spawning by user with Medium integrity level to change service ImagePath or FailureCommand
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
    - https://pentestlab.blog/2017/03/30/weak-service-permissions/
tags:
    - attack.privilege_escalation
    - attack.t1134
status: experimental
author: Teymur Kheirkhabarov
date: 2019/10/26
modified: 2019/11/11
logsource:
    category: process_creation
    product: windows
detection:
    scbynonadmin:
        Image|endswith: '\sc.exe'
        IntegrityLevel: 'Medium'
    binpath:
        CommandLine|contains|all:
            - 'config'
            - 'binPath'
    failurecommand:
        CommandLine|contains|all: 
            - 'failure'
            - 'command'
    condition: scbynonadmin and (binpath or failurecommand)
falsepositives:
    - Unknown
level: high

```





### es-qs
    
```
((Image.keyword:*\\\\sc.exe AND IntegrityLevel:"Medium") AND ((CommandLine.keyword:*config* AND CommandLine.keyword:*binPath*) OR (CommandLine.keyword:*failure* AND CommandLine.keyword:*command*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/d937b75f-a665-4480-88a5-2f20e9f9b22a <<EOF\n{\n  "metadata": {\n    "title": "Possible Privilege Escalation via Weak Service Permissions",\n    "description": "Detection of sc.exe utility spawning by user with Medium integrity level to change service ImagePath or FailureCommand",\n    "tags": [\n      "attack.privilege_escalation",\n      "attack.t1134"\n    ],\n    "query": "((Image.keyword:*\\\\\\\\sc.exe AND IntegrityLevel:\\"Medium\\") AND ((CommandLine.keyword:*config* AND CommandLine.keyword:*binPath*) OR (CommandLine.keyword:*failure* AND CommandLine.keyword:*command*)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((Image.keyword:*\\\\\\\\sc.exe AND IntegrityLevel:\\"Medium\\") AND ((CommandLine.keyword:*config* AND CommandLine.keyword:*binPath*) OR (CommandLine.keyword:*failure* AND CommandLine.keyword:*command*)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Possible Privilege Escalation via Weak Service Permissions\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image.keyword:*\\\\sc.exe AND IntegrityLevel:"Medium") AND ((CommandLine.keyword:*config* AND CommandLine.keyword:*binPath*) OR (CommandLine.keyword:*failure* AND CommandLine.keyword:*command*)))
```


### splunk
    
```
((Image="*\\\\sc.exe" IntegrityLevel="Medium") ((CommandLine="*config*" CommandLine="*binPath*") OR (CommandLine="*failure*" CommandLine="*command*")))
```


### logpoint
    
```
(event_id="1" Image="*\\\\sc.exe" IntegrityLevel="Medium" ((CommandLine="*config*" CommandLine="*binPath*") OR (CommandLine="*failure*" CommandLine="*command*")))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*.*\\sc\\.exe)(?=.*Medium)))(?=.*(?:.*(?:.*(?:.*(?=.*.*config.*)(?=.*.*binPath.*))|.*(?:.*(?=.*.*failure.*)(?=.*.*command.*))))))'
```



