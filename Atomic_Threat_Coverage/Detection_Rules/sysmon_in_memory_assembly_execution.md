| Title                    | Suspicious In-Memory Module Execution       |
|:-------------------------|:------------------|
| **Description**          | Detects the access to processes by other suspicious processes which have reflectively loaded libraries in their memory space. An example is SilentTrinity C2 behaviour. Generally speaking, when Sysmon EventID 10 cannot reference a stack call to a dll loaded from disk (the standard way), it will display "UNKNOWN" as the module name. Usually this means the stack call points to a module that was reflectively loaded in memory. Adding to this, it is not common to see such few calls in the stack (ntdll.dll --> kernelbase.dll --> unknown) which essentially means that most of the functions required by the process to execute certain routines are already present in memory, not requiring any calls to external libraries. The latter should also be considered suspicious. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1055: Process Injection](https://attack.mitre.org/techniques/T1055)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0014_10_windows_sysmon_ProcessAccess](../Data_Needed/DN_0014_10_windows_sysmon_ProcessAccess.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1055: Process Injection](../Triggers/T1055.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Low</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://azure.microsoft.com/en-ca/blog/detecting-in-memory-attacks-with-sysmon-and-azure-security-center/](https://azure.microsoft.com/en-ca/blog/detecting-in-memory-attacks-with-sysmon-and-azure-security-center/)</li></ul>  |
| **Author**               | Perez Diego (@darkquassar), oscd.community |


## Detection Rules

### Sigma rule

```
title: Suspicious In-Memory Module Execution
id: 5f113a8f-8b61-41ca-b90f-d374fa7e4a39
description: Detects the access to processes by other suspicious processes which have reflectively loaded libraries in their memory space. An example is SilentTrinity
    C2 behaviour. Generally speaking, when Sysmon EventID 10 cannot reference a stack call to a dll loaded from disk (the standard way), it will display "UNKNOWN"
    as the module name. Usually this means the stack call points to a module that was reflectively loaded in memory. Adding to this, it is not common to see such
    few calls in the stack (ntdll.dll --> kernelbase.dll --> unknown) which essentially means that most of the functions required by the process to execute certain
    routines are already present in memory, not requiring any calls to external libraries. The latter should also be considered suspicious.
status: experimental
date: 27/10/2019
author: Perez Diego (@darkquassar), oscd.community
references:
    - https://azure.microsoft.com/en-ca/blog/detecting-in-memory-attacks-with-sysmon-and-azure-security-center/
tags:
    - attack.privilege_escalation
    - attack.t1055
logsource:
    product: windows
    service: sysmon
detection:
    selection_01: 
        EventID: 10
        CallTrace: 
            - "C:\\Windows\\SYSTEM32\\ntdll.dll+*|C:\\Windows\\System32\\KERNELBASE.dll+*|UNKNOWN(*)"
            - "*UNKNOWN(*)|UNKNOWN(*)"
    selection_02: 
        EventID: 10
        CallTrace: "*UNKNOWN*"
    granted_access:
        GrantedAccess:
            - "0x1F0FFF"
            - "0x1F1FFF"
            - "0x143A"
            - "0x1410"
            - "0x1010"
            - "0x1F2FFF"
            - "0x1F3FFF"
            - "0x1FFFFF"
    condition: selection_01 OR (selection_02 AND granted_access)
fields:
    - ComputerName
    - User
    - SourceImage
    - TargetImage
    - CallTrace
level: critical
falsepositives:
    - Low

```





### es-qs
    
```
(EventID:"10" AND (CallTrace.keyword:(C\\:\\\\Windows\\\\SYSTEM32\\\\ntdll.dll\\+*|C\\:\\\\Windows\\\\System32\\\\KERNELBASE.dll\\+*|UNKNOWN\\(*\\) OR *UNKNOWN\\(*\\)|UNKNOWN\\(*\\)) OR (CallTrace.keyword:*UNKNOWN* AND GrantedAccess:("0x1F0FFF" OR "0x1F1FFF" OR "0x143A" OR "0x1410" OR "0x1010" OR "0x1F2FFF" OR "0x1F3FFF" OR "0x1FFFFF"))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/5f113a8f-8b61-41ca-b90f-d374fa7e4a39 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious In-Memory Module Execution",\n    "description": "Detects the access to processes by other suspicious processes which have reflectively loaded libraries in their memory space. An example is SilentTrinity C2 behaviour. Generally speaking, when Sysmon EventID 10 cannot reference a stack call to a dll loaded from disk (the standard way), it will display \\"UNKNOWN\\" as the module name. Usually this means the stack call points to a module that was reflectively loaded in memory. Adding to this, it is not common to see such few calls in the stack (ntdll.dll --> kernelbase.dll --> unknown) which essentially means that most of the functions required by the process to execute certain routines are already present in memory, not requiring any calls to external libraries. The latter should also be considered suspicious.",\n    "tags": [\n      "attack.privilege_escalation",\n      "attack.t1055"\n    ],\n    "query": "(EventID:\\"10\\" AND (CallTrace.keyword:(C\\\\:\\\\\\\\Windows\\\\\\\\SYSTEM32\\\\\\\\ntdll.dll\\\\+*|C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\KERNELBASE.dll\\\\+*|UNKNOWN\\\\(*\\\\) OR *UNKNOWN\\\\(*\\\\)|UNKNOWN\\\\(*\\\\)) OR (CallTrace.keyword:*UNKNOWN* AND GrantedAccess:(\\"0x1F0FFF\\" OR \\"0x1F1FFF\\" OR \\"0x143A\\" OR \\"0x1410\\" OR \\"0x1010\\" OR \\"0x1F2FFF\\" OR \\"0x1F3FFF\\" OR \\"0x1FFFFF\\"))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"10\\" AND (CallTrace.keyword:(C\\\\:\\\\\\\\Windows\\\\\\\\SYSTEM32\\\\\\\\ntdll.dll\\\\+*|C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\KERNELBASE.dll\\\\+*|UNKNOWN\\\\(*\\\\) OR *UNKNOWN\\\\(*\\\\)|UNKNOWN\\\\(*\\\\)) OR (CallTrace.keyword:*UNKNOWN* AND GrantedAccess:(\\"0x1F0FFF\\" OR \\"0x1F1FFF\\" OR \\"0x143A\\" OR \\"0x1410\\" OR \\"0x1010\\" OR \\"0x1F2FFF\\" OR \\"0x1F3FFF\\" OR \\"0x1FFFFF\\"))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious In-Memory Module Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nComputerName = {{_source.ComputerName}}\\n        User = {{_source.User}}\\n SourceImage = {{_source.SourceImage}}\\n TargetImage = {{_source.TargetImage}}\\n   CallTrace = {{_source.CallTrace}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"10" AND (CallTrace.keyword:(C\\:\\\\Windows\\\\SYSTEM32\\\\ntdll.dll\\+*|C\\:\\\\Windows\\\\System32\\\\KERNELBASE.dll\\+*|UNKNOWN\\(*\\) *UNKNOWN\\(*\\)|UNKNOWN\\(*\\)) OR (CallTrace.keyword:*UNKNOWN* AND GrantedAccess:("0x1F0FFF" "0x1F1FFF" "0x143A" "0x1410" "0x1010" "0x1F2FFF" "0x1F3FFF" "0x1FFFFF"))))
```


### splunk
    
```
(EventID="10" ((CallTrace="C:\\\\Windows\\\\SYSTEM32\\\\ntdll.dll+*|C:\\\\Windows\\\\System32\\\\KERNELBASE.dll+*|UNKNOWN(*)" OR CallTrace="*UNKNOWN(*)|UNKNOWN(*)") OR (CallTrace="*UNKNOWN*" (GrantedAccess="0x1F0FFF" OR GrantedAccess="0x1F1FFF" OR GrantedAccess="0x143A" OR GrantedAccess="0x1410" OR GrantedAccess="0x1010" OR GrantedAccess="0x1F2FFF" OR GrantedAccess="0x1F3FFF" OR GrantedAccess="0x1FFFFF")))) | table ComputerName,User,SourceImage,TargetImage,CallTrace
```


### logpoint
    
```
(event_id="10" (CallTrace IN ["C:\\\\Windows\\\\SYSTEM32\\\\ntdll.dll+*|C:\\\\Windows\\\\System32\\\\KERNELBASE.dll+*|UNKNOWN(*)", "*UNKNOWN(*)|UNKNOWN(*)"] OR (CallTrace="*UNKNOWN*" GrantedAccess IN ["0x1F0FFF", "0x1F1FFF", "0x143A", "0x1410", "0x1010", "0x1F2FFF", "0x1F3FFF", "0x1FFFFF"])))
```


### grep
    
```
grep -P '^(?:.*(?=.*10)(?=.*(?:.*(?:.*(?:.*C:\\Windows\\SYSTEM32\\ntdll\\.dll\\+.*\\|C:\\Windows\\System32\\KERNELBASE\\.dll\\+.*\\|UNKNOWN\\(.*\\)|.*.*UNKNOWN\\(.*\\)\\|UNKNOWN\\(.*\\))|.*(?:.*(?=.*.*UNKNOWN.*)(?=.*(?:.*0x1F0FFF|.*0x1F1FFF|.*0x143A|.*0x1410|.*0x1010|.*0x1F2FFF|.*0x1F3FFF|.*0x1FFFFF)))))))'
```



