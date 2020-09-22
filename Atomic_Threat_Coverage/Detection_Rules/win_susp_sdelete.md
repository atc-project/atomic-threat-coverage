| Title                    | Secure Deletion with SDelete       |
|:-------------------------|:------------------|
| **Description**          | Detects renaming of file while deletion with SDelete tool |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0040: Impact](https://attack.mitre.org/tactics/TA0040)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1107: File Deletion](https://attack.mitre.org/techniques/T1107)</li><li>[T1070.004: File Deletion](https://attack.mitre.org/techniques/T1070.004)</li><li>[T1066: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1066)</li><li>[T1027.005: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027.005)</li><li>[T1485: Data Destruction](https://attack.mitre.org/techniques/T1485)</li><li>[T1553.002: Code Signing](https://attack.mitre.org/techniques/T1553.002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0058_4656_handle_to_an_object_was_requested](../Data_Needed/DN_0058_4656_handle_to_an_object_was_requested.md)</li><li>[DN_0060_4658_handle_to_an_object_was_closed](../Data_Needed/DN_0060_4658_handle_to_an_object_was_closed.md)</li><li>[DN_0062_4663_attempt_was_made_to_access_an_object](../Data_Needed/DN_0062_4663_attempt_was_made_to_access_an_object.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1070.004: File Deletion](../Triggers/T1070.004.md)</li><li>[T1485: Data Destruction](../Triggers/T1485.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitime usage of SDelete</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet](https://jpcertcc.github.io/ToolAnalysisResultSheet)</li><li>[https://www.jpcert.or.jp/english/pub/sr/ir_research.html](https://www.jpcert.or.jp/english/pub/sr/ir_research.html)</li><li>[https://technet.microsoft.com/en-us/en-en/sysinternals/sdelete.aspx](https://technet.microsoft.com/en-us/en-en/sysinternals/sdelete.aspx)</li></ul>  |
| **Author**               | Thomas Patzke |
| Other Tags           | <ul><li>attack.s0195</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Secure Deletion with SDelete
id: 39a80702-d7ca-4a83-b776-525b1f86a36d
status: experimental
description: Detects renaming of file while deletion with SDelete tool
author: Thomas Patzke
date: 2017/06/14
modified: 2020/08/2
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://technet.microsoft.com/en-us/en-en/sysinternals/sdelete.aspx
tags:
    - attack.impact
    - attack.defense_evasion
    - attack.t1107           # an old one
    - attack.t1070.004
    - attack.t1066           # an old one
    - attack.t1027.005
    - attack.t1485
    - attack.t1553.002
    - attack.s0195
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4656
            - 4663
            - 4658
        ObjectName:
            - '*.AAA'
            - '*.ZZZ'
    condition: selection
falsepositives:
    - Legitime usage of SDelete
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "4656" -or $_.ID -eq "4663" -or $_.ID -eq "4658") -and ($_.message -match "ObjectName.*.*.AAA" -or $_.message -match "ObjectName.*.*.ZZZ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:("4656" OR "4663" OR "4658") AND winlog.event_data.ObjectName.keyword:(*.AAA OR *.ZZZ))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/39a80702-d7ca-4a83-b776-525b1f86a36d <<EOF\n{\n  "metadata": {\n    "title": "Secure Deletion with SDelete",\n    "description": "Detects renaming of file while deletion with SDelete tool",\n    "tags": [\n      "attack.impact",\n      "attack.defense_evasion",\n      "attack.t1107",\n      "attack.t1070.004",\n      "attack.t1066",\n      "attack.t1027.005",\n      "attack.t1485",\n      "attack.t1553.002",\n      "attack.s0195"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:(\\"4656\\" OR \\"4663\\" OR \\"4658\\") AND winlog.event_data.ObjectName.keyword:(*.AAA OR *.ZZZ))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:(\\"4656\\" OR \\"4663\\" OR \\"4658\\") AND winlog.event_data.ObjectName.keyword:(*.AAA OR *.ZZZ))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Secure Deletion with SDelete\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:("4656" "4663" "4658") AND ObjectName.keyword:(*.AAA *.ZZZ))
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="4656" OR EventCode="4663" OR EventCode="4658") (ObjectName="*.AAA" OR ObjectName="*.ZZZ"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id IN ["4656", "4663", "4658"] ObjectName IN ["*.AAA", "*.ZZZ"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*4656|.*4663|.*4658))(?=.*(?:.*.*\\.AAA|.*.*\\.ZZZ)))'
```



