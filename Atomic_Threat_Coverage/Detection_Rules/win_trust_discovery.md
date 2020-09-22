| Title                    | Domain Trust Discovery       |
|:-------------------------|:------------------|
| **Description**          | Identifies execution of nltest.exe and dsquery.exe for domain trust discovery. This technique is used by attackers to enumerate Active Directory trusts. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1482: Domain Trust Discovery](https://attack.mitre.org/techniques/T1482)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1482: Domain Trust Discovery](../Triggers/T1482.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate use of the utilities by legitimate user for legitimate reason</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/03e231a6-74bc-467a-acb1-e5676b0fb55e.html](https://eqllib.readthedocs.io/en/latest/analytics/03e231a6-74bc-467a-acb1-e5676b0fb55e.html)</li></ul>  |
| **Author**               | E.M. Anhaus (orignally from Atomic Blue Detections, Tony Lambert), oscd.community |


## Detection Rules

### Sigma rule

```
title: Domain Trust Discovery
id: 3bad990e-4848-4a78-9530-b427d854aac0
description: Identifies execution of nltest.exe and dsquery.exe for domain trust discovery. This technique is used by attackers to enumerate Active Directory trusts.
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Tony Lambert), oscd.community
date: 2019/10/24
modified: 2019/11/11
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md
    - https://eqllib.readthedocs.io/en/latest/analytics/03e231a6-74bc-467a-acb1-e5676b0fb55e.html
tags:
    - attack.discovery
    - attack.t1482
logsource:
    category: process_creation
    product: windows
detection:
    selection:
      - Image|endswith: '\nltest.exe'
        CommandLine|contains: 'domain_trusts'
      - Image|endswith: '\dsquery.exe'
        CommandLine|contains: 'trustedDomain'
    condition: selection
falsepositives:
    - Legitimate use of the utilities by legitimate user for legitimate reason
level: medium

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\\\nltest.exe" -and $_.message -match "CommandLine.*.*domain_trusts.*") -or ($_.message -match "Image.*.*\\\\dsquery.exe" -and $_.message -match "CommandLine.*.*trustedDomain.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\\\nltest.exe AND winlog.event_data.CommandLine.keyword:*domain_trusts*) OR (winlog.event_data.Image.keyword:*\\\\dsquery.exe AND winlog.event_data.CommandLine.keyword:*trustedDomain*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/3bad990e-4848-4a78-9530-b427d854aac0 <<EOF\n{\n  "metadata": {\n    "title": "Domain Trust Discovery",\n    "description": "Identifies execution of nltest.exe and dsquery.exe for domain trust discovery. This technique is used by attackers to enumerate Active Directory trusts.",\n    "tags": [\n      "attack.discovery",\n      "attack.t1482"\n    ],\n    "query": "((winlog.event_data.Image.keyword:*\\\\\\\\nltest.exe AND winlog.event_data.CommandLine.keyword:*domain_trusts*) OR (winlog.event_data.Image.keyword:*\\\\\\\\dsquery.exe AND winlog.event_data.CommandLine.keyword:*trustedDomain*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((winlog.event_data.Image.keyword:*\\\\\\\\nltest.exe AND winlog.event_data.CommandLine.keyword:*domain_trusts*) OR (winlog.event_data.Image.keyword:*\\\\\\\\dsquery.exe AND winlog.event_data.CommandLine.keyword:*trustedDomain*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Domain Trust Discovery\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image.keyword:*\\\\nltest.exe AND CommandLine.keyword:*domain_trusts*) OR (Image.keyword:*\\\\dsquery.exe AND CommandLine.keyword:*trustedDomain*))
```


### splunk
    
```
((Image="*\\\\nltest.exe" CommandLine="*domain_trusts*") OR (Image="*\\\\dsquery.exe" CommandLine="*trustedDomain*"))
```


### logpoint
    
```
((Image="*\\\\nltest.exe" CommandLine="*domain_trusts*") OR (Image="*\\\\dsquery.exe" CommandLine="*trustedDomain*"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*.*\\nltest\\.exe)(?=.*.*domain_trusts.*))|.*(?:.*(?=.*.*\\dsquery\\.exe)(?=.*.*trustedDomain.*))))'
```



