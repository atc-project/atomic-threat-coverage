| Title                | Suspicious eventlog clear or configuration using wevtutil                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects clearing or configuration of eventlogs uwing wevtutil. Might be used by ransomwares during the attack (seen by NotPetya and others)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1070: Indicator Removal on Host](../Triggers/T1070.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Admin activity</li><li>Scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Ecco |
| Other Tags           | <ul><li>car.2016-04-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious eventlog clear or configuration using wevtutil
id: cc36992a-4671-4f21-a91d-6c2b72a2edf5
description: Detects clearing or configuration of eventlogs uwing wevtutil. Might be used by ransomwares during the attack (seen by NotPetya and others)
author: Ecco
date: 2019/09/26
tags:
    - attack.execution
    - attack.t1070
    - car.2016-04-002
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection_binary_1:
        Image: '*\wevtutil.exe'
    selection_binary_2:
        OriginalFileName: 'wevtutil.exe'
    selection_clear_1:
        CommandLine: '* cl *'
    selection_clear_2:
        CommandLine: '* clear-log *'
    selection_disable_1:
        CommandLine: '* sl *'
    selection_disable_2:
        CommandLine: '* set-log *'
    condition: (1 of selection_binary_*) and (1 of selection_clear_* or 1 of selection_disable_*)
    
falsepositives:
    - Admin activity
    - Scripts and administrative tools used in the monitored environment

```





### es-qs
    
```
((Image.keyword:*\\\\wevtutil.exe OR OriginalFileName:"wevtutil.exe") AND (CommandLine.keyword:*\\ cl\\ * OR CommandLine.keyword:*\\ clear\\-log\\ * OR CommandLine.keyword:*\\ sl\\ * OR CommandLine.keyword:*\\ set\\-log\\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-eventlog-clear-or-configuration-using-wevtutil <<EOF\n{\n  "metadata": {\n    "title": "Suspicious eventlog clear or configuration using wevtutil",\n    "description": "Detects clearing or configuration of eventlogs uwing wevtutil. Might be used by ransomwares during the attack (seen by NotPetya and others)",\n    "tags": [\n      "attack.execution",\n      "attack.t1070",\n      "car.2016-04-002"\n    ],\n    "query": "((Image.keyword:*\\\\\\\\wevtutil.exe OR OriginalFileName:\\"wevtutil.exe\\") AND (CommandLine.keyword:*\\\\ cl\\\\ * OR CommandLine.keyword:*\\\\ clear\\\\-log\\\\ * OR CommandLine.keyword:*\\\\ sl\\\\ * OR CommandLine.keyword:*\\\\ set\\\\-log\\\\ *))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((Image.keyword:*\\\\\\\\wevtutil.exe OR OriginalFileName:\\"wevtutil.exe\\") AND (CommandLine.keyword:*\\\\ cl\\\\ * OR CommandLine.keyword:*\\\\ clear\\\\-log\\\\ * OR CommandLine.keyword:*\\\\ sl\\\\ * OR CommandLine.keyword:*\\\\ set\\\\-log\\\\ *))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious eventlog clear or configuration using wevtutil\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image.keyword:*\\\\wevtutil.exe OR OriginalFileName:"wevtutil.exe") AND (CommandLine.keyword:* cl * OR CommandLine.keyword:* clear\\-log * OR CommandLine.keyword:* sl * OR CommandLine.keyword:* set\\-log *))
```


### splunk
    
```
((Image="*\\\\wevtutil.exe" OR OriginalFileName="wevtutil.exe") (CommandLine="* cl *" OR CommandLine="* clear-log *" OR CommandLine="* sl *" OR CommandLine="* set-log *"))
```


### logpoint
    
```
(event_id="1" (Image="*\\\\wevtutil.exe" OR OriginalFileName="wevtutil.exe") (CommandLine="* cl *" OR CommandLine="* clear-log *" OR CommandLine="* sl *" OR CommandLine="* set-log *"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*.*\\wevtutil\\.exe|.*wevtutil\\.exe)))(?=.*(?:.*(?:.*.* cl .*|.*.* clear-log .*|.*.* sl .*|.*.* set-log .*))))'
```



