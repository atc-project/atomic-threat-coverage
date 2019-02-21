| Title                | Possible Shim Database Persistence via sdbinst.exe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects execution of sdbinst writing to default shim database path C:\Windows\AppPatch\*                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1138: Application Shimming](https://attack.mitre.org/techniques/T1138)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1138: Application Shimming](../Triggers/T1138.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html)</li></ul>                                                          |
| Author               | Markus Neis                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Possible Shim Database Persistence via sdbinst.exe 
status: experimental
description: Detects execution of sdbinst writing to default shim database path C:\Windows\AppPatch\*
references:
    - https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html
tags:
    - attack.persistence
    - attack.t1138
author: Markus Neis
date: 2018-08-03
logsource:
    product: windows
    service: sysmon
detection:
    selection:
      EventID: 1
      Image:
      - '*\sdbinst.exe'
      CommandLine: 
        - '*\AppPatch\*}.sdb*'            
    condition: selection
falsepositives:
    - Unknown 
level: high

```





### Kibana query

```
(EventID:"1" AND Image.keyword:(*\\\\sdbinst.exe) AND CommandLine.keyword:(*\\\\AppPatch\\*\\}.sdb*))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Possible-Shim-Database-Persistence-via-sdbinst.exe <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND Image.keyword:(*\\\\\\\\sdbinst.exe) AND CommandLine.keyword:(*\\\\\\\\AppPatch\\\\*\\\\}.sdb*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Possible Shim Database Persistence via sdbinst.exe\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"1" AND Image:("*\\\\sdbinst.exe") AND CommandLine:("*\\\\AppPatch\\*\\}.sdb*"))
```





### Splunk

```
(EventID="1" (Image="*\\\\sdbinst.exe") (CommandLine="*\\\\AppPatch\\*}.sdb*"))
```





### Logpoint

```
(EventID="1" Image IN ["*\\\\sdbinst.exe"] CommandLine IN ["*\\\\AppPatch\\*}.sdb*"])
```





### Grep

```
grep -P '^(?:.*(?=.*1)(?=.*(?:.*.*\\sdbinst\\.exe))(?=.*(?:.*.*\\AppPatch\\.*\\}\\.sdb.*)))'
```





### Fieldlist

```
CommandLine\nEventID\nImage
```

