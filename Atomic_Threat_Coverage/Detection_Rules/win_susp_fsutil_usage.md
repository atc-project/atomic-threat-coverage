| Title                | Fsutil suspicious invocation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious parameters of fsutil (deleting USN journal, configuring it with small size..). Might be used by ransomwares during the attack (seen by NotPetya and others)                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | high |
| False Positives      | <ul><li>Admin activity</li><li>Scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)</li></ul>  |
| Author               | Ecco |


## Detection Rules

### Sigma rule

```
title: Fsutil suspicious invocation
id: add64136-62e5-48ea-807e-88638d02df1e
description: Detects suspicious parameters of fsutil (deleting USN journal, configuring it with small size..). Might be used by ransomwares during the attack (seen
    by NotPetya and others)
author: Ecco
date: 2019/09/26
level: high
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn
logsource:
    category: process_creation
    product: windows
detection:
    binary_1:
        Image: '*\fsutil.exe'
    binary_2:
        OriginalFileName: 'fsutil.exe'
    selection:
        CommandLine: 
            - '* deletejournal *'  # usn deletejournal ==> generally ransomware or attacker
            - '* createjournal *'  # usn createjournal ==> can modify config to set it to a tiny size
 
    condition: (1 of binary_*) and selection
    
falsepositives:
    - Admin activity
    - Scripts and administrative tools used in the monitored environment

```





### es-qs
    
```
((Image.keyword:*\\\\fsutil.exe OR OriginalFileName:"fsutil.exe") AND CommandLine.keyword:(*\\ deletejournal\\ * OR *\\ createjournal\\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Fsutil-suspicious-invocation <<EOF\n{\n  "metadata": {\n    "title": "Fsutil suspicious invocation",\n    "description": "Detects suspicious parameters of fsutil (deleting USN journal, configuring it with small size..). Might be used by ransomwares during the attack (seen by NotPetya and others)",\n    "tags": "",\n    "query": "((Image.keyword:*\\\\\\\\fsutil.exe OR OriginalFileName:\\"fsutil.exe\\") AND CommandLine.keyword:(*\\\\ deletejournal\\\\ * OR *\\\\ createjournal\\\\ *))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((Image.keyword:*\\\\\\\\fsutil.exe OR OriginalFileName:\\"fsutil.exe\\") AND CommandLine.keyword:(*\\\\ deletejournal\\\\ * OR *\\\\ createjournal\\\\ *))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Fsutil suspicious invocation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image.keyword:*\\\\fsutil.exe OR OriginalFileName:"fsutil.exe") AND CommandLine.keyword:(* deletejournal * * createjournal *))
```


### splunk
    
```
((Image="*\\\\fsutil.exe" OR OriginalFileName="fsutil.exe") (CommandLine="* deletejournal *" OR CommandLine="* createjournal *"))
```


### logpoint
    
```
(event_id="1" (Image="*\\\\fsutil.exe" OR OriginalFileName="fsutil.exe") CommandLine IN ["* deletejournal *", "* createjournal *"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*.*\\fsutil\\.exe|.*fsutil\\.exe)))(?=.*(?:.*.* deletejournal .*|.*.* createjournal .*)))'
```



