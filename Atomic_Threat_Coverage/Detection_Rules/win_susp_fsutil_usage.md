| Title                    | Fsutil Suspicious Invocation       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious parameters of fsutil (deleting USN journal, configuring it with small size..). Might be used by ransomwares during the attack (seen by NotPetya and others) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1070: Indicator Removal on Host](../Triggers/T1070.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Admin activity</li><li>Scripts and administrative tools used in the monitored environment</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)</li><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.yaml)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/c91f422a-5214-4b17-8664-c5fcf115c0a2.html](https://eqllib.readthedocs.io/en/latest/analytics/c91f422a-5214-4b17-8664-c5fcf115c0a2.html)</li></ul>  |
| **Author**               | Ecco, E.M. Anhaus, oscd.community |


## Detection Rules

### Sigma rule

```
title: Fsutil Suspicious Invocation
id: add64136-62e5-48ea-807e-88638d02df1e
description: Detects suspicious parameters of fsutil (deleting USN journal, configuring it with small size..). Might be used by ransomwares during the attack (seen by NotPetya and others)
author: Ecco, E.M. Anhaus, oscd.community
date: 2019/09/26
modified: 2019/11/11
level: high
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.yaml
    - https://eqllib.readthedocs.io/en/latest/analytics/c91f422a-5214-4b17-8664-c5fcf115c0a2.html
tags:
    - attack.defense_evasion
    - attack.t1070
logsource:
    category: process_creation
    product: windows
detection:
    binary_1:
        Image|endswith: '\fsutil.exe'
    binary_2:
        OriginalFileName: 'fsutil.exe'
    selection:
        CommandLine|contains: 
            - 'deletejournal'  # usn deletejournal ==> generally ransomware or attacker
            - 'createjournal'  # usn createjournal ==> can modify config to set it to a tiny size
    condition: (1 of binary_*) and selection
falsepositives:
    - Admin activity
    - Scripts and administrative tools used in the monitored environment

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\\\fsutil.exe" -or $_.message -match "OriginalFileName.*fsutil.exe") -and ($_.message -match "CommandLine.*.*deletejournal.*" -or $_.message -match "CommandLine.*.*createjournal.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\\\fsutil.exe OR OriginalFileName:"fsutil.exe") AND winlog.event_data.CommandLine.keyword:(*deletejournal* OR *createjournal*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/add64136-62e5-48ea-807e-88638d02df1e <<EOF\n{\n  "metadata": {\n    "title": "Fsutil Suspicious Invocation",\n    "description": "Detects suspicious parameters of fsutil (deleting USN journal, configuring it with small size..). Might be used by ransomwares during the attack (seen by NotPetya and others)",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1070"\n    ],\n    "query": "((winlog.event_data.Image.keyword:*\\\\\\\\fsutil.exe OR OriginalFileName:\\"fsutil.exe\\") AND winlog.event_data.CommandLine.keyword:(*deletejournal* OR *createjournal*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((winlog.event_data.Image.keyword:*\\\\\\\\fsutil.exe OR OriginalFileName:\\"fsutil.exe\\") AND winlog.event_data.CommandLine.keyword:(*deletejournal* OR *createjournal*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Fsutil Suspicious Invocation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image.keyword:*\\\\fsutil.exe OR OriginalFileName:"fsutil.exe") AND CommandLine.keyword:(*deletejournal* *createjournal*))
```


### splunk
    
```
((Image="*\\\\fsutil.exe" OR OriginalFileName="fsutil.exe") (CommandLine="*deletejournal*" OR CommandLine="*createjournal*"))
```


### logpoint
    
```
((Image="*\\\\fsutil.exe" OR OriginalFileName="fsutil.exe") CommandLine IN ["*deletejournal*", "*createjournal*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*.*\\fsutil\\.exe|.*fsutil\\.exe)))(?=.*(?:.*.*deletejournal.*|.*.*createjournal.*)))'
```



