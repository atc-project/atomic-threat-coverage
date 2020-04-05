| Title                    | Tasks Folder Evasion       |
|:-------------------------|:------------------|
| **Description**          | The Tasks folder in system32 and syswow64 are globally writable paths. Adversaries can take advantage of this and load or influence any script hosts or ANY .NET Application in Tasks to load and execute a custom assembly into cscript, wscript, regsvr32, mshta, eventvwr |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li><li>[T1211: Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211)</li><li>[T1059: Command-Line Interface](https://attack.mitre.org/techniques/T1059)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1064: Scripting](../Triggers/T1064.md)</li><li>[T1211: Exploitation for Defense Evasion](../Triggers/T1211.md)</li><li>[T1059: Command-Line Interface](../Triggers/T1059.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/subTee/status/1216465628946563073](https://twitter.com/subTee/status/1216465628946563073)</li><li>[https://gist.github.com/am0nsec/8378da08f848424e4ab0cc5b317fdd26](https://gist.github.com/am0nsec/8378da08f848424e4ab0cc5b317fdd26)</li></ul>  |
| **Author**               | Sreeman |


## Detection Rules

### Sigma rule

```
title: Tasks Folder Evasion
id: cc4e02ba-9c06-48e2-b09e-2500cace9ae0
status: experimental
description: The Tasks folder in system32 and syswow64 are globally writable paths. Adversaries can take advantage of this and load or influence any script hosts or ANY .NET Application in Tasks to load and execute a custom assembly into cscript, wscript, regsvr32, mshta, eventvwr 
references: 
    - https://twitter.com/subTee/status/1216465628946563073
    - https://gist.github.com/am0nsec/8378da08f848424e4ab0cc5b317fdd26
date: 2020/13/01
author: Sreeman
tags:
    - attack.t1064
    - attack.t1211
    - attack.t1059
    - attack.defense_evasion
    - attack.persistence
logsource:
    product: Windows
detection:
    selection1:
        CommandLine|contains:
            - 'echo '
            - 'copy '
            - 'type '
            - 'file createnew'
    selection2:
        CommandLine|contains:
            - ' C:\Windows\System32\Tasks\'
            - ' C:\Windows\SysWow64\Tasks\'
    condition: selection1 and selection2
fields:
    - CommandLine
    - ParentProcess
    - CommandLine
falsepositives:
    - Unknown
level: high

```





### es-qs
    
```
(CommandLine.keyword:(*echo\\ * OR *copy\\ * OR *type\\ * OR *file\\ createnew*) AND CommandLine.keyword:(*\\ C\\:\\\\Windows\\\\System32\\\\Tasks\\* OR *\\ C\\:\\\\Windows\\\\SysWow64\\\\Tasks\\*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/cc4e02ba-9c06-48e2-b09e-2500cace9ae0 <<EOF\n{\n  "metadata": {\n    "title": "Tasks Folder Evasion",\n    "description": "The Tasks folder in system32 and syswow64 are globally writable paths. Adversaries can take advantage of this and load or influence any script hosts or ANY .NET Application in Tasks to load and execute a custom assembly into cscript, wscript, regsvr32, mshta, eventvwr",\n    "tags": [\n      "attack.t1064",\n      "attack.t1211",\n      "attack.t1059",\n      "attack.defense_evasion",\n      "attack.persistence"\n    ],\n    "query": "(CommandLine.keyword:(*echo\\\\ * OR *copy\\\\ * OR *type\\\\ * OR *file\\\\ createnew*) AND CommandLine.keyword:(*\\\\ C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\Tasks\\\\* OR *\\\\ C\\\\:\\\\\\\\Windows\\\\\\\\SysWow64\\\\\\\\Tasks\\\\*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(CommandLine.keyword:(*echo\\\\ * OR *copy\\\\ * OR *type\\\\ * OR *file\\\\ createnew*) AND CommandLine.keyword:(*\\\\ C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\Tasks\\\\* OR *\\\\ C\\\\:\\\\\\\\Windows\\\\\\\\SysWow64\\\\\\\\Tasks\\\\*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Tasks Folder Evasion\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n  CommandLine = {{_source.CommandLine}}\\nParentProcess = {{_source.ParentProcess}}\\n  CommandLine = {{_source.CommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:(*echo * *copy * *type * *file createnew*) AND CommandLine.keyword:(* C\\:\\\\Windows\\\\System32\\\\Tasks\\* * C\\:\\\\Windows\\\\SysWow64\\\\Tasks\\*))
```


### splunk
    
```
((CommandLine="*echo *" OR CommandLine="*copy *" OR CommandLine="*type *" OR CommandLine="*file createnew*") (CommandLine="* C:\\\\Windows\\\\System32\\\\Tasks\\*" OR CommandLine="* C:\\\\Windows\\\\SysWow64\\\\Tasks\\*")) | table CommandLine,ParentProcess,CommandLine
```


### logpoint
    
```
(CommandLine IN ["*echo *", "*copy *", "*type *", "*file createnew*"] CommandLine IN ["* C:\\\\Windows\\\\System32\\\\Tasks\\*", "* C:\\\\Windows\\\\SysWow64\\\\Tasks\\*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*echo .*|.*.*copy .*|.*.*type .*|.*.*file createnew.*))(?=.*(?:.*.* C:\\Windows\\System32\\Tasks\\.*|.*.* C:\\Windows\\SysWow64\\Tasks\\.*)))'
```



