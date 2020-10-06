| Title                    | Local Accounts Discovery       |
|:-------------------------|:------------------|
| **Description**          | Local accounts, System Owner/User discovery using operating systems utilities |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1033: System Owner/User Discovery](https://attack.mitre.org/techniques/T1033)</li><li>[T1087.001: Local Account](https://attack.mitre.org/techniques/T1087/001)</li><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1033: System Owner/User Discovery](../Triggers/T1033.md)</li><li>[T1087.001: Local Account](../Triggers/T1087.001.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Legitimate administrator or user enumerates local users for legitimate reason</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.yaml)</li></ul>  |
| **Author**               | Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: Local Accounts Discovery
id: 502b42de-4306-40b4-9596-6f590c81f073
status: experimental
description: Local accounts, System Owner/User discovery using operating systems utilities
author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
date: 2019/10/21
modified: 2020/09/01
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
      - Image|endswith: '\whoami.exe'
      - Image|endswith: '\wmic.exe'
        CommandLine|contains|all:
            - 'useraccount'
            - 'get'
      - Image|endswith: 
            - '\quser.exe'
            - '\qwinsta.exe'
      - Image|endswith: '\cmdkey.exe'
        CommandLine|contains: '/list'
      - Image|endswith: '\cmd.exe'
        CommandLine|contains|all: 
            - '/c'
            - 'dir '
            - '\Users\'
    filter_1:
        CommandLine|contains:
            - ' rmdir '       # don't match on 'dir'   "C:\Windows\System32\cmd.exe" /q /c rmdir /s /q "C:\Users\XX\AppData\Local\Microsoft\OneDrive\19.232.1124.0005"
    selection_2:
        Image|endswith:
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains: 'user'
    filter_2:
        CommandLine|contains:
            - '/domain'       # local account discovery only
            - '/add'          # discovery only
            - '/delete'       # discovery only
            - '/active'       # discovery only
            - '/expires'      # discovery only
            - '/passwordreq'  # discovery only
            - '/scriptpath'   # discovery only
            - '/times'        # discovery only
            - '/workstations' # discovery only
    condition: (selection_1 and not filter_1) or ( selection_2 and not filter_2)
fields:
    - Image
    - CommandLine
    - User
    - LogonGuid
    - Hashes
    - ParentProcessGuid
    - ParentCommandLine
falsepositives:
     - Legitimate administrator or user enumerates local users for legitimate reason
level: low
tags:
    - attack.discovery
    - attack.t1033
    - attack.t1087.001
    - attack.t1087  # an old one

```





### powershell
    
```
Get-WinEvent | where {((($_.message -match "Image.*.*\\\\whoami.exe" -or ($_.message -match "Image.*.*\\\\wmic.exe" -and $_.message -match "CommandLine.*.*useraccount.*" -and $_.message -match "CommandLine.*.*get.*") -or ($_.message -match "Image.*.*\\\\quser.exe" -or $_.message -match "Image.*.*\\\\qwinsta.exe") -or ($_.message -match "Image.*.*\\\\cmdkey.exe" -and $_.message -match "CommandLine.*.*/list.*") -or ($_.message -match "Image.*.*\\\\cmd.exe" -and $_.message -match "CommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*dir .*" -and $_.message -match "CommandLine.*.*\\\\Users\\\\.*")) -and  -not (($_.message -match "CommandLine.*.* rmdir .*"))) -or ((($_.message -match "Image.*.*\\\\net.exe" -or $_.message -match "Image.*.*\\\\net1.exe") -and $_.message -match "CommandLine.*.*user.*") -and  -not (($_.message -match "CommandLine.*.*/domain.*" -or $_.message -match "CommandLine.*.*/add.*" -or $_.message -match "CommandLine.*.*/delete.*" -or $_.message -match "CommandLine.*.*/active.*" -or $_.message -match "CommandLine.*.*/expires.*" -or $_.message -match "CommandLine.*.*/passwordreq.*" -or $_.message -match "CommandLine.*.*/scriptpath.*" -or $_.message -match "CommandLine.*.*/times.*" -or $_.message -match "CommandLine.*.*/workstations.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(((winlog.event_data.Image.keyword:*\\\\whoami.exe OR (winlog.event_data.Image.keyword:*\\\\wmic.exe AND winlog.event_data.CommandLine.keyword:*useraccount* AND winlog.event_data.CommandLine.keyword:*get*) OR winlog.event_data.Image.keyword:(*\\\\quser.exe OR *\\\\qwinsta.exe) OR (winlog.event_data.Image.keyword:*\\\\cmdkey.exe AND winlog.event_data.CommandLine.keyword:*\\/list*) OR (winlog.event_data.Image.keyword:*\\\\cmd.exe AND winlog.event_data.CommandLine.keyword:*\\/c* AND winlog.event_data.CommandLine.keyword:*dir\\ * AND winlog.event_data.CommandLine.keyword:*\\\\Users\\\\*)) AND (NOT (winlog.event_data.CommandLine.keyword:(*\\ rmdir\\ *)))) OR ((winlog.event_data.Image.keyword:(*\\\\net.exe OR *\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:*user*) AND (NOT (winlog.event_data.CommandLine.keyword:(*\\/domain* OR *\\/add* OR *\\/delete* OR *\\/active* OR *\\/expires* OR *\\/passwordreq* OR *\\/scriptpath* OR *\\/times* OR *\\/workstations*)))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/502b42de-4306-40b4-9596-6f590c81f073 <<EOF\n{\n  "metadata": {\n    "title": "Local Accounts Discovery",\n    "description": "Local accounts, System Owner/User discovery using operating systems utilities",\n    "tags": [\n      "attack.discovery",\n      "attack.t1033",\n      "attack.t1087.001",\n      "attack.t1087"\n    ],\n    "query": "(((winlog.event_data.Image.keyword:*\\\\\\\\whoami.exe OR (winlog.event_data.Image.keyword:*\\\\\\\\wmic.exe AND winlog.event_data.CommandLine.keyword:*useraccount* AND winlog.event_data.CommandLine.keyword:*get*) OR winlog.event_data.Image.keyword:(*\\\\\\\\quser.exe OR *\\\\\\\\qwinsta.exe) OR (winlog.event_data.Image.keyword:*\\\\\\\\cmdkey.exe AND winlog.event_data.CommandLine.keyword:*\\\\/list*) OR (winlog.event_data.Image.keyword:*\\\\\\\\cmd.exe AND winlog.event_data.CommandLine.keyword:*\\\\/c* AND winlog.event_data.CommandLine.keyword:*dir\\\\ * AND winlog.event_data.CommandLine.keyword:*\\\\\\\\Users\\\\\\\\*)) AND (NOT (winlog.event_data.CommandLine.keyword:(*\\\\ rmdir\\\\ *)))) OR ((winlog.event_data.Image.keyword:(*\\\\\\\\net.exe OR *\\\\\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:*user*) AND (NOT (winlog.event_data.CommandLine.keyword:(*\\\\/domain* OR *\\\\/add* OR *\\\\/delete* OR *\\\\/active* OR *\\\\/expires* OR *\\\\/passwordreq* OR *\\\\/scriptpath* OR *\\\\/times* OR *\\\\/workstations*)))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(((winlog.event_data.Image.keyword:*\\\\\\\\whoami.exe OR (winlog.event_data.Image.keyword:*\\\\\\\\wmic.exe AND winlog.event_data.CommandLine.keyword:*useraccount* AND winlog.event_data.CommandLine.keyword:*get*) OR winlog.event_data.Image.keyword:(*\\\\\\\\quser.exe OR *\\\\\\\\qwinsta.exe) OR (winlog.event_data.Image.keyword:*\\\\\\\\cmdkey.exe AND winlog.event_data.CommandLine.keyword:*\\\\/list*) OR (winlog.event_data.Image.keyword:*\\\\\\\\cmd.exe AND winlog.event_data.CommandLine.keyword:*\\\\/c* AND winlog.event_data.CommandLine.keyword:*dir\\\\ * AND winlog.event_data.CommandLine.keyword:*\\\\\\\\Users\\\\\\\\*)) AND (NOT (winlog.event_data.CommandLine.keyword:(*\\\\ rmdir\\\\ *)))) OR ((winlog.event_data.Image.keyword:(*\\\\\\\\net.exe OR *\\\\\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:*user*) AND (NOT (winlog.event_data.CommandLine.keyword:(*\\\\/domain* OR *\\\\/add* OR *\\\\/delete* OR *\\\\/active* OR *\\\\/expires* OR *\\\\/passwordreq* OR *\\\\/scriptpath* OR *\\\\/times* OR *\\\\/workstations*)))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Local Accounts Discovery\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n            Image = {{_source.Image}}\\n      CommandLine = {{_source.CommandLine}}\\n             User = {{_source.User}}\\n        LogonGuid = {{_source.LogonGuid}}\\n           Hashes = {{_source.Hashes}}\\nParentProcessGuid = {{_source.ParentProcessGuid}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(((Image.keyword:*\\\\whoami.exe OR (Image.keyword:*\\\\wmic.exe AND CommandLine.keyword:*useraccount* AND CommandLine.keyword:*get*) OR Image.keyword:(*\\\\quser.exe *\\\\qwinsta.exe) OR (Image.keyword:*\\\\cmdkey.exe AND CommandLine.keyword:*\\/list*) OR (Image.keyword:*\\\\cmd.exe AND CommandLine.keyword:*\\/c* AND CommandLine.keyword:*dir * AND CommandLine.keyword:*\\\\Users\\\\*)) AND (NOT (CommandLine.keyword:(* rmdir *)))) OR ((Image.keyword:(*\\\\net.exe *\\\\net1.exe) AND CommandLine.keyword:*user*) AND (NOT (CommandLine.keyword:(*\\/domain* *\\/add* *\\/delete* *\\/active* *\\/expires* *\\/passwordreq* *\\/scriptpath* *\\/times* *\\/workstations*)))))
```


### splunk
    
```
(((Image="*\\\\whoami.exe" OR (Image="*\\\\wmic.exe" CommandLine="*useraccount*" CommandLine="*get*") OR (Image="*\\\\quser.exe" OR Image="*\\\\qwinsta.exe") OR (Image="*\\\\cmdkey.exe" CommandLine="*/list*") OR (Image="*\\\\cmd.exe" CommandLine="*/c*" CommandLine="*dir *" CommandLine="*\\\\Users\\\\*")) NOT ((CommandLine="* rmdir *"))) OR (((Image="*\\\\net.exe" OR Image="*\\\\net1.exe") CommandLine="*user*") NOT ((CommandLine="*/domain*" OR CommandLine="*/add*" OR CommandLine="*/delete*" OR CommandLine="*/active*" OR CommandLine="*/expires*" OR CommandLine="*/passwordreq*" OR CommandLine="*/scriptpath*" OR CommandLine="*/times*" OR CommandLine="*/workstations*")))) | table Image,CommandLine,User,LogonGuid,Hashes,ParentProcessGuid,ParentCommandLine
```


### logpoint
    
```
(((Image="*\\\\whoami.exe" OR (Image="*\\\\wmic.exe" CommandLine="*useraccount*" CommandLine="*get*") OR Image IN ["*\\\\quser.exe", "*\\\\qwinsta.exe"] OR (Image="*\\\\cmdkey.exe" CommandLine="*/list*") OR (Image="*\\\\cmd.exe" CommandLine="*/c*" CommandLine="*dir *" CommandLine="*\\\\Users\\\\*"))  -(CommandLine IN ["* rmdir *"])) OR ((Image IN ["*\\\\net.exe", "*\\\\net1.exe"] CommandLine="*user*")  -(CommandLine IN ["*/domain*", "*/add*", "*/delete*", "*/active*", "*/expires*", "*/passwordreq*", "*/scriptpath*", "*/times*", "*/workstations*"])))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*(?:.*(?:.*.*\\whoami\\.exe|.*(?:.*(?=.*.*\\wmic\\.exe)(?=.*.*useraccount.*)(?=.*.*get.*))|.*(?:.*.*\\quser\\.exe|.*.*\\qwinsta\\.exe)|.*(?:.*(?=.*.*\\cmdkey\\.exe)(?=.*.*/list.*))|.*(?:.*(?=.*.*\\cmd\\.exe)(?=.*.*/c.*)(?=.*.*dir .*)(?=.*.*\\Users\\\\.*)))))(?=.*(?!.*(?:.*(?=.*(?:.*.* rmdir .*))))))|.*(?:.*(?=.*(?:.*(?=.*(?:.*.*\\net\\.exe|.*.*\\net1\\.exe))(?=.*.*user.*)))(?=.*(?!.*(?:.*(?=.*(?:.*.*/domain.*|.*.*/add.*|.*.*/delete.*|.*.*/active.*|.*.*/expires.*|.*.*/passwordreq.*|.*.*/scriptpath.*|.*.*/times.*|.*.*/workstations.*))))))))'
```



