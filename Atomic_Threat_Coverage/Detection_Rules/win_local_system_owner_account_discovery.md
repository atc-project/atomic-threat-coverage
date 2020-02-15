| Title                | Local accounts discovery                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Local accounts, System Owner/User discovery using operating systems utilities                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1033: System Owner/User Discovery](https://attack.mitre.org/techniques/T1033)</li><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1033: System Owner/User Discovery](../Triggers/T1033.md)</li><li>[T1087: Account Discovery](../Triggers/T1087.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Legitimate administrator or user enumerates local users for legitimate reason</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.yaml)</li></ul>  |
| Author               | Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: Local accounts discovery
id: 502b42de-4306-40b4-9596-6f590c81f073
status: experimental
description: Local accounts, System Owner/User discovery using operating systems utilities
author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
date: 2019/10/21
modified: 2019/11/04
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
            - 'dir'
            - '\Users\'
    selection_2:
        Image|endswith:
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains: 'user'
    filter:
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
    condition: selection_1 or ( selection_2 and not filter )
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
    - attack.t1087

```





### es-qs
    
```
((Image.keyword:*\\\\whoami.exe OR (Image.keyword:*\\\\wmic.exe AND CommandLine.keyword:*useraccount* AND CommandLine.keyword:*get*) OR Image.keyword:(*\\\\quser.exe OR *\\\\qwinsta.exe) OR (Image.keyword:*\\\\cmdkey.exe AND CommandLine.keyword:*\\/list*) OR (Image.keyword:*\\\\cmd.exe AND CommandLine.keyword:*\\/c* AND CommandLine.keyword:*dir* AND CommandLine.keyword:*\\\\Users\\*)) OR ((Image.keyword:(*\\\\net.exe OR *\\\\net1.exe) AND CommandLine.keyword:*user*) AND (NOT (CommandLine.keyword:(*\\/domain* OR *\\/add* OR *\\/delete* OR *\\/active* OR *\\/expires* OR *\\/passwordreq* OR *\\/scriptpath* OR *\\/times* OR *\\/workstations*)))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Local-accounts-discovery <<EOF\n{\n  "metadata": {\n    "title": "Local accounts discovery",\n    "description": "Local accounts, System Owner/User discovery using operating systems utilities",\n    "tags": [\n      "attack.discovery",\n      "attack.t1033",\n      "attack.t1087"\n    ],\n    "query": "((Image.keyword:*\\\\\\\\whoami.exe OR (Image.keyword:*\\\\\\\\wmic.exe AND CommandLine.keyword:*useraccount* AND CommandLine.keyword:*get*) OR Image.keyword:(*\\\\\\\\quser.exe OR *\\\\\\\\qwinsta.exe) OR (Image.keyword:*\\\\\\\\cmdkey.exe AND CommandLine.keyword:*\\\\/list*) OR (Image.keyword:*\\\\\\\\cmd.exe AND CommandLine.keyword:*\\\\/c* AND CommandLine.keyword:*dir* AND CommandLine.keyword:*\\\\\\\\Users\\\\*)) OR ((Image.keyword:(*\\\\\\\\net.exe OR *\\\\\\\\net1.exe) AND CommandLine.keyword:*user*) AND (NOT (CommandLine.keyword:(*\\\\/domain* OR *\\\\/add* OR *\\\\/delete* OR *\\\\/active* OR *\\\\/expires* OR *\\\\/passwordreq* OR *\\\\/scriptpath* OR *\\\\/times* OR *\\\\/workstations*)))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((Image.keyword:*\\\\\\\\whoami.exe OR (Image.keyword:*\\\\\\\\wmic.exe AND CommandLine.keyword:*useraccount* AND CommandLine.keyword:*get*) OR Image.keyword:(*\\\\\\\\quser.exe OR *\\\\\\\\qwinsta.exe) OR (Image.keyword:*\\\\\\\\cmdkey.exe AND CommandLine.keyword:*\\\\/list*) OR (Image.keyword:*\\\\\\\\cmd.exe AND CommandLine.keyword:*\\\\/c* AND CommandLine.keyword:*dir* AND CommandLine.keyword:*\\\\\\\\Users\\\\*)) OR ((Image.keyword:(*\\\\\\\\net.exe OR *\\\\\\\\net1.exe) AND CommandLine.keyword:*user*) AND (NOT (CommandLine.keyword:(*\\\\/domain* OR *\\\\/add* OR *\\\\/delete* OR *\\\\/active* OR *\\\\/expires* OR *\\\\/passwordreq* OR *\\\\/scriptpath* OR *\\\\/times* OR *\\\\/workstations*)))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Local accounts discovery\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n            Image = {{_source.Image}}\\n      CommandLine = {{_source.CommandLine}}\\n             User = {{_source.User}}\\n        LogonGuid = {{_source.LogonGuid}}\\n           Hashes = {{_source.Hashes}}\\nParentProcessGuid = {{_source.ParentProcessGuid}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image.keyword:*\\\\whoami.exe OR (Image.keyword:*\\\\wmic.exe AND CommandLine.keyword:*useraccount* AND CommandLine.keyword:*get*) OR Image.keyword:(*\\\\quser.exe *\\\\qwinsta.exe) OR (Image.keyword:*\\\\cmdkey.exe AND CommandLine.keyword:*\\/list*) OR (Image.keyword:*\\\\cmd.exe AND CommandLine.keyword:*\\/c* AND CommandLine.keyword:*dir* AND CommandLine.keyword:*\\\\Users\\*)) OR ((Image.keyword:(*\\\\net.exe *\\\\net1.exe) AND CommandLine.keyword:*user*) AND (NOT (CommandLine.keyword:(*\\/domain* *\\/add* *\\/delete* *\\/active* *\\/expires* *\\/passwordreq* *\\/scriptpath* *\\/times* *\\/workstations*)))))
```


### splunk
    
```
((Image="*\\\\whoami.exe" OR (Image="*\\\\wmic.exe" CommandLine="*useraccount*" CommandLine="*get*") OR (Image="*\\\\quser.exe" OR Image="*\\\\qwinsta.exe") OR (Image="*\\\\cmdkey.exe" CommandLine="*/list*") OR (Image="*\\\\cmd.exe" CommandLine="*/c*" CommandLine="*dir*" CommandLine="*\\\\Users\\*")) OR (((Image="*\\\\net.exe" OR Image="*\\\\net1.exe") CommandLine="*user*") NOT ((CommandLine="*/domain*" OR CommandLine="*/add*" OR CommandLine="*/delete*" OR CommandLine="*/active*" OR CommandLine="*/expires*" OR CommandLine="*/passwordreq*" OR CommandLine="*/scriptpath*" OR CommandLine="*/times*" OR CommandLine="*/workstations*")))) | table Image,CommandLine,User,LogonGuid,Hashes,ParentProcessGuid,ParentCommandLine
```


### logpoint
    
```
(event_id="1" ((Image="*\\\\whoami.exe" OR (Image="*\\\\wmic.exe" CommandLine="*useraccount*" CommandLine="*get*") OR Image IN ["*\\\\quser.exe", "*\\\\qwinsta.exe"] OR (Image="*\\\\cmdkey.exe" CommandLine="*/list*") OR (Image="*\\\\cmd.exe" CommandLine="*/c*" CommandLine="*dir*" CommandLine="*\\\\Users\\*")) OR (event_id="1" (Image IN ["*\\\\net.exe", "*\\\\net1.exe"] CommandLine="*user*")  -(CommandLine IN ["*/domain*", "*/add*", "*/delete*", "*/active*", "*/expires*", "*/passwordreq*", "*/scriptpath*", "*/times*", "*/workstations*"]))))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?:.*.*\\whoami\\.exe|.*(?:.*(?=.*.*\\wmic\\.exe)(?=.*.*useraccount.*)(?=.*.*get.*))|.*(?:.*.*\\quser\\.exe|.*.*\\qwinsta\\.exe)|.*(?:.*(?=.*.*\\cmdkey\\.exe)(?=.*.*/list.*))|.*(?:.*(?=.*.*\\cmd\\.exe)(?=.*.*/c.*)(?=.*.*dir.*)(?=.*.*\\Users\\.*))))|.*(?:.*(?=.*(?:.*(?=.*(?:.*.*\\net\\.exe|.*.*\\net1\\.exe))(?=.*.*user.*)))(?=.*(?!.*(?:.*(?=.*(?:.*.*/domain.*|.*.*/add.*|.*.*/delete.*|.*.*/active.*|.*.*/expires.*|.*.*/passwordreq.*|.*.*/scriptpath.*|.*.*/times.*|.*.*/workstations.*))))))))'
```



