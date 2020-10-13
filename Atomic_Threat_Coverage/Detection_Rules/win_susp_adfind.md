| Title                    | Suspicious AdFind Execution       |
|:-------------------------|:------------------|
| **Description**          | Detects the execution of a AdFind for Active Directory enumeration |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1016: System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016)</li><li>[T1018: Remote System Discovery](https://attack.mitre.org/techniques/T1018)</li><li>[T1482: Domain Trust Discovery](https://attack.mitre.org/techniques/T1482)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1016: System Network Configuration Discovery](../Triggers/T1016.md)</li><li>[T1018: Remote System Discovery](../Triggers/T1018.md)</li><li>[T1482: Domain Trust Discovery](../Triggers/T1482.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Administrative activity</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://social.technet.microsoft.com/wiki/contents/articles/7535.adfind-command-examples.aspx](https://social.technet.microsoft.com/wiki/contents/articles/7535.adfind-command-examples.aspx)</li><li>[https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/fin6/Emulation_Plan/Phase1.md](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/fin6/Emulation_Plan/Phase1.md)</li></ul>  |
| **Author**               | FPT.EagleEye Team |


## Detection Rules

### Sigma rule

```
title: Suspicious AdFind Execution
id: 75df3b17-8bcc-4565-b89b-c9898acef911
status: experimental
description: Detects the execution of a AdFind for Active Directory enumeration 
references:
    - https://social.technet.microsoft.com/wiki/contents/articles/7535.adfind-command-examples.aspx
    - https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/fin6/Emulation_Plan/Phase1.md
author: FPT.EagleEye Team
date: 2020/09/26
tags:
    - attack.discovery
    - attack.t1016
    - attack.t1018
    - attack.t1482
    #- attack.t1069.002
    #- attack.t1087.002
logsource:
    product: windows
    service: process_creation
detection:
    selection:
        ProcessCommandline|contains: 'objectcategory'
        Image: 
            - '*\adfind.exe'
    condition: selection
falsepositives:
    - Administrative activity
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "ProcessCommandline.*.*objectcategory.*" -and ($_.message -match "Image.*.*\\adfind.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(ProcessCommandline.keyword:*objectcategory* AND winlog.event_data.Image.keyword:(*\\adfind.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/75df3b17-8bcc-4565-b89b-c9898acef911 <<EOF
{
  "metadata": {
    "title": "Suspicious AdFind Execution",
    "description": "Detects the execution of a AdFind for Active Directory enumeration",
    "tags": [
      "attack.discovery",
      "attack.t1016",
      "attack.t1018",
      "attack.t1482"
    ],
    "query": "(ProcessCommandline.keyword:*objectcategory* AND winlog.event_data.Image.keyword:(*\\\\adfind.exe))"
  },
  "trigger": {
    "schedule": {
      "interval": "30m"
    }
  },
  "input": {
    "search": {
      "request": {
        "body": {
          "size": 0,
          "query": {
            "bool": {
              "must": [
                {
                  "query_string": {
                    "query": "(ProcessCommandline.keyword:*objectcategory* AND winlog.event_data.Image.keyword:(*\\\\adfind.exe))",
                    "analyze_wildcard": true
                  }
                }
              ],
              "filter": {
                "range": {
                  "timestamp": {
                    "gte": "now-30m/m"
                  }
                }
              }
            }
          }
        },
        "indices": [
          "winlogbeat-*"
        ]
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "not_eq": 0
      }
    }
  },
  "actions": {
    "send_email": {
      "throttle_period": "15m",
      "email": {
        "profile": "standard",
        "from": "root@localhost",
        "to": "root@localhost",
        "subject": "Sigma Rule 'Suspicious AdFind Execution'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}{{_source}}\n================================================================================\n{{/ctx.payload.hits.hits}}",
        "attachments": {
          "data.json": {
            "data": {
              "format": "json"
            }
          }
        }
      }
    }
  }
}
EOF

```


### graylog
    
```
(ProcessCommandline.keyword:*objectcategory* AND Image.keyword:(*\\adfind.exe))
```


### splunk
    
```
(ProcessCommandline="*objectcategory*" (Image="*\\adfind.exe"))
```


### logpoint
    
```
(ProcessCommandline="*objectcategory*" Image IN ["*\\adfind.exe"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*objectcategory.*)(?=.*(?:.*.*\adfind\.exe)))'
```



