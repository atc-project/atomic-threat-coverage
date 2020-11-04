| Title                    | Suspicious Access to Sensitive File Extensions       |
|:-------------------------|:------------------|
| **Description**          | Detects known sensitive file extensions |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0009: Collection](https://attack.mitre.org/tactics/TA0009)</li></ul>  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Help Desk operator doing backup or re-imaging end user machine or pentest or backup software</li><li>Users working with these data types or exchanging message files</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: Suspicious Access to Sensitive File Extensions
id: 91c945bc-2ad1-4799-a591-4d00198a1215
description: Detects known sensitive file extensions
author: Samir Bousseaden
date: 2019/04/03
tags:
    - attack.collection
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 5145
        RelativeTargetName:
            - '*.pst'
            - '*.ost'
            - '*.msg'
            - '*.nst'
            - '*.oab'
            - '*.edb'
            - '*.nsf'
            - '*.bak'
            - '*.dmp'
            - '*.kirbi'
            - '*\groups.xml'
            - '*.rdp'
    condition: selection
fields:
    - ComputerName
    - SubjectDomainName
    - SubjectUserName
    - RelativeTargetName
falsepositives:
    - Help Desk operator doing backup or re-imaging end user machine or pentest or backup software
    - Users working with these data types or exchanging message files
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "5145") -and ($_.message -match "RelativeTargetName.*.*.pst" -or $_.message -match "RelativeTargetName.*.*.ost" -or $_.message -match "RelativeTargetName.*.*.msg" -or $_.message -match "RelativeTargetName.*.*.nst" -or $_.message -match "RelativeTargetName.*.*.oab" -or $_.message -match "RelativeTargetName.*.*.edb" -or $_.message -match "RelativeTargetName.*.*.nsf" -or $_.message -match "RelativeTargetName.*.*.bak" -or $_.message -match "RelativeTargetName.*.*.dmp" -or $_.message -match "RelativeTargetName.*.*.kirbi" -or $_.message -match "RelativeTargetName.*.*\\groups.xml" -or $_.message -match "RelativeTargetName.*.*.rdp")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:("5145") AND RelativeTargetName.keyword:(*.pst OR *.ost OR *.msg OR *.nst OR *.oab OR *.edb OR *.nsf OR *.bak OR *.dmp OR *.kirbi OR *\\groups.xml OR *.rdp))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/91c945bc-2ad1-4799-a591-4d00198a1215 <<EOF
{
  "metadata": {
    "title": "Suspicious Access to Sensitive File Extensions",
    "description": "Detects known sensitive file extensions",
    "tags": [
      "attack.collection"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:(\"5145\") AND RelativeTargetName.keyword:(*.pst OR *.ost OR *.msg OR *.nst OR *.oab OR *.edb OR *.nsf OR *.bak OR *.dmp OR *.kirbi OR *\\\\groups.xml OR *.rdp))"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:(\"5145\") AND RelativeTargetName.keyword:(*.pst OR *.ost OR *.msg OR *.nst OR *.oab OR *.edb OR *.nsf OR *.bak OR *.dmp OR *.kirbi OR *\\\\groups.xml OR *.rdp))",
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
      "email": {
        "to": "root@localhost",
        "subject": "Sigma Rule 'Suspicious Access to Sensitive File Extensions'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      ComputerName = {{_source.ComputerName}}\n SubjectDomainName = {{_source.SubjectDomainName}}\n   SubjectUserName = {{_source.SubjectUserName}}\nRelativeTargetName = {{_source.RelativeTargetName}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(EventID:("5145") AND RelativeTargetName.keyword:(*.pst *.ost *.msg *.nst *.oab *.edb *.nsf *.bak *.dmp *.kirbi *\\groups.xml *.rdp))
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="5145") (RelativeTargetName="*.pst" OR RelativeTargetName="*.ost" OR RelativeTargetName="*.msg" OR RelativeTargetName="*.nst" OR RelativeTargetName="*.oab" OR RelativeTargetName="*.edb" OR RelativeTargetName="*.nsf" OR RelativeTargetName="*.bak" OR RelativeTargetName="*.dmp" OR RelativeTargetName="*.kirbi" OR RelativeTargetName="*\\groups.xml" OR RelativeTargetName="*.rdp")) | table ComputerName,SubjectDomainName,SubjectUserName,RelativeTargetName
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id IN ["5145"] RelativeTargetName IN ["*.pst", "*.ost", "*.msg", "*.nst", "*.oab", "*.edb", "*.nsf", "*.bak", "*.dmp", "*.kirbi", "*\\groups.xml", "*.rdp"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*5145))(?=.*(?:.*.*\.pst|.*.*\.ost|.*.*\.msg|.*.*\.nst|.*.*\.oab|.*.*\.edb|.*.*\.nsf|.*.*\.bak|.*.*\.dmp|.*.*\.kirbi|.*.*\groups\.xml|.*.*\.rdp)))'
```



