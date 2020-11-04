| Title                    | Detection of Possible Rotten Potato       |
|:-------------------------|:------------------|
| **Description**          | Detection of child processes spawned with SYSTEM privileges by parents with LOCAL SERVICE or NETWORK SERVICE privileges |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1134: Access Token Manipulation](https://attack.mitre.org/techniques/T1134)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Enrichment** |<ul><li>[EN_0001_cache_sysmon_event_id_1_info](../Enrichments/EN_0001_cache_sysmon_event_id_1_info.md)</li><li>[EN_0002_enrich_sysmon_event_id_1_with_parent_info](../Enrichments/EN_0002_enrich_sysmon_event_id_1_with_parent_info.md)</li></ul> |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment](https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)</li><li>[https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov |


## Detection Rules

### Sigma rule

```
title: Detection of Possible Rotten Potato
id: 6c5808ee-85a2-4e56-8137-72e5876a5096
description: Detection of child processes spawned with SYSTEM privileges by parents with LOCAL SERVICE or NETWORK SERVICE privileges
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
    - https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
tags:
    - attack.privilege_escalation
    - attack.t1134
status: experimental
author: Teymur Kheirkhabarov
date: 2019/10/26
modified: 2019/11/11
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentUser:
            - 'NT AUTHORITY\NETWORK SERVICE'
            - 'NT AUTHORITY\LOCAL SERVICE'
        User: 'NT AUTHORITY\SYSTEM'
    rundllexception:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains: 'DavSetCookie'
    condition: selection and not rundllexception
falsepositives:
    - Unknown
level: high
enrichment:
    - EN_0001_cache_sysmon_event_id_1_info                # http://bit.ly/314zc6x
    - EN_0002_enrich_sysmon_event_id_1_with_parent_info   # http://bit.ly/2KmSC0l

```





### powershell
    
```
Get-WinEvent | where {((($_.message -match "NT AUTHORITY\\NETWORK SERVICE" -or $_.message -match "NT AUTHORITY\\LOCAL SERVICE") -and $_.message -match "User.*NT AUTHORITY\\SYSTEM") -and  -not ($_.message -match "Image.*.*\\rundll32.exe" -and $_.message -match "CommandLine.*.*DavSetCookie.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((ParentUser:("NT\ AUTHORITY\\NETWORK\ SERVICE" OR "NT\ AUTHORITY\\LOCAL\ SERVICE") AND winlog.event_data.User:"NT\ AUTHORITY\\SYSTEM") AND (NOT (winlog.event_data.Image.keyword:*\\rundll32.exe AND winlog.event_data.CommandLine.keyword:*DavSetCookie*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/6c5808ee-85a2-4e56-8137-72e5876a5096 <<EOF
{
  "metadata": {
    "title": "Detection of Possible Rotten Potato",
    "description": "Detection of child processes spawned with SYSTEM privileges by parents with LOCAL SERVICE or NETWORK SERVICE privileges",
    "tags": [
      "attack.privilege_escalation",
      "attack.t1134"
    ],
    "query": "((ParentUser:(\"NT\\ AUTHORITY\\\\NETWORK\\ SERVICE\" OR \"NT\\ AUTHORITY\\\\LOCAL\\ SERVICE\") AND winlog.event_data.User:\"NT\\ AUTHORITY\\\\SYSTEM\") AND (NOT (winlog.event_data.Image.keyword:*\\\\rundll32.exe AND winlog.event_data.CommandLine.keyword:*DavSetCookie*)))"
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
                    "query": "((ParentUser:(\"NT\\ AUTHORITY\\\\NETWORK\\ SERVICE\" OR \"NT\\ AUTHORITY\\\\LOCAL\\ SERVICE\") AND winlog.event_data.User:\"NT\\ AUTHORITY\\\\SYSTEM\") AND (NOT (winlog.event_data.Image.keyword:*\\\\rundll32.exe AND winlog.event_data.CommandLine.keyword:*DavSetCookie*)))",
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
        "subject": "Sigma Rule 'Detection of Possible Rotten Potato'",
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
((ParentUser:("NT AUTHORITY\\NETWORK SERVICE" "NT AUTHORITY\\LOCAL SERVICE") AND User:"NT AUTHORITY\\SYSTEM") AND (NOT (Image.keyword:*\\rundll32.exe AND CommandLine.keyword:*DavSetCookie*)))
```


### splunk
    
```
(((ParentUser="NT AUTHORITY\\NETWORK SERVICE" OR ParentUser="NT AUTHORITY\\LOCAL SERVICE") User="NT AUTHORITY\\SYSTEM") NOT (Image="*\\rundll32.exe" CommandLine="*DavSetCookie*"))
```


### logpoint
    
```
((ParentUser IN ["NT AUTHORITY\\NETWORK SERVICE", "NT AUTHORITY\\LOCAL SERVICE"] User="NT AUTHORITY\\SYSTEM")  -(Image="*\\rundll32.exe" CommandLine="*DavSetCookie*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*(?:.*NT AUTHORITY\NETWORK SERVICE|.*NT AUTHORITY\LOCAL SERVICE))(?=.*NT AUTHORITY\SYSTEM)))(?=.*(?!.*(?:.*(?=.*.*\rundll32\.exe)(?=.*.*DavSetCookie.*)))))'
```



