| Title                    | Transfering Files with Credential Data via Network Shares       |
|:-------------------------|:------------------|
| **Description**          | Transfering files with well-known filenames (sensitive files with credential data) using network shares |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Transfering sensitive files for legitimate administration work by legitimate administrator</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov, oscd.community |


## Detection Rules

### Sigma rule

```
title: Transfering Files with Credential Data via Network Shares
id: 910ab938-668b-401b-b08c-b596e80fdca5
description: Transfering files with well-known filenames (sensitive files with credential data) using network shares
author: Teymur Kheirkhabarov, oscd.community
date: 2019/10/22
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5145
        RelativeTargetName|contains:
            - '\mimidrv'
            - '\lsass'
            - '\windows\minidump\'
            - '\hiberfil'
            - '\sqldmpr'
            - '\sam'
            - '\ntds.dit'
            - '\security'
    condition: selection
falsepositives:
    - Transfering sensitive files for legitimate administration work by legitimate administrator
level: medium
status: experimental

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "5145" -and ($_.message -match "RelativeTargetName.*.*\\mimidrv.*" -or $_.message -match "RelativeTargetName.*.*\\lsass.*" -or $_.message -match "RelativeTargetName.*.*\\windows\\minidump\\.*" -or $_.message -match "RelativeTargetName.*.*\\hiberfil.*" -or $_.message -match "RelativeTargetName.*.*\\sqldmpr.*" -or $_.message -match "RelativeTargetName.*.*\\sam.*" -or $_.message -match "RelativeTargetName.*.*\\ntds.dit.*" -or $_.message -match "RelativeTargetName.*.*\\security.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"5145" AND RelativeTargetName.keyword:(*\\mimidrv* OR *\\lsass* OR *\\windows\\minidump\* OR *\\hiberfil* OR *\\sqldmpr* OR *\\sam* OR *\\ntds.dit* OR *\\security*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/910ab938-668b-401b-b08c-b596e80fdca5 <<EOF
{
  "metadata": {
    "title": "Transfering Files with Credential Data via Network Shares",
    "description": "Transfering files with well-known filenames (sensitive files with credential data) using network shares",
    "tags": [
      "attack.credential_access",
      "attack.t1003"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"5145\" AND RelativeTargetName.keyword:(*\\\\mimidrv* OR *\\\\lsass* OR *\\\\windows\\\\minidump\\* OR *\\\\hiberfil* OR *\\\\sqldmpr* OR *\\\\sam* OR *\\\\ntds.dit* OR *\\\\security*))"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"5145\" AND RelativeTargetName.keyword:(*\\\\mimidrv* OR *\\\\lsass* OR *\\\\windows\\\\minidump\\* OR *\\\\hiberfil* OR *\\\\sqldmpr* OR *\\\\sam* OR *\\\\ntds.dit* OR *\\\\security*))",
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
        "subject": "Sigma Rule 'Transfering Files with Credential Data via Network Shares'",
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
(EventID:"5145" AND RelativeTargetName.keyword:(*\\mimidrv* *\\lsass* *\\windows\\minidump\* *\\hiberfil* *\\sqldmpr* *\\sam* *\\ntds.dit* *\\security*))
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="5145" (RelativeTargetName="*\\mimidrv*" OR RelativeTargetName="*\\lsass*" OR RelativeTargetName="*\\windows\\minidump\*" OR RelativeTargetName="*\\hiberfil*" OR RelativeTargetName="*\\sqldmpr*" OR RelativeTargetName="*\\sam*" OR RelativeTargetName="*\\ntds.dit*" OR RelativeTargetName="*\\security*"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="5145" RelativeTargetName IN ["*\\mimidrv*", "*\\lsass*", "*\\windows\\minidump\*", "*\\hiberfil*", "*\\sqldmpr*", "*\\sam*", "*\\ntds.dit*", "*\\security*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*5145)(?=.*(?:.*.*\mimidrv.*|.*.*\lsass.*|.*.*\windows\minidump\.*|.*.*\hiberfil.*|.*.*\sqldmpr.*|.*.*\sam.*|.*.*\ntds\.dit.*|.*.*\security.*)))'
```



