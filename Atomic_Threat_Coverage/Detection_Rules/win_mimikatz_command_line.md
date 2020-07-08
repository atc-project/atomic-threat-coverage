| Title                    | Mimikatz Command Line       |
|:-------------------------|:------------------|
| **Description**          | Detection well-known mimikatz command line arguments |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate Administrator using tool for password recovery</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov, oscd.community |
| Other Tags           | <ul><li>attack.t1003.002</li><li>attack.t1003.004</li><li>attack.t1003.001</li><li>attack.t1003.006</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Mimikatz Command Line
id: a642964e-bead-4bed-8910-1bb4d63e3b4d
description: Detection well-known mimikatz command line arguments
author: Teymur Kheirkhabarov, oscd.community
date: 2019/10/22
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.credential_access
    - attack.t1003
    - attack.t1003.002
    - attack.t1003.004
    - attack.t1003.001
    - attack.t1003.006
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        CommandLine|contains:
            - DumpCreds
            - invoke-mimikatz
    selection_2:
        CommandLine|contains:
            - rpc
            - token
            - crypto
            - dpapi
            - sekurlsa
            - kerberos
            - lsadump
            - privilege
            - process
    selection_3:
        CommandLine|contains:
            - '::'
    condition: selection_1 or selection_2 and selection_3
falsepositives:
    - Legitimate Administrator using tool for password recovery
level: medium
status: experimental

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*DumpCreds.*" -or $_.message -match "CommandLine.*.*invoke-mimikatz.*") -or (($_.message -match "CommandLine.*.*rpc.*" -or $_.message -match "CommandLine.*.*token.*" -or $_.message -match "CommandLine.*.*crypto.*" -or $_.message -match "CommandLine.*.*dpapi.*" -or $_.message -match "CommandLine.*.*sekurlsa.*" -or $_.message -match "CommandLine.*.*kerberos.*" -or $_.message -match "CommandLine.*.*lsadump.*" -or $_.message -match "CommandLine.*.*privilege.*" -or $_.message -match "CommandLine.*.*process.*") -and ($_.message -match "CommandLine.*.*::.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:(*DumpCreds* OR *invoke\-mimikatz*) OR (winlog.event_data.CommandLine.keyword:(*rpc* OR *token* OR *crypto* OR *dpapi* OR *sekurlsa* OR *kerberos* OR *lsadump* OR *privilege* OR *process*) AND winlog.event_data.CommandLine.keyword:(*\:\:*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/a642964e-bead-4bed-8910-1bb4d63e3b4d <<EOF
{
  "metadata": {
    "title": "Mimikatz Command Line",
    "description": "Detection well-known mimikatz command line arguments",
    "tags": [
      "attack.credential_access",
      "attack.t1003",
      "attack.t1003.002",
      "attack.t1003.004",
      "attack.t1003.001",
      "attack.t1003.006"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:(*DumpCreds* OR *invoke\\-mimikatz*) OR (winlog.event_data.CommandLine.keyword:(*rpc* OR *token* OR *crypto* OR *dpapi* OR *sekurlsa* OR *kerberos* OR *lsadump* OR *privilege* OR *process*) AND winlog.event_data.CommandLine.keyword:(*\\:\\:*)))"
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
                    "query": "(winlog.event_data.CommandLine.keyword:(*DumpCreds* OR *invoke\\-mimikatz*) OR (winlog.event_data.CommandLine.keyword:(*rpc* OR *token* OR *crypto* OR *dpapi* OR *sekurlsa* OR *kerberos* OR *lsadump* OR *privilege* OR *process*) AND winlog.event_data.CommandLine.keyword:(*\\:\\:*)))",
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
        "subject": "Sigma Rule 'Mimikatz Command Line'",
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
(CommandLine.keyword:(*DumpCreds* *invoke\-mimikatz*) OR (CommandLine.keyword:(*rpc* *token* *crypto* *dpapi* *sekurlsa* *kerberos* *lsadump* *privilege* *process*) AND CommandLine.keyword:(*\:\:*)))
```


### splunk
    
```
((CommandLine="*DumpCreds*" OR CommandLine="*invoke-mimikatz*") OR ((CommandLine="*rpc*" OR CommandLine="*token*" OR CommandLine="*crypto*" OR CommandLine="*dpapi*" OR CommandLine="*sekurlsa*" OR CommandLine="*kerberos*" OR CommandLine="*lsadump*" OR CommandLine="*privilege*" OR CommandLine="*process*") (CommandLine="*::*")))
```


### logpoint
    
```
(event_id="1" (CommandLine IN ["*DumpCreds*", "*invoke-mimikatz*"] OR (CommandLine IN ["*rpc*", "*token*", "*crypto*", "*dpapi*", "*sekurlsa*", "*kerberos*", "*lsadump*", "*privilege*", "*process*"] CommandLine IN ["*::*"])))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*.*DumpCreds.*|.*.*invoke-mimikatz.*)|.*(?:.*(?=.*(?:.*.*rpc.*|.*.*token.*|.*.*crypto.*|.*.*dpapi.*|.*.*sekurlsa.*|.*.*kerberos.*|.*.*lsadump.*|.*.*privilege.*|.*.*process.*))(?=.*(?:.*.*::.*)))))'
```



