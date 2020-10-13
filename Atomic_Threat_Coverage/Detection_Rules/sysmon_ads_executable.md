| Title                    | Executable in ADS       |
|:-------------------------|:------------------|
| **Description**          | Detects the creation of an ADS data stream that contains an executable (non-empty imphash) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)</li><li>[T1564.004: NTFS File Attributes](https://attack.mitre.org/techniques/T1564/004)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0019_15_windows_sysmon_FileCreateStreamHash](../Data_Needed/DN_0019_15_windows_sysmon_FileCreateStreamHash.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1027: Obfuscated Files or Information](../Triggers/T1027.md)</li><li>[T1564.004: NTFS File Attributes](../Triggers/T1564.004.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/0xrawsec/status/1002478725605273600?s=21](https://twitter.com/0xrawsec/status/1002478725605273600?s=21)</li></ul>  |
| **Author**               | Florian Roth, @0xrawsec |
| Other Tags           | <ul><li>attack.s0139</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Executable in ADS
id: b69888d4-380c-45ce-9cf9-d9ce46e67821
status: experimental
description: Detects the creation of an ADS data stream that contains an executable (non-empty imphash)
references:
    - https://twitter.com/0xrawsec/status/1002478725605273600?s=21
tags:
    - attack.defense_evasion
    - attack.t1027          # an old one
    - attack.s0139
    - attack.t1564.004
author: Florian Roth, @0xrawsec
date: 2018/06/03
modified: 2020/08/26
logsource:
    product: windows
    service: sysmon
    definition: 'Requirements: Sysmon config with Imphash logging activated'
detection:
    selection:
        EventID: 15
    filter1:
        Imphash: '00000000000000000000000000000000'
    filter2:
        Imphash: null
    condition: selection and not 1 of filter*
fields:
    - TargetFilename
    - Image
falsepositives:
    - unknown
level: critical


```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "15" -and  -not (($_.message -match "Imphash.*00000000000000000000000000000000") -or (-not Imphash="*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"15" AND (NOT ((winlog.event_data.Imphash:("00000000000000000000000000000000" OR "00000000000000000000000000000000")) OR (NOT _exists_:winlog.event_data.Imphash))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/b69888d4-380c-45ce-9cf9-d9ce46e67821 <<EOF
{
  "metadata": {
    "title": "Executable in ADS",
    "description": "Detects the creation of an ADS data stream that contains an executable (non-empty imphash)",
    "tags": [
      "attack.defense_evasion",
      "attack.t1027",
      "attack.s0139",
      "attack.t1564.004"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"15\" AND (NOT ((winlog.event_data.Imphash:(\"00000000000000000000000000000000\" OR \"00000000000000000000000000000000\")) OR (NOT _exists_:winlog.event_data.Imphash))))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"15\" AND (NOT ((winlog.event_data.Imphash:(\"00000000000000000000000000000000\" OR \"00000000000000000000000000000000\")) OR (NOT _exists_:winlog.event_data.Imphash))))",
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
        "subject": "Sigma Rule 'Executable in ADS'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nTargetFilename = {{_source.TargetFilename}}\n         Image = {{_source.Image}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(EventID:"15" AND (NOT ((Imphash:("00000000000000000000000000000000" "00000000000000000000000000000000")) OR (NOT _exists_:Imphash))))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="15" NOT ((Imphash="00000000000000000000000000000000") OR (NOT Imphash="*"))) | table TargetFilename,Image
```


### logpoint
    
```
(event_id="15"  -((Imphash="00000000000000000000000000000000") OR (-Imphash=*)))
```


### grep
    
```
grep -P '^(?:.*(?=.*15)(?=.*(?!.*(?:.*(?:.*(?:.*(?=.*00000000000000000000000000000000))|.*(?:.*(?=.*(?!Imphash))))))))'
```



