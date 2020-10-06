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
(winlog.channel:"Microsoft\\-Windows\\-Sysmon\\/Operational" AND winlog.event_id:"15" AND (NOT ((winlog.event_data.Imphash:("00000000000000000000000000000000" OR "00000000000000000000000000000000")) OR (NOT _exists_:winlog.event_data.Imphash))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/b69888d4-380c-45ce-9cf9-d9ce46e67821 <<EOF\n{\n  "metadata": {\n    "title": "Executable in ADS",\n    "description": "Detects the creation of an ADS data stream that contains an executable (non-empty imphash)",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1027",\n      "attack.s0139",\n      "attack.t1564.004"\n    ],\n    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"15\\" AND (NOT ((winlog.event_data.Imphash:(\\"00000000000000000000000000000000\\" OR \\"00000000000000000000000000000000\\")) OR (NOT _exists_:winlog.event_data.Imphash))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"15\\" AND (NOT ((winlog.event_data.Imphash:(\\"00000000000000000000000000000000\\" OR \\"00000000000000000000000000000000\\")) OR (NOT _exists_:winlog.event_data.Imphash))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Executable in ADS\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nTargetFilename = {{_source.TargetFilename}}\\n         Image = {{_source.Image}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
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



