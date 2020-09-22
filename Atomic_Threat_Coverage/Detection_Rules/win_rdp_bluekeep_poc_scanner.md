| Title                    | Scanner PoC for CVE-2019-0708 RDP RCE Vuln       |
|:-------------------------|:------------------|
| **Description**          | Detects the use of a scanner by zerosum0x0 that discovers targets vulnerable to  CVE-2019-0708 RDP RCE aka BlueKeep |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1210: Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0057_4625_account_failed_to_logon](../Data_Needed/DN_0057_4625_account_failed_to_logon.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unlikely</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://twitter.com/AdamTheAnalyst/status/1134394070045003776](https://twitter.com/AdamTheAnalyst/status/1134394070045003776)</li><li>[https://github.com/zerosum0x0/CVE-2019-0708](https://github.com/zerosum0x0/CVE-2019-0708)</li></ul>  |
| **Author**               | Florian Roth (rule), Adam Bradbury (idea) |
| Other Tags           | <ul><li>car.2013-07-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Scanner PoC for CVE-2019-0708 RDP RCE Vuln
id: 8400629e-79a9-4737-b387-5db940ab2367
description: Detects the use of a scanner by zerosum0x0 that discovers targets vulnerable to  CVE-2019-0708 RDP RCE aka BlueKeep
references:
    - https://twitter.com/AdamTheAnalyst/status/1134394070045003776
    - https://github.com/zerosum0x0/CVE-2019-0708
tags:
    - attack.lateral_movement
    - attack.t1210
    - car.2013-07-002
author: Florian Roth (rule), Adam Bradbury (idea)
date: 2019/06/02
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        AccountName: AAAAAAA
    condition: selection
falsepositives:
    - Unlikely
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4625" -and $_.message -match "AccountName.*AAAAAAA") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4625" AND winlog.event_data.AccountName:"AAAAAAA")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/8400629e-79a9-4737-b387-5db940ab2367 <<EOF\n{\n  "metadata": {\n    "title": "Scanner PoC for CVE-2019-0708 RDP RCE Vuln",\n    "description": "Detects the use of a scanner by zerosum0x0 that discovers targets vulnerable to  CVE-2019-0708 RDP RCE aka BlueKeep",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1210",\n      "car.2013-07-002"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"4625\\" AND winlog.event_data.AccountName:\\"AAAAAAA\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"4625\\" AND winlog.event_data.AccountName:\\"AAAAAAA\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Scanner PoC for CVE-2019-0708 RDP RCE Vuln\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4625" AND AccountName:"AAAAAAA")
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4625" AccountName="AAAAAAA")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4625" AccountName="AAAAAAA")
```


### grep
    
```
grep -P '^(?:.*(?=.*4625)(?=.*AAAAAAA))'
```



