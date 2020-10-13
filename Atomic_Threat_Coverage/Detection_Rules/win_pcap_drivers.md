| Title                    | Windows Pcap Drivers       |
|:-------------------------|:------------------|
| **Description**          | Detects Windows Pcap driver installation based on a list of associated .sys files. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1040: Network Sniffing](../Triggers/T1040.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://ragged-lab.blogspot.com/2020/06/capturing-pcap-driver-installations.html#more](https://ragged-lab.blogspot.com/2020/06/capturing-pcap-driver-installations.html#more)</li></ul>  |
| **Author**               | Cian Heasley |


## Detection Rules

### Sigma rule

```
title: Windows Pcap Drivers
id: 7b687634-ab20-11ea-bb37-0242ac130002
status: experimental
description: Detects Windows Pcap driver installation based on a list of associated .sys files.
author: Cian Heasley
date: 2020/06/10
references:
    - https://ragged-lab.blogspot.com/2020/06/capturing-pcap-driver-installations.html#more
tags:
    - attack.discovery
    - attack.credential_access
    - attack.t1040
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 4697
        ServiceFileName:
          - '*pcap*'
          - '*npcap*'
          - '*npf*'
          - '*nm3*'
          - '*ndiscap*'
          - '*nmnt*'
          - '*windivert*'
          - '*USBPcap*'
          - '*pktmon*'
    condition: selection
fields:
    - EventID
    - ServiceFileName
    - Account_Name
    - Computer_Name
    - Originating_Computer
    - ServiceName
falsepositives:
    - unknown
level: medium

```





### powershell
    
```
Get-WinEvent -LogName System | where {($_.ID -eq "4697" -and ($_.message -match "ServiceFileName.*.*pcap.*" -or $_.message -match "ServiceFileName.*.*npcap.*" -or $_.message -match "ServiceFileName.*.*npf.*" -or $_.message -match "ServiceFileName.*.*nm3.*" -or $_.message -match "ServiceFileName.*.*ndiscap.*" -or $_.message -match "ServiceFileName.*.*nmnt.*" -or $_.message -match "ServiceFileName.*.*windivert.*" -or $_.message -match "ServiceFileName.*.*USBPcap.*" -or $_.message -match "ServiceFileName.*.*pktmon.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"4697" AND winlog.event_data.ServiceFileName.keyword:(*pcap* OR *npcap* OR *npf* OR *nm3* OR *ndiscap* OR *nmnt* OR *windivert* OR *USBPcap* OR *pktmon*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/7b687634-ab20-11ea-bb37-0242ac130002 <<EOF
{
  "metadata": {
    "title": "Windows Pcap Drivers",
    "description": "Detects Windows Pcap driver installation based on a list of associated .sys files.",
    "tags": [
      "attack.discovery",
      "attack.credential_access",
      "attack.t1040"
    ],
    "query": "(winlog.event_id:\"4697\" AND winlog.event_data.ServiceFileName.keyword:(*pcap* OR *npcap* OR *npf* OR *nm3* OR *ndiscap* OR *nmnt* OR *windivert* OR *USBPcap* OR *pktmon*))"
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
                    "query": "(winlog.event_id:\"4697\" AND winlog.event_data.ServiceFileName.keyword:(*pcap* OR *npcap* OR *npf* OR *nm3* OR *ndiscap* OR *nmnt* OR *windivert* OR *USBPcap* OR *pktmon*))",
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
        "subject": "Sigma Rule 'Windows Pcap Drivers'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n             EventID = {{_source.EventID}}\n     ServiceFileName = {{_source.ServiceFileName}}\n        Account_Name = {{_source.Account_Name}}\n       Computer_Name = {{_source.Computer_Name}}\nOriginating_Computer = {{_source.Originating_Computer}}\n         ServiceName = {{_source.ServiceName}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(EventID:"4697" AND ServiceFileName.keyword:(*pcap* *npcap* *npf* *nm3* *ndiscap* *nmnt* *windivert* *USBPcap* *pktmon*))
```


### splunk
    
```
(source="WinEventLog:System" EventCode="4697" (ServiceFileName="*pcap*" OR ServiceFileName="*npcap*" OR ServiceFileName="*npf*" OR ServiceFileName="*nm3*" OR ServiceFileName="*ndiscap*" OR ServiceFileName="*nmnt*" OR ServiceFileName="*windivert*" OR ServiceFileName="*USBPcap*" OR ServiceFileName="*pktmon*")) | table EventCode,ServiceFileName,Account_Name,Computer_Name,Originating_Computer,ServiceName
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4697" ServiceFileName IN ["*pcap*", "*npcap*", "*npf*", "*nm3*", "*ndiscap*", "*nmnt*", "*windivert*", "*USBPcap*", "*pktmon*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*4697)(?=.*(?:.*.*pcap.*|.*.*npcap.*|.*.*npf.*|.*.*nm3.*|.*.*ndiscap.*|.*.*nmnt.*|.*.*windivert.*|.*.*USBPcap.*|.*.*pktmon.*)))'
```



