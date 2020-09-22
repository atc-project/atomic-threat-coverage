| Title                    | USB Device Plugged       |
|:-------------------------|:------------------|
| **Description**          | Detects plugged USB devices |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0001: Initial Access](https://attack.mitre.org/tactics/TA0001)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1200: Hardware Additions](https://attack.mitre.org/techniques/T1200)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0052_2003_query_to_load_usb_drivers](../Data_Needed/DN_0052_2003_query_to_load_usb_drivers.md)</li><li>[DN_0053_2100_pnp_or_power_operation_for_usb_device](../Data_Needed/DN_0053_2100_pnp_or_power_operation_for_usb_device.md)</li><li>[DN_0054_2102_pnp_or_power_operation_for_usb_device](../Data_Needed/DN_0054_2102_pnp_or_power_operation_for_usb_device.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Legitimate administrative activity</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://df-stream.com/2014/01/the-windows-7-event-log-and-usb-device/](https://df-stream.com/2014/01/the-windows-7-event-log-and-usb-device/)</li><li>[https://www.techrepublic.com/article/how-to-track-down-usb-flash-drive-usage-in-windows-10s-event-viewer/](https://www.techrepublic.com/article/how-to-track-down-usb-flash-drive-usage-in-windows-10s-event-viewer/)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: USB Device Plugged
id: 1a4bd6e3-4c6e-405d-a9a3-53a116e341d4
description: Detects plugged USB devices
references:
    - https://df-stream.com/2014/01/the-windows-7-event-log-and-usb-device/
    - https://www.techrepublic.com/article/how-to-track-down-usb-flash-drive-usage-in-windows-10s-event-viewer/
status: experimental
author: Florian Roth
date: 2017/11/09
tags:
    - attack.initial_access
    - attack.t1200
logsource:
    product: windows
    service: driver-framework
detection:
    selection:
        EventID:
            - 2003  # Loading drivers
            - 2100  # Pnp or power management
            - 2102  # Pnp or power management
    condition: selection
falsepositives:
    - Legitimate administrative activity
level: low

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-DriverFrameworks-UserMode/Operational | where {(($_.ID -eq "2003" -or $_.ID -eq "2100" -or $_.ID -eq "2102")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\\-Windows\\-DriverFrameworks\\-UserMode\\/Operational" AND winlog.event_id:("2003" OR "2100" OR "2102"))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/1a4bd6e3-4c6e-405d-a9a3-53a116e341d4 <<EOF\n{\n  "metadata": {\n    "title": "USB Device Plugged",\n    "description": "Detects plugged USB devices",\n    "tags": [\n      "attack.initial_access",\n      "attack.t1200"\n    ],\n    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-DriverFrameworks\\\\-UserMode\\\\/Operational\\" AND winlog.event_id:(\\"2003\\" OR \\"2100\\" OR \\"2102\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-DriverFrameworks\\\\-UserMode\\\\/Operational\\" AND winlog.event_id:(\\"2003\\" OR \\"2100\\" OR \\"2102\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'USB Device Plugged\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
EventID:("2003" "2100" "2102")
```


### splunk
    
```
(source="Microsoft-Windows-DriverFrameworks-UserMode/Operational" (EventCode="2003" OR EventCode="2100" OR EventCode="2102"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-DriverFrameworks-UserMode/Operational" event_id IN ["2003", "2100", "2102"])
```


### grep
    
```
grep -P '^(?:.*2003|.*2100|.*2102)'
```



