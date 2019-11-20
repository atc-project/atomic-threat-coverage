| Title                | USB Device Plugged                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects plugged USB devices                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0001: Initial Access](https://attack.mitre.org/tactics/TA0001)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1200: Hardware Additions](https://attack.mitre.org/techniques/T1200)</li></ul>  |
| Data Needed          | <ul><li>[DN_0054_2102_pnp_or_power_operation_for_usb_device](../Data_Needed/DN_0054_2102_pnp_or_power_operation_for_usb_device.md)</li><li>[DN_0053_2100_pnp_or_power_operation_for_usb_device](../Data_Needed/DN_0053_2100_pnp_or_power_operation_for_usb_device.md)</li><li>[DN_0052_2003_query_to_load_usb_drivers](../Data_Needed/DN_0052_2003_query_to_load_usb_drivers.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1200: Hardware Additions](../Triggers/T1200.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Legitimate administrative activity</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://df-stream.com/2014/01/the-windows-7-event-log-and-usb-device/](https://df-stream.com/2014/01/the-windows-7-event-log-and-usb-device/)</li><li>[https://www.techrepublic.com/article/how-to-track-down-usb-flash-drive-usage-in-windows-10s-event-viewer/](https://www.techrepublic.com/article/how-to-track-down-usb-flash-drive-usage-in-windows-10s-event-viewer/)</li></ul>  |
| Author               | Florian Roth |


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





### splunk
    
```
(EventID="2003" OR EventID="2100" OR EventID="2102")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[USB Device Plugged]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: USB Device Plugged status: experimental \
description: Detects plugged USB devices \
references: ['https://df-stream.com/2014/01/the-windows-7-event-log-and-usb-device/', 'https://www.techrepublic.com/article/how-to-track-down-usb-flash-drive-usage-in-windows-10s-event-viewer/'] \
tags: ['attack.initial_access', 'attack.t1200'] \
author: Florian Roth \
date:  \
falsepositives: ['Legitimate administrative activity'] \
level: low
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects plugged USB devices
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="2003" OR EventID="2100" OR EventID="2102") | stats values(*) AS * by _time | search NOT [| inputlookup USB_Device_Plugged_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.initial_access,sigma_tag=attack.t1200,level=low"
```
