| Title                | WMI Persistence                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious WMI event filter and command line event consumer based on event id 5861 and 5859 (Windows 10, 2012 and higher)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li></ul>  |
| Data Needed          | <ul><li>[DN_0081_5861_wmi_activity](../Data_Needed/DN_0081_5861_wmi_activity.md)</li><li>[DN_0080_5859_wmi_activity](../Data_Needed/DN_0080_5859_wmi_activity.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Unknown (data set is too small; further testing needed)</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/mattifestation/status/899646620148539397](https://twitter.com/mattifestation/status/899646620148539397)</li><li>[https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/](https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: WMI Persistence
id: 0b7889b4-5577-4521-a60a-3376ee7f9f7b
status: experimental
description: Detects suspicious WMI event filter and command line event consumer based on event id 5861 and 5859 (Windows 10, 2012 and higher)
author: Florian Roth
references:
    - https://twitter.com/mattifestation/status/899646620148539397
    - https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
tags:
    - attack.execution
    - attack.persistence
    - attack.t1047
logsource:
    product: windows
    service: wmi
detection:
    selection:
        EventID: 5861
    keywords:
        Message:
            - '*ActiveScriptEventConsumer*'
            - '*CommandLineEventConsumer*'
            - '*CommandLineTemplate*'
        # - 'Binding EventFilter'  # too many false positive with HP Health Driver
    selection2:
        EventID: 5859
    condition: selection and 1 of keywords or selection2
falsepositives:
    - Unknown (data set is too small; further testing needed)
level: medium


```





### splunk
    
```
((EventID="5861" (Message="*ActiveScriptEventConsumer*" OR Message="*CommandLineEventConsumer*" OR Message="*CommandLineTemplate*")) OR EventID="5859")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[WMI Persistence]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: WMI Persistence status: experimental \
description: Detects suspicious WMI event filter and command line event consumer based on event id 5861 and 5859 (Windows 10, 2012 and higher) \
references: ['https://twitter.com/mattifestation/status/899646620148539397', 'https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/'] \
tags: ['attack.execution', 'attack.persistence', 'attack.t1047'] \
author: Florian Roth \
date:  \
falsepositives: ['Unknown (data set is too small; further testing needed)'] \
level: medium
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects suspicious WMI event filter and command line event consumer based on event id 5861 and 5859 (Windows 10, 2012 and higher)
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((EventID="5861" (Message="*ActiveScriptEventConsumer*" OR Message="*CommandLineEventConsumer*" OR Message="*CommandLineTemplate*")) OR EventID="5859") | stats values(*) AS * by _time | search NOT [| inputlookup WMI_Persistence_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.persistence,sigma_tag=attack.t1047,level=medium"
```
