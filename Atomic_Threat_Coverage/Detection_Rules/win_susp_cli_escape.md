| Title                | Suspicious Commandline Escape                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious process that use escape characters                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1140: Deobfuscate/Decode Files or Information](../Triggers/T1140.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/vysecurity/status/885545634958385153](https://twitter.com/vysecurity/status/885545634958385153)</li><li>[https://twitter.com/Hexacorn/status/885553465417756673](https://twitter.com/Hexacorn/status/885553465417756673)</li><li>[https://twitter.com/Hexacorn/status/885570278637678592](https://twitter.com/Hexacorn/status/885570278637678592)</li><li>[https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html](https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html)</li><li>[http://www.windowsinspired.com/understanding-the-command-line-string-and-arguments-received-by-a-windows-program/](http://www.windowsinspired.com/understanding-the-command-line-string-and-arguments-received-by-a-windows-program/)</li></ul>  |
| Author               | juju4 |


## Detection Rules

### Sigma rule

```
title: Suspicious Commandline Escape
id: f0cdd048-82dc-4f7a-8a7a-b87a52b6d0fd
description: Detects suspicious process that use escape characters
status: experimental
references:
    - https://twitter.com/vysecurity/status/885545634958385153
    - https://twitter.com/Hexacorn/status/885553465417756673
    - https://twitter.com/Hexacorn/status/885570278637678592
    - https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html
    - http://www.windowsinspired.com/understanding-the-command-line-string-and-arguments-received-by-a-windows-program/
author: juju4
modified: 2018/12/11
tags:
    - attack.defense_evasion
    - attack.t1140
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            # - <TAB>   # no TAB modifier in sigmac yet, so this matches <TAB> (or TAB in elasticsearch backends without DSL queries)
            - ^h^t^t^p
            - h"t"t"p
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: low

```





### splunk
    
```
(CommandLine="^h^t^t^p" OR CommandLine="h\\"t\\"t\\"p")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious Commandline Escape]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious Commandline Escape status: experimental \
description: Detects suspicious process that use escape characters \
references: ['https://twitter.com/vysecurity/status/885545634958385153', 'https://twitter.com/Hexacorn/status/885553465417756673', 'https://twitter.com/Hexacorn/status/885570278637678592', 'https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html', 'http://www.windowsinspired.com/understanding-the-command-line-string-and-arguments-received-by-a-windows-program/'] \
tags: ['attack.defense_evasion', 'attack.t1140'] \
author: juju4 \
date:  \
falsepositives: ['False positives depend on scripts and administrative tools used in the monitored environment'] \
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
description = Detects suspicious process that use escape characters
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="^h^t^t^p" OR CommandLine="h\"t\"t\"p") | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_Commandline_Escape_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1140,level=low"
```
