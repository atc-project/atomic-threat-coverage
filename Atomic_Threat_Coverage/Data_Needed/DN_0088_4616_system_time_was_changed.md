| Title              | DN_0088_4616_system_time_was_changed       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | The system time was changed |
| **Logging Policy** | <ul><li>[LP0046_windows_audit_security_state_change](../Logging_Policies/LP0046_windows_audit_security_state_change.md)</li></ul> |
| **References**     | <ul><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4616](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4616)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>ComputerName</li><li>Computer</li><li>Hostname</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>PreviousTime</li><li>NewTime</li><li>ProcessId</li><li>ProcessName</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4616</EventID> 
    <Version>1</Version> 
    <Level>0</Level> 
    <Task>12288</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2015-10-09T05:04:29.995794600Z" /> 
    <EventRecordID>1101699</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="4" ThreadID="148" /> 
    <Channel>Security</Channel> 
    <Computer>DC01.contoso.local</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data> 
    <Data Name="SubjectUserName">dadmin</Data> 
    <Data Name="SubjectDomainName">CONTOSO</Data> 
    <Data Name="SubjectLogonId">0x48f29</Data> 
    <Data Name="PreviousTime">2015-10-09T05:04:30.000941900Z</Data> 
    <Data Name="NewTime">2015-10-09T05:04:30.000000000Z</Data> 
    <Data Name="ProcessId">0x1074</Data> 
    <Data Name="ProcessName">C:\\Windows\\WinSxS\\amd64\_microsoft-windows-com-surrogate-core\_31bf3856ad364e35\_6.3.9600.16384\_none\_25a8f00faa8f185c\\dllhost.exe</Data> 
  </EventData>
</Event>

```




