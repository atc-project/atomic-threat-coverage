| Title              | DN_0059_4657_registry_value_was_modified       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | This event generates when a registry key value was modified. It doesn't generate  when a registry key was modified. This event generates only if "Set Value" auditing  is set in registry key’s SACL |
| **Logging Policy** | <ul><li>[LP0103_windows_audit_registry](../Logging_Policies/LP0103_windows_audit_registry.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4657.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4657.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>ObjectName</li><li>ObjectValueName</li><li>HandleId</li><li>OperationType</li><li>OldValueType</li><li>OldValue</li><li>NewValueType</li><li>NewValue</li><li>ProcessId</li><li>ProcessName</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4657</EventID> 
    <Version>0</Version> 
    <Level>0</Level> 
    <Task>12801</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2015-09-24T01:28:43.639634100Z" /> 
    <EventRecordID>744725</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="4" ThreadID="4824" /> 
    <Channel>Security</Channel> 
    <Computer>DC01.contoso.local</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data> 
    <Data Name="SubjectUserName">dadmin</Data> 
    <Data Name="SubjectDomainName">CONTOSO</Data> 
    <Data Name="SubjectLogonId">0x364eb</Data> 
    <Data Name="ObjectName">\\REGISTRY\\MACHINE</Data> 
    <Data Name="ObjectValueName">Name\_New</Data> 
    <Data Name="HandleId">0x54</Data> 
    <Data Name="OperationType">%%1905</Data> 
    <Data Name="OldValueType">%%1873</Data> 
    <Data Name="OldValue" /> 
    <Data Name="NewValueType">%%1873</Data> 
    <Data Name="NewValue">Andrei</Data> 
    <Data Name="ProcessId">0xce4</Data> 
    <Data Name="ProcessName">C:\\Windows\\regedit.exe</Data> 
  </EventData>
</Event>

```




