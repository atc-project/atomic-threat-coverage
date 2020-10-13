| Title              | DN_0063_4697_service_was_installed_in_the_system       |
|:-------------------|:------------------|
| **Description**    | A service was installed in the system |
| **Logging Policy** | <ul><li>[LP_0100_windows_audit_security_system_extension](../Logging_Policies/LP_0100_windows_audit_security_system_extension.md)</li></ul> |
| **References**     | <ul><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>ServiceName</li><li>ServiceFileName</li><li>ServiceType</li><li>ServiceStartType</li><li>ServiceAccount</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
     <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
     <EventID>4697</EventID> 
     <Version>0</Version> 
     <Level>0</Level> 
     <Task>12289</Task> 
     <Opcode>0</Opcode> 
     <Keywords>0x8020000000000000</Keywords> 
     <TimeCreated SystemTime="2015-11-12T01:36:11.991070500Z" /> 
     <EventRecordID>2778</EventRecordID> 
     <Correlation ActivityID="{913FBE70-1CE6-0000-67BF-3F91E61CD101}" /> 
     <Execution ProcessID="736" ThreadID="2800" /> 
     <Channel>Security</Channel> 
     <Computer>atc-win-10.atc.local</Computer> 
     <Security /> 
   </System>
  - <EventData>
     <Data Name="SubjectUserSid">S-1-5-18</Data> 
     <Data Name="SubjectUserName">atc-win-10$</Data> 
     <Data Name="SubjectDomainName">CONTOSO</Data> 
     <Data Name="SubjectLogonId">0x3e7</Data> 
     <Data Name="ServiceName">AppHostSvc</Data> 
     <Data Name="ServiceFileName">%windir%\\system32\\svchost.exe -k apphost</Data> 
     <Data Name="ServiceType">0x20</Data> 
     <Data Name="ServiceStartType">2</Data> 
     <Data Name="ServiceAccount">localSystem</Data> 
   </EventData>
</Event>

```




