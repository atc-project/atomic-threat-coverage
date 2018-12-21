| Title          | DN_0004_windows_account_logon_4624                                                                                                      |
|:---------------|:-----------------------------------------------------------------------------------------------------------------|
| Description    | An account was successfully logged on.                                                                                                |
| Logging Policy | <ul><li>[LP_0004_windows_audit_logon](../Logging_Policies/LP_0004_windows_audit_logon.md)</li></ul> |
| References     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-4688.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-4688.md)</li></ul>                                  |
| Platform       | Windows    																																															  |
| Type           | Windows Log        																																															  |
| Channel        | Security     																																															  |
| Provider       | Microsoft-Windows-Security-Auditing    																																															  |
| Fields         | <ul><li>EventID</li><li>AccountName</li><li>Hostname</li><li>Computer</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>TargetUserSid</li><li>TargetUserName</li><li>TargetDomainName</li><li>TargetLogonId</li><li>LogonType</li><li>LogonProcessName</li><li>AuthenticationPackageName</li><li>WorkstationName</li><li>LogonGuid</li><li>TransmittedServices</li><li>LmPackageName</li><li>KeyLength</li><li>ProcessId</li><li>ProcessName</li><li>IpAddress</li><li>IpPort</li><li>ImpersonationLevel</li><li>RestrictedAdminMode</li><li>TargetOutboundUserName</li><li>TargetOutboundDomainName</li><li>VirtualAccount</li><li>TargetLinkedLogonId</li><li>ElevatedToken</li></ul>                                               |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4624</EventID> 
    <Version>2</Version> 
    <Level>0</Level> 
    <Task>12544</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2015-11-12T00:24:35.079785200Z" /> 
    <EventRecordID>211</EventRecordID> 
    <Correlation ActivityID="{00D66690-1CDF-0000-AC66-D600DF1CD101}" /> 
    <Execution ProcessID="716" ThreadID="760" /> 
    <Channel>Security</Channel> 
    <Computer>WIN-GG82ULGC9GO</Computer> 
    <Security /> 
    </System>
  - <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data> 
    <Data Name="SubjectUserName">WIN-GG82ULGC9GO$</Data> 
    <Data Name="SubjectDomainName">WORKGROUP</Data> 
    <Data Name="SubjectLogonId">0x3e7</Data> 
    <Data Name="TargetUserSid">S-1-5-21-1377283216-344919071-3415362939-500</Data> 
    <Data Name="TargetUserName">Administrator</Data> 
    <Data Name="TargetDomainName">WIN-GG82ULGC9GO</Data> 
    <Data Name="TargetLogonId">0x8dcdc</Data> 
    <Data Name="LogonType">2</Data> 
    <Data Name="LogonProcessName">User32</Data> 
    <Data Name="AuthenticationPackageName">Negotiate</Data> 
    <Data Name="WorkstationName">WIN-GG82ULGC9GO</Data> 
    <Data Name="LogonGuid">{00000000-0000-0000-0000-000000000000}</Data> 
    <Data Name="TransmittedServices">-</Data> 
    <Data Name="LmPackageName">-</Data> 
    <Data Name="KeyLength">0</Data> 
    <Data Name="ProcessId">0x44c</Data> 
    <Data Name="ProcessName">C:\\Windows\\System32\\svchost.exe</Data> 
    <Data Name="IpAddress">127.0.0.1</Data> 
    <Data Name="IpPort">0</Data> 
    <Data Name="ImpersonationLevel">%%1833</Data> 
    <Data Name="RestrictedAdminMode">-</Data> 
    <Data Name="TargetOutboundUserName">-</Data> 
    <Data Name="TargetOutboundDomainName">-</Data> 
    <Data Name="VirtualAccount">%%1843</Data> 
    <Data Name="TargetLinkedLogonId">0x0</Data> 
    <Data Name="ElevatedToken">%%1842</Data> 
    </EventData>
 </Event>

```




