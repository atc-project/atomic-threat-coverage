| Title              | DN_0043_770_dns_server_plugin_dll_has_been_loaded       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Windows DNS server plug-in DLL has been loaded |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html](https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | DNS Server     |
| **Provider**       | Microsoft-Windows-DNS-Server-Service    |
| **Fields**         | <ul><li>EventID</li><li>Hostname</li><li>Computer</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-DNS-Server-Service" Guid="{71A551F5-C893-4849-886B-B5EC8502641E}" /> 
    <EventID>770</EventID> 
    <Version>0</Version> 
    <Level>4</Level> 
    <Task>0</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8000000000008000</Keywords> 
    <TimeCreated SystemTime="2017-05-09T08:54:26.798142300Z" /> 
    <EventRecordID>264</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="2312" ThreadID="3068" /> 
    <Channel>DNS Server</Channel> 
    <Computer>dc1.lab.internal</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  - <EventData Name="DNS_EVENT_PLUGIN_DLL_LOAD_OK">
    <Data Name="param1">\\192.168.0.149\dll\wtf.dll</Data> 
    <Data Name="param2">dc1.lab.internal</Data> 
  </EventData>
</Event>

```




