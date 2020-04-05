| Title              | DN_0052_2003_query_to_load_usb_drivers       |
|:-------------------|:------------------|
| **Description**    | Host Process has been asked to load drivers for USB device |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://www.techrepublic.com/article/how-to-track-down-usb-flash-drive-usage-in-windows-10s-event-viewer/](https://www.techrepublic.com/article/how-to-track-down-usb-flash-drive-usage-in-windows-10s-event-viewer/)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-DriverFrameworks-UserMode/Operational     |
| **Provider**       | Microsoft-Windows-DriverFrameworks-UserMode    |
| **Fields**         | <ul><li>EventID</li><li>ComputerName</li><li>Computer</li><li>UMDFHostDeviceArrivalBegin</li><li>lifetime</li><li>instance</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-DriverFrameworks-UserMode" Guid="{2E35AAEB-857F-4BEB-A418-2E6C0E54D988}" />
    <EventID>2003</EventID>
    <Version>1</Version>
    <Level>4</Level>
    <Task>33</Task>
    <Opcode>1</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2017-07-22T21:01:03.421562800Z" />
    <EventRecordID>65</EventRecordID>
    <Correlation />
    <Execution ProcessID="5420" ThreadID="4108" />
    <Channel>Microsoft-Windows-DriverFrameworks-UserMode/Operational</Channel>
    <Computer>ALPHA</Computer>
    <Security UserID="S-1-5-19" />
  </System>
    - <UserData>
      - <UMDFHostDeviceArrivalBegin instance="SWD\WPDBUSENUM\_??_USBSTOR#DISK&amp;VEN_LEXAR&amp;PROD_DIGITAL_FILM&amp;REV_#W1.#______________0302080000002D74AE7900000000000&amp;0#{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}" lifetime="{5B5CB3FD-BDA8-42E0-8DCD-50A1FD1FA199}" xmlns="http://www.microsoft.com/DriverFrameworks/UserMode/Event">
      </UMDFHostDeviceArrivalBegin>
    </UserData>
</Event>

```




