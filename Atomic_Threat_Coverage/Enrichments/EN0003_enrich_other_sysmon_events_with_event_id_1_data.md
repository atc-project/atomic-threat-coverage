| Title              | EN0003_enrich_other_sysmon_events_with_event_id_1_data |
|:-------------------|:-----------------------------------------------------------------------------------------------------------------|
| **Description**    | Enrich other Sysmon Events with data from Events ID 1 (Process Create)  — Integrity Level, User, Parent Image and CommandLine fields. |
| **Data Needed**    |<ul><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul> |
| **Data to enrich** |<ul><li>[DN0006_2_windows_sysmon_process_changed_a_file_creation_time](../Data_Needed/DN0006_2_windows_sysmon_process_changed_a_file_creation_time.md)</li><li>[DN0007_3_windows_sysmon_network_connection](../Data_Needed/DN0007_3_windows_sysmon_network_connection.md)</li><li>[DN0009_5_windows_sysmon_process_terminated](../Data_Needed/DN0009_5_windows_sysmon_process_terminated.md)</li><li>[DN0011_7_windows_sysmon_image_loaded](../Data_Needed/DN0011_7_windows_sysmon_image_loaded.md)</li><li>[DN0013_9_windows_sysmon_RawAccessRead](../Data_Needed/DN0013_9_windows_sysmon_RawAccessRead.md)</li><li>[DN0015_11_windows_sysmon_FileCreate](../Data_Needed/DN0015_11_windows_sysmon_FileCreate.md)</li><li>[DN0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN0016_12_windows_sysmon_RegistryEvent.md)</li><li>[DN0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN0018_14_windows_sysmon_RegistryEvent](../Data_Needed/DN0018_14_windows_sysmon_RegistryEvent.md)</li><li>[DN0019_15_windows_sysmon_FileCreateStreamHash](../Data_Needed/DN0019_15_windows_sysmon_FileCreateStreamHash.md)</li><li>[DN0020_17_windows_sysmon_PipeEvent](../Data_Needed/DN0020_17_windows_sysmon_PipeEvent.md)</li><li>[DN0021_18_windows_sysmon_PipeEvent](../Data_Needed/DN0021_18_windows_sysmon_PipeEvent.md)</li></ul> |
| **References**     |<ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-privilege-escalation-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)</li></ul> |
| **Author**         | Teymur Kheirkhabarov           |
| **Requirements**   |<ul><li>[EN0001_cache_sysmon_event_id_1_info](../Enrichments/EN0001_cache_sysmon_event_id_1_info.md)</li></ul>> |
| **New fields**     |<ul><li>event_data.IntegrityLevel</li><li>event_data.User</li><li>event_data.CommandLine</li><li>event_data.ParentImage</li><li>IntegrityLevel</li><li>User</li><li>CommandLine</li><li>ParentImage</li></ul> |


### Config

We can use Logstash to enrich other Sysmon Events with data from Sysmon Event ID 1, cached in Memcached. 
Here is the config example:

```
filter {
  # Add additional information from cache, that is available only in Process Creation event (User, IL...)
  if [source_name] == "Microsoft-Windows-Sysmon" and [event_id] != 1 and [event_data][ProcessGuid] {
    # Enrich event with additional information about process
    memcached {
      # get info from cache
      hosts => ["127.0.0.1:11211"]
      get => {
        "%{computer_name}_%{[event_data][ProcessGuid]}" => "[@metadata][processinfo]"
      }
    }
    if [@metadata][processinfo] {
      kv {
        source => "[@metadata][processinfo]"
        target => "[@metadata][processinfo]"
        field_split => ","
        value_split => "="
      }
      # Enrich event
      if [@metadata][processinfo][IntegrityLevel] {
        mutate {
          add_field => { "[event_data][IntegrityLevel]" => "%{[@metadata][processinfo][IntegrityLevel]}" }
        }
      }
      if [@metadata][processinfo][User] {
        mutate {
          add_field => { "[event_data][User]" => "%{[@metadata][processinfo][User]}" }
        }
      }
      if [@metadata][processinfo][CommandLine] {
        mutate {
          add_field => { "[event_data][CommandLine]" => "%{[@metadata][processinfo][CommandLine]}" }
        }
      }
      if [@metadata][processinfo][ParentImage] {
        mutate {
          add_field => { "[event_data][ParentImage]" => "%{[@metadata][processinfo][ParentImage]}" }
        }
      }
    }
  }
}
```
