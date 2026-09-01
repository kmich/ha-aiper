# Automation Examples

Below are a few safe, copy-paste automation examples for your Aiper devices.

*(Note: Replace `sensor.scuba_x1_status` with your actual entity IDs).*

## 1. Notification When Cleaning Finishes

```yaml
alias: "Pool: Notify when Aiper finishes cleaning"
trigger:
  - platform: state
    entity_id: sensor.scuba_x1_status
    to: "Idle"
    from: "Running"
action:
  - service: notify.notify
    data:
      title: "Pool Cleaner Finished"
      message: "The Aiper has finished its cleaning cycle and is now idle."
```

## 2. Low Battery Alert

```yaml
alias: "Pool: Aiper Low Battery"
trigger:
  - platform: numeric_state
    entity_id: sensor.scuba_x1_battery
    below: 15
condition:
  - condition: state
    entity_id: binary_sensor.scuba_x1_charging
    state: "off"
action:
  - service: notify.notify
    data:
      title: "Aiper Battery Low"
      message: "Your pool robot is at {{ states('sensor.scuba_x1_battery') }}%. Please charge it."
```

## 3. Water Quality Alert (HydroComm)

```yaml
alias: "Pool: Water Quality Warning"
trigger:
  - platform: numeric_state
    entity_id: sensor.hydrocomm_ph
    above: 7.8
  - platform: numeric_state
    entity_id: sensor.hydrocomm_ph
    below: 7.0
  - platform: numeric_state
    entity_id: sensor.hydrocomm_free_chlorine
    below: 1.0
action:
  - service: notify.notify
    data:
      title: "Pool Chemistry Alert!"
      message: >
        Check the pool! 
        pH is {{ states('sensor.hydrocomm_ph') }}
        Chlorine is {{ states('sensor.hydrocomm_free_chlorine') }} mg/L.
```

## 4. Maintenance Reminder (Filter / Brush)

```yaml
alias: "Pool: Maintenance Reminder"
trigger:
  - platform: numeric_state
    entity_id: sensor.scuba_x1_micromesh_filter
    below: 10
action:
  - service: notify.notify
    data:
      title: "Aiper Maintenance Needed"
      message: "The filter life is below 10%. Time to clean or replace it."
```

## 5. Alert When the Cloud Connection Drops

Uses the "Aiper Cloud" device added in v1.4.0. The `for:` delay avoids paging
you for a brief reconnect.

```yaml
alias: "Pool: Aiper cloud link down"
trigger:
  - platform: state
    entity_id: binary_sensor.aiper_cloud_cloud_connected
    to: "off"
    for:
      minutes: 15
action:
  - service: notify.notify
    data:
      title: "Aiper cloud connection lost"
      message: >
        Home Assistant hasn't had an Aiper cloud connection for 15 minutes.
        State: {{ states('sensor.aiper_cloud_connection_state') }}.
        Last update: {{ states('sensor.aiper_cloud_last_cloud_update') }}.
```
