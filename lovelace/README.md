# Aiper dashboard examples

[Example dashboard](example-dashboard.yaml) uses built-in Home Assistant cards
and fits one or two sections per row depending on screen width.

1. Create a dashboard in **Settings → Dashboards**. Open it and select
   **Edit dashboard → Raw configuration editor**.
2. Paste the example YAML. Keep both sections for a mixed account. Keep the
   **Pool cleaner** section for a cleaner-only account or **Water quality**
   for a monitor-only account.
3. Open each Aiper device in **Settings → Devices & services → Aiper**. Copy
   its actual entity IDs into the corresponding YAML fields and Markdown
   templates. The example uses devices named Pool Cleaner and Pool Monitor.

| Display | Entity to select |
| --- | --- |
| Cleaner status, battery, and current run | **Status**, **Battery**, **Current Cleaning Time** |
| Cleaner freshness | **Last Device Report** |
| Last completed run | **Cleaning finished** on supported models, or **Last Cleaning Start** and **Last Cleaning Duration** for reported history |
| Optional cleaner commands | **Cleaning mode**, **Clean path**, **Running** where exposed |
| Optional schedule | **Next Scheduled Clean** where exposed |
| Water quality | **pH**, **ORP**, **Free Chlorine**, **Water Quality Score** |
| Water sample freshness | **Water Sample Time** |

Enable **Water Sample Time** on the monitor if it is disabled. The fallback
history fields can also be enabled from the cleaner's entity list. Remove any
optional control cards your device does not expose if you want them hidden
while editing.

**Last Device Report** uses MQTT device telemetry timestamps. While the
cleaner is submerged, the age increases until another timestamped device
report arrives. **Latest sample** uses the timestamp of the monitor's water
measurement. Either card shows an explicit empty message when it has no timestamp.

[Mushroom example](mushroom-example.yaml) uses the optional Mushroom card set.
