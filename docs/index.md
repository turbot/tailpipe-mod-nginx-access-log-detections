# Nginx Access Log Detections Mod

[Tailpipe](https://tailpipe.io) is an open-source CLI tool that allows you to collect logs and query them with SQL.

The [Nginx Access Log Detections Mod](https://hub.powerpipe.io/mods/turbot/tailpipe-mod-nginx-access-log-detections) contains pre-built dashboards and detections, which can be used to monitor and analyze activity across your Nginx servers.

<img src="https://raw.githubusercontent.com/turbot/tailpipe-mod-nginx-access-log-detections/main/docs/images/nginx_access_log_activity_dashboard.png" width="50%" type="thumbnail"/>
<img src="https://raw.githubusercontent.com/turbot/tailpipe-mod-nginx-access-log-detections/main/docs/images/nginx_access_log_detection_dashboard.png" width="50%" type="thumbnail"/>

## Documentation

- **[Dashboards →](https://hub.powerpipe.io/mods/turbot/tailpipe-mod-nginx-access-log-detections/dashboards)**
- **[Benchmarks and detections →](https://hub.powerpipe.io/mods/turbot/tailpipe-mod-nginx-access-log-detections/benchmarks)**

## Getting Started

Install Powerpipe from the [downloads](https://powerpipe.io/downloads) page:

```sh
# MacOS
brew install turbot/tap/powerpipe
```

```sh
# Linux or Windows (WSL)
sudo /bin/sh -c "$(curl -fsSL https://powerpipe.io/install/powerpipe.sh)"
```

This mod also requires Nginx access logs to be collected using [Tailpipe](https://tailpipe.io) with the [Nginx plugin](https://hub.tailpipe.io/plugins/turbot/nginx):
- [Get started with the Nginx plugin for Tailpipe →](https://hub.tailpipe.io/plugins/turbot/nginx#getting-started)

Install the mod:

```sh
mkdir dashboards
cd dashboards
powerpipe mod install github.com/turbot/tailpipe-mod-nginx-access-log-detections
```

### Browsing Dashboards

Start the dashboard server:

```sh
powerpipe server
```

Browse and view your dashboards at **http://localhost:9033**.

### Running Benchmarks in Your Terminal

Instead of running benchmarks in a dashboard, you can also run them within your
terminal with the `powerpipe benchmark` command:

List available benchmarks:

```sh
powerpipe benchmark list
```

Run a benchmark:

```sh
powerpipe benchmark run nginx_access_log_detections.benchmark.access_log_detections
```

Different output formats are also available, for more information please see
[Output Formats](https://powerpipe.io/docs/reference/cli/benchmark#output-formats).