locals {
  nginx_performance_common_tags = merge(local.nginx_access_log_detections_common_tags, {
    category = "Performance"
  })
}

benchmark "nginx_performance_detections" {
  title       = "Nginx Performance Detections"
  description = "This benchmark contains performance-focused detections when scanning Nginx access logs."
  type        = "detection"
  children = [
    detection.nginx_slow_response_time,
    detection.nginx_response_time_anomalies,
    detection.nginx_upstream_latency,
    detection.nginx_request_queue_size,
    detection.nginx_memory_leak_detection,
    detection.nginx_connection_pool_exhaustion,
    detection.nginx_ddos_early_warning
  ]

  tags = merge(local.nginx_performance_common_tags, {
    type = "Benchmark"
  })
}

detection "nginx_slow_response_time" {
  title           = "Slow Response Time Detected"
  description     = "Detect endpoints with consistently high response times exceeding threshold."
  severity        = "high"
  display_columns = ["endpoint", "avg_response_time", "request_count", "p95_response_time"]

  query = query.nginx_slow_response_time

  tags = merge(local.nginx_performance_common_tags, {
    mitre_attack_ids = "TA0040:T1499.004" // Impact: Application or System Exploitation
  })
}

query "nginx_slow_response_time" {
  sql = <<-EOQ
    with response_stats as (
      select
        request_uri as endpoint,
        count(*) as request_count,
        avg(request_time) as avg_response_time,
        percentile_cont(0.95) within group (order by request_time) as p95_response_time
      from
        nginx_access_log
      group by
        request_uri
      having
        count(*) >= 10  -- Minimum request threshold
    )
    select
      endpoint,
      round(avg_response_time::numeric, 3) as avg_response_time,
      request_count,
      round(p95_response_time::numeric, 3) as p95_response_time
    from
      response_stats
    where
      avg_response_time > 2  -- 2 second threshold
      or p95_response_time > 5  -- 5 second p95 threshold
    order by
      avg_response_time desc;
  EOQ
}

detection "nginx_response_time_anomalies" {
  title           = "Response Time Anomalies Detected"
  description     = "Detect sudden increases in response time compared to historical patterns."
  severity        = "high"
  display_columns = ["window_start", "window_end", "avg_response_time", "historical_avg", "deviation_percent"]

  query = query.nginx_response_time_anomalies

  tags = merge(local.nginx_performance_common_tags, {
    mitre_attack_ids = "TA0040:T1499.003" // Impact: Application Exhaustion Flood
  })
}

query "nginx_response_time_anomalies" {
  sql = <<-EOQ
    with time_windows as (
      select
        time_bucket('5 minutes', tp_timestamp) as window_start,
        time_bucket('5 minutes', tp_timestamp) + interval '5 minutes' as window_end,
        avg(request_time) as avg_response_time,
        avg(avg(request_time)) over (
          order by time_bucket('5 minutes', tp_timestamp)
          rows between 12 preceding and 1 preceding
        ) as historical_avg
      from
        nginx_access_log
      group by
        time_bucket('5 minutes', tp_timestamp)
    )
    select
      window_start,
      window_end,
      round(avg_response_time::numeric, 3) as avg_response_time,
      round(historical_avg::numeric, 3) as historical_avg,
      round(((avg_response_time - historical_avg) / historical_avg * 100)::numeric, 2) as deviation_percent
    from
      time_windows
    where
      historical_avg > 0
      and ((avg_response_time - historical_avg) / historical_avg) > 1  -- 100% increase threshold
    order by
      window_start desc;
  EOQ
}

detection "nginx_upstream_latency" {
  title           = "High Upstream Server Latency"
  description     = "Detect high latency from upstream servers when Nginx is used as a reverse proxy."
  severity        = "medium"
  display_columns = ["upstream", "avg_upstream_time", "request_count", "max_upstream_time"]

  query = query.nginx_upstream_latency

  tags = merge(local.nginx_performance_common_tags, {
    mitre_attack_ids = "TA0040:T1499.004" // Impact: Application or System Exploitation
  })
}

query "nginx_upstream_latency" {
  sql = <<-EOQ
    select
      upstream_addr as upstream,
      round(avg(upstream_response_time)::numeric, 3) as avg_upstream_time,
      count(*) as request_count,
      round(max(upstream_response_time)::numeric, 3) as max_upstream_time
    from
      nginx_access_log
    where
      upstream_addr is not null
    group by
      upstream_addr
    having
      avg(upstream_response_time) > 1  -- 1 second threshold
    order by
      avg_upstream_time desc;
  EOQ
}

detection "nginx_request_queue_size" {
  title           = "High Request Queue Size"
  description     = "Detect when the request queue size becomes too large, indicating potential capacity issues."
  severity        = "high"
  display_columns = ["window_start", "window_end", "queue_size", "request_count"]

  query = query.nginx_request_queue_size

  tags = merge(local.nginx_performance_common_tags, {
    mitre_attack_ids = "TA0040:T1499.002" // Impact: Service Exhaustion Flood
  })
}

query "nginx_request_queue_size" {
  sql = <<-EOQ
    with queue_windows as (
      select
        time_bucket('1 minute', tp_timestamp) as window_start,
        time_bucket('1 minute', tp_timestamp) + interval '1 minute' as window_end,
        count(*) filter (where request_time > 0.1) as queue_size,  -- Requests taking longer than 100ms
        count(*) as request_count
      from
        nginx_access_log
      group by
        time_bucket('1 minute', tp_timestamp)
    )
    select
      window_start,
      window_end,
      queue_size,
      request_count
    from
      queue_windows
    where
      queue_size >= 100  -- Queue size threshold
    order by
      window_start desc;
  EOQ
}

detection "nginx_memory_leak_detection" {
  title           = "Potential Memory Leak Detection"
  description     = "Detect patterns indicating potential memory leaks through response size analysis"
  severity        = "critical"
  display_columns = ["endpoint", "avg_response_size", "growth_rate", "window_start"]

  query = query.nginx_memory_leak_detection

  tags = merge(local.nginx_performance_common_tags, {
    mitre_attack_ids = "TA0040:T1499.004" // Impact: Application or System Exploitation
  })
}

query "nginx_memory_leak_detection" {
  sql = <<-EOQ
    with response_trends as (
      select
        request_uri as endpoint,
        time_bucket('1 hour', tp_timestamp) as window_start,
        avg(bytes_sent) as avg_response_size,
        (avg(bytes_sent) - lag(avg(bytes_sent)) over (
          partition by request_uri
          order by time_bucket('1 hour', tp_timestamp)
        )) / nullif(lag(avg(bytes_sent)) over (
          partition by request_uri
          order by time_bucket('1 hour', tp_timestamp)
        ), 0) * 100 as growth_rate
      from
        nginx_access_log
      group by
        request_uri,
        time_bucket('1 hour', tp_timestamp)
    )
    select
      endpoint,
      round(avg_response_size::numeric, 2) as avg_response_size,
      round(growth_rate::numeric, 2) as growth_rate,
      window_start
    from
      response_trends
    where
      growth_rate > 50
      and avg_response_size > 1048576
    order by
      growth_rate desc;
  EOQ
}

detection "nginx_connection_pool_exhaustion" {
  title           = "Connection Pool Exhaustion Risk"
  description     = "Detect risk of connection pool exhaustion based on concurrent connections"
  severity        = "critical"
  display_columns = ["timestamp", "concurrent_connections", "rejection_rate"]

  query = query.nginx_connection_pool_exhaustion

  tags = merge(local.nginx_performance_common_tags, {
    mitre_attack_ids = "TA0040:T1499.002" // Impact: Service Exhaustion Flood
  })
}

query "nginx_connection_pool_exhaustion" {
  sql = <<-EOQ
    with connection_stats as (
      select
        time_bucket('1 minute', tp_timestamp) as timestamp,
        count(*) as concurrent_connections,
        count(*) filter (where status = 503) / nullif(count(*), 0)::float * 100 as rejection_rate
      from
        nginx_access_log
      group by
        time_bucket('1 minute', tp_timestamp)
    )
    select
      timestamp,
      concurrent_connections,
      round(rejection_rate::numeric, 2) as rejection_rate
    from
      connection_stats
    where
      concurrent_connections > 1000
      or rejection_rate > 5
    order by
      timestamp desc;
  EOQ
}

detection "nginx_ddos_early_warning" {
  title           = "DDoS Attack Early Warning"
  description     = "Detect early signs of DDoS attacks through traffic pattern analysis"
  severity        = "critical"
  display_columns = ["window_start", "request_rate", "unique_ips", "avg_response_time"]

  query = query.nginx_ddos_early_warning

  tags = merge(local.nginx_performance_common_tags, {
    mitre_attack_ids = "TA0040:T1498,TA0040:T1499.002" // Impact: Network Denial of Service, Service Exhaustion Flood
  })
}

query "nginx_ddos_early_warning" {
  sql = <<-EOQ
    with traffic_patterns as (
      select
        time_bucket('30 seconds', tp_timestamp) as window_start,
        count(*) / 30.0 as request_rate,
        count(distinct remote_addr) as unique_ips,
        avg(request_time) as avg_response_time,
        stddev(request_time) as response_time_stddev
      from
        nginx_access_log
      group by
        time_bucket('30 seconds', tp_timestamp)
    )
    select
      window_start,
      round(request_rate::numeric, 2) as request_rate,
      unique_ips,
      round(avg_response_time::numeric, 3) as avg_response_time
    from
      traffic_patterns
    where
      request_rate > 1000
      or (unique_ips > 500 and avg_response_time > 2)
    order by
      window_start desc;
  EOQ
}
