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
    detection.nginx_response_time_exceeded,
    detection.nginx_response_time_anomaly_detected,
    detection.nginx_upstream_latency_increased,
    detection.nginx_request_queue_size_increased,
    detection.nginx_memory_leak_detected,
    detection.nginx_connection_pool_exhausted,
    detection.nginx_ddos_early_warning_detected
  ]

  tags = merge(local.nginx_performance_common_tags, {
    type = "Benchmark"
  })
}

detection "nginx_response_time_exceeded" {
  title           = "Nginx Response Time Exceeded"
  description     = "Detect when response time was exceeded in Nginx logs to check for potential performance bottlenecks, resource constraints, or application inefficiencies that degrade user experience."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.nginx_response_time_exceeded

  tags = merge(local.nginx_performance_common_tags, {
    mitre_attack_ids = "TA0040:T1499.004"
  })
}

query "nginx_response_time_exceeded" {
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

detection "nginx_response_time_anomaly_detected" {
  title           = "Nginx Response Time Anomaly Detected"
  description     = "Detect when response time anomalies were detected in Nginx logs to check for potential application degradation, infrastructure changes, or unusual traffic patterns affecting system performance."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.nginx_response_time_anomaly_detected

  tags = merge(local.nginx_performance_common_tags, {
    mitre_attack_ids = "TA0040:T1499.003"
  })
}

query "nginx_response_time_anomaly_detected" {
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

detection "nginx_upstream_latency_increased" {
  title           = "Nginx Upstream Latency Increased"
  description     = "Detect when upstream server latency was increased in Nginx logs to check for potential backend service issues, network congestion, or resource constraints affecting dependent systems."
  severity        = "medium"
  display_columns = local.detection_display_columns

  query = query.nginx_upstream_latency_increased

  tags = merge(local.nginx_performance_common_tags, {
    mitre_attack_ids = "TA0040:T1499.004"
  })
}

query "nginx_upstream_latency_increased" {
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

detection "nginx_request_queue_size_increased" {
  title           = "Nginx Request Queue Size Increased"
  description     = "Detect when request queue size was increased in Nginx logs to check for potential capacity limitations, traffic spikes, or worker process bottlenecks affecting server responsiveness."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.nginx_request_queue_size_increased

  tags = merge(local.nginx_performance_common_tags, {
    mitre_attack_ids = "TA0040:T1499.002"
  })
}

query "nginx_request_queue_size_increased" {
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

detection "nginx_memory_leak_detected" {
  title           = "Nginx Memory Leak Detected"
  description     = "Detect when potential memory leak was detected in Nginx logs to check for application resource mismanagement, memory corruption, or growing response sizes indicating data accumulation issues."
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.nginx_memory_leak_detected

  tags = merge(local.nginx_performance_common_tags, {
    mitre_attack_ids = "TA0040:T1499.004"
  })
}

query "nginx_memory_leak_detected" {
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

detection "nginx_connection_pool_exhausted" {
  title           = "Nginx Connection Pool Exhausted"
  description     = "Detect when connection pool was exhausted in Nginx logs to check for potential resource limits, connection leaks, or traffic surges exceeding server capacity."
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.nginx_connection_pool_exhausted

  tags = merge(local.nginx_performance_common_tags, {
    mitre_attack_ids = "TA0040:T1499.002"
  })
}

query "nginx_connection_pool_exhausted" {
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

detection "nginx_ddos_early_warning_detected" {
  title           = "Nginx DDoS Early Warning Detected"
  description     = "Detect when early signs of DDoS attack were detected in Nginx logs to check for potential coordinated attacks, traffic anomalies, or resource exhaustion attempts targeting the web server."
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.nginx_ddos_early_warning_detected

  tags = merge(local.nginx_performance_common_tags, {
    mitre_attack_ids = "TA0040:T1498,TA0040:T1499.002"
  })
}

query "nginx_ddos_early_warning_detected" {
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
