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
    detection.nginx_cache_performance
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
    type = "Latency"
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
    type = "Anomaly"
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
    type = "Latency"
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
    type = "Capacity"
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
