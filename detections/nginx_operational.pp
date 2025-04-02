locals {
  nginx_operational_common_tags = merge(local.nginx_access_log_detections_common_tags, {
    category = "Operational"
  })
}

benchmark "nginx_operational_detections" {
  title       = "Nginx Operational Detections"
  description = "This benchmark contains operational detections when scanning Nginx access logs."
  type        = "detection"
  children = [
    detection.nginx_high_error_rate,
    detection.nginx_unusual_traffic_spike,
    detection.nginx_high_bandwidth_usage,
    detection.nginx_error_rate_by_endpoint
  ]

  tags = merge(local.nginx_operational_common_tags, {
    type = "Benchmark"
  })
}

detection "nginx_high_error_rate" {
  title           = "High Error Rate Detected"
  description     = "Detect when the rate of 5xx errors exceeds a threshold within a time window."
  severity        = "high"
  display_columns = ["error_count", "total_requests", "error_rate", "window_start", "window_end"]

  query = query.nginx_high_error_rate

  tags = merge(local.nginx_operational_common_tags, {
    mitre_attack_ids = "TA0040:T1499.004" // Impact: Application or System Exploitation
  })
}

query "nginx_high_error_rate" {
  sql = <<-EOQ
    with error_windows as (
      select
        count(*) filter (where status >= 500) as error_count,
        count(*) as total_requests,
        (count(*) filter (where status >= 500))::float / count(*) as error_rate,
        time_bucket('5 minutes', tp_timestamp) as window_start,
        time_bucket('5 minutes', tp_timestamp) + interval '5 minutes' as window_end
      from
        nginx_access_log
      group by
        time_bucket('5 minutes', tp_timestamp)
      having
        count(*) >= 100  -- Minimum request threshold
        and (count(*) filter (where status >= 500))::float / count(*) >= 0.02  -- 2% error rate threshold
    )
    select
      *
    from
      error_windows
    order by
      window_start desc;
  EOQ
}

detection "nginx_unusual_traffic_spike" {
  title           = "Unusual Traffic Spike Detected"
  description     = "Detect unusual spikes in traffic volume compared to historical patterns."
  severity        = "medium"
  display_columns = ["request_count", "avg_historical_requests", "deviation_percent", "window_start", "window_end"]

  query = query.nginx_unusual_traffic_spike

  tags = merge(local.nginx_operational_common_tags, {
    mitre_attack_ids = "TA0040:T1498" // Impact: Network Denial of Service
  })
}

query "nginx_unusual_traffic_spike" {
  sql = <<-EOQ
    with traffic_windows as (
      select
        count(*) as request_count,
        time_bucket('5 minutes', tp_timestamp) as window_start,
        avg(count(*)) over (
          order by time_bucket('5 minutes', tp_timestamp)
          rows between 12 preceding and 1 preceding
        ) as avg_historical_requests,
        time_bucket('5 minutes', tp_timestamp) + interval '5 minutes' as window_end
      from
        nginx_access_log
      group by
        time_bucket('5 minutes', tp_timestamp)
    )
    select
      request_count,
      round(avg_historical_requests::numeric, 2) as avg_historical_requests,
      round(((request_count - avg_historical_requests) / avg_historical_requests * 100)::numeric, 2) as deviation_percent,
      window_start,
      window_end
    from
      traffic_windows
    where
      avg_historical_requests > 0
      and ((request_count - avg_historical_requests) / avg_historical_requests) > 2  -- 200% increase threshold
    order by
      window_start desc;
  EOQ
}

detection "nginx_high_bandwidth_usage" {
  title           = "High Bandwidth Usage Detected"
  description     = "Detect endpoints or IPs consuming unusually high bandwidth."
  severity        = "medium"
  display_columns = ["request_ip", "endpoint", "total_bytes", "request_count", "avg_bytes_per_request"]

  query = query.nginx_high_bandwidth_usage

  tags = merge(local.nginx_operational_common_tags, {
    mitre_attack_ids = "TA0040:T1496.002" // Impact: Resource Hijacking: Bandwidth Hijacking
  })
}

query "nginx_high_bandwidth_usage" {
  sql = <<-EOQ
    select
      remote_addr as request_ip,
      request_uri as endpoint,
      sum(bytes_sent) as total_bytes,
      count(*) as request_count,
      round((sum(bytes_sent)::float / count(*))::numeric, 2) as avg_bytes_per_request
    from
      nginx_access_log
    group by
      remote_addr,
      request_uri
    having
      sum(bytes_sent) > 100 * 1024 * 1024  -- 100MB threshold
    order by
      total_bytes desc
    limit 100;
  EOQ
}

detection "nginx_error_rate_by_endpoint" {
  title           = "High Error Rate by Endpoint"
  description     = "Detect endpoints with unusually high error rates."
  severity        = "high"
  display_columns = ["endpoint", "error_count", "total_requests", "error_rate"]

  query = query.nginx_error_rate_by_endpoint

  tags = merge(local.nginx_operational_common_tags, {
    mitre_attack_ids = "TA0040:T1499.004" // Impact: Application or System Exploitation
  })
}

query "nginx_error_rate_by_endpoint" {
  sql = <<-EOQ
    select
      request_uri as endpoint,
      count(*) filter (where status >= 400) as error_count,
      count(*) as total_requests,
      round((count(*) filter (where status >= 400))::float / count(*)::numeric, 4) as error_rate
    from
      nginx_access_log
    group by
      request_uri
    having
      count(*) >= 50  -- Minimum request threshold
      and (count(*) filter (where status >= 400))::float / count(*) >= 0.1  -- 10% error rate threshold
    order by
      error_rate desc,
      total_requests desc;
  EOQ
} 