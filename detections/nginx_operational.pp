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
    detection.nginx_error_rate_increased,
    detection.nginx_traffic_spike_detected,
    detection.nginx_bandwidth_usage_exceeded,
    detection.nginx_endpoint_error_rate_increased
  ]

  tags = merge(local.nginx_operational_common_tags, {
    type = "Benchmark"
  })
}

detection "nginx_error_rate_increased" {
  title           = "Nginx Error Rate Increased"
  description     = "Detect when error rate was increased in Nginx logs to check for potential system instability, service unavailability, or application failures that could impact user experience."
  severity        = "high"
  display_columns = ["error_count", "total_requests", "error_rate", "window_start", "window_end"]

  query = query.nginx_error_rate_increased

  tags = merge(local.nginx_operational_common_tags, {
    mitre_attack_ids = "TA0040:T1499.004"
  })
}

query "nginx_error_rate_increased" {
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

detection "nginx_traffic_spike_detected" {
  title           = "Nginx Traffic Spike Detected"
  description     = "Detect when unusual traffic spikes were detected in Nginx logs to check for potential denial of service attacks, viral content, or unexpected user behavior patterns."
  severity        = "medium"
  display_columns = ["request_count", "avg_historical_requests", "deviation_percent", "window_start", "window_end"]

  query = query.nginx_traffic_spike_detected

  tags = merge(local.nginx_operational_common_tags, {
    mitre_attack_ids = "TA0040:T1498"
  })
}

query "nginx_traffic_spike_detected" {
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

detection "nginx_bandwidth_usage_exceeded" {
  title           = "Nginx Bandwidth Usage Exceeded"
  description     = "Detect when bandwidth usage was exceeded in Nginx logs to check for potential cost overruns, infrastructure capacity issues, or malicious data exfiltration activities."
  severity        = "medium"
  display_columns = ["request_ip", "endpoint", "total_bytes", "request_count", "avg_bytes_per_request"]

  query = query.nginx_bandwidth_usage_exceeded

  tags = merge(local.nginx_operational_common_tags, {
    mitre_attack_ids = "TA0040:T1496.002"
  })
}

query "nginx_bandwidth_usage_exceeded" {
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

detection "nginx_endpoint_error_rate_increased" {
  title           = "Nginx Endpoint Error Rate Increased"
  description     = "Detect when endpoint error rate was increased in Nginx logs to check for specific application failures, problematic API endpoints, or targeted attack patterns affecting particular resources."
  severity        = "high"
  display_columns = ["endpoint", "error_count", "total_requests", "error_rate"]

  query = query.nginx_endpoint_error_rate_increased

  tags = merge(local.nginx_operational_common_tags, {
    mitre_attack_ids = "TA0040:T1499.004"
  })
}

query "nginx_endpoint_error_rate_increased" {
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