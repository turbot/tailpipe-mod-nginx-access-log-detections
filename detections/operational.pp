locals {
  operational_common_tags = merge(local.nginx_access_log_detections_common_tags, {
    category = "Operational"
  })
}

benchmark "operational_detections" {
  title       = "Operational Detections"
  description = "This benchmark contains operational detections when scanning access logs."
  type        = "detection"
  children = [
    detection.error_rate_increased,
    detection.traffic_spike_detected,
    detection.bandwidth_usage_exceeded,
    detection.endpoint_error_rate_increased
  ]

  tags = merge(local.operational_common_tags, {
    type = "Benchmark"
  })
}

detection "error_rate_increased" {
  title           = "Error Rate Increased"
  description     = "Detect when error rate was increased in logs to check for potential system instability, service unavailability, or application failures that could impact user experience."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.error_rate_increased

  tags = merge(local.operational_common_tags, {
    mitre_attack_ids = "TA0040:T1499.004"
  })
}

query "error_rate_increased" {
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

detection "traffic_spike_detected" {
  title           = "Traffic Spike Detected"
  description     = "Detect when unusual traffic spikes were detected in logs to check for potential denial of service attacks, viral content, or unexpected user behavior patterns."
  severity        = "medium"
  display_columns = local.detection_display_columns

  query = query.traffic_spike_detected

  tags = merge(local.operational_common_tags, {
    mitre_attack_ids = "TA0040:T1498"
  })
}

query "traffic_spike_detected" {
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

detection "bandwidth_usage_exceeded" {
  title           = "Bandwidth Usage Exceeded"
  description     = "Detect when bandwidth usage was exceeded in logs to check for potential cost overruns, infrastructure capacity issues, or malicious data exfiltration activities."
  severity        = "medium"
  display_columns = local.detection_display_columns

  query = query.bandwidth_usage_exceeded

  tags = merge(local.operational_common_tags, {
    mitre_attack_ids = "TA0040:T1496.002"
  })
}

query "bandwidth_usage_exceeded" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    group by
      remote_addr,
      request_uri
    having
      sum(bytes_sent) > 100 * 1024 * 1024  -- 100MB threshold
    order by
      total_bytes desc;
  EOQ
}

detection "endpoint_error_rate_increased" {
  title           = "Endpoint Error Rate Increased"
  description     = "Detect when endpoint error rate was increased in logs to check for specific application failures, problematic API endpoints, or targeted attack patterns affecting particular resources."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.endpoint_error_rate_increased

  tags = merge(local.operational_common_tags, {
    mitre_attack_ids = "TA0040:T1499.004"
  })
}

query "endpoint_error_rate_increased" {
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