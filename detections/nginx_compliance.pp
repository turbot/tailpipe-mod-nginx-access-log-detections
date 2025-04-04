locals {
  nginx_compliance_common_tags = merge(local.nginx_access_log_detections_common_tags, {
    category = "Compliance"
  })
}

benchmark "nginx_compliance_detections" {
  title       = "Nginx Compliance Detections"
  description = "This benchmark contains compliance-focused detections when scanning Nginx access logs."
  type        = "detection"
  children = [
    detection.nginx_pii_data_exposed,
    detection.nginx_restricted_resource_accessed,
    detection.nginx_unauthorized_ip_accessed,
    detection.nginx_data_privacy_requirements_violated
  ]

  tags = merge(local.nginx_compliance_common_tags, {
    type = "Benchmark"
  })
}

detection "nginx_pii_data_exposed" {
  title           = "Nginx PII Data Exposed"
  description     = "Detect when personally identifiable information (PII) was exposed in Nginx URLs to check for potential data privacy violations, regulatory non-compliance, or sensitive information leakage risks."
  severity        = "critical"
  display_columns = ["request_ip", "request_path", "pii_type", "status_code", "timestamp"]

  query = query.nginx_pii_data_exposed

  tags = merge(local.nginx_compliance_common_tags, {
    mitre_attack_ids = "TA0009:T1213"
  })
}

query "nginx_pii_data_exposed" {
  sql = <<-EOQ
    with pii_patterns as (
      select request_uri as request_path,
        remote_addr as request_ip,
        status as status_code,
        tp_timestamp as timestamp,
        case
          when request_uri ~ '[0-9]{3}-[0-9]{2}-[0-9]{4}' then 'SSN'
          when request_uri ~ '[0-9]{16}' then 'Credit Card'
          when request_uri ~ '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' then 'Email'
          when request_uri ~ '(?:password|passwd|pwd)=[^&]+' then 'Password'
          when request_uri ~ '[0-9]{10}' then 'Phone Number'
        end as pii_type
      from
        nginx_access_log
      where
        request_uri ~ '[0-9]{3}-[0-9]{2}-[0-9]{4}'  -- SSN pattern
        or request_uri ~ '[0-9]{16}'  -- Credit card pattern
        or request_uri ~ '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'  -- Email pattern
        or request_uri ~ '(?:password|passwd|pwd)=[^&]+'  -- Password in URL
        or request_uri ~ '[0-9]{10}'  -- Phone number pattern
    )
    select
      *
    from
      pii_patterns
    order by
      timestamp desc;
  EOQ
}

detection "nginx_restricted_resource_accessed" {
  title           = "Nginx Restricted Resource Accessed"
  description     = "Detect when restricted resources or administrative areas were accessed in Nginx logs to check for potential unauthorized access, privilege escalation, or inadequate access control risks."
  severity        = "high"
  display_columns = ["request_ip", "request_path", "request_method", "status_code", "timestamp"]

  query = query.nginx_restricted_resource_accessed

  tags = merge(local.nginx_compliance_common_tags, {
    mitre_attack_ids = "TA0007:T1083,TA0001:T1190"
  })
}

query "nginx_restricted_resource_accessed" {
  sql = <<-EOQ
    select
      remote_addr as request_ip,
      request_uri as request_path,
      request_method,
      status as status_code,
      tp_timestamp as timestamp
    from
      nginx_access_log
    where
      (
        lower(request_uri) like '%/admin%'
        or lower(request_uri) like '%/manager%'
        or lower(request_uri) like '%/console%'
        or lower(request_uri) like '%/dashboard%'
        or lower(request_uri) like '%/management%'
        or lower(request_uri) like '%/phpmyadmin%'
        or lower(request_uri) like '%/wp-admin%'
        or lower(request_uri) like '%/administrator%'
      )
      and status != 404  -- Exclude 404s to reduce noise
    order by
      timestamp desc;
  EOQ
}

detection "nginx_unauthorized_ip_accessed" {
  title           = "Nginx Unauthorized IP Accessed"
  description     = "Detect when access from unauthorized IP ranges or geographic locations was detected in Nginx logs to check for potential network-level access control bypasses, geofencing violations, or unauthorized resource access risks."
  severity        = "high"
  display_columns = ["request_ip", "request_count", "first_access", "last_access"]

  query = query.nginx_unauthorized_ip_accessed

  tags = merge(local.nginx_compliance_common_tags, {
    mitre_attack_ids = "TA0005:T1535"
  })
}

query "nginx_unauthorized_ip_accessed" {
  sql = <<-EOQ
    with unauthorized_access as (
      select
        remote_addr as request_ip,
        count(*) as request_count,
        min(tp_timestamp) as first_access,
        max(tp_timestamp) as last_access
      from
        nginx_access_log
      where
        remote_addr not like '10.%'
        and remote_addr not like '172.%'
        and remote_addr not like '192.168.%'
      group by
        remote_addr
    )
    select
      *
    from
      unauthorized_access
    order by
      request_count desc;
  EOQ
}

detection "nginx_data_privacy_requirements_violated" {
  title           = "Nginx Data Privacy Requirements Violated"
  description     = "Detect when data privacy requirements were violated in Nginx logs to check for potential regulatory non-compliance, inadequate data protection controls, or sensitive information handling risks."
  severity        = "high"
  display_columns = ["endpoint", "total_requests", "sensitive_data_count", "unique_ips"]

  query = query.nginx_data_privacy_requirements_violated

  tags = merge(local.nginx_compliance_common_tags, {
    mitre_attack_ids = "TA0009:T1213,TA0043:T1592"
  })
}

query "nginx_data_privacy_requirements_violated" {
  sql = <<-EOQ
    with privacy_endpoints as (
      select
        request_uri as endpoint,
        count(*) as total_requests,
        count(*) filter (
          where request_uri ~ '(?i)(ssn|email|password|credit|card|phone|address|dob|birth)'
        ) as sensitive_data_count,
        count(distinct remote_addr) as unique_ips
      from
        nginx_access_log
      where
        -- Focus on API endpoints and form submissions
        (request_uri like '/api/%' or request_method = 'POST')
      group by
        request_uri
      having
        count(*) filter (
          where request_uri ~ '(?i)(ssn|email|password|credit|card|phone|address|dob|birth)'
        ) > 0
    )
    select
      endpoint,
      total_requests,
      sensitive_data_count,
      unique_ips,
      round((sensitive_data_count::float / total_requests * 100)::numeric, 2) as sensitive_data_percentage
    from
      privacy_endpoints
    order by
      sensitive_data_count desc;
  EOQ
} 