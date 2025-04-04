locals {
  security_common_tags = merge(local.nginx_access_log_detections_common_tags, {
    category = "Security"
  })
}

benchmark "security_detections" {
  title       = "Security Detections"
  description = "This benchmark contains security-focused detections when scanning access logs."
  type        = "detection"
  children = [
    detection.api_key_exposed,
    detection.authentication_brute_forced,
    detection.bot_activity_detected,
    detection.command_injection_attempted,
    detection.data_privacy_requirements_violated,
    detection.directory_traversal_attempted,
    detection.pii_data_exposed,
    detection.protocol_violated,
    detection.rate_limit_exceeded,
    detection.restricted_resource_accessed,
    detection.sensitive_file_accessed,
    detection.session_cookie_theft_attempted,
    detection.sql_injection_attempted,
    detection.suspicious_user_agent_detected,
    detection.unauthorized_ip_accessed,
    detection.unusual_region_accessed,
    detection.xss_attempted,
    detection.zero_day_pattern_detected,
  ]

  tags = merge(local.security_common_tags, {
    type = "Benchmark"
  })
}

detection "sql_injection_attempted" {
  title           = "SQL Injection Attempted"
  description     = "Detect when SQL injection was attempted in access logs to check for potential database compromise, unauthorized data access, or data manipulation risks."
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.sql_injection_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0009:T1190"
  })
}

query "sql_injection_attempted" {
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
      lower(request_uri) like '%select%from%'
      or lower(request_uri) like '%union%select%'
      or lower(request_uri) like '%insert%into%'
      or lower(request_uri) like '%delete%from%'
      or lower(request_uri) like '%update%set%'
      or lower(request_uri) like '%drop%table%'
      or lower(request_uri) like '%or%1=1%'
      or lower(request_uri) like '%or%1%=%1%'
    order by
      tp_timestamp desc;
  EOQ
}

detection "directory_traversal_attempted" {
  title           = "Directory Traversal Attempted"
  description     = "Detect when directory traversal was attempted in access logs to check for unauthorized file system access, sensitive data exposure, or server configuration leakage risks."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.directory_traversal_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0007:T1083,TA0009:T1083"
  })
}

query "directory_traversal_attempted" {
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
      -- Plain directory traversal attempts
      request_uri like '%../%'
      or request_uri like '%/../%'
      or request_uri like '%/./%'
      or request_uri like '%...%'
      or request_uri like '%\\..\\%'
      -- URL-encoded variants (both cases)
      or request_uri like '%..%2f%'
      or request_uri like '%..%2F%'
      or request_uri like '%%%2e%%2e%%2f%'
      or request_uri like '%%%2E%%2E%%2F%'
      or request_uri like '%%%2e%%2e/%'
      or request_uri like '%%%2E%%2E/%'
      -- Double-encoded variants
      or request_uri like '%25%32%65%25%32%65%25%32%66%'
      -- Backslash variants
      or request_uri like '%5c..%5c%'
      or request_uri like '%5C..%5C%'
      or request_uri like '%%%5c..%%5c%'
      or request_uri like '%%%5C..%%5C%'
    order by
      tp_timestamp desc;
  EOQ
}

detection "authentication_brute_forced" {
  title           = "Authentication Brute Forced"
  description     = "Detect when authentication was brute forced in access logs to check for credential compromise, unauthorized access, or account takeover risks."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.authentication_brute_forced

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0006:T1110.001,TA0006:T1110.003"
  })
}

query "authentication_brute_forced" {
  sql = <<-EOQ
    with failed_auths as (
      select
        remote_addr as request_ip,
        count(*) as failed_attempts,
        min(tp_timestamp) as first_attempt,
        max(tp_timestamp) as last_attempt
      from
        nginx_access_log
      where
        status in (401, 403)
      group by
        remote_addr
      having
        count(*) >= 10
        and (max(tp_timestamp) - min(tp_timestamp)) <= interval '5 minutes'
    )
    select
      *
    from
      failed_auths
    order by
      failed_attempts desc;
  EOQ
}

detection "suspicious_user_agent_detected" {
  title           = "Suspicious User Agent Detected"
  description     = "Detect requests from known malicious or suspicious user agents."
  severity        = "medium"
  display_columns = local.detection_display_columns

  query = query.suspicious_user_agents

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0043:T1592"
  })
}

query "suspicious_user_agents" {
  sql = <<-EOQ
    select
      remote_addr as request_ip,
      http_user_agent as user_agent,
      request_uri as request_path,
      status as status_code,
      tp_timestamp as timestamp
    from
      nginx_access_log
    where
      lower(http_user_agent) like '%sqlmap%'
      or lower(http_user_agent) like '%nikto%'
      or lower(http_user_agent) like '%nmap%'
      or lower(http_user_agent) like '%masscan%'
      or lower(http_user_agent) like '%zgrab%'
      or lower(http_user_agent) like '%gobuster%'
      or lower(http_user_agent) like '%dirbuster%'
      or lower(http_user_agent) like '%hydra%'
      or lower(http_user_agent) like '%burpsuite%'
      or lower(http_user_agent) like '%nessus%'
      or lower(http_user_agent) like '%metasploit%'
      or lower(http_user_agent) like '%sqlninja%'
      or lower(http_user_agent) like '%python%'
      or lower(http_user_agent) like '%curl%'
      or lower(http_user_agent) like '%wget%'
      or http_user_agent is null
    order by
      tp_timestamp desc;
  EOQ
}

detection "xss_attempted" {
  title           = "Cross-Site Scripting (XSS) Attempted"
  description     = "Detect potential XSS attacks in request parameters and paths."
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.xss_attempts

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0009:T1059.007"
  })
}

query "xss_attempts" {
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
      -- Plain XSS patterns
      lower(request_uri) like '%<script%'
      or lower(request_uri) like '%javascript:%'
      or lower(request_uri) like '%onerror=%'
      or lower(request_uri) like '%onload=%'
      or lower(request_uri) like '%onclick=%'
      or lower(request_uri) like '%alert(%'
      or lower(request_uri) like '%eval(%'
      or lower(request_uri) like '%document.cookie%'
      or lower(request_uri) like '%<img%src=%'
      -- URL-encoded variants (%%% to match literal % anywhere)
      or lower(request_uri) like '%%%3cscript%'
      or lower(request_uri) like '%%%3a%'  -- :
      or lower(request_uri) like '%%%3d%'  -- =
      or lower(request_uri) like '%%%28%'  -- (
      or lower(request_uri) like '%%%2e%'  -- .
      -- Double-encoded variants
      or lower(request_uri) like '%%%253c%'  -- <
      or lower(request_uri) like '%%%253a%'  -- :
      or lower(request_uri) like '%%%253d%'  -- =
      or lower(request_uri) like '%%%2528%'  -- (
      -- Additional XSS vectors
      or lower(request_uri) like '%onmouseover=%'
      or lower(request_uri) like '%%%3d%'  -- =
      or lower(request_uri) like '%onfocus=%'
      or lower(request_uri) like '%%%3d%'  -- =
      or lower(request_uri) like '%expression(%'
      or lower(request_uri) like '%%%28%'  -- (
      or lower(request_uri) like '%<svg%'
      or lower(request_uri) like '%%%3csvg%'
    order by
      tp_timestamp desc;
  EOQ
}

detection "command_injection_attempted" {
  title           = "Command Injection Attempted"
  description     = "Detect potential command injection attempts in request parameters."
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.command_injection_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0009:T1059"
  })
}

query "command_injection_attempted" {
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
      lower(request_uri) like '%;%'
      or lower(request_uri) like '%|%'
      or lower(request_uri) like '%`%'
      or lower(request_uri) like '%$(%'
      or lower(request_uri) like '%$${%'
      or lower(request_uri) like '%&&%'
      or lower(request_uri) like '%||%'
      or lower(request_uri) like '%>%'
      or lower(request_uri) like '%<%'
      or lower(request_uri) like '%%%3b%' 
      or lower(request_uri) like '%%%7c%' 
      or lower(request_uri) like '%%%60%' 
      or lower(request_uri) like '%%%24%' 
      or lower(request_uri) like '%%%3e%' 
      or lower(request_uri) like '%%%3c%' 
      or lower(request_uri) like '%%%2f%' 
    order by
      tp_timestamp desc;
  EOQ
}

detection "sensitive_file_accessed" {
  title           = "Sensitive File Access Attempted"
  description     = "Detect attempts to access sensitive configuration or system files."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.sensitive_file_accessed

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0009:T1083"
  })
}

query "sensitive_file_accessed" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      -- Plain paths
      lower(request_uri) like '%.env%'
      or lower(request_uri) like '%.git%'
      or lower(request_uri) like '%wp-config.php%'
      or lower(request_uri) like '%config.php%'
      or lower(request_uri) like '%/etc/%'
      or lower(request_uri) like '%/var/log/%'
      or lower(request_uri) like '%.htaccess%'
      or lower(request_uri) like '%.htpasswd%'
      or lower(request_uri) like '%/proc/%'
      or lower(request_uri) like '%/sys/%'
      or lower(request_uri) like '%%%2e%' 
      or lower(request_uri) like '%%%2f%' 
    order by
      tp_timestamp desc;
  EOQ
}

detection "protocol_violated" {
  title           = "HTTP Protocol Violations"
  description     = "Detect malformed requests and protocol violations that may indicate malicious activity."
  severity        = "medium"
  display_columns = local.detection_display_columns

  query = query.protocol_violated

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0005:T1211,TA0040:T1499.004"
  })
}

query "protocol_violated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      request_method not in ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT')
      or server_protocol not in ('HTTP/1.0', 'HTTP/1.1', 'HTTP/2.0')
      or length(request_uri) > 2048  -- Extremely long URLs
    order by
      tp_timestamp desc;
  EOQ
}

detection "rate_limit_exceeded" {
  title           = "Rate Limit Exceeded"
  description     = "Detect IPs exceeding request rate limits, which may indicate DoS attempts or aggressive scanning."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.rate_limit_exceeded

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0040:T1499.002"
  })
}

query "rate_limit_exceeded" {
  sql = <<-EOQ
    with rate_windows as (
      select
        remote_addr as request_ip,
        count(*) as request_count,
        count(distinct request_uri) as unique_paths,
        time_bucket('1 minute', tp_timestamp) as window_start,
        time_bucket('1 minute', tp_timestamp) + interval '1 minute' as window_end
      from
        nginx_access_log
      group by
        remote_addr,
        time_bucket('1 minute', tp_timestamp)
      having
        count(*) > 300  -- More than 300 requests per minute
    )
    select
      *
    from
      rate_windows
    order by
      request_count desc;
  EOQ
}

detection "bot_activity_detected" {
  title           = "Automated Bot Activity Detected"
  description     = "Detect patterns of automated bot activity based on request patterns and user agents."
  severity        = "medium"
  display_columns = local.detection_display_columns

  query = query.bot_activity_detected

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0043:T1595.002,TA0043:T1592.002"
  })
}

query "bot_activity_detected" {
  sql = <<-EOQ
    with bot_activity as (
      select
        remote_addr as request_ip,
        http_user_agent as user_agent,
        count(*) as request_count,
        count(distinct request_uri) as unique_paths,
        count(*)::float / nullif(
          extract(epoch from (max(tp_timestamp) - min(tp_timestamp))),
          0
        ) as avg_requests_per_second
      from
        nginx_access_log
      group by
        remote_addr,
        http_user_agent
      having
        count(*) >= 100  -- Minimum request threshold
        and count(*)::float / nullif(
          extract(epoch from (max(tp_timestamp) - min(tp_timestamp))),
          0
        ) > 2  -- More than 2 requests per second on average
    )
    select
      request_ip,
      user_agent,
      request_count,
      unique_paths,
      round(avg_requests_per_second::numeric, 2) as avg_requests_per_second
    from
      bot_activity
    order by
      request_count desc;
  EOQ
}

detection "api_key_exposed" {
  title           = "API Key or Token Exposure"
  description     = "Detect potential exposure of API keys or tokens in URLs"
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.api_key_exposed

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0006:T1552"
  })
}

query "api_key_exposed" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
      case
        when request_uri ~ '(?i)[a-z0-9]{32,}' then 'Potential API Key'
        when request_uri ~ '(?i)bearer\s+[a-zA-Z0-9-._~+/]+=*' then 'Bearer Token'
        when request_uri ~ '(?i)key=[a-zA-Z0-9-]{20,}' then 'API Key Parameter'
      end as token_type,
      tp_timestamp as timestamp
    from
      nginx_access_log
    where
      request_uri ~ '(?i)[a-z0-9]{32,}'
      or request_uri ~ '(?i)bearer\s+[a-zA-Z0-9-._~+/]+=*'
      or request_uri ~ '(?i)key=[a-zA-Z0-9-]{20,}'
    order by
      timestamp desc;
  EOQ
}

detection "zero_day_pattern_detected" {
  title           = "Potential Zero-Day Attack Pattern Detected"
  description     = "Detect unusual patterns that might indicate zero-day exploitation attempts"
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.zero_day_attack_patterns

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0007:T1190"
  })
}

query "zero_day_attack_patterns" {
  sql = <<-EOQ
    with unusual_patterns as (
      select
        ${local.detection_sql_columns}
        case
          when request_uri ~ '[\\x00-\\x01]|\\xff' then 'Binary Data Injection'
          when request_uri ~ '\\.\\.|%2e%2e' then 'Path Manipulation'
          when http_user_agent ~ '\\{.*\\}|\\$\\{.*\\}' then 'Template Injection'
          when request_uri ~ '\\[.*\\]' then 'Array Manipulation'
        end as pattern_type,
        count(*) as request_count,
        count(distinct remote_addr) as unique_ips,
        min(tp_timestamp) as first_seen
      from
        nginx_access_log
      where
        request_uri ~ '[\\x00-\\x01]|\\xff'
        or request_uri ~ '\\.\\.|%2e%2e'
        or http_user_agent ~ '\\{.*\\}|\\$\\{.*\\}'
        or request_uri ~ '\\[.*\\]'
      group by
        case
          when request_uri ~ '[\\x00-\\x01]|\\xff' then 'Binary Data Injection'
          when request_uri ~ '\\.\\.|%2e%2e' then 'Path Manipulation'
          when http_user_agent ~ '\\{.*\\}|\\$\\{.*\\}' then 'Template Injection'
          when request_uri ~ '\\[.*\\]' then 'Array Manipulation'
        end
    )
    select
      *
    from
      unusual_patterns
    where
      request_count > 10
    order by
      request_count desc;
  EOQ
}

detection "unusual_region_accessed" {
  title           = "Access from Unusual Cloud Regions"
  description     = "Detect access attempts from unusual or unauthorized cloud regions based on IP geolocation."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.unusual_region_accessed

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0005:T1535"
  })
}

query "unusual_region_accessed" {
  sql = <<-EOQ
    with ip_activity as (
      select
        remote_addr as request_ip,
        request_uri as request_path,
        geoip_country_name as geo_location,
        count(*) as request_count,
        min(tp_timestamp) as first_seen,
        max(tp_timestamp) as last_seen
      from
        nginx_access_log
      where
        geoip_country_name not in ('United States', 'Canada', 'United Kingdom')
      group by
        remote_addr,
        request_uri,
        geoip_country_name
      having
        count(*) > 50
    )
    select
      *
    from
      ip_activity
    order by
      request_count desc;
  EOQ
}

detection "session_cookie_theft_attempted" {
  title           = "Session Cookie Theft Attempted"
  description     = "Detect potential attempts to steal or manipulate web session cookies."
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.session_cookie_theft_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0005:T1550.004"
  })
}

query "session_cookie_theft_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      -- Detect cookie manipulation patterns
      (http_cookie like '%document.cookie%'
      or http_cookie like '%<script%'
      or http_cookie like '%eval(%'
      or http_cookie like '%alert(%')
      -- Detect multiple different session IDs from same IP
      or remote_addr in (
        select remote_addr
        from nginx_access_log
        where http_cookie is not null
        group by remote_addr
        having count(distinct http_cookie) > 10
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "pii_data_exposed" {
  title           = "PII Data Exposed"
  description     = "Detect when personally identifiable information (PII) was exposed in URLs to check for potential data privacy violations, regulatory non-compliance, or sensitive information leakage risks."
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.pii_data_exposed

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0009:T1213"
  })
}

query "pii_data_exposed" {
  sql = <<-EOQ
    with pii_patterns as (
      select 
        ${local.detection_sql_columns}
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

detection "restricted_resource_accessed" {
  title           = "Restricted Resource Accessed"
  description     = "Detect when restricted resources or administrative areas were accessed in logs to check for potential unauthorized access, privilege escalation, or inadequate access control risks."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.restricted_resource_accessed

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0007:T1083,TA0001:T1190"
  })
}

query "restricted_resource_accessed" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
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

detection "unauthorized_ip_accessed" {
  title           = "Unauthorized IP Accessed"
  description     = "Detect when access from unauthorized IP ranges or geographic locations was detected in logs to check for potential network-level access control bypasses, geofencing violations, or unauthorized resource access risks."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.unauthorized_ip_accessed

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0005:T1535"
  })
}

query "unauthorized_ip_accessed" {
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

detection "data_privacy_requirements_violated" {
  title           = "Data Privacy Requirements Violated"
  description     = "Detect when data privacy requirements were violated in logs to check for potential regulatory non-compliance, inadequate data protection controls, or sensitive information handling risks."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.data_privacy_requirements_violated

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0009:T1213,TA0043:T1592"
  })
}

query "data_privacy_requirements_violated" {
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