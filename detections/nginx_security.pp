locals {
  nginx_security_common_tags = merge(local.nginx_access_log_detections_common_tags, {
    category = "Security"
  })
}

benchmark "nginx_security_detections" {
  title       = "Nginx Security Detections"
  description = "This benchmark contains security-focused detections when scanning Nginx access logs."
  type        = "detection"
  children = [
    detection.nginx_sql_injection_attempts,
    detection.nginx_directory_traversal_attempts,
    detection.nginx_brute_force_auth_attempts,
    detection.nginx_suspicious_user_agents,
    detection.nginx_xss_attempts,
    detection.nginx_command_injection_attempts,
    detection.nginx_sensitive_file_access,
    detection.nginx_protocol_violations,
    detection.nginx_rate_limit_violations,
    detection.nginx_bot_detection,
    detection.nginx_api_key_exposure,
    detection.nginx_zero_day_attack_patterns,
    detection.nginx_unusual_region_access,
    detection.nginx_session_cookie_theft
  ]

  tags = merge(local.nginx_security_common_tags, {
    type = "Benchmark"
  })
}

detection "nginx_sql_injection_attempts" {
  title           = "SQL Injection Attempts Detected"
  description     = "Detect potential SQL injection attempts in URL parameters and request paths."
  severity        = "critical"
  display_columns = ["request_ip", "request_path", "request_method", "status_code", "timestamp"]

  query = query.nginx_sql_injection_attempts

  tags = merge(local.nginx_security_common_tags, {
    mitre_attack_ids = "TA0009:T1190"
  })
}

query "nginx_sql_injection_attempts" {
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

detection "nginx_directory_traversal_attempts" {
  title           = "Directory Traversal Attempts Detected"
  description     = "Detect attempts to traverse directories using ../ patterns in URLs."
  severity        = "high"
  display_columns = ["request_ip", "request_path", "request_method", "status_code", "timestamp"]

  query = query.nginx_directory_traversal_attempts

  tags = merge(local.nginx_security_common_tags, {
    mitre_attack_ids = "TA0009:T1083"
  })
}

query "nginx_directory_traversal_attempts" {
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

detection "nginx_brute_force_auth_attempts" {
  title           = "Authentication Brute Force Attempts"
  description     = "Detect potential brute force authentication attempts based on high frequency of 401/403 errors from the same IP."
  severity        = "high"
  display_columns = ["request_ip", "failed_attempts", "first_attempt", "last_attempt"]

  query = query.nginx_brute_force_auth_attempts

  tags = merge(local.nginx_security_common_tags, {
    mitre_attack_ids = "TA0006:T1110"
  })
}

query "nginx_brute_force_auth_attempts" {
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

detection "nginx_suspicious_user_agents" {
  title           = "Suspicious User Agents Detected"
  description     = "Detect requests from known malicious or suspicious user agents."
  severity        = "medium"
  display_columns = ["request_ip", "user_agent", "request_path", "status_code", "timestamp"]

  query = query.nginx_suspicious_user_agents

  tags = merge(local.nginx_security_common_tags, {
    mitre_attack_ids = "TA0043:T1592"
  })
}

query "nginx_suspicious_user_agents" {
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

detection "nginx_xss_attempts" {
  title           = "Cross-Site Scripting (XSS) Attempts"
  description     = "Detect potential XSS attacks in request parameters and paths."
  severity        = "critical"
  display_columns = ["request_ip", "request_path", "request_method", "status_code", "timestamp"]

  query = query.nginx_xss_attempts

  tags = merge(local.nginx_security_common_tags, {
    mitre_attack_ids = "TA0009:T1059.007"
  })
}

query "nginx_xss_attempts" {
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

detection "nginx_command_injection_attempts" {
  title           = "Command Injection Attempts"
  description     = "Detect potential command injection attempts in request parameters."
  severity        = "critical"
  display_columns = ["request_ip", "request_path", "request_method", "status_code", "timestamp"]

  query = query.nginx_command_injection_attempts

  tags = merge(local.nginx_security_common_tags, {
    mitre_attack_ids = "TA0009:T1059"
  })
}

query "nginx_command_injection_attempts" {
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

detection "nginx_sensitive_file_access" {
  title           = "Sensitive File Access Attempts"
  description     = "Detect attempts to access sensitive configuration or system files."
  severity        = "high"
  display_columns = ["request_ip", "request_path", "request_method", "status_code", "timestamp"]

  query = query.nginx_sensitive_file_access

  tags = merge(local.nginx_security_common_tags, {
    mitre_attack_ids = "TA0009:T1083"
  })
}

query "nginx_sensitive_file_access" {
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

detection "nginx_protocol_violations" {
  title           = "HTTP Protocol Violations"
  description     = "Detect malformed requests and protocol violations that may indicate malicious activity."
  severity        = "medium"
  display_columns = ["request_ip", "request_path", "request_method", "status_code", "http_version", "timestamp"]

  query = query.nginx_protocol_violations

  tags = merge(local.nginx_security_common_tags, {
    mitre_attack_ids = "TA0005:T1211,TA0040:T1499.004"
  })
}

query "nginx_protocol_violations" {
  sql = <<-EOQ
    select
      remote_addr as request_ip,
      request_uri as request_path,
      request_method,
      status as status_code,
      server_protocol as http_version,
      tp_timestamp as timestamp
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

detection "nginx_rate_limit_violations" {
  title           = "Rate Limit Violations"
  description     = "Detect IPs exceeding request rate limits, which may indicate DoS attempts or aggressive scanning."
  severity        = "high"
  display_columns = ["request_ip", "request_count", "unique_paths", "window_start", "window_end"]

  query = query.nginx_rate_limit_violations

  tags = merge(local.nginx_security_common_tags, {
    mitre_attack_ids = "TA0040:T1499.002"
  })
}

query "nginx_rate_limit_violations" {
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

detection "nginx_bot_detection" {
  title           = "Automated Bot Activity"
  description     = "Detect patterns of automated bot activity based on request patterns and user agents."
  severity        = "medium"
  display_columns = ["request_ip", "user_agent", "request_count", "unique_paths", "avg_requests_per_second"]

  query = query.nginx_bot_detection

  tags = merge(local.nginx_security_common_tags, {
    mitre_attack_ids = "TA0043:T1595.002,TA0043:T1592.002"
  })
}

query "nginx_bot_detection" {
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

detection "nginx_api_key_exposure" {
  title           = "API Key or Token Exposure"
  description     = "Detect potential exposure of API keys or tokens in URLs"
  severity        = "critical"
  display_columns = ["request_ip", "request_path", "token_type", "timestamp"]

  query = query.nginx_api_key_exposure

  tags = merge(local.nginx_security_common_tags, {
    mitre_attack_ids = "TA0006:T1552"
  })
}

query "nginx_api_key_exposure" {
  sql = <<-EOQ
    select
      remote_addr as request_ip,
      request_uri as request_path,
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

detection "nginx_zero_day_attack_patterns" {
  title           = "Potential Zero-Day Attack Patterns"
  description     = "Detect unusual patterns that might indicate zero-day exploitation attempts"
  severity        = "critical"
  display_columns = ["pattern_type", "request_count", "unique_ips", "first_seen"]

  query = query.nginx_zero_day_attack_patterns

  tags = merge(local.nginx_security_common_tags, {
    mitre_attack_ids = "TA0007:T1190"
  })
}

query "nginx_zero_day_attack_patterns" {
  sql = <<-EOQ
    with unusual_patterns as (
      select
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

detection "nginx_unusual_region_access" {
  title           = "Access from Unusual Cloud Regions"
  description     = "Detect access attempts from unusual or unauthorized cloud regions based on IP geolocation."
  severity        = "high"
  display_columns = ["request_ip", "request_path", "geo_location", "request_count", "first_seen", "last_seen"]

  query = query.nginx_unusual_region_access

  tags = merge(local.nginx_security_common_tags, {
    mitre_attack_ids = "TA0005:T1535"
  })
}

query "nginx_unusual_region_access" {
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

detection "nginx_session_cookie_theft" {
  title           = "Session Cookie Theft Attempts"
  description     = "Detect potential attempts to steal or manipulate web session cookies."
  severity        = "critical"
  display_columns = ["request_ip", "request_path", "cookie_header", "user_agent", "timestamp"]

  query = query.nginx_session_cookie_theft

  tags = merge(local.nginx_security_common_tags, {
    mitre_attack_ids = "TA0005:T1550.004"
  })
}

query "nginx_session_cookie_theft" {
  sql = <<-EOQ
    select
      remote_addr as request_ip,
      request_uri as request_path,
      http_cookie as cookie_header,
      http_user_agent as user_agent,
      tp_timestamp as timestamp
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