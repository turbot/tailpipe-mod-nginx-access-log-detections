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
    detection.nginx_bot_detection
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
      lower(request_uri) like any (array[
        '%select%from%',
        '%union%select%',
        '%insert%into%',
        '%delete%from%',
        '%update%set%',
        '%drop%table%',
        '%or%1=1%',
        '%\'%or%\'1\'=\'1%'
      ])
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
      request_uri like '%../%'
      or request_uri like '%..\\%'
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
      lower(http_user_agent) like any (array[
        '%sqlmap%',
        '%nikto%',
        '%nmap%',
        '%masscan%',
        '%zgrab%',
        '%gobuster%',
        '%dirbuster%',
        '%hydra%',
        '%burpsuite%',
        '%nessus%'
      ])
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
      lower(request_uri) like any (array[
        '%<script%',
        '%javascript:%',
        '%onerror=%',
        '%onload=%',
        '%onclick=%',
        '%alert(%',
        '%eval(%',
        '%document.cookie%',
        '%<img%src=%'
      ])
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
      lower(request_uri) like any (array[
        '%;%',
        '%|%',
        '%`%',
        '%$(%',
        '%${%',
        '%&&%',
        '%||%',
        '%>%',
        '%<%',
        '%2f2f%'  -- URL encoded //
      ])
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
      lower(request_uri) like any (array[
        '%.env%',
        '%.git%',
        '%wp-config.php%',
        '%config.php%',
        '%/etc/%',
        '%/var/log/%',
        '%.htaccess%',
        '%.htpasswd%',
        '%/proc/%',
        '%/sys/%'
      ])
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
    type = "Protocol"
  })
}

query "nginx_protocol_violations" {
  sql = <<-EOQ
    select
      remote_addr as request_ip,
      request_uri as request_path,
      request_method,
      status as status_code,
      http_version,
      tp_timestamp as timestamp
    from
      nginx_access_log
    where
      request_method not in ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT')
      or http_version not in ('HTTP/1.0', 'HTTP/1.1', 'HTTP/2.0')
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
    type = "DDoS"
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
    type = "Bot"
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