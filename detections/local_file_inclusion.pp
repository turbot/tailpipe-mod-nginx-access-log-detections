locals {
  local_file_inclusion_common_tags = merge(local.nginx_access_log_detections_common_tags, {
    category    = "Security"
    attack_type = "Local File Inclusion"
  })
}

benchmark "local_file_inclusion_detections" {
  title       = "Local File Inclusion (LFI) Detections"
  description = "This benchmark contains LFI focused detections when scanning Nginx access logs."
  type        = "detection"
  children = [
    detection.encoded_path_traversal,
    detection.header_based_local_file_inclusion,
    detection.hidden_file_access,
    detection.os_file_access,
    detection.path_traversal,
    detection.restricted_file_access,
  ]

  tags = merge(local.local_file_inclusion_common_tags, {
    type = "Benchmark"
  })
}

detection "path_traversal" {
  title           = "Path Traversal"
  description     = "Detect directory traversal attacks using path sequences like '../' that attempt to access files outside the intended directory."
  documentation   = file("./detections/docs/path_traversal.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.path_traversal

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0007:T1083",
    owasp_top_10     = "A01:2021-Broken Access Control"
  })
}

query "path_traversal" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      request_uri is not null
      and (
        -- Directory traversal sequences
        request_uri ilike '%../%'
        or request_uri ilike '%..\\%'
        or request_uri ilike '%/./%'
        or request_uri ilike '%\\.\\%'
        or request_uri ilike '%/.%'
        or request_uri ilike '%\\\\%'
        -- Most common exploits
        or request_uri ilike '%../..%'
        or request_uri ilike '%../../../%'
        or request_uri ilike '%../../../../%'
        or request_uri ilike '%..//%'
        or request_uri ilike '%../../../../../../../../%'
        -- Bypass techniques
        or request_uri ilike '%..;/%'
        or request_uri ilike '%..///%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "encoded_path_traversal" {
  title           = "Encoded Path Traversal"
  description     = "Detect directory traversal attacks using URL encoded or otherwise obfuscated path sequences to bypass security filters."
  documentation   = file("./detections/docs/encoded_path_traversal.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.encoded_path_traversal

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0007:T1083",
    owasp_top_10     = "A01:2021-Broken Access Control"
  })
}

query "encoded_path_traversal" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      request_uri is not null
      and (
        -- URL encoded traversal sequences
        request_uri ilike '%..%2f%'
        or request_uri ilike '%..%2F%'
        or request_uri ilike '%..%5c%'
        or request_uri ilike '%..%5C%'
        or request_uri ilike '%%2e%2e%2f%'
        or request_uri ilike '%2e%2e/%'
        or request_uri ilike '%2e%2e%2f%'
        or request_uri ilike '%2e%2e%5c%'
        -- Double URL encoding
        or request_uri ilike '%%252e%252e%252f%'
        or request_uri ilike '%%252e%252e%255c%'
        -- Unicode/UTF-8 encoding
        or request_uri ilike '%..%c0%af%'
        or request_uri ilike '%..%e0%80%af%'
        or request_uri ilike '%..%c1%1c%'
        or request_uri ilike '%..%c1%9c%'
        -- Overlong UTF-8 encoding
        or request_uri ilike '%..%c0%2f%'
        or request_uri ilike '%..%c0%5c%'
        or request_uri ilike '%..%c0%80%af%'
        -- Hex-encoded
        or request_uri ilike '%2e2e2f%'
        or request_uri ilike '%2e2e5c%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "header_based_local_file_inclusion" {
  title           = "Header-based Local File Inclusion"
  description     = "Detect attempts to include local files through HTTP header manipulation."
  documentation   = file("./detections/docs/header_based_local_file_inclusion.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.header_based_local_file_inclusion

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0007:T1083",
    owasp_top_10     = "A01:2021-Broken Access Control"
  })
}

query "header_based_local_file_inclusion" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      http_user_agent is not null
      and (
        -- Path traversal in User-Agent
        http_user_agent ilike '%../%'
        or http_user_agent ilike '%/../%'
        or http_user_agent ilike '%\\..\\%'
        or http_user_agent ilike '%\\.\\%'
        -- Encoded path traversal in User-Agent
        or http_user_agent ilike '%..%2f%'
        or http_user_agent ilike '%..%2F%'
        or http_user_agent ilike '%%2e%2e%2f%'
        or http_user_agent ilike '%%2E%2E%2F%'
        or http_user_agent ilike '%..%5c%'
        or http_user_agent ilike '%..%5C%'
        -- OS file access in User-Agent
        or http_user_agent ilike '%/etc/passwd%'
        or http_user_agent ilike '%/etc/shadow%'
        or http_user_agent ilike '%/etc/hosts%'
        or http_user_agent ilike '%/proc/self/%'
        or http_user_agent ilike '%win.ini%'
        or http_user_agent ilike '%system32%'
        or http_user_agent ilike '%boot.ini%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "os_file_access" {
  title           = "OS File Access"
  description     = "Detect attempts to access operating system files through web requests."
  documentation   = file("./detections/docs/os_file_access.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.os_file_access

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0007:T1083",
    owasp_top_10     = "A01:2021-Broken Access Control"
  })
}

query "os_file_access" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      request_uri is not null
      and (
        -- Unix/Linux sensitive files
        request_uri ilike '%/etc/passwd%'
        or request_uri ilike '%/etc/shadow%'
        or request_uri ilike '%/etc/hosts%'
        or request_uri ilike '%/etc/fstab%'
        or request_uri ilike '%/etc/issue%'
        or request_uri ilike '%/etc/profile%'
        or request_uri ilike '%/etc/ssh%'
        or request_uri ilike '%/proc/version%'
        or request_uri ilike '%/proc/self%'
        or request_uri ilike '%/proc/cpuinfo%'
        or request_uri ilike '%/var/log/auth.log%'
        or request_uri ilike '%/var/log/secure%'
        -- Windows sensitive files
        or request_uri ilike '%c:\\windows\\win.ini%'
        or request_uri ilike '%c:\\boot.ini%'
        or request_uri ilike '%c:\\windows\\system32\\config%'
        or request_uri ilike '%c:\\windows\\repair%'
        or request_uri ilike '%c:\\windows\\debug\\netsetup.log%'
        or request_uri ilike '%c:\\windows\\iis%log%'
        or request_uri ilike '%c:\\sysprep.inf%'
        or request_uri ilike '%c:\\sysprep\\sysprep.xml%'
        -- Web server files
        or request_uri ilike '%/var/log/apache%'
        or request_uri ilike '%/var/log/httpd%'
        or request_uri ilike '%/usr/local/apache%'
        or request_uri ilike '%/usr/local/nginx%'
        or request_uri ilike '%/var/log/nginx%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "hidden_file_access" {
  title           = "Hidden File Access"
  description     = "Detect attempts to access hidden files and directories through web requests."
  documentation   = file("./detections/docs/hidden_file_access.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.hidden_file_access

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0007:T1083",
    owasp_top_10     = "A01:2021-Broken Access Control"
  })
}

query "hidden_file_access" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      request_uri is not null
      and (
        -- Common hidden files and directories
        request_uri ilike '%/.git/%'
        or request_uri ilike '%/.svn/%'
        or request_uri ilike '%/.DS_Store%'
        or request_uri ilike '%/.htpasswd%'
        or request_uri ilike '%/.npmrc%'
        or request_uri ilike '%/.env%'
        or request_uri ilike '%/.aws/%'
        or request_uri ilike '%/.ssh/%'
        or request_uri ilike '%/.bash_history%'
        or request_uri ilike '%/.htaccess%'
        or request_uri ilike '%/.htpasswd%'
        or request_uri ilike '%/.config/%'
        or request_uri ilike '%/.vscode/%'
        or request_uri ilike '%/.idea/%'
        -- Docker/Kubernetes files
        or request_uri ilike '%/docker-compose%'
        or request_uri ilike '%/Dockerfile%'
        or request_uri ilike '%/kubernetes/%'
        or request_uri ilike '%/kubeconfig%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "restricted_file_access" {
  title           = "Restricted File Access"
  description     = "Detect attempts to access restricted files and directories through web requests."
  documentation   = file("./detections/docs/restricted_file_access.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.restricted_file_access

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0007:T1083",
    owasp_top_10     = "A01:2021-Broken Access Control"
  })
}

query "restricted_file_access" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      request_uri is not null
      and (
        -- Common application config files
        request_uri ilike '%/config.php%'
        or request_uri ilike '%/configuration.php%'
        or request_uri ilike '%/db.php%'
        or request_uri ilike '%/database.php%'
        or request_uri ilike '%/settings.php%'
        or request_uri ilike '%/conf.php%'
        or request_uri ilike '%/wp-config.php%'
        or request_uri ilike '%/config.xml%'
        or request_uri ilike '%/app.config%'
        or request_uri ilike '%/appsettings.json%'
        or request_uri ilike '%/config.yml%'
        or request_uri ilike '%/config.yaml%'
        or request_uri ilike '%/.env%'
        or request_uri ilike '%/.htaccess%'
        or request_uri ilike '%/.svn/%'
        or request_uri ilike '%/.git/%'
        -- Popular application source files
        or request_uri ilike '%/web.config%'
        or request_uri ilike '%/php.ini%'
        or request_uri ilike '%/.htpasswd%'
        or request_uri ilike '%.inc%'
        -- Temporary or backup files that may contain sensitive data
        or request_uri ilike '%~%'
        or request_uri ilike '%.bak%'
        or request_uri ilike '%.backup%'
        or request_uri ilike '%.old%'
        or request_uri ilike '%.orig%'
        or request_uri ilike '%.tmp%'
        or request_uri ilike '%.temp%'
        or request_uri ilike '%.swp%'
      )
    order by
      tp_timestamp desc;
  EOQ
} 