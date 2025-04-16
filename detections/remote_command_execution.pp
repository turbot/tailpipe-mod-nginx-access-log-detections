locals {
  remote_command_execution_common_tags = merge(local.nginx_access_log_detections_common_tags, {
    category    = "Security"
    attack_type = "Remote Command Execution"
  })
}

benchmark "remote_command_execution_detections" {
  title       = "Remote Command Execution (RCE) Detections"
  description = "This benchmark contains RCE focused detections when scanning Nginx access logs."
  type        = "detection"
  children = [
    detection.log4shell_vulnerability,
    detection.spring4shell_vulnerability,
  ]

  tags = merge(local.remote_command_execution_common_tags, {
    type = "Benchmark"
  })
}

detection "log4shell_vulnerability" {
  title           = "Log4Shell Vulnerability"
  description     = "Detect Log4Shell (CVE-2021-44228) exploitation attempts that target the Java Log4j library vulnerability, allowing attackers to execute arbitrary commands."
  documentation   = file("./detections/docs/log4shell_vulnerability.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.log4shell_vulnerability

  tags = merge(local.remote_command_execution_common_tags, {
    mitre_attack_ids = "TA0002:T1059",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "log4shell_vulnerability" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      request_uri is not null
      and (
        -- JNDI lookup patterns
        request_uri ilike '%$${jndi:%'
        or request_uri ilike '%$%7bjndi:%'
        or request_uri ilike '%$${%7bjndi:%'
        or request_uri ilike '%jndi://%'
        
        -- Common protocol exploits
        or request_uri ilike '%jndi:ldap:%'
        or request_uri ilike '%jndi:dns:%'
        or request_uri ilike '%jndi:rmi:%'
        or request_uri ilike '%jndi:http:%'
        or request_uri ilike '%jndi:iiop:%'
        or request_uri ilike '%jndi:corba:%'
        
        -- Base64 encoded variants
        or request_uri ilike '%jTmRp%'
        or request_uri ilike '%ak5kaQ%'
        or request_uri ilike '%JE5ESQB%'
        or request_uri ilike '%SnNkaQ%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "spring4shell_vulnerability" {
  title           = "Spring4Shell Vulnerability"
  description     = "Detect Spring4Shell (CVE-2022-22965) exploitation attempts that target Spring Framework's class injection vulnerability, allowing attackers to execute arbitrary commands."
  documentation   = file("./detections/docs/spring4shell_vulnerability.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.spring4shell_vulnerability

  tags = merge(local.remote_command_execution_common_tags, {
    mitre_attack_ids = "TA0002:T1059",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "spring4shell_vulnerability" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      request_uri is not null
      and (
        -- Class pattern indicators
        request_uri ilike '%class.module.classLoader%'
        or request_uri ilike '%class.classLoader%'
        or request_uri ilike '%ClassLoader%'
        
        -- Property access patterns
        or request_uri ilike '%?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%'
        or request_uri ilike '%?class.module.classLoader.resources.context.parent.pipeline.first.suffix=%'
        or request_uri ilike '%?class.module.classLoader.resources.context.parent.pipeline.first.directory=%'
        or request_uri ilike '%?class.module.classLoader.resources.context.parent.pipeline.first.prefix=%'
        or request_uri ilike '%?class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=%'
        
        -- URL encoded variants
        or request_uri ilike '%class%2Emodule%2EclassLoader%'
        or request_uri ilike '%tomcatwar.jsp%'
        
        -- Common payloads
        or request_uri ilike '%Pattern=%25%7Bc2%7Di%'
        or request_uri ilike '%class.module.classLoader.DefaultAssertionStatus%'
      )
    order by
      tp_timestamp desc;
  EOQ
}
