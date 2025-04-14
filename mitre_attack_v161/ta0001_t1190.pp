locals {
  mitre_attack_v161_ta0001_t1190_common_tags = merge(local.mitre_attack_v161_ta0001_common_tags, {
    mitre_attack_technique_id = "T1190"
  })
}

benchmark "mitre_attack_v161_ta0001_t1190" {
  title         = "T1190 Exploit Public-Facing Application"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0001_t1190.md")
  children = [
    # Local File Inclusion exploits
    detection.header_based_local_file_inclusion,

    # SQL Injection exploits
    detection.sql_injection_blind_based,
    detection.sql_injection_common_patterns,
    detection.sql_injection_error_based,
    detection.sql_injection_time_based,
    detection.sql_injection_union_based,
    detection.sql_injection_user_agent_based
  ]

  tags = local.mitre_attack_v161_ta0001_t1190_common_tags
}
