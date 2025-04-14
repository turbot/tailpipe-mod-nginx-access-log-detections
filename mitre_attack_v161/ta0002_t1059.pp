locals {
  mitre_attack_v161_ta0002_t1059_common_tags = merge(local.mitre_attack_v161_ta0002_common_tags, {
    mitre_attack_technique_id = "T1059"
  })
}

benchmark "mitre_attack_v161_ta0002_t1059" {
  title         = "T1059 Command and Scripting Interpreter"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0002_t1059.md")
  children = [
    benchmark.mitre_attack_v161_ta0002_t1059_007,
    detection.log4shell_vulnerability,
    detection.spring4shell_vulnerability
  ]

  tags = local.mitre_attack_v161_ta0002_t1059_common_tags
}


benchmark "mitre_attack_v161_ta0002_t1059_007" {
  title         = "T1059.007 Command and Scripting Interpreter: JavaScript"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0002_t1059_007.md")
  children = [
    detection.cross_site_scripting_angular_template,
    detection.cross_site_scripting_attribute_injection,
    detection.cross_site_scripting_common_patterns,
    detection.cross_site_scripting_dom_based,
    detection.cross_site_scripting_encoding,
    detection.cross_site_scripting_html_injection,
    detection.cross_site_scripting_javascript_methods,
    detection.cross_site_scripting_javascript_uri,
    detection.cross_site_scripting_script_tag
  ]

  tags = merge(local.mitre_attack_v161_ta0002_t1059_common_tags, {
    mitre_attack_technique_id = "T1059.007"
  })
} 