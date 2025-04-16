locals {
  owasp_top_10_2021_a03_common_tags = merge(local.owasp_top_10_2021_common_tags, {
    owasp_top_10_version = "2021_a03"
  })
}

benchmark "owasp_top_10_2021_a03" {
  title         = "A03:2021 - Injection"
  description   = "Injection slides down to the third position. 94% of the applications were tested for some form of injection with a max incidence rate of 19%, an average incidence rate of 3%, and 274k occurrences."
  type          = "detection"
  documentation = file("./owasp_top_10_2021/docs/a01.md")
  children = [
    # SQL Injection detections
    detection.sql_injection_blind_based,
    detection.sql_injection_common_patterns,
    detection.sql_injection_error_based,
    detection.sql_injection_time_based,
    detection.sql_injection_union_based,
    detection.sql_injection_user_agent_based,

    # Cross-Site Scripting detections (explicitly tagged with A03)
    detection.cross_site_scripting_angular_template,
    detection.cross_site_scripting_attribute_injection,
    detection.cross_site_scripting_common_patterns,
    detection.cross_site_scripting_dom_based,
    detection.cross_site_scripting_encoding,
    detection.cross_site_scripting_html_injection,
    detection.cross_site_scripting_javascript_methods,
    detection.cross_site_scripting_javascript_uri,
    detection.cross_site_scripting_script_tag,

    # Remote Command Execution detections
    detection.log4shell_vulnerability,
    detection.spring4shell_vulnerability
  ]

  tags = merge(local.owasp_top_10_2021_a03_common_tags, {
    type = "Benchmark"
  })
}
