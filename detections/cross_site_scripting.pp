locals {
  cross_site_scripting_common_tags = merge(local.nginx_access_log_detections_common_tags, {
    category = "Cross-Site Scripting"
  })
}

benchmark "cross_site_scripting_detections" {
  title       = "Cross-Site Scripting (XSS) Detections"
  description = "This benchmark contains cross-site scripting (XSS) focused detections when scanning access logs."
  type        = "detection"
  children = [
    detection.cross_site_scripting_angular_template,
    detection.cross_site_scripting_attribute_injection,
    detection.cross_site_scripting_common_patterns,
    detection.cross_site_scripting_dom_based,
    detection.cross_site_scripting_encoding,
    detection.cross_site_scripting_html_injection,
    detection.cross_site_scripting_javascript_methods,
    detection.cross_site_scripting_javascript_uri,
    detection.cross_site_scripting_script_tag,
  ]

  tags = merge(local.cross_site_scripting_common_tags, {
    type = "Benchmark"
  })
}

detection "cross_site_scripting_angular_template" {
  title           = "Cross-Site Scripting AngularJS Template"
  description     = "Detect potential AngularJS template injection attacks that can lead to Cross-Site Scripting in requests and User-Agent headers."
  documentation   = file("./detections/docs/cross_site_scripting_angular_template.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.cross_site_scripting_angular_template

  tags = merge(local.cross_site_scripting_common_tags, {
    mitre_attack_ids = "TA0002:T1059.007",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "cross_site_scripting_angular_template" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      (
        request_uri is not null
        and (
          -- Common AngularJS injection patterns
          request_uri ilike '%constructor.constructor%'
          or request_uri ilike '%$eval%'
          or request_uri ilike '%ng-init%'
          or request_uri ilike '%ng-bind%'
          or request_uri ilike '%ng-include%'
        )
      )
      OR
      (
        http_user_agent is not null
        and (
          -- Common AngularJS injection patterns
          http_user_agent ilike '%constructor.constructor%'
          or http_user_agent ilike '%$eval%'
          or http_user_agent ilike '%ng-init%'
          or http_user_agent ilike '%ng-bind%'
          or http_user_agent ilike '%ng-include%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cross_site_scripting_attribute_injection" {
  title           = "Cross-Site Scripting Attribute Injection"
  description     = "Detect Cross-Site Scripting attacks using HTML attribute injection, such as event handlers or dangerous attributes in requests and User-Agent headers."
  documentation   = file("./detections/docs/cross_site_scripting_attribute_injection.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.cross_site_scripting_attribute_injection

  tags = merge(local.cross_site_scripting_common_tags, {
    mitre_attack_ids = "TA0002:T1059.007",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "cross_site_scripting_attribute_injection" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      (
        request_uri is not null
        and (
          -- Attribute injection patterns
          request_uri ilike '%onerror=%'
          or request_uri ilike '%onload=%'
          or request_uri ilike '%onmouseover=%'
          or request_uri ilike '%onmouseout=%'
          or request_uri ilike '%onclick=%'
          or request_uri ilike '%onfocus=%'
          or request_uri ilike '%onblur=%'
          or request_uri ilike '%onchange=%'
          or request_uri ilike '%onsubmit=%'
          or request_uri ilike '%onkeypress=%'
          -- Less common event handlers
          or request_uri ilike '%onreadystatechange=%'
          or request_uri ilike '%onbeforeonload=%'
          or request_uri ilike '%onanimationstart=%'
          -- Dangerous attributes
          or request_uri ilike '%formaction=%'
          or request_uri ilike '%xlink:href=%'
          or request_uri ilike '%data:text/html%'
          or request_uri ilike '%pattern=%'
        )
      )
      OR
      (
        http_user_agent is not null
        and (
          -- Attribute injection patterns
          http_user_agent ilike '%onerror=%'
          or http_user_agent ilike '%onload=%'
          or http_user_agent ilike '%onmouseover=%'
          or http_user_agent ilike '%onmouseout=%'
          or http_user_agent ilike '%onclick=%'
          or http_user_agent ilike '%onfocus=%'
          or http_user_agent ilike '%onblur=%'
          or http_user_agent ilike '%onchange=%'
          or http_user_agent ilike '%onsubmit=%'
          or http_user_agent ilike '%onkeypress=%'
          -- Less common event handlers
          or http_user_agent ilike '%onreadystatechange=%'
          or http_user_agent ilike '%onbeforeonload=%'
          or http_user_agent ilike '%onanimationstart=%'
          -- Dangerous attributes
          or http_user_agent ilike '%formaction=%'
          or http_user_agent ilike '%xlink:href=%'
          or http_user_agent ilike '%data:text/html%'
          or http_user_agent ilike '%pattern=%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cross_site_scripting_encoding" {
  title           = "Cross-Site Scripting Encoding"
  description     = "Detect Cross-Site Scripting attacks using various encoding techniques to bypass filters in requests and User-Agent headers."
  documentation   = file("./detections/docs/cross_site_scripting_encoding.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.cross_site_scripting_encoding

  tags = merge(local.cross_site_scripting_common_tags, {
    mitre_attack_ids = "TA0002:T1059.007",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "cross_site_scripting_encoding" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      (
        request_uri is not null
        and (
          -- HTML entity encoding
          request_uri ilike '%&#x3C;script%' -- Hex entity encoded <script
          or request_uri ilike '%&#60;script%' -- Decimal entity encoded <script
          or request_uri ilike '%&#x3c;%&#x2f;script&#x3e;%' -- Hex encoded </script>
          or request_uri ilike '%&#x3c;img%&#x6f;nerror%' -- Hex encoded <img and onerror
          -- Base64 encoding
          or request_uri ilike '%data:text/html;base64,%'
          -- URL encoding
          or request_uri ilike '%\\u00%'
          or request_uri ilike '%\\x%'
          -- UTF-7 encoding (IE specific)
          or request_uri ilike '%+ADw-%'
        )
      )
      or
      (
        http_user_agent is not null
        and (
          -- HTML entity encoding
          http_user_agent ilike '%&#x3C;script%' -- Hex entity encoded <script
          or http_user_agent ilike '%&#60;script%' -- Decimal entity encoded <script
          or http_user_agent ilike '%&#x3c;%&#x2f;script&#x3e;%' -- Hex encoded </script>
          or http_user_agent ilike '%&#x3c;img%&#x6f;nerror%' -- Hex encoded <img and onerror
          -- Base64 encoding
          or http_user_agent ilike '%data:text/html;base64,%'
          -- URL encoding
          or http_user_agent ilike '%\\u00%'
          or http_user_agent ilike '%\\x%'
          -- UTF-7 encoding (IE specific)
          or http_user_agent ilike '%+ADw-%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cross_site_scripting_html_injection" {
  title           = "Cross-Site Scripting HTML Injection"
  description     = "Detect Cross-Site Scripting attacks using HTML tag injection that may execute JavaScript in requests and User-Agent headers."
  documentation   = file("./detections/docs/cross_site_scripting_html_injection.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.cross_site_scripting_html_injection

  tags = merge(local.cross_site_scripting_common_tags, {
    mitre_attack_ids = "TA0002:T1059.007",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "cross_site_scripting_html_injection" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      (
        request_uri is not null
        and (
          -- Common HTML tags that can be used for XSS
          request_uri ilike '%<iframe%src=%'
          or request_uri ilike '%<img%src=%' and (
              request_uri ilike '%onerror=%' 
              or request_uri ilike '%onload=%'
          )
          or request_uri ilike '%<svg%on%=' -- SVG with event handlers
          or request_uri ilike '%<svg><script%' -- SVG containing script
          or request_uri ilike '%<object%data=%' and request_uri not ilike '%application/pdf%'
          or request_uri ilike '%<embed%src=%' and request_uri not ilike '%application/pdf%'
          or request_uri ilike '%<video%src=%' and (
              request_uri ilike '%onerror=%' 
              or request_uri ilike '%onload=%'
          )
          or request_uri ilike '%<audio%src=%' and (
              request_uri ilike '%onerror=%' 
              or request_uri ilike '%onload=%'
          )
        )
      )
      or
      (
        http_user_agent is not null
        and (
          -- Common HTML tags that can be used for XSS
          http_user_agent ilike '%<iframe%src=%'
          or http_user_agent ilike '%<img%src=%' and (
              http_user_agent ilike '%onerror=%' 
              or http_user_agent ilike '%onload=%'
          )
          or http_user_agent ilike '%<svg%on%=' -- SVG with event handlers
          or http_user_agent ilike '%<svg><script%' -- SVG containing script
          or http_user_agent ilike '%<object%data=%' and http_user_agent not ilike '%application/pdf%'
          or http_user_agent ilike '%<embed%src=%' and http_user_agent not ilike '%application/pdf%'
          or http_user_agent ilike '%<video%src=%' and (
              http_user_agent ilike '%onerror=%' 
              or http_user_agent ilike '%onload=%'
          )
          or http_user_agent ilike '%<audio%src=%' and (
              http_user_agent ilike '%onerror=%' 
              or http_user_agent ilike '%onload=%'
          )
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cross_site_scripting_javascript_methods" {
  title           = "Cross-Site Scripting JavaScript Methods"
  description     = "Detect Cross-Site Scripting attacks using dangerous JavaScript methods like eval(), setTimeout(), and Function() in requests and User-Agent headers."
  documentation   = file("./detections/docs/cross_site_scripting_javascript_methods.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.cross_site_scripting_javascript_methods

  tags = merge(local.cross_site_scripting_common_tags, {
    mitre_attack_ids = "TA0002:T1059.007",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "cross_site_scripting_javascript_methods" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      (
        request_uri is not null
        and (
          -- JavaScript method patterns
          request_uri ilike '%eval(%'
          or request_uri ilike '%setTimeout(%'
          or request_uri ilike '%setInterval(%'
          or request_uri ilike '%Function(%'
          or request_uri ilike '%fetch(%'
          or request_uri ilike '%document.write%'
          or request_uri ilike '%document.cookie%'
        )
      )
      or
      (
        http_user_agent is not null
        and (
          -- JavaScript method patterns
          http_user_agent ilike '%eval(%'
          or http_user_agent ilike '%setTimeout(%'
          or http_user_agent ilike '%setInterval(%'
          or http_user_agent ilike '%Function(%'
          or http_user_agent ilike '%fetch(%'
          or http_user_agent ilike '%document.write%'
          or http_user_agent ilike '%document.cookie%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cross_site_scripting_javascript_uri" {
  title           = "Cross-Site Scripting JavaScript URI"
  description     = "Detect Cross-Site Scripting attacks using javascript: URI schemes in attributes like href or src in requests and User-Agent headers."
  documentation   = file("./detections/docs/cross_site_scripting_javascript_uri.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.cross_site_scripting_javascript_uri

  tags = merge(local.cross_site_scripting_common_tags, {
    mitre_attack_ids = "TA0002:T1059.007",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "cross_site_scripting_javascript_uri" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      (
        request_uri is not null
        and (
          -- JavaScript URI schemes
          request_uri ilike '%javascript:%'
          or request_uri ilike '%vbscript:%'
          -- Obfuscated javascript: URIs
          or request_uri ilike '%jav&#x0A;ascript:%'
          or request_uri ilike '%javascript:url(%'
        )
      )
      or
      (
        http_user_agent is not null
        and (
          -- JavaScript URI schemes
          http_user_agent ilike '%javascript:%'
          or http_user_agent ilike '%vbscript:%'
          -- Obfuscated javascript: URIs
          or http_user_agent ilike '%jav&#x0A;ascript:%'
          or http_user_agent ilike '%javascript:url(%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cross_site_scripting_script_tag" {
  title           = "Cross-Site Scripting Script Tag"
  description     = "Detect Cross-Site Scripting attacks using script tags to execute arbitrary JavaScript code in requests and User-Agent headers."
  documentation   = file("./detections/docs/cross_site_scripting_script_tag.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.cross_site_scripting_script_tag

  tags = merge(local.cross_site_scripting_common_tags, {
    mitre_attack_ids = "TA0002:T1059.007",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "cross_site_scripting_script_tag" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      (
        request_uri is not null
        and (
          -- Standard script tags
          request_uri ilike '%<script>%'
          or request_uri ilike '%<script%src%'
          or request_uri ilike '%<script/%'
          -- Obfuscated script tags
          or request_uri ilike '%<scr%ipt%'
          or request_uri ilike '%<scr\\x00ipt%'
          or request_uri ilike '%<s%00cript%'
        )
      )
      OR
      (
        http_user_agent is not null
        and (
          -- Standard script tags
          http_user_agent ilike '%<script>%'
          or http_user_agent ilike '%<script%src%'
          or http_user_agent ilike '%<script/%'
          -- Obfuscated script tags
          or http_user_agent ilike '%<scr%ipt%'
          or http_user_agent ilike '%<scr\\x00ipt%'
          or http_user_agent ilike '%<s%00cript%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cross_site_scripting_common_patterns" {
  title           = "Cross-Site Scripting Common Patterns"
  description     = "Detect basic Cross-Site Scripting (XSS) attack patterns in HTTP requests and User-Agent headers."
  documentation   = file("./detections/docs/cross_site_scripting_common_patterns.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.cross_site_scripting_common_patterns

  tags = merge(local.cross_site_scripting_common_tags, {
    mitre_attack_ids = "TA0002:T1059.007",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "cross_site_scripting_common_patterns" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      (
        request_uri is not null
        and (
          -- Common XSS patterns
          request_uri ilike '%alert(%'
          or request_uri ilike '%prompt(%'
          or request_uri ilike '%confirm(%'
          or request_uri ilike '%eval(%'
          or request_uri ilike '%document.cookie%'
          or request_uri ilike '%document.domain%'
          or request_uri ilike '%document.write%'
          -- URL encoded variants
          or request_uri ilike '%&#x3C;script%'
          or request_uri ilike '%\\x3Cscript%'
        )
      )
      OR
      (
        http_user_agent is not null
        and (
          -- Common XSS patterns
          http_user_agent ilike '%alert(%'
          or http_user_agent ilike '%prompt(%'
          or http_user_agent ilike '%confirm(%'
          or http_user_agent ilike '%eval(%'
          or http_user_agent ilike '%document.cookie%'
          or http_user_agent ilike '%document.domain%'
          or http_user_agent ilike '%document.write%'
          -- URL encoded variants
          or http_user_agent ilike '%&#x3C;script%'
          or http_user_agent ilike '%\\x3Cscript%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cross_site_scripting_dom_based" {
  title           = "Cross-Site Scripting DOM Based"
  description     = "Detect potential DOM-based Cross-Site Scripting attacks targeting JavaScript DOM manipulation in requests and User-Agent headers."
  documentation   = file("./detections/docs/cross_site_scripting_dom_based.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.cross_site_scripting_dom_based

  tags = merge(local.cross_site_scripting_common_tags, {
    mitre_attack_ids = "TA0002:T1059.007",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "cross_site_scripting_dom_based" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      nginx_access_log
    where
      (
        request_uri is not null
        and (
          -- DOM manipulation methods
          request_uri ilike '%document.getElementById%'
          or request_uri ilike '%document.querySelector%'
          or request_uri ilike '%document.write%'
          or request_uri ilike '%innerHTML%'
          or request_uri ilike '%outerHTML%'
          or request_uri ilike '%document.location%'
          or request_uri ilike '%window.location%'
          or request_uri ilike '%document.URL%'
          or request_uri ilike '%document.documentURI%'
          or request_uri ilike '%document.referrer%'
          or request_uri ilike '%window.name%'
          or request_uri ilike '%location.hash%'
          or request_uri ilike '%location.search%'
          or request_uri ilike '%location.href%'
        )
      )
      or
      (
        http_user_agent is not null
        and (
          -- DOM manipulation methods
          http_user_agent ilike '%document.getElementById%'
          or http_user_agent ilike '%document.querySelector%'
          or http_user_agent ilike '%document.write%'
          or http_user_agent ilike '%innerHTML%'
          or http_user_agent ilike '%outerHTML%'
          or http_user_agent ilike '%document.location%'
          or http_user_agent ilike '%window.location%'
          or http_user_agent ilike '%document.URL%'
          or http_user_agent ilike '%document.documentURI%'
          or http_user_agent ilike '%document.referrer%'
          or http_user_agent ilike '%window.name%'
          or http_user_agent ilike '%location.hash%'
          or http_user_agent ilike '%location.search%'
          or http_user_agent ilike '%location.href%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
} 