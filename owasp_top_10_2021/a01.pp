locals {
  owasp_top_10_2021_a01_common_tags = merge(local.owasp_top_10_2021_common_tags, {
    owasp_top_10_version = "2021_a01"
  })
}

benchmark "owasp_top_10_2021_a01" {
  title         = "A01:2021 - Broken Access Control"
  description   = "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits."
  type          = "detection"
  documentation = file("./owasp_top_10_2021/docs/a01.md")
  children = [
    detection.encoded_path_traversal,
    detection.hidden_file_access,
    detection.os_file_access,
    detection.path_traversal,
    detection.restricted_file_access,
  ]

  tags = merge(local.owasp_top_10_2021_a01_common_tags, {
    type = "Benchmark"
  })
}
