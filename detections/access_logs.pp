benchmark "access_log_detections" {
  title       = "Access Log Detections"
  description = "This benchmark contains recommendations when scanning Nginx access logs."
  type        = "detection"
  children = [
    benchmark.cross_site_scripting_detections,
    benchmark.local_file_inclusion_detections,
    benchmark.remote_command_execution_detections,
    benchmark.sql_injection_detections,
  ]

  tags = merge(local.nginx_access_log_detections_common_tags, {
    type = "Benchmark"
  })
} 