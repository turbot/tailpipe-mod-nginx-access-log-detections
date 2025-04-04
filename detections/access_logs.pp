benchmark "access_log_detections" {
  title       = "Access Log Detections"
  description = "This benchmark contains detections for security, operational, performance, and compliance issues when analyzing access logs."
  type        = "detection"
  children = [
    benchmark.security_detections,
    benchmark.operational_detections,
    benchmark.performance_detections,
  ]

  tags = merge(local.nginx_access_log_detections_common_tags, {
    type = "Benchmark"
  })
}
