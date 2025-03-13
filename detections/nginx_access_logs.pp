benchmark "nginx_access_log_detections" {
  title       = "Nginx Access Log Detections"
  description = "This benchmark contains recommendations when scanning Nginx access logs."
  type        = "detection"
  children = [
    benchmark.nginx_security_detections,
    benchmark.nginx_operational_detections,
    benchmark.nginx_performance_detections,
    benchmark.nginx_compliance_detections
  ]

  tags = merge(local.nginx_access_log_detections_common_tags, {
    type = "Benchmark"
  })
}
