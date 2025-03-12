locals {
  nginx_access_log_detections_common_tags = {
    category = "Detections"
    plugin   = "nginx"
    service  = "Nginx/AccessLog"
  }
}

