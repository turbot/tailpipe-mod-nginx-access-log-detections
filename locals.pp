locals {
  nginx_access_log_detections_common_tags = {
    category = "Detections"
    plugin   = "nginx"
    service  = "Nginx/AccessLog"
  }
}


locals {
  # Local internal variables to build the SQL select clause for common
  # dimensions. Do not edit directly.
  detection_sql_columns = <<-EOQ
  tp_timestamp as timestamp,
  request_method || ' ' || request_uri as operation,
  tp_source_ip as source_ip,
  server_name as server,
  tp_id as detection_id,
  *
  EOQ
}

locals {
  # Local internal variables to build the SQL select clause for common
  # dimensions. Do not edit directly.
  detection_display_columns = [
    "timestamp",
    "request_method",
    "request_uri",
    "tp_source_ip",
    "status",
    "server_name",
  ]
}