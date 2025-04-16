mod "nginx_access_log_detections" {
  # hub metadata
  title         = "Nginx Access Log Detections"
  description   = "Search your Nginx access logs for high risk actions using Tailpipe."
  color         = "#009900"
  documentation = file("./docs/index.md")
  icon          = "/images/mods/turbot/nginx-access-log-detections.svg"
  categories    = ["nginx", "dashboard", "detections"]
  database      = var.database

  opengraph {
    title       = "Tailpipe Mod for Nginx Access Log Detections"
    description = "Search your Nginx access logs for high risk actions using Tailpipe."
    image       = "/images/mods/turbot/nginx-access-log-detections-social-graphic.png"
  }
}
