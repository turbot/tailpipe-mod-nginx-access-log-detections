dashboard "activity_dashboard" {
  title         = "Access Log Activity Dashboard"
  documentation = file("./dashboards/docs/activity_dashboard.md")

  tags = {
    type    = "Dashboard"
    service = "Nginx/AccessLog"
  }

  container {
    # Analysis
    card {
      query = query.activity_dashboard_total_logs
      width = 2
    }

    card {
      query = query.activity_dashboard_success_count
      width = 2
      type  = "ok"
    }

    card {
      query = query.activity_dashboard_redirect_count
      width = 2
      type  = "info"
    }

    card {
      query = query.activity_dashboard_bad_request_count
      width = 2
      type  = "alert"
    }

    card {
      query = query.activity_dashboard_error_count
      width = 2
      type  = "alert"
    }
  }

  container {
    chart {
      title = "Requests by Day"
      query = query.activity_dashboard_requests_by_day
      width = 6
      type  = "line"
    }

    chart {
      title = "Requests by HTTP Method"
      query = query.activity_dashboard_requests_by_http_method
      width = 6
      type  = "bar"
    }

    chart {
      title = "Requests by Status Code"
      query = query.activity_dashboard_requests_by_status_code
      width = 6
      type  = "pie"
    }

    chart {
      title = "Top 10 User Agents (Requests)"
      query = query.activity_dashboard_requests_by_user_agent
      width = 6
      type  = "pie"
    }

    chart {
      title = "Top 10 Clients (Requests)"
      query = query.activity_dashboard_top_10_clients
      width = 6
      type  = "table"
    }

    chart {
      title = "Top 10 URLs (Requests)"
      query = query.activity_dashboard_top_10_urls
      width = 6
      type  = "table"
    }

    chart {
      title = "Top 10 URLs (Successful Requests)"
      query = query.activity_dashboard_requests_by_successful_requests
      width = 6
      type  = "table"
    }

    chart {
      title = "Top 10 URLs (Errors)"
      query = query.activity_dashboard_requests_by_errors
      width = 6
      type  = "table"
    }
  }
}

# Queries
query "activity_dashboard_total_logs" {
  title       = "Log Count"
  description = "Count the total Nginx log entries."

  sql = <<-EOQ
    select
      count(*) as "Total Requests"
    from
      nginx_access_log;
  EOQ
}

query "activity_dashboard_success_count" {
  title       = "Successful Request Count"
  description = "Count of successful HTTP requests (status 2xx)."

  sql = <<-EOQ
    select
      count(*) as "Successful (2xx)"
    from
      nginx_access_log
    where
      status between 200 and 299;
  EOQ
}

query "activity_dashboard_redirect_count" {
  title       = "Redirect Request Count"
  description = "Count of redirect HTTP requests (status 3xx)."

  sql = <<-EOQ
    select
      count(*) as "Redirections (3xx)"
    from
      nginx_access_log
    where
      status between 300 and 399;
  EOQ
}

query "activity_dashboard_bad_request_count" {
  title       = "Bad Request Count"
  description = "Count of client error HTTP requests (status 4xx)."

  sql = <<-EOQ
    select
      count(*) as "Bad Requests (4xx)"
    from
      nginx_access_log
    where
      status between 400 and 499;
  EOQ
}

query "activity_dashboard_error_count" {
  title       = "Server Error Count"
  description = "Count of server error HTTP requests (status 5xx)."

  sql = <<-EOQ
    select
      count(*) as "Server Errors (5xx)"
    from
      nginx_access_log
    where
      status between 500 and 599;
  EOQ
}

query "activity_dashboard_top_10_clients" {
  title       = "Top 10 Clients (Requests)"
  description = "List the top 10 client IPs by request count."

  sql = <<-EOQ
    select
      remote_addr as "Client IP",
      count(*) as "Request Count"
    from
      nginx_access_log
    group by
      remote_addr
    order by
      count(*) desc,
      remote_addr
    limit 10;
  EOQ
}

query "activity_dashboard_top_10_urls" {
  title       = "Top 10 URLs (Requests)"
  description = "List the top 10 requested URLs by request count."

  sql = <<-EOQ
    select
      request_uri as "URL",
      count(*) as "Request Count"
    from
      nginx_access_log
    where
      request_uri is not null
    group by
      request_uri
    order by
      count(*) desc,
      request_uri
    limit 10;
  EOQ
}

query "activity_dashboard_requests_by_day" {
  title       = "Requests by Day"
  description = "Count of requests grouped by day."

  sql = <<-EOQ
    select
      strftime(tp_timestamp, '%Y-%m-%d') as "Date",
      count(*) as "Request Count"
    from
      nginx_access_log
    group by
      strftime(tp_timestamp, '%Y-%m-%d')
    order by
      strftime(tp_timestamp, '%Y-%m-%d');
  EOQ
}

query "activity_dashboard_requests_by_status_code" {
  title       = "Requests by Status Code"
  description = "Count of rqeuests grouped by status code."

  sql = <<-EOQ
    select
      case
        when status between 200 and 299 then '2xx Success'
        when status between 300 and 399 then '3xx Redirect'
        when status between 400 and 499 then '4xx Client Error'
        when status between 500 and 599 then '5xx Server Error'
        else 'Other'
      end as "Status Category",
      count(*) as "Request Count"
    from
      nginx_access_log
    where
      status is not null
    group by
      "Status Category"
    order by
      "Status Category";
  EOQ
}

query "activity_dashboard_requests_by_http_method" {
  title       = "Requests by HTTP Method"
  description = "Distribution of HTTP methods used in requests."

  sql = <<-EOQ
    select
      request_method as "HTTP Method",
      count(*) as "Request Count"
    from
      nginx_access_log
    where
      request_method is not null
    group by
      request_method
    order by
      count(*) asc,
      request_method;
  EOQ
}

query "activity_dashboard_requests_by_successful_requests" {
  title       = "Top 10 URLs (Successful Requests)"
  description = "List the top 10 requested URLs by successful request count."

  sql = <<-EOQ
    select
      request_uri as "Path",
      count(*) as "Request Count",
      string_agg(distinct status::text, ', ' order by status::text) as "Status Codes"
    from
      nginx_access_log
    where
      status between 200 and 299
      and request_uri is not null
    group by
      request_uri
    order by
      count(*) desc,
      request_uri
    limit 10;
  EOQ
}

query "activity_dashboard_requests_by_errors" {
  title       = "Top 10 URLs (Errors)"
  description = "List the top 10 requested URLs by error count."

  sql = <<-EOQ
    select
      request_uri as "Path",
      count(*) as "Error Count",
      string_agg(distinct status::text, ', ' order by status::text) as "Status Codes"
    from
      nginx_access_log
    where
      status between 400 and 599
      and request_uri is not null
    group by
      request_uri
    order by
      count(*) desc,
      request_uri
    limit 10;
  EOQ
}

query "activity_dashboard_requests_by_user_agent" {
  title       = "Top 10 User Agents (Requests)"
  description = "Distribution of user agents in requests."

  sql = <<-EOQ
    select
      http_user_agent as "User Agent",
      count(*) as "Request Count"
    from
      nginx_access_log
    where
      http_user_agent is not null
    group by
      http_user_agent
    order by
      count(*) desc,
      http_user_agent
    limit 10;
  EOQ
}
