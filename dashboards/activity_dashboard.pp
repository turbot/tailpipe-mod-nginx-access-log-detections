dashboard "activity_dashboard" {
  title = "Nginx Log Activity Dashboard"

  tags = {
    type = "Dashboard"
    service = "Nginx"
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
      query = query.activity_dashboard_bad_request_count
      width = 2
      type  = "info"
    }

    card {
      query = query.activity_dashboard_error_count
      width = 2
      type  = "alert"
    }
  }

  container {
    chart {
      title = "Top 10 Clients (Request Count)"
      query = query.activity_dashboard_top_10_clients
      width = 6
      type  = "table"
    }

    chart {
      title = "Top 10 URIs (Request Count)"
      query = query.activity_dashboard_top_10_urls
      width = 6
      type  = "table"
    }

    chart {
      title = "Status Code Distribution"
      query = query.activity_dashboard_status_distribution
      width = 6
      type  = "pie"
    }

    chart {
      title = "Top 10 Slowest Endpoints"
      query = query.activity_dashboard_slowest_endpoints
      width = 6
      type  = "table"
    }
  }

  container {
    chart {
      title = "Requests by Hour of Day"
      query = query.activity_dashboard_requests_by_hour
      width = 6
      type  = "column"
    }

    chart {
      title = "Requests by Day of Week"
      query = query.activity_dashboard_requests_by_day
      width = 6
      type  = "bar"
    }
  }

  container {
    chart {
      title = "Request Volume Over Time"
      query = query.activity_dashboard_request_volume
      width = 12
      type  = "line"
      display = "line"
    }
  }
}

# Queries
query "activity_dashboard_total_logs" {
  sql = <<-EOQ
    select
      count(*) as "Total Requests"
    from 
      nginx_access_log;
  EOQ
}

query "activity_dashboard_success_count" {
  sql = <<-EOQ
    select
      count(*) as "Successful (200-399)"
    from 
      nginx_access_log
    where
      status between 200 and 399;
  EOQ
}

query "activity_dashboard_bad_request_count" {
  sql = <<-EOQ
    select
      count(*) as "Bad Requests (400-499)"
    from 
      nginx_access_log
    where
      status between 400 and 499;
  EOQ
}

query "activity_dashboard_error_count" {
  sql = <<-EOQ
    select
      count(*) as "Server Errors (500-599)"
    from 
      nginx_access_log
    where
      status between 500 and 599;
  EOQ
}

query "activity_dashboard_top_10_clients" {
  sql = <<-EOQ
    select
      remote_addr as "Client IP",
      count(*) as "Request Count"
    from
      nginx_access_log
    group by
      remote_addr
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "activity_dashboard_top_10_urls" {
  sql = <<-EOQ
    select
      request_uri as "URL",
      count(*) as "Request Count"
    from
      nginx_access_log
    group by
      request_uri
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "activity_dashboard_requests_by_hour" {
  sql = <<-EOQ
    select
      extract(hour from tp_timestamp) as "Hour",
      count(*) as "Request Count"
    from
      nginx_access_log
    group by
      extract(hour from tp_timestamp)
    order by
      extract(hour from tp_timestamp);
  EOQ
}

query "activity_dashboard_requests_by_day" {
  sql = <<-EOQ
    select
      case extract(dow from tp_timestamp)
        when 0 then 'Sunday'
        when 1 then 'Monday'
        when 2 then 'Tuesday'
        when 3 then 'Wednesday'
        when 4 then 'Thursday'
        when 5 then 'Friday'
        when 6 then 'Saturday'
      end as "Day of Week",
      count(*) as "Request Count"
    from
      nginx_access_log
    group by
      extract(dow from tp_timestamp)
    order by
      extract(dow from tp_timestamp);
  EOQ
}

query "activity_dashboard_request_volume" {
  sql = <<-EOQ
    select
      strftime(tp_timestamp, '%Y-%m-%d') as "Date",
      count(*) as "Daily Requests"
    from
      nginx_access_log
    group by
      strftime(tp_timestamp, '%Y-%m-%d')
    order by
      strftime(tp_timestamp, '%Y-%m-%d') asc;
  EOQ
}

query "activity_dashboard_status_distribution" {
  sql = <<-EOQ
    select
      case
        when status between 200 and 299 then '2xx Success'
        when status between 300 and 399 then '3xx Redirect'
        when status between 400 and 499 then '4xx Client Error'
        when status between 500 and 599 then '5xx Server Error'
        else 'Other'
      end as "Status Category",
      count(*) as "Count"
    from
      nginx_access_log
    group by
      case
        when status between 200 and 299 then '2xx Success'
        when status between 300 and 399 then '3xx Redirect'
        when status between 400 and 499 then '4xx Client Error'
        when status between 500 and 599 then '5xx Server Error'
        else 'Other'
      end;
  EOQ
}

query "activity_dashboard_slowest_endpoints" {
  sql = <<-EOQ
    select
      request_uri as "Endpoint",
      case 
        when avg(request_time) < 1 then round(avg(request_time) * 1000)::text || 'ms'
        else round(avg(request_time), 1)::text || 's'
      end as "Avg Response Time",
      count(*) as "Request Count"
    from
      nginx_access_log
    group by
      request_uri
    having
      count(*) > 10  -- Only show endpoints with more than 10 requests
    order by
      avg(request_time) desc
    limit 10;
  EOQ
}
