# OAuth Debug Implementation for app-logs-by-ip

## Summary

Successfully implemented full OAuth debug logging that appears in `just app-logs-by-ip` command output.

## Changes Made

### 1. Enhanced RequestLogger Integration (src/shared/logging.py)

#### Request Logging Enhancement
```python
# Pass ALL log_data to RequestLogger for full visibility in app-logs-by-ip
request_key = await request_logger.log_request(
    ip=ip,
    hostname=log_data.get("hostname", ""),
    method=log_data.get("method", ""),
    path=log_data.get("path", ""),
    query=log_data.get("query", ""),
    user_agent=log_data.get("user_agent", ""),
    auth_user=extra_context.get("auth_user"),
    referer=log_data.get("referer", ""),
    # Include ALL enhanced logging data for OAuth debugging
    request_body=log_data.get("request_body", ""),
    request_body_size=log_data.get("request_body_size", 0),
    request_body_truncated=log_data.get("request_body_truncated", False),
    request_form_data=log_data.get("request_form_data", {}),
    critical_headers=log_data.get("critical_headers", {}),
    is_critical_endpoint=log_data.get("is_critical_endpoint", False),
    **{k: v for k, v in extra_context.items() if k not in ["hostname", "auth_user"]}
)
```

#### Response Logging Enhancement
```python
# Pass ALL enhanced OAuth response data for app-logs-by-ip visibility
await request_logger.log_response(
    ip=ip,
    status=log_data.get("status", 0),
    duration_ms=duration_ms,
    response_size=len(log_data.get("response_body", "")),
    error=error,
    # Include ALL enhanced OAuth debugging data
    response_body=log_data.get("response_body", ""),
    response_body_size=log_data.get("response_body_size", 0),
    response_body_truncated=log_data.get("response_body_truncated", False),
    response_json=log_data.get("response_json", {}),
    response_json_masked=log_data.get("response_json_masked", {}),
    critical_response_headers=log_data.get("critical_response_headers", {}),
    oauth_failure_analysis=log_data.get("oauth_failure_analysis", {}),
    is_critical_endpoint=log_data.get("is_critical_endpoint", False),
    hostname=extra_context.get("hostname", ""),
    path=extra_context.get("path", ""),
    **{k: v for k, v in extra_context.items() if k not in ["ip", "status", "hostname", "path"]}
)
```

### 2. Enhanced Justfile app-logs-by-ip Display

Updated the jq formatting to show OAuth debug fields:

```bash
# Show critical endpoint flag
(if .is_critical_endpoint then " [CRITICAL]" else "" end) +
# Show request body for OAuth endpoints
(if .request_body and (.request_body | length) > 0 and (.request_body | length) < 200 then 
    " body=" + .request_body 
 else "" end) +
# Show form data for token endpoint
(if .request_form_data and (.request_form_data | length) > 0 then 
    " form_data=" + (.request_form_data | tojson | .[0:100])
 else "" end) +
# Show critical headers
(if .critical_headers and (.critical_headers | length) > 0 then
    " headers=" + (.critical_headers | to_entries | map(.key + ":" + (.value | .[0:20])) | join(","))
 else "" end) +
# Show response body for errors
(if .response_body and .status >= 400 and (.response_body | length) < 300 then 
    " response=" + .response_body 
 else "" end) +
# Show OAuth failure analysis
(if .oauth_failure_analysis then 
    " oauth_fail=" + (.oauth_failure_analysis | tojson | .[0:100])
 else "" end) +
# Show error details
(if .error and .error.message then 
    " error=" + .error.message
 else "" end)
```

## Result

Now `just app-logs-by-ip <ip>` shows:

1. **Error Messages**: Full error text for 4xx/5xx responses
2. **OAuth Flow Markers**: [OAuth:token], [OAuth:mcp], etc.
3. **Critical Endpoint Flags**: [CRITICAL] for important endpoints
4. **Request Bodies**: For OAuth/MCP endpoints (when small enough)
5. **Form Data**: OAuth token exchange parameters
6. **Headers**: Critical headers like Authorization (masked)
7. **Response Bodies**: For error responses
8. **OAuth Failure Analysis**: Detailed failure context

## Example Output

```
2025-08-03 18:04:56Z [ERROR] everything.atradev.org 34.162.142.92 -> 503 (13.28ms) error=Token not valid for everything.atradev.org. Please re-authenticate with this resource.
2025-08-03 17:38:18Z [ERROR] auth.atradev.org 34.162.142.92 -> 500 (8.0ms) error=Proxy error: object of type 'async_generator' has no len()
2025-08-03 18:19:02Z [INFO] auth.atradev.org 34.162.102.82 - POST /token [OAuth:token_exchange]
```

## Key Insight

The crucial fix was ensuring ALL enhanced logging data from structlog was passed to RequestLogger's `log_request()` and `log_response()` methods. The RequestLogger already supported arbitrary **extra_fields, but the logging.py module wasn't passing the enhanced OAuth data through.

## Next Steps

The enhanced logging now provides full visibility into OAuth flows through the standard `just app-logs-by-ip` command, making it easy to debug authentication issues without requiring special commands or direct log access.