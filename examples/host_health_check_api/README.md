# Make your host health observable !

This example implements a simple web service using **Axum** that exposes a `/health` endpoint to check the compliance of the local host against an expected system configuration. The health check can be about packages, services, content of configuration files... whatever regent modules can offer. Instead of querying everything aside, have a local agent handling all of that and query this agent once. Attributes of the expected state are checked in parallel.

## Endpoints

- **GET `/health`**
  - Triggers a health check on the local system.
  - Returns a JSON-formatted `HealthCheckResponse` object indicating compliance status.

## Responses

```json
{
  "date": "2026-01-26T22:08:59+00:00",
  "status": {
    "NotCompliant": [
      "Service(start httpd)",
      "Service(enable httpd)"
    ]
  }
}
```
```json
{
  "date": "2026-01-26T22:25:07+00:00",
  "status": "Compliant"
}
```