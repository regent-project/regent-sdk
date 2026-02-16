# Make your host health observable !

In this example, we have a binary running on the target host which makes it observable by exposing a webserver and a `/health` route. Whenever this route is called, the binary runs a compliance check on its host and responds accordingly.

## Endpoints

- **GET `/health`**
  - Triggers a health check on the local system.
  - Returns a JSON-formatted `HealthCheckResponse` object indicating compliance status.

## Responses

### Host compliant

Status code : 200

```json
{
  "date": "2026-01-27T20:17:56+00:00",
  "status": "Compliant",
  "remediations": []
}
```
### Host not compliant
Status code : 422

```json
{
  "date": "2026-01-27T20:17:10+00:00",
  "status": "NotCompliant",
  "remediations": [
    "Start service httpd",
    "Enable service httpd"
  ]
}
```