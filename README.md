# Veilance Telemetry API

> **Development Status:** This project is still under active development and is not ready for production use.

This is the early Flask API used by Veilance to receive browser telemetry uploads.

The API accepts compressed telemetry data from the Veilance browser extension, validates the payload, performs basic duplicate detection, and stores accepted telemetry through the configured SQL backend.

## Current Features

* Flask-based REST API
* API versioning under `/api/v1`
* Client IP lookup endpoint
* Gzip-compressed telemetry uploads
* JSON payload validation
* Wallet address support
* Domain-based deduplication
* SQL-backed telemetry storage
* Standard Veilance JSON API responses

## API Endpoints

### Get Client IP

```http
GET /api/v1/telemetry/ip
```

Returns the IP address detected for the incoming request.

Example response:

```json
{
  "output": {
    "ok": true,
    "ip_address": "127.0.0.1"
  }
}
```

The exact response envelope depends on `settings.build_json_report()`.

---

### Upload Telemetry

```http
POST /api/v1/telemetry/upload
```

Telemetry uploads use `multipart/form-data`.

Expected fields:

```text
ip_address
client_id
wallet_address
domain_name
telemetry
```

The `telemetry` field must contain a gzip-compressed JSON file.

Example:

```bash
curl -X POST \
  -F "ip_address=127.0.0.1" \
  -F "client_id=example-client-id" \
  -F "wallet_address=example-wallet-address" \
  -F "domain_name=example.com" \
  -F "telemetry=@telemetry.json.gz;type=application/gzip" \
  http://127.0.0.1:5132/api/v1/telemetry/upload
```

## Telemetry Format

After decompression, the telemetry file must contain valid JSON with the following top-level fields:

```json
{
  "schemaVersion": "veilance.telemetry-snapshot-batch.v1",
  "batchId": "example-batch-id",
  "contributorId": "example-contributor-id",
  "observations": []
}
```

The current API validates that these fields exist:

```text
schemaVersion
batchId
contributorId
observations
```

More extensive schema validation is expected to be added as development continues.

## Upload Flow

The current upload process is:

```text
Browser Extension
      |
      | multipart/form-data
      v
Veilance API
      |
      +--> Read gzip telemetry file
      |
      +--> Decompress gzip
      |
      +--> Parse JSON
      |
      +--> Validate required fields
      |
      +--> Validate wallet/domain
      |
      +--> Check duplicate key
      |
      +--> Store telemetry in SQL
```

## Deduplication

The API currently creates a deduplication key from:

```python
settings.get_hash(domain_name)
```

and checks it using:

```python
sql.find_telemetry_by_deduplication_key(dedupe_key)
```

If the key already exists, the upload is rejected.

This implementation is still being developed and the deduplication strategy may change.

## Project Structure

The API currently depends on internal Veilance modules:

```text
lib/
├── connectors/
│   └── sql.py
└── settings.py
```

`lib.settings` handles functionality such as:

* API response formatting
* Client IP detection
* Hash generation

`lib.connectors.sql` handles telemetry database operations.

## Development

Install the required Python packages:

```bash
pip install flask flask-limiter
```

Additional database dependencies may be required depending on the SQL connector configuration.

Register the blueprint with the Flask application:

```python
app.register_blueprint(veilance_v1)
```

Then start the development server:

```python
app.run(
    host="0.0.0.0",
    port=5132,
    debug=True
)
```

## Security Notice

This API is currently intended for development and testing.

Before production deployment, additional work is expected around areas such as:

* Strict telemetry schema validation
* Upload size limits
* Rate limiting
* Authentication and abuse prevention
* Trusted proxy/IP handling
* Database constraints
* Duplicate detection
* Input length validation
* HTTPS enforcement
* Error handling
* Logging and monitoring

Do not treat the current implementation as a production-hardened telemetry ingestion service.

## Status

**Early development / unstable API**

Endpoints, telemetry formats, validation rules, database structure, and upload behavior may change without notice while Veilance development continues.

## Veilance

This API is part of the Veilance project and is intended to support privacy-focused browser observability and opt-in telemetry collection.
