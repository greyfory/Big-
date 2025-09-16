# Big-

**Military-safe Auto-Allow for Pi-hole (ultra-deterministic, AI-formatted, all integrations)**

This repository contains a complete implementation of a secure, deterministic auto-allow system for Pi-hole that enables users to approve blocked domains via browser extensions while maintaining strict security controls through threat intelligence, heuristics, and human confirmation.

## Overview

The system provides:
- **Secure domain approval** via browser extension with device authentication
- **Threat intelligence integration** with multiple security feeds
- **Time-limited allows** with automatic expiry
- **Spike detection** and auto-revocation capabilities
- **Optional Unbound integration** for hot-blocking
- **Comprehensive audit logging** in JSONL format
- **Deterministic behavior** with no randomness

## Implementation

The complete system is implemented in `autoallowmonolith.py` - a single, self-contained Python script that includes:

- Configuration management with YAML
- Flask web server for mediation API
- Pi-hole API integration
- Threat intelligence feed updater
- TTL expiry system
- Installation and deployment scripts
- Systemd and cron integration

## Quick Start

1. **Install the system:**
   ```bash
   sudo python3 autoallowmonolith.py install
   ```

2. **Configure authentication:**
   Edit `/etc/pihole/autoallow/config.yaml` and update:
   - `pihole.token` - Your Pi-hole API token
   - `auth.device_tokens` - Strong tokens for each device

3. **Enable the service:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now piautoallow
   ```

4. **Update threat intelligence:**
   ```bash
   sudo python3 autoallowmonolith.py update-ti
   ```

5. **Test the service:**
   ```bash
   curl -s http://127.0.0.1:8787/status
   ```

## API Endpoints

### POST /approve
Approve a blocked domain for temporary access.

**Request:**
```json
{
  "domain": "example.com",
  "device": "my-laptop", 
  "token": "device-specific-token",
  "ttl_hours": 4
}
```

**Response:**
```json
{
  "ok": true,
  "domain": "example.com", 
  "ttl_hours": 4
}
```

### POST /revoke  
Manually revoke access to a domain.

**Request:**
```json
{
  "domain": "example.com",
  "device": "my-laptop",
  "token": "device-specific-token"
}
```

### GET /status
Get system status and configuration.

**Response:**
```json
{
  "ok": true,
  "now": 1234567890.123,
  "ti_loaded": 50000,
  "config": {...}
}
```

## Security Features

- **Authentication**: Device-specific tokens required for all operations
- **Threat Intelligence**: Automatic blocking of domains in security feeds
- **Heuristics**: Punycode detection, long label rejection
- **Rate limiting**: Cooldown periods between requests
- **Human confirmation**: Optional manual approval prompts
- **Audit logging**: Complete JSONL audit trail
- **Auto-expiry**: Time-limited allows with automatic cleanup
- **Spike detection**: Automatic revocation on suspicious activity

## Configuration

The system uses `/etc/pihole/autoallow/config.yaml` for configuration. Key settings:

```yaml
pihole:
  url: "http://127.0.0.1/admin/api.php"
  token: "YOUR_PIHOLE_API_TOKEN"

auth:
  device_tokens:
    laptop: "strong-random-token-1"
    phone: "strong-random-token-2"

approval:
  mode: "prompt"  # or "autoifcleanandtrusted"
  prompt_timeout: 60

thresholds:
  cooldown_seconds: 300
  default_ttl_hours: 4
  post_spike_ratio: 8.0
```

## Installation Details

The install command automatically:
- Installs Python dependencies (Flask, PyYAML, requests)
- Creates configuration files with secure defaults
- Sets up systemd service for automatic startup
- Configures cron jobs for threat intel updates and TTL cleanup
- Creates Unbound integration files (optional)

## Commands

- `sudo python3 autoallowmonolith.py install` - Install and configure system
- `python3 autoallowmonolith.py run` - Run mediator server
- `sudo python3 autoallowmonolith.py update-ti` - Update threat intelligence
- `sudo python3 autoallowmonolith.py expire` - Process TTL expiries
- `sudo python3 autoallowmonolith.py revoke <domain>` - Manual domain revocation

## Browser Integration

Create a browser extension that sends POST requests to `http://127.0.0.1:8787/approve` with the current tab's domain and your device credentials when the user clicks "Allow".

## Logs

All activities are logged to `/etc/pihole/autoallow/piautoallow.log` in JSONL format with UTC timestamps:

```json
{"ts": "2024-01-01T12:00:00Z", "event": "allow", "domain": "example.com", "device": "laptop", "ttl_h": 4}
{"ts": "2024-01-01T16:00:00Z", "event": "expire_blacklist", "domain": "example.com"}
```

## Architecture

The system follows a deterministic design with:
- Fixed timeouts for all network operations
- No randomness in decision making
- Explicit configuration for all behaviors  
- Fail-closed security model
- Complete auditability

This implementation provides military-grade security for Pi-hole auto-allow functionality while maintaining usability and operational simplicity.