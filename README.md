# 🚀 Bitbucket Runner Exporter

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![Docker](https://img.shields.io/badge/Docker-Required-2496ED?style=flat&logo=docker)](https://docker.com/)
[![Prometheus](https://img.shields.io/badge/Prometheus-Compatible-E6522C?style=flat&logo=prometheus)](https://prometheus.io/)

> 🔥 **Level up your Bitbucket CI/CD monitoring game!** This exporter tracks your self-hosted runner performance in real-time, giving you the insights you need to optimize your builds.

## ✨ What's This About?

Ever wondered how your Bitbucket runners are performing? This lightweight exporter monitors Docker containers running your builds and exposes detailed metrics via Prometheus. Perfect for DevOps teams who want to squeeze every bit of performance from their CI/CD infrastructure.

## 🎯 Features

- 📊 **Real-time metrics** - CPU, memory, network, and disk I/O monitoring
- 🏷️ **Custom labels** - Add your own labels for better organization
- ⚙️ **Config file support** - YAML configuration for easy deployment
- 🐳 **Docker native** - Monitors Docker containers directly
- 🎨 **Prometheus ready** - Works seamlessly with your existing monitoring stack

## 🚀 Quick Start

### Prerequisites

- Go 1.23+ (for building from source)
- Docker daemon running on the host system
- Prometheus (optional, for visualization)

### Installation

```bash
# Clone the repo
git clone <repository-url>
cd bitbucket-runner-exporter

# Build the binary
go build -o bitbucket-runner-exporter

# Run with default settings
./bitbucket-runner-exporter
```

> **Note**: This tool runs directly on the host system and monitors Docker containers via the Docker socket. It cannot be containerized since it needs access to monitor host containers.

## ⚡ Usage Examples

### Basic Usage

```bash
# Start with default settings (port 8080, bind to all interfaces)
./bitbucket-runner-exporter

# Custom port and bind address
./bitbucket-runner-exporter -port 9090 -bind 127.0.0.1

# Add extra labels to all metrics
./bitbucket-runner-exporter \
  -extra-label "environment=production" \
  -extra-label "region=us-west-2" \
  -extra-label "team=backend"
```

### Configuration File

Create a `config.yml` file:

```yaml
bind: 0.0.0.0
port: 8080
labels:
  environment: production
  region: us-west-2
  team: backend
  size: large
  platform: linux/amd64
```

Then run:

```bash
./bitbucket-runner-exporter -config-file config.yml
```

## 🛠️ Command Line Options

| Flag           | Description                    | Default   | Example                   |
|----------------|--------------------------------|-----------|---------------------------|
| `-port`        | Server port                    | `8080`    | `-port 9090`              |
| `-bind`        | Bind address                   | `0.0.0.0` | `-bind 127.0.0.1`         |
| `-extra-label` | Add custom labels (repeatable) | –         | `-extra-label "env=prod"` |
| `-config-file` | Use YAML config file           | –         | `-config-file config.yml` |
| `-version`     | Show current version           | –         | –                         |

## 📊 Metrics Reference

All metrics include `runner_uuid` and `pipeline_uuid` labels automatically extracted from container names, plus any custom labels you define.

### Container Status
```prometheus
# HELP bitbucket_agent_build_status Status of the build container (1 if running, 0 if not)
# TYPE bitbucket_agent_build_status gauge
bitbucket_agent_build_status{runner_uuid="01e28ace-9bfd-5c00-9707-c8fa17f8e99e", pipeline_uuid="b723372a-da8e-41ad-9780-f14ad9d0d326"} 1
```

### CPU Metrics
```prometheus
# HELP bitbucket_agent_build_cpu_usage_cores CPU usage in cores for build container
# TYPE bitbucket_agent_build_cpu_usage_cores gauge
bitbucket_agent_build_cpu_usage_cores{runner_uuid="...", pipeline_uuid="..."} 1.25

# HELP bitbucket_agent_build_cpu_limit_cores CPU limit in cores for build container
# TYPE bitbucket_agent_build_cpu_limit_cores gauge
bitbucket_agent_build_cpu_limit_cores{runner_uuid="...", pipeline_uuid="..."} 2.00
```

### Memory Metrics
```prometheus
# HELP bitbucket_agent_build_memory_usage Memory usage in bytes for build container
# TYPE bitbucket_agent_build_memory_usage gauge
bitbucket_agent_build_memory_usage{runner_uuid="...", pipeline_uuid="..."} 1073741824

# HELP bitbucket_agent_build_memory_limit Memory limit in bytes for build container
# TYPE bitbucket_agent_build_memory_limit gauge
bitbucket_agent_build_memory_limit{runner_uuid="...", pipeline_uuid="..."} 2147483648
```

### Network Metrics
```prometheus
# HELP bitbucket_agent_build_network_receive_bytes Network receive bytes for build container
# TYPE bitbucket_agent_build_network_receive_bytes gauge
bitbucket_agent_build_network_receive_bytes{runner_uuid="...", pipeline_uuid="..."} 1048576

# HELP bitbucket_agent_build_network_transmit_bytes Network transmit bytes for build container
# TYPE bitbucket_agent_build_network_transmit_bytes gauge
bitbucket_agent_build_network_transmit_bytes{runner_uuid="...", pipeline_uuid="..."} 2097152
```

### Disk I/O Metrics
```prometheus
# HELP bitbucket_agent_build_block_input_bytes Block input bytes for build container
# TYPE bitbucket_agent_build_block_input_bytes gauge
bitbucket_agent_build_block_input_bytes{runner_uuid="...", pipeline_uuid="..."} 5242880

# HELP bitbucket_agent_build_block_output_bytes Block output bytes for build container
# TYPE bitbucket_agent_build_block_output_bytes gauge
bitbucket_agent_build_block_output_bytes{runner_uuid="...", pipeline_uuid="..."} 1048576
```

### Process Metrics
```prometheus
# HELP bitbucket_agent_build_pids Number of active PIDs in build container
# TYPE bitbucket_agent_build_pids gauge
bitbucket_agent_build_pids{runner_uuid="...", pipeline_uuid="..."} 42
```

## 🔍 How It Works

The exporter works by:

1. **Host Monitoring**: Runs directly on the host system with access to Docker socket
2. **Container Discovery**: Scans for Docker containers with names matching the pattern `{RUNNER_UUID}_{PIPELINE_UUID}_build`
3. **Metrics Collection**: Uses Docker API to gather container statistics from running build containers
4. **Label Extraction**: Automatically extracts runner and pipeline UUIDs from container names
5. **Prometheus Export**: Exposes metrics on `/metrics` endpoint (default port 8080)

### Container Name Format

Build containers follow this naming convention:
```
96da62a5-abee-497e-b1f6-7774432a3396_1d1ff376-c967-4ebe-a84f-cd2d56ee0872_build
├─────────── runner_uuid ──────────┤ ├───────────── pipeline_uuid ────────────┤
```

## 🚢 Production Deployment

### Systemd Service (Recommended)

Create a systemd service for production deployment:

```bash
# Create service file
sudo tee /etc/systemd/system/bitbucket-runner-exporter.service > /dev/null <<EOF
[Unit]
Description=Bitbucket Runner Exporter
After=docker.service
Requires=docker.service

[Service]
Type=simple
User=bitbucket-exporter
ExecStart=/opt/bitbucket-runner-exporter/bitbucket-runner-exporter -config-file /etc/bitbucket-runner-exporter/config.yml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Create user and directories
sudo useradd --system --shell /bin/false bitbucket-exporter
sudo mkdir -p /opt/bitbucket-runner-exporter /etc/bitbucket-runner-exporter

# Add user to docker group for Docker socket access
sudo usermod -aG docker bitbucket-exporter

# Copy binary and config
sudo cp bitbucket-runner-exporter /opt/bitbucket-runner-exporter/
sudo cp config.yml /etc/bitbucket-runner-exporter/
sudo chown -R bitbucket-exporter:bitbucket-exporter /opt/bitbucket-runner-exporter

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable bitbucket-runner-exporter
sudo systemctl start bitbucket-runner-exporter
```

### Prometheus Configuration

Add this job to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'bitbucket-runner-exporter'
    static_configs:
      - targets: ['localhost:8080']
    scrape_interval: 30s
    metrics_path: /metrics
```

### Multiple Runners

If you have multiple runner hosts, deploy on each host separately:

```bash
# Host 1
./bitbucket-runner-exporter -port 8080 -extra-label "host=runner-01"

# Host 2  
./bitbucket-runner-exporter -port 8080 -extra-label "host=runner-02"

# Host 3
./bitbucket-runner-exporter -port 8080 -extra-label "host=runner-03"
```

Then configure Prometheus to scrape all hosts:

```yaml
scrape_configs:
  - job_name: 'bitbucket-runner-exporters'
    static_configs:
      - targets: 
        - 'runner-01.example.com:8080'
        - 'runner-02.example.com:8080' 
        - 'runner-03.example.com:8080'
```

## 🤝 Contributing

We love contributions! Whether it's:

- 🐛 Bug reports
- 💡 Feature requests  
- 📖 Documentation improvements
- 🔧 Code contributions

Feel free to open an issue or submit a PR!

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🌟 Star History

If this project helped you, consider giving it a ⭐! It helps others discover this tool.

---

<div align="center">
  <i>Built with ❤️ for the DevOps community</i>
</div>