# Nutanix LLDP Report Tool

A GoLang utility to collect LLDP and NIC status information from Nutanix hosts, exporting results to CSV. Supports querying Nutanix Prism Central APIs and direct host IP input for flexible deployment.

## Author

Prajwal Vernekar (prajwal.vernekar@nutanix.com)

## Disclaimer

Use this tool at your own risk. Ensure proper permissions and testing in non-production environments first.

---

## Features

- Collects LLDP data from network interfaces on Nutanix hosts.
- Gathers NIC details, including MAC Address, NIC Model, PCI Slot, and Interface Status.
- Supports querying Nutanix Prism Central APIs to discover hosts.
- Runs commands over SSH for direct IP-based collection.
- Export results to a CSV file for analysis.
- Configurable via flags, environment variables, or an external config file.
- Supports multi-threading for faster execution.
- Debug logs and output directory for troubleshooting.

---

## Requirements

- Go 1.20+ environment
- SSH access configured on hosts
- Nutanix Prism Central API credentials

## Usage

### Basic Usage

- To query via Prism Central API:
getTor --pcs


- To query via direct host IPs:
getTor


### Flags

| Flag                       | Description                                                      | Example                                |
|----------------------------|------------------------------------------------------------------|----------------------------------------|
| `--apipass`               | API password (overrides config/env)                              | `--apipass mypassword`                |
| `--sshpass`               | SSH password (overrides config/env)                                | `--sshpass mysshpassword`             |
| `--sshkey`                | Path to SSH private key (preferred over password)                | `--sshkey /path/to/private/key`       |
| `--config`                | Path to config file (without extension)                           | `--config custom_config`              |
| `--create-config`         | Generate a dummy config file and exit                            | `--create-config`                     |
| `--debug`                 | Enable verbose debug output                                        | `--debug`                            |
| `--version`               | Show version and build details                                    | `--version`                          |

### Example

```getTor --pcs --apipass mypassword --sshkey ~/.ssh/id_rsa --create-config```


### Configuration File (`config.yaml`)

You can customize the operation via a YAML file:  

```api_user: admin  
api_pass: yourapipass  
ssh_user: root  
ssh_pass: yoursshpass  
ssh_key_file: /path/to/key  
pc_ip_file: pc_ips.txt  
host_ip_file: host_ips.txt  
csv_file: output.csv  
max_threads: 20  
debug_dir: my_debug  
max_retries: 5  
base_retry_delay_seconds: 3  
api_timeout_seconds: 15  
ssh_timeout_seconds: 15  
command_timeout_seconds: 10  
host_timeout_minutes: 5  
log_file: mylog.log
```

---

## Building Binaries

You can build the executable binaries for your target platform using Go. For example:

Linux AMD64  
```GOOS=linux GOARCH=amd64 go build -ldflags="-X main.version=v1.0.0 -X main.buildDate=$(date +%Y-%m-%d)" -o getTor-linux-amd64 main.go```

macOS AMD64  
```GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.version=v1.0.0 -X main.buildDate=$(date +%Y-%m-%d)" -o getTor-darwin-amd64 main.go```

macOS ARM64  
```GOOS=darwin GOARCH=arm64 go build -ldflags="-X main.version=v1.0.0 -X main.buildDate=$(date +%Y-%m-%d)" -o getTor-darwin-arm64 main.go```

Windows AMD64  
```GOOS=windows GOARCH=amd64 go build -ldflags="-X main.version=v1.0.0 -X main.buildDate=$(date +%Y-%m-%d)" -o getTor-windows-amd64.exe main.go```

  
> Place your built binaries in a `dist/` folder or similar for easier management.

---

## Releases

Pre-built binaries for supported platforms are available in the [Releases](https://github.com/lTSPV75BRO/nutanix-lldp-report/releases) section of this repository, making it easy to download and use without building from source.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Contributing

Contributions are welcome! Please fork the repository, create a branch, and submit a pull request.

---
*Happy network auditing with the Nutanix LLDP tool!*
