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

- Go 1.20+ environment (To build)
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
| `-apipass`               | API password (overrides config/env)                              | `-apipass mypassword`                |
| `-sshpass`               | SSH password (overrides config/env)                                | `-sshpass mysshpassword`             |
| `-sshkey`                | Path to SSH private key (preferred over password)                | `-sshkey /path/to/private/key`       |
| `-config`                | Path to config file (without extension)                           | `-config custom_config`              |
| `-create-config`         | Generate a dummy config file and exit                            | `-create-config`                     |
| `-debug`                 | Enable verbose debug output                                        | `-debug`                            |
| `-insecure-skip`         | Skip TLS certificate verification                                 | `-insecure-skip`                     |
| `-insecure-ssh`         | Skip SSH host key verification (NOT recommended)                   | `-insecure-ssh`                     |
| `-show-env`                 | Display environment variables that can be used                | `-show-env`                            |
| `-ssh-known-hosts`         | Path to SSH known_hosts file (defaults to ~/.ssh/known_hosts)   `-ssh-known-hosts /path/to/known_hosts` |
| `-version`               | Show version and build details                                    | `-version`                          |

### Example

```getTor -pcs -apipass mypassword -sshkey ~/.ssh/id_rsa -create-config```


### Configuration File (`config.yaml`)

You can customize the operation via a YAML file:  

```
api_user: admin
# api_pass: yourapipass_here                                # Provide your PC API password or override with --apipass or env GETTOR_API_PASS
ssh_user: root
# ssh_pass: your_ssh_password_here                          # SSH password (less secure; prefer ssh_key_file or env GETTOR_SSH_PASS)
# ssh_key_file: /path/to/private_key                        # Preferred SSH key file path (or env GETTOR_SSH_KEY_FILE)
pc_ip_file: pc_ips.txt                                      # File with Nutanix PC IPs for --pcs (or env GETTOR_PC_IP_FILE)
host_ip_file: host_ips.txt                                  # File with direct host IPs (or env GETTOR_HOST_IP_FILE)
# csv_file: lldp_neighbors.csv                              # Output CSV filename
# max_threads: 10                                           # Max concurrent threads
# debug_dir: debug_output                                   # Directory for debug outputs
# max_retries: 3                                            # Max retries for operations
# base_retry_delay_seconds: 2                               # Base delay for retries
# api_timeout_seconds: 10                                   # API request timeout
# ssh_timeout_seconds: 10                                   # SSH connection timeout
# command_timeout_seconds: 5                                # SSH command timeout
# host_timeout_minutes: 2                                   # Per-host processing timeout
# log_file: getTor.log                                      # Log file path
# insecure_skip: false                                      # Set true to skip TLS certificate verification (NOT recommended)
# sshknownhostsfile: "/path/to/your/known_hosts"            # Optional: Path to SSH known_hosts file. Defaults to ~/.ssh/known_hosts.
# insecuressh: false                                        # Optional: Set to true to skip SSH host key verification. NOT RECOMMENDED.
# debug: true                                               # Set Debug true/false # Feature not yet implemented!!
```

---

## Sample Output

```
Host IP,Hostname,Interface,MAC Address,PCI Slot,NIC Model,Interface Status,Peer Switch,Peer Port ID,Port Description,Redundancy
10.48.X2.XX,Galactus-4,eth0,40:a6:b7:94:XX:XX,Slot 1,Intel Corporation Ethernet Controller XXV710 for 25GbE SFP28,up,p4r6r09-leaf1,ethernet22:4,Big Cloud Fabric Switch Port ethernet22:4,REDUNDANT
10.48.X2.XX,Galactus-4,eth1,40:a6:b7:94:XX:XX,Slot 1,Intel Corporation Ethernet Controller XXV710 for 25GbE SFP28,up,p4r6r09-leaf2,ethernet22:4,Big Cloud Fabric Switch Port ethernet22:4,REDUNDANT
10.48.X2.XX,Galactus-5,eth0,00:e0:ed:e9:XX:XX,Slot 1,Intel Corporation Ethernet Controller XXV710 for 25GbE SFP28,up,p4r6r09-leaf1,ethernet23:2,Big Cloud Fabric Switch Port ethernet23:2,REDUNDANT
10.48.X2.XX,Galactus-5,eth1,00:e0:ed:e9:XX:XX,Slot 1,Intel Corporation Ethernet Controller XXV710 for 25GbE SFP28,up,p4r6r09-leaf2,ethernet23:2,Big Cloud Fabric Switch Port ethernet23:2,REDUNDANT
10.48.X2.XX,Galactus-2,eth0,40:a6:b7:94:XX:XX,Slot 1,Intel Corporation Ethernet Controller XXV710 for 25GbE SFP28,up,p4r6r09-leaf1,ethernet22:2,Big Cloud Fabric Switch Port ethernet22:2,REDUNDANT
10.48.X2.XX,Galactus-2,eth1,40:a6:b7:94:XX:XX,Slot 1,Intel Corporation Ethernet Controller XXV710 for 25GbE SFP28,up,p4r6r09-leaf2,ethernet22:2,Big Cloud Fabric Switch Port ethernet22:2,REDUNDANT
10.48.X2.XX,Galactus-3,eth0,40:a6:b7:94:XX:XX,Slot 1,Intel Corporation Ethernet Controller XXV710 for 25GbE SFP28,up,p4r6r09-leaf1,ethernet22:3,Big Cloud Fabric Switch Port ethernet22:3,REDUNDANT
10.48.X2.XX,Galactus-3,eth1,40:a6:b7:94:XX:XX,Slot 1,Intel Corporation Ethernet Controller XXV710 for 25GbE SFP28,up,p4r6r09-leaf2,ethernet22:3,Big Cloud Fabric Switch Port ethernet22:3,REDUNDANT
10.48.X2.XX,Galactus-1,eth0,40:a6:b7:94:XX:XX,Slot 1,Intel Corporation Ethernet Controller XXV710 for 25GbE SFP28,up,p4r6r09-leaf1,ethernet22:1,Big Cloud Fabric Switch Port ethernet22:1,REDUNDANT
10.48.X2.XX,Galactus-1,eth1,40:a6:b7:94:XX:XX,Slot 1,Intel Corporation Ethernet Controller XXV710 for 25GbE SFP28,up,p4r6r09-leaf2,ethernet22:1,Big Cloud Fabric Switch Port ethernet22:1,REDUNDANT
```

---

## Building Binaries

You can build the executable binaries for your target platform using Go. For example:

Linux AMD64  
```GOOS=linux GOARCH=amd64 go build -ldflags="-X main.version=Cust_Version -X main.buildDate=$(date +%Y-%m-%d)" -o getTor-linux-amd64 main.go```

macOS AMD64  
```GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.version=Cust_Version -X main.buildDate=$(date +%Y-%m-%d)" -o getTor-darwin-amd64 main.go```

macOS ARM64  
```GOOS=darwin GOARCH=arm64 go build -ldflags="-X main.version=Cust_Version -X main.buildDate=$(date +%Y-%m-%d)" -o getTor-darwin-arm64 main.go```

Windows AMD64  
```GOOS=windows GOARCH=amd64 go build -ldflags="-X main.version=Cust_Version -X main.buildDate=$(date +%Y-%m-%d)" -o getTor-windows-amd64.exe main.go```

  
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
