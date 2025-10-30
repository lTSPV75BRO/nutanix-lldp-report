// Author: Prajwal Vernekar (prajwal.vernekar@nutanix.com)
// Description:
//     This program collects LLDP and NIC status information from hosts and exports it to CSV format.
//     It supports querying Nutanix Prism Central (PC) APIs for host discovery or direct host IP input.
//
// Usage:
//     - Configuration can be via flags, environment variables, or a config file (config.yaml or config.json).
//     - Run the program with:
//         getTor --pcs              # to use PC API
//         getTor                    # to use direct host IPs
//         getTor --apipass APIPASS  # Password for PC API user (or env: API_PASS)
//         getTor --sshpass SSHPASS  # Password for SSH user (or env: SSH_PASS)
//         getTor --sshkey KEYFILE   # Path to SSH private key file (preferred over password)
//         getTor --debug            # Enable verbose debug output
//         getTor --version          # Show version and build info
//         getTor --config FILE      # Path to config file (without extension)
//         getTor --create-config    # Create a dummy config file and exit
//
// Config File Example (config.yaml):
// api_user: admin
// api_pass: yourapipass
// ssh_user: root
// ssh_pass: yoursshpass  # Avoid if using key
// ssh_key_file: /path/to/key
// pc_ip_file: pc_ips.txt
// host_ip_file: host_ips.txt
// csv_file: output.csv
// max_threads: 20
// debug_dir: my_debug
// max_retries: 5
// base_retry_delay_seconds: 3
// api_timeout_seconds: 15
// ssh_timeout_seconds: 15
// command_timeout_seconds: 10
// host_timeout_minutes: 5
// log_file: mylog.log
//
// Disclaimer:
//     Use at your own risk. Running this program implies acceptance of associated risks.
//     The developer or Comp shall not be held liable for any consequences resulting from its use.

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus" // Structured logging
	"github.com/spf13/viper"     // Configuration management
	"golang.org/x/crypto/ssh"
)

// Embedded version info (set via ldflags during build, e.g., go build -ldflags="-X main.version=1.0.0 -X main.buildDate=$(date +%Y-%m-%d)")
var (
	version   = "1.0.1"
	buildDate = "unknown"
)

// Configurable settings (defaults; overridden by config file/env/flags)
var (
	apiUser        = defaultApiUser
	sshUser        = defaultSshUser
	csvFile        = defaultCsvFile
	pcIpFile       = defaultPcIpFile
	hostIpFile     = defaultHostIpFile
	maxThreads     = defaultMaxThreads
	debugDir       = defaultDebugDir
	maxRetries     = defaultMaxRetries
	baseRetryDelay = defaultBaseRetryDelay
	apiTimeout     = defaultApiTimeout
	sshTimeout     = defaultSshTimeout
	commandTimeout = defaultCommandTimeout
	hostTimeout    = defaultHostTimeout
	logFile        = defaultLogFile
	enrollValid    bool
	hostMutexes    sync.Map
	logger         *logrus.Logger
	debugMode      bool
)

const (
	defaultApiUser        = "admin"
	defaultSshUser        = "root"
	defaultCsvFile        = "lldp_neighbors.csv"
	defaultPcIpFile       = "pc_ips.txt"
	defaultHostIpFile     = "host_ips.txt"
	defaultConfigFile     = "config"
	defaultMaxThreads     = 10
	defaultDebugDir       = "debug_output"
	defaultMaxRetries     = 3
	defaultBaseRetryDelay = 2 * time.Second
	defaultApiTimeout     = 10 * time.Second
	defaultSshTimeout     = 10 * time.Second
	defaultCommandTimeout = 5 * time.Second
	defaultHostTimeout    = 2 * time.Minute
	defaultLogFile        = "getTor.log"
	enroll                = `CiAgICAgXyAgIF8gX19fX19fX18gXyAgIF8gIF9fICAgICAgX18KICAgIHwgXCB8IHwtLS0tLS0tLXwgXCB8IHwgXCBcICAgIC8gLwogICAgfCAgXHwgfCAgIHx8ICAgfCAgXHwgfCAgXCBcICAvIC8KICAgIHwgLiBgIHwgICB8fCAgIHwgLiBgIHwgICB8IHx8IHwKICAgIHwgfFwgIHwgICB8fCAgIHwgfFwgIHwgIC8gLyAgXCBcCiAgICB8X3wgXF98ICAgfHwgICB8X3wgXF98IC9fLyAgICBcX1wKCkRldmVsb3BlZCBieSBQcmFqd2FsIFZlcm5la2FyIGF0IE51dGFuaXgK`
)

func init() {
	// Initialize structured logging with logrus
	logger = logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)
}

func isEnrollValid(encodedStr string) bool {
	cleanB64 := strings.Join(strings.Split(strings.Trim(encodedStr, `"""`), "\n"), "\n")
	decoded, err := base64.StdEncoding.DecodeString(cleanB64)
	if err != nil {
		logger.WithError(err).Error("Script appears tampered or corrupted")
		return false
	}
	fmt.Println(string(decoded))
	return true
}

func main() {
	// Flags
	usePcs := flag.Bool("pcs", false, "Use PC API to fetch hosts")
	apiPassPtr := flag.String("apipass", "", "Password for API user (overrides config/env)")
	sshPassPtr := flag.String("sshpass", "", "Password for SSH user (overrides config/env)")
	sshKeyFilePtr := flag.String("sshkey", "", "Path to SSH private key file (overrides config)")
	createConfigFlag := flag.Bool("create-config", false, "Create a dummy config file and exit")
	insecureSkipFlag := flag.Bool("insecure-skip", false, "Skip TLS certificate verification for HTTPS (NOT recommended for production)")
	flag.BoolVar(&debugMode, "debug", false, "Enable debug mode")
	showVersion := flag.Bool("version", false, "Show version and build info")
	configFile := flag.String("config", defaultConfigFile, "Path to config file (without extension)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Version: %s\nBuild Date: %s\n", version, buildDate)
		os.Exit(0)
	}

	// Load config with Viper
	viper.SetConfigName(*configFile)
	viper.AddConfigPath(".")
	viper.SetEnvPrefix("gettor")
	viper.AutomaticEnv() // Bind env vars
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			logger.WithError(err).Fatal("Error reading config file")
		} else {
			logger.Info("No config file found; Expecting default file named: config.yaml")
		}
	}

	// Override defaults with config values
	apiUser = viper.GetString("api_user")
	if apiUser == "" {
		apiUser = defaultApiUser
	}
	sshUser = viper.GetString("ssh_user")
	if sshUser == "" {
		sshUser = defaultSshUser
	}
	csvFile = viper.GetString("csv_file")
	if csvFile == "" {
		csvFile = defaultCsvFile
	}
	pcIpFile = viper.GetString("pc_ip_file")
	if pcIpFile == "" {
		pcIpFile = defaultPcIpFile
	}
	hostIpFile = viper.GetString("host_ip_file")
	if hostIpFile == "" {
		hostIpFile = defaultHostIpFile
	}
	maxThreads = viper.GetInt("max_threads")
	if maxThreads <= 0 {
		maxThreads = defaultMaxThreads
	}
	debugDir = viper.GetString("debug_dir")
	if debugDir == "" {
		debugDir = defaultDebugDir
	}
	maxRetries = viper.GetInt("max_retries")
	if maxRetries <= 0 {
		maxRetries = defaultMaxRetries
	}
	baseRetryDelay = time.Duration(viper.GetInt("base_retry_delay_seconds")) * time.Second
	if baseRetryDelay <= 0 {
		baseRetryDelay = defaultBaseRetryDelay
	}
	apiTimeout = time.Duration(viper.GetInt("api_timeout_seconds")) * time.Second
	if apiTimeout <= 0 {
		apiTimeout = defaultApiTimeout
	}
	sshTimeout = time.Duration(viper.GetInt("ssh_timeout_seconds")) * time.Second
	if sshTimeout <= 0 {
		sshTimeout = defaultSshTimeout
	}
	commandTimeout = time.Duration(viper.GetInt("command_timeout_seconds")) * time.Second
	if commandTimeout <= 0 {
		commandTimeout = defaultCommandTimeout
	}
	hostTimeout = time.Duration(viper.GetInt("host_timeout_minutes")) * time.Minute
	if hostTimeout <= 0 {
		hostTimeout = defaultHostTimeout
	}
	logFile = viper.GetString("log_file")
	if logFile == "" {
		logFile = defaultLogFile
	}

	// Override with flags if set (flags take highest precedence)
	if *apiPassPtr != "" {
		viper.Set("api_pass", *apiPassPtr)
	}
	if *sshPassPtr != "" {
		viper.Set("ssh_pass", *sshPassPtr)
	}
	if *sshKeyFilePtr != "" {
		viper.Set("ssh_key_file", *sshKeyFilePtr)
	}

	if *createConfigFlag {
		err := createDummyConfig(*configFile)
		if err != nil {
			logger.WithError(err).Fatal("Failed to create dummy config")
		}
		os.Exit(0)
	}

	if debugMode {
		logger.SetLevel(logrus.DebugLevel)
		logger.Debug("Debug mode enabled")
	}
	// Override with flags if set (flags take highest precedence)
	if insecureSkipFlag != nil && *insecureSkipFlag {
		viper.Set("insecure_skip", true)
	}
	if viper.GetBool("insecure_skip") {
		logger.Warn("TLS verification is disabled due to --insecure-skip (use only for trusted/self-signed targets)")
	}

	// Update logger output if log_file changed
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		mw := io.MultiWriter(os.Stdout, file)
		logger.SetOutput(mw)
	} else {
		logger.WithError(err).Warn("Failed to open log file; using stdout")
	}

	// Validate authentication
	if !viper.IsSet("ssh_key_file") && !viper.IsSet("ssh_pass") {
		logger.Fatal("SSH authentication required; provide --sshkey, --sshpass, or set in config/env")
	}
	if *usePcs && !viper.IsSet("api_pass") {
		logger.Fatal("API password is required for --pcs; provide --apipass or set in config/env")
	}

	err = os.MkdirAll(debugDir, os.ModePerm)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create debug directory")
	}

	enrollValid = isEnrollValid(enroll)

	var allHosts []string
	var fetchErr error
	if *usePcs {
		pcs, err := getIpsFromFile(pcIpFile)
		if err != nil {
			logger.WithError(err).Fatal("Failed to load PC IPs")
		}
		if len(pcs) == 0 {
			logger.Fatal("No PC IPs found; add to pc_ips.txt and rerun")
		}
		for _, pcIp := range pcs {
			hosts, err := fetchHostIps(pcIp)
			if err != nil {
				logger.WithError(err).WithField("pc_ip", pcIp).Warn("Failed to fetch hosts from PC")
				continue
			}
			allHosts = append(allHosts, hosts...)
		}
	} else {
		allHosts, fetchErr = getIpsFromFile(hostIpFile)
		if fetchErr != nil {
			logger.WithError(fetchErr).Fatal("Failed to load host IPs")
		}
		if len(allHosts) == 0 {
			logger.Fatal("No host IPs found; add to host_ips.txt and rerun")
		}
	}

	logger.WithField("count", len(allHosts)).Info("Found hosts to query")
	if len(allHosts) == 0 {
		logger.Info("No hosts to process; exiting")
		return
	}

	// Setup signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Info("Shutdown signal received; cancelling operations")
		cancel()
	}()

	resultsChan := make(chan []map[string]string, len(allHosts))
	var wg sync.WaitGroup

	sem := make(chan struct{}, maxThreads)

	for _, host := range allHosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer func() { <-sem }()
			collectHostData(h, resultsChan, &wg, ctx)
		}(host)
	}

	wg.Wait()
	close(resultsChan)

	var allResults []map[string]string
	for res := range resultsChan {
		if res != nil {
			allResults = append(allResults, res...)
		}
	}

	if err := writeCsv(allResults); err != nil {
		logger.WithError(err).Error("Failed to write CSV")
	}
}

// createDummyConfig creates a dummy config file if it doesn't exist
func createDummyConfig(filename string) error {
	// Check if file exists (including with .yaml or .json extension)
	extensions := []string{"", ".yaml", ".json", ".yml"}
	var exists bool
	for _, ext := range extensions {
		if _, err := os.Stat(filename + ext); err == nil {
			exists = true
			filename += ext // Use the existing extension for message
			break
		}
	}
	if exists {
		return fmt.Errorf("config file %s already exists; not overwriting", filename)
	}

	// Default to .yaml if no extension
	if !strings.HasSuffix(filename, ".yaml") && !strings.HasSuffix(filename, ".json") && !strings.HasSuffix(filename, ".yml") {
		filename += ".yaml"
	}

	dummyContent := `# Default getTor configuration file (YAML format)
# Uncomment and set values as needed

api_user: admin
# api_pass: yourapipass_here  # Provide your PC API password or override with --apipass or env GETTOR_API_PASS
ssh_user: root
# ssh_pass: your_ssh_password_here  # SSH password (less secure; prefer ssh_key_file or env GETTOR_SSH_PASS)
# ssh_key_file: /path/to/private_key  # Preferred SSH key file path (or env GETTOR_SSH_KEY_FILE)
pc_ip_file: pc_ips.txt  # File with Nutanix PC IPs for --pcs (or env GETTOR_PC_IP_FILE)
host_ip_file: host_ips.txt  # File with direct host IPs (or env GETTOR_HOST_IP_FILE)
# csv_file: lldp_neighbors.csv  # Output CSV filename
# max_threads: 10  # Max concurrent threads
# debug_dir: debug_output  # Directory for debug outputs
# max_retries: 3  # Max retries for operations
# base_retry_delay_seconds: 2  # Base delay for retries
# api_timeout_seconds: 10  # API request timeout
# ssh_timeout_seconds: 10  # SSH connection timeout
# command_timeout_seconds: 5  # SSH command timeout
# host_timeout_minutes: 2  # Per-host processing timeout
# log_file: getTor.log  # Log file path
# insecure_skip: false  # Set true to skip TLS certificate verification (NOT recommended)
# debug: true # Set Debug true/false # Feature not yet implemented!!
`

	err := os.WriteFile(filename, []byte(dummyContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to create dummy config: %v", err)
	}
	fmt.Printf("Dummy config file created at %s\n", filename)
	return nil
}

// getIpsFromFile reads IPs from a file with retries
func getIpsFromFile(filePath string) ([]string, error) {
	var ips []string
	var err error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		file, openErr := os.Open(filePath)
		if openErr == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					ips = append(ips, line)
				}
			}
			logger.WithField("file", filePath).WithField("count", len(ips)).Debug("Loaded IPs")
			return ips, nil
		}
		err = openErr
		if os.IsNotExist(err) {
			newFile, createErr := os.Create(filePath)
			if createErr != nil {
				return nil, fmt.Errorf("could not create %s: %v", filePath, createErr)
			}
			defer newFile.Close()
			if strings.Contains(strings.ToLower(filePath), "host") {
				newFile.WriteString("# Add your HOST IPs below (one per line)\n")
			} else if strings.Contains(strings.ToLower(filePath), "pc") {
				newFile.WriteString("# Add your Nutanix PC IPs below (one per line)\n")
			}
			logger.WithField("file", filePath).Info("Created template file. Please add IPs and rerun.")
			return nil, fmt.Errorf("template created for %s; rerun after adding IPs", filePath)
		}
		logger.WithError(err).WithFields(logrus.Fields{
			"file":    filePath,
			"attempt": attempt,
		}).Warn("Error reading file")
		time.Sleep(baseRetryDelay * time.Duration(math.Pow(2, float64(attempt-1))))
	}
	return nil, fmt.Errorf("failed to read %s after %d attempts: %v", filePath, maxRetries, err)
}

// fetchHostIps queries Nutanix API for host IPs with exponential backoff
func fetchHostIps(pcIp string) ([]string, error) {
	var hosts []string
	var err error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		logger.WithFields(logrus.Fields{
			"pc_ip":   pcIp,
			"attempt": attempt,
		}).Info("Querying Nutanix API")
		url := fmt.Sprintf("https://%s:9440/api/nutanix/v3/hosts/list", pcIp)
		req, reqErr := http.NewRequest("POST", url, bytes.NewBufferString("{}"))
		if reqErr != nil {
			err = reqErr
			continue
		}
		req.SetBasicAuth(apiUser, viper.GetString("api_pass"))
		req.Header.Set("Content-Type", "application/json")

		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: viper.GetBool("insecure_skip")}
		client := &http.Client{Transport: tr, Timeout: apiTimeout}
		resp, respErr := client.Do(req)
		if respErr != nil {
			err = respErr
			time.Sleep(baseRetryDelay * time.Duration(math.Pow(2, float64(attempt-1))))
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("API request failed with status %d", resp.StatusCode)
			time.Sleep(baseRetryDelay * time.Duration(math.Pow(2, float64(attempt-1))))
			continue
		}

		var data struct {
			Entities []struct {
				Status struct {
					Resources struct {
						Hypervisor struct {
							IP string `json:"ip"`
						} `json:"hypervisor"`
					} `json:"resources"`
				} `json:"status"`
			} `json:"entities"`
		}
		if decodeErr := json.NewDecoder(resp.Body).Decode(&data); decodeErr != nil {
			err = decodeErr
			time.Sleep(baseRetryDelay * time.Duration(math.Pow(2, float64(attempt-1))))
			continue
		}

		for _, entity := range data.Entities {
			if ip := entity.Status.Resources.Hypervisor.IP; ip != "" {
				hosts = append(hosts, ip)
			}
		}
		logger.WithFields(logrus.Fields{
			"pc_ip": pcIp,
			"count": len(hosts),
		}).Debug("Found hosts from PC")
		return hosts, nil
	}
	return nil, fmt.Errorf("failed to fetch hosts from %s after %d attempts: %v", pcIp, maxRetries, err)
}

// sshConnect establishes an SSH client connection with exponential backoff
func sshConnect(hostIp string) (*ssh.Client, error) {
	var client *ssh.Client
	var err error
	var auth []ssh.AuthMethod

	// Prefer key if provided, else password
	keyPath := viper.GetString("ssh_key_file")
	pass := viper.GetString("ssh_pass")
	if keyPath != "" {
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read private key: %v", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("unable to parse private key: %v", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
		logger.Info("Using SSH key authentication")
	} else if pass != "" {
		auth = append(auth, ssh.Password(pass))
		logger.Warn("Using SSH password authentication (less secure; consider switching to keys)")
	} else {
		return nil, fmt.Errorf("no SSH authentication method provided")
	}

	for attempt := 1; attempt <= maxRetries; attempt++ {
		logger.WithFields(logrus.Fields{
			"host":    hostIp,
			"user":    sshUser,
			"attempt": attempt,
		}).Debug("Connecting via SSH")
		// Read and parse the allowed host public key (host key file configured via ssh_host_key_file)
		hostKeyPath := viper.GetString("ssh_host_key_file")
		if hostKeyPath == "" {
			return nil, fmt.Errorf("missing required SSH host key file config (ssh_host_key_file)")
		}
		publicKeyBytes, err := os.ReadFile(hostKeyPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read SSH host key file: %v", err)
		}
		publicKey, err := ssh.ParsePublicKey(publicKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse SSH host public key: %v", err)
		}

		config := &ssh.ClientConfig{
			User:            sshUser,
			Auth:            auth,
			HostKeyCallback: ssh.FixedHostKey(publicKey),
			Timeout:         sshTimeout,
		}
		client, err = ssh.Dial("tcp", hostIp+":22", config)
		if err == nil {
			logger.WithField("host", hostIp).Info("SSH connection established")
			return client, nil
		}
		logger.WithError(err).WithFields(logrus.Fields{
			"host":    hostIp,
			"attempt": attempt,
		}).Warn("SSH connection failed")
		time.Sleep(baseRetryDelay * time.Duration(math.Pow(2, float64(attempt-1))))
	}
	return nil, fmt.Errorf("failed to connect to %s after %d attempts: %v", hostIp, maxRetries, err)
}

// runSshCommand runs a command over SSH with timeout and exponential backoff for session creation
func runSshCommand(client *ssh.Client, command, hostIp, interfaceName string, timeout time.Duration) (string, error) {
	logger.WithFields(logrus.Fields{
		"host":      hostIp,
		"interface": interfaceName,
		"command":   command,
	}).Debug("Running SSH command")

	var session *ssh.Session
	var err error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		session, err = client.NewSession()
		if err == nil {
			break
		}
		logger.WithError(err).WithFields(logrus.Fields{
			"host":    hostIp,
			"attempt": attempt,
		}).Warn("Session creation failed")
		time.Sleep(baseRetryDelay * time.Duration(math.Pow(2, float64(attempt-1))))
	}
	if err != nil {
		return "", fmt.Errorf("failed to create session after %d attempts: %v", maxRetries, err)
	}
	defer session.Close()

	var output bytes.Buffer
	done := make(chan error, 1)

	go func() {
		stdout, err := session.StdoutPipe()
		if err != nil {
			done <- err
			return
		}
		if err := session.Start(command); err != nil {
			done <- err
			return
		}
		_, err = io.Copy(&output, stdout)
		if err != nil {
			done <- err
			return
		}
		done <- session.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			return "", fmt.Errorf("command failed: %v", err)
		}
	case <-time.After(timeout):
		logger.WithField("host", hostIp).Warn("Command timed out")
		session.Signal(ssh.SIGTERM)
		<-done // Wait for goroutine to finish
		return "", fmt.Errorf("command timed out")
	}

	finalOutput := output.String()
	logger.WithFields(logrus.Fields{
		"host":       hostIp,
		"interface":  interfaceName,
		"output_len": len(finalOutput),
	}).Debug("Command executed")
	saveDebugOutput(hostIp, command, finalOutput)
	return finalOutput, nil
}

// getHostMutex returns a mutex for serializing commands per host
func getHostMutex(hostIp string) *sync.Mutex {
	mu, _ := hostMutexes.LoadOrStore(hostIp, &sync.Mutex{})
	return mu.(*sync.Mutex)
}

// listInterfaces lists network interfaces
func listInterfaces(client *ssh.Client, hostIp string) ([]string, error) {
	mu := getHostMutex(hostIp)
	mu.Lock()
	defer mu.Unlock()
	output, err := runSshCommand(client, "ip link show", hostIp, "general", commandTimeout)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`\d+: (eth\d+):`)
	matches := re.FindAllStringSubmatch(output, -1)
	var interfaces []string
	for _, match := range matches {
		if len(match) > 1 {
			interfaces = append(interfaces, match[1])
		}
	}
	logger.WithField("host", hostIp).WithField("interfaces", interfaces).Debug("Found interfaces")
	return interfaces, nil
}

// getHostname gets the hostname
func getHostname(client *ssh.Client, hostIp string) (string, error) {
	mu := getHostMutex(hostIp)
	mu.Lock()
	defer mu.Unlock()
	output, err := runSshCommand(client, "hostname", hostIp, "general", commandTimeout)
	if err != nil {
		return "UNKNOWN", err
	}
	hostname := strings.TrimSpace(output)
	logger.WithField("host", hostIp).WithField("hostname", hostname).Debug("Got hostname")
	return hostname, nil
}

// getInterfaceStatus gets the interface status
func getInterfaceStatus(client *ssh.Client, interfaceName, hostIp string) (string, error) {
	mu := getHostMutex(hostIp)
	mu.Lock()
	defer mu.Unlock()
	output, err := runSshCommand(client, fmt.Sprintf("ethtool %s", interfaceName), hostIp, interfaceName, commandTimeout)
	if err != nil {
		return "unknown", err
	}
	if strings.Contains(output, "command not found") || output == "" {
		logger.WithField("host", hostIp).WithField("interface", interfaceName).Debug("ethtool not found or no output")
		return "ethtool missing", nil
	}
	re := regexp.MustCompile(`Link detected: (yes|no)`)
	match := re.FindStringSubmatch(output)
	if len(match) > 1 {
		status := "up"
		if match[1] != "yes" {
			status = "down"
		}
		logger.WithField("host", hostIp).WithField("interface", interfaceName).WithField("status", status).Debug("Interface status")
		return status, nil
	}
	logger.WithField("host", hostIp).WithField("interface", interfaceName).Debug("Interface status: unknown")
	return "unknown", nil
}

// getMacAddress gets the MAC address
func getMacAddress(client *ssh.Client, interfaceName, hostIp string) (string, error) {
	mu := getHostMutex(hostIp)
	mu.Lock()
	defer mu.Unlock()
	output, err := runSshCommand(client, fmt.Sprintf("cat /sys/class/net/%s/address", interfaceName), hostIp, interfaceName, commandTimeout)
	if err != nil {
		return "UNKNOWN", err
	}
	mac := strings.TrimSpace(output)
	logger.WithField("host", hostIp).WithField("interface", interfaceName).WithField("mac", mac).Debug("MAC Address")
	return mac, nil
}

// getBusInfo gets the bus info
func getBusInfo(client *ssh.Client, interfaceName, hostIp string) (string, error) {
	mu := getHostMutex(hostIp)
	mu.Lock()
	defer mu.Unlock()
	output, err := runSshCommand(client, fmt.Sprintf("ethtool -i %s", interfaceName), hostIp, interfaceName, commandTimeout)
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`bus-info:\s+(\S+)`)
	match := re.FindStringSubmatch(output)
	if len(match) > 1 {
		logger.WithField("host", hostIp).WithField("interface", interfaceName).WithField("bus", match[1]).Debug("Bus info")
		return match[1], nil
	}
	logger.WithField("host", hostIp).WithField("interface", interfaceName).Debug("Bus info not found")
	return "", nil
}

// getPciSlot gets the PCI slot using the existing client
func getPciSlot(client *ssh.Client, hostIp, busInfo string) (string, error) {
	if busInfo == "" {
		return "UNKNOWN", nil
	}
	mu := getHostMutex(hostIp)
	mu.Lock()
	defer mu.Unlock()

	// First try lspci
	cmd := fmt.Sprintf("sudo lspci -vv -s %s | grep 'Physical'", busInfo)
	output, err := runSshCommand(client, cmd, hostIp, "", commandTimeout)
	if err == nil {
		re := regexp.MustCompile(`Physical Slot:\s*(\S+)`)
		match := re.FindStringSubmatch(output)
		if len(match) > 1 {
			logger.WithField("host", hostIp).WithField("slot", match[1]).Debug("Slot from lspci")
			return fmt.Sprintf("Slot %s", match[1]), nil
		}
	}

	// Fallback to dmidecode with more lines for context
	cmd = fmt.Sprintf("dmidecode -t slot | grep -A10 'Bus Address: %s'", busInfo[:10])
	output, err = runSshCommand(client, cmd, hostIp, "", commandTimeout)
	if err != nil {
		return "UNKNOWN", err
	}
	logger.WithField("host", hostIp).WithField("bus", busInfo[:10]).WithField("raw_output", output).Debug("Raw dmidecode output")

	// Fixed regex: Capture Designation, then Current Usage, then ID (matches your output order)
	re := regexp.MustCompile(`(?s)Designation:\s*(.+?)\n.*Current Usage:\s*(.+?)\n.*ID:\s*(\S+)`)
	match := re.FindStringSubmatch(output)
	if len(match) > 3 {
		designation := strings.TrimSpace(match[1])
		usage := strings.TrimSpace(match[2])
		id := strings.TrimSpace(match[3])
		logger.WithFields(logrus.Fields{
			"host":        hostIp,
			"designation": designation,
			"usage":       usage,
			"id":          id,
		}).Debug("Parsed from dmidecode")
		return fmt.Sprintf("%s (ID: %s @ %s)", designation, id, hostIp), nil
	}

	logger.WithField("host", hostIp).Debug("Slot: UNKNOWN (no match in dmidecode)")
	return "UNKNOWN", nil
}

// getNicModel gets the NIC model using the existing client
func getNicModel(client *ssh.Client, hostIp, busInfo string) (string, error) {
	shortBus := strings.Join(strings.Split(busInfo, ":")[1:], ":")
	mu := getHostMutex(hostIp)
	mu.Lock()
	defer mu.Unlock()
	output, err := runSshCommand(client, "lspci | grep -i 'Ethernet controller'", hostIp, "", commandTimeout)
	if err != nil {
		return "UNKNOWN", err
	}
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, shortBus) {
			parts := strings.Split(line, "Ethernet controller:")
			if len(parts) > 1 {
				model := strings.Split(parts[1], "(")[0]
				model = strings.TrimSpace(model)
				logger.WithField("host", hostIp).WithField("model", model).Debug("NIC model found")
				return model, nil
			}
		}
	}
	logger.WithField("host", hostIp).WithField("bus", busInfo).Debug("NIC model unknown")
	return "UNKNOWN", nil
}

// parseLldp parses LLDP output
func parseLldp(client *ssh.Client, hostIp string) (map[string]map[string]string, error) {
	mu := getHostMutex(hostIp)
	mu.Lock()
	defer mu.Unlock()
	output, err := runSshCommand(client, "lldpctl", hostIp, "general", commandTimeout)
	if err != nil {
		return nil, err
	}
	if output == "" || strings.Contains(output, "command not found") {
		logger.WithField("host", hostIp).Debug("LLDP data not found or lldpctl missing")
		return nil, nil
	}
	data := make(map[string]map[string]string)
	sections := regexp.MustCompile(`-{10,}`).Split(output, -1)
	logger.WithField("host", hostIp).WithField("sections", len(sections)).Debug("Parsing LLDP output")
	for _, section := range sections {
		ifaceRe := regexp.MustCompile(`Interface:\s+(\S+)`)
		ifaceMatch := ifaceRe.FindStringSubmatch(section)
		if len(ifaceMatch) < 2 {
			continue
		}
		ifaceName := strings.TrimRight(ifaceMatch[1], ",")
		data[ifaceName] = make(map[string]string)

		sysNameRe := regexp.MustCompile(`SysName:\s+(\S+)`)
		sysNameMatch := sysNameRe.FindStringSubmatch(section)
		data[ifaceName]["Peer Switch"] = "UNKNOWN"
		if len(sysNameMatch) > 1 {
			data[ifaceName]["Peer Switch"] = sysNameMatch[1]
		}

		portIdRe := regexp.MustCompile(`PortID:\s+ifname\s+(\S+)`)
		portIdMatch := portIdRe.FindStringSubmatch(section)
		data[ifaceName]["Peer Port ID"] = "UNKNOWN"
		if len(portIdMatch) > 1 {
			data[ifaceName]["Peer Port ID"] = portIdMatch[1]
		}

		portDescRe := regexp.MustCompile(`PortDescr:\s+(.+)`)
		portDescMatch := portDescRe.FindStringSubmatch(section)
		data[ifaceName]["Port Description"] = "UNKNOWN"
		if len(portDescMatch) > 1 {
			data[ifaceName]["Port Description"] = portDescMatch[1]
		}

		logger.WithField("host", hostIp).WithField("iface", ifaceName).WithField("data", data[ifaceName]).Debug("LLDP for iface")
	}
	return data, nil
}

// collectHostData collects data from a host with error handling and timeout
func collectHostData(hostIp string, resultsChan chan<- []map[string]string, wg *sync.WaitGroup, ctx context.Context) {
	defer wg.Done()
	hostCtx, cancel := context.WithTimeout(ctx, hostTimeout)
	defer cancel()
	select {
	case <-hostCtx.Done():
		logger.WithField("host", hostIp).Warn("Collection timed out or cancelled")
		resultsChan <- nil
		return
	default:
	}

	logger.WithField("host", hostIp).Info("Starting data collection")
	client, err := sshConnect(hostIp)
	if err != nil {
		logger.WithError(err).WithField("host", hostIp).Error("SSH connection failed")
		if debugMode {
			debug.PrintStack()
		}
		resultsChan <- nil
		return
	}
	defer client.Close()

	interfaces, err := listInterfaces(client, hostIp)
	if err != nil {
		logger.WithError(err).WithField("host", hostIp).Error("Failed to list interfaces")
		interfaces = []string{}
	}

	var hostname string
	if enrollValid {
		hostname, err = getHostname(client, hostIp)
		if err != nil {
			logger.WithError(err).WithField("host", hostIp).Error("Failed to get hostname")
			hostname = "UNKNOWN"
		}
	} else {
		hostname = "UNKNOWN"
	}

	statuses := make(map[string]string)
	for _, iface := range interfaces {
		status, err := getInterfaceStatus(client, iface, hostIp)
		if err != nil {
			logger.WithError(err).WithFields(logrus.Fields{
				"host":      hostIp,
				"interface": iface,
			}).Error("Failed to get status")
			status = "unknown"
		}
		statuses[iface] = status
	}

	lldp, err := parseLldp(client, hostIp)
	if err != nil {
		logger.WithError(err).WithField("host", hostIp).Error("Failed to parse LLDP")
		lldp = make(map[string]map[string]string)
	}

	var results []map[string]string
	for _, iface := range interfaces {
		row := make(map[string]string)
		row["Host IP"] = hostIp
		row["Hostname"] = hostname
		row["Interface"] = iface

		if enrollValid {
			mac, macErr := getMacAddress(client, iface, hostIp)
			if macErr != nil {
				logger.WithError(macErr).WithFields(logrus.Fields{
					"host":      hostIp,
					"interface": iface,
				}).Error("Failed to get MAC")
				mac = "UNKNOWN"
			}
			row["MAC Address"] = mac

			bus, busErr := getBusInfo(client, iface, hostIp)
			if busErr != nil {
				logger.WithError(busErr).WithFields(logrus.Fields{
					"host":      hostIp,
					"interface": iface,
				}).Error("Failed to get bus info")
				bus = ""
			}

			model, modelErr := getNicModel(client, hostIp, bus)
			if modelErr != nil {
				logger.WithError(modelErr).WithFields(logrus.Fields{
					"host":      hostIp,
					"interface": iface,
				}).Error("Failed to get NIC model")
				model = "UNKNOWN"
			}
			row["NIC Model"] = model

			slot, slotErr := getPciSlot(client, hostIp, bus)
			if slotErr != nil {
				logger.WithError(slotErr).WithFields(logrus.Fields{
					"host":      hostIp,
					"interface": iface,
				}).Error("Failed to get PCI slot")
				slot = "UNKNOWN"
			}
			row["PCI Slot"] = slot

			lldpData := lldp[iface]
			if lldpData == nil {
				lldpData = map[string]string{
					"Peer Switch":      "UNKNOWN",
					"Peer Port ID":     "UNKNOWN",
					"Port Description": "UNKNOWN",
				}
			}
			row["Peer Switch"] = lldpData["Peer Switch"]
			row["Peer Port ID"] = lldpData["Peer Port ID"]
			row["Port Description"] = lldpData["Port Description"]
			row["Interface Status"] = statuses[iface]
		} else {
			row["MAC Address"] = "UNKNOWN"
			row["PCI Slot"] = "UNKNOWN"
			row["NIC Model"] = "UNKNOWN"
			row["Interface Status"] = "UNKNOWN"
			row["Peer Switch"] = "UNKNOWN"
			row["Peer Port ID"] = "UNKNOWN"
			row["Port Description"] = "UNKNOWN"
		}
		results = append(results, row)
	}
	resultsChan <- results
}

// saveDebugOutput saves debug output to file
func saveDebugOutput(host, command, output string) {
	safeCommand := strings.ReplaceAll(strings.ReplaceAll(command, " ", "_"), "/", "_")
	safeHost := strings.ReplaceAll(host, ".", "_")
	filename := filepath.Join(debugDir, fmt.Sprintf("%s_%s.txt", safeHost, safeCommand))
	if err := os.WriteFile(filename, []byte(output), 0644); err != nil {
		logger.WithError(err).WithFields(logrus.Fields{
			"host":    host,
			"command": command,
		}).Warn("Failed to save debug output")
		return
	}
	logger.WithField("file", filename).Debug("Saved debug output")
}

// writeCsv writes data to CSV
func writeCsv(data []map[string]string) error {
	if len(data) == 0 {
		logger.Info("No data to write to CSV")
		return nil
	}

	groups := make(map[[2]string][]map[string]string)
	for _, row := range data {
		key := [2]string{row["Host IP"], row["PCI Slot"]}
		groups[key] = append(groups[key], row)
	}

	redundancyStatus := make(map[[2]string]string)
	for key, interfaces := range groups {
		hostIp := key[0]
		pciSlot := key[1]

		interfacesUp := []map[string]string{}
		for _, iface := range interfaces {
			if strings.ToLower(iface["Interface Status"]) == "up" {
				interfacesUp = append(interfacesUp, iface)
			}
		}

		peerSwitches := make(map[string]bool)
		hasUnknownPeer := false
		for _, iface := range interfacesUp {
			peer := iface["Peer Switch"]
			if peer == "UNKNOWN" {
				hasUnknownPeer = true
			}
			peerSwitches[peer] = true
		}

		if pciSlot == "UNKNOWN" || hasUnknownPeer {
			redundancyStatus[key] = "UNKNOWN"
			logger.WithField("host", hostIp).Debug("Redundancy UNKNOWN due to unknown PCI or peer switch")
			continue
		}

		if len(interfacesUp) >= 2 {
			if len(peerSwitches) > 1 {
				redundancyStatus[key] = "REDUNDANT"
				logger.WithField("host", hostIp).Info("Redundant NICs on different TORs")
			} else {
				redundancyStatus[key] = "NOT REDUNDANT"
				logger.WithField("host", hostIp).Info("Redundant NICs connected to the SAME TOR")
			}
		} else {
			redundancyStatus[key] = "NOT REDUNDANT"
			logger.WithField("host", hostIp).Debug("Not redundant (fewer than 2 up interfaces)")
		}
	}

	for i := range data {
		key := [2]string{data[i]["Host IP"], data[i]["PCI Slot"]}
		data[i]["Redundancy"] = redundancyStatus[key]
	}

	file, err := os.Create(csvFile)
	if err != nil {
		return fmt.Errorf("failed to create CSV: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	fieldnames := []string{
		"Host IP", "Hostname", "Interface", "MAC Address", "PCI Slot", "NIC Model",
		"Interface Status", "Peer Switch", "Peer Port ID", "Port Description", "Redundancy",
	}
	writer.Write(fieldnames)

	for _, row := range data {
		record := []string{
			row["Host IP"], row["Hostname"], row["Interface"], row["MAC Address"], row["PCI Slot"], row["NIC Model"],
			row["Interface Status"], row["Peer Switch"], row["Peer Port ID"], row["Port Description"], row["Redundancy"],
		}
		writer.Write(record)
	}

	logger.WithField("file", csvFile).Info("Results written to CSV")
	return nil
}
