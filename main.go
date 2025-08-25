package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

const version = "0.1.0"

type extraLabelsFlag []string

func (e *extraLabelsFlag) String() string {
	return strings.Join(*e, ",")
}

func (e *extraLabelsFlag) Set(value string) error {
	*e = append(*e, value)
	return nil
}

type Config struct {
	Port   string            `yaml:"port"`
	Bind   string            `yaml:"bind"`
	Labels map[string]string `yaml:"labels"`
}

func loadConfig(filename string) (*Config, error) {
	if filename == "" {
		return &Config{}, nil
	}

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", filename)
	}

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

var (
	extraLabelNames  []string
	extraLabelValues []string

	buildStatus          *prometheus.GaugeVec
	cpuUsageCores        *prometheus.GaugeVec
	cpuLimitCores        *prometheus.GaugeVec
	memoryUsage          *prometheus.GaugeVec
	memoryLimit          *prometheus.GaugeVec
	networkReceiveBytes  *prometheus.GaugeVec
	networkTransmitBytes *prometheus.GaugeVec
	blockInputBytes      *prometheus.GaugeVec
	blockOutputBytes     *prometheus.GaugeVec
	pids                 *prometheus.GaugeVec
)

func initMetrics() {
	baseLabels := []string{"runner_uuid", "pipeline_uuid"}
	allLabels := append(baseLabels, extraLabelNames...)

	buildStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bitbucket_agent_build_status",
			Help: "Status of the build container (1 if running, 0 if not)",
		},
		allLabels,
	)

	cpuUsageCores = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bitbucket_agent_build_cpu_usage_cores",
			Help: "CPU usage in cores for build container",
		},
		allLabels,
	)

	cpuLimitCores = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bitbucket_agent_build_cpu_limit_cores",
			Help: "CPU limit in cores for build container",
		},
		allLabels,
	)

	memoryUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bitbucket_agent_build_memory_usage",
			Help: "Memory usage in bytes for build container",
		},
		allLabels,
	)

	memoryLimit = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bitbucket_agent_build_memory_limit",
			Help: "Memory limit in bytes for build container",
		},
		allLabels,
	)

	networkReceiveBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bitbucket_agent_build_network_receive_bytes",
			Help: "Network receive bytes for build container",
		},
		allLabels,
	)

	networkTransmitBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bitbucket_agent_build_network_transmit_bytes",
			Help: "Network transmit bytes for build container",
		},
		allLabels,
	)

	blockInputBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bitbucket_agent_build_block_input_bytes",
			Help: "Block input bytes for build container",
		},
		allLabels,
	)

	blockOutputBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bitbucket_agent_build_block_output_bytes",
			Help: "Block output bytes for build container",
		},
		allLabels,
	)

	pids = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bitbucket_agent_build_pids",
			Help: "Number of active PIDs in build container",
		},
		allLabels,
	)
}

type DockerExporter struct {
	client *client.Client
}

func NewDockerExporter() (*DockerExporter, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	return &DockerExporter{client: cli}, nil
}

func (d *DockerExporter) findBuildContainer(ctx context.Context) (*types.Container, error) {
	containers, err := d.client.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	buildPattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_build$`)

	var buildContainers []types.Container
	for _, container := range containers {
		if container.State == "running" {
			for _, name := range container.Names {
				cleanName := strings.TrimPrefix(name, "/")
				if buildPattern.MatchString(cleanName) {
					buildContainers = append(buildContainers, container)
					break
				}
			}
		}
	}

	if len(buildContainers) == 0 {
		return nil, nil
	}

	sort.Slice(buildContainers, func(i, j int) bool {
		return buildContainers[i].Created > buildContainers[j].Created
	})

	return &buildContainers[0], nil
}

func (d *DockerExporter) getContainerStats(ctx context.Context, containerID string) (*container.Stats, error) {
	stats, err := d.client.ContainerStats(ctx, containerID, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get container stats: %w", err)
	}
	defer stats.Body.Close()

	var statsJSON container.Stats
	if err := json.NewDecoder(stats.Body).Decode(&statsJSON); err != nil {
		return nil, fmt.Errorf("failed to decode stats JSON: %w", err)
	}

	return &statsJSON, nil
}

func (d *DockerExporter) calculateCPUUsage(stats *container.Stats) float64 {
	cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage - stats.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stats.CPUStats.SystemUsage - stats.PreCPUStats.SystemUsage)

	if systemDelta > 0 && cpuDelta > 0 {
		cpuPercent := (cpuDelta / systemDelta) * float64(len(stats.CPUStats.CPUUsage.PercpuUsage))
		return cpuPercent
	}
	return 0
}

func (d *DockerExporter) getCPULimit(ctx context.Context, containerID string) float64 {
	inspect, err := d.client.ContainerInspect(ctx, containerID)
	if err != nil {
		return 0
	}

	if inspect.HostConfig.Resources.NanoCPUs > 0 {
		return float64(inspect.HostConfig.Resources.NanoCPUs) / 1e9
	}

	info, err := d.client.Info(ctx)
	if err != nil {
		return 0
	}

	return float64(info.NCPU)
}

func (d *DockerExporter) updateMetrics(ctx context.Context) error {
	buildStatus.Reset()
	cpuUsageCores.Reset()
	cpuLimitCores.Reset()
	memoryUsage.Reset()
	memoryLimit.Reset()
	networkReceiveBytes.Reset()
	networkTransmitBytes.Reset()
	blockInputBytes.Reset()
	blockOutputBytes.Reset()
	pids.Reset()

	container, err := d.findBuildContainer(ctx)
	if err != nil {
		return fmt.Errorf("failed to find build container: %w", err)
	}

	if container == nil {
		emptyLabels := make([]string, len(extraLabelNames)+2)
		buildStatus.WithLabelValues(emptyLabels...).Set(0)
		return nil
	}

	containerName := ""
	if len(container.Names) > 0 {
		containerName = strings.TrimPrefix(container.Names[0], "/")
	}

	runnerUUID := ""
	pipelineUUID := ""

	if containerName != "" {
		parts := strings.Split(containerName, "_")
		if len(parts) >= 3 && parts[len(parts)-1] == "build" {
			runnerUUID = parts[0]
			pipelineUUID = parts[1]
		}
	}

	labels := append([]string{runnerUUID, pipelineUUID}, extraLabelValues...)

	buildStatus.WithLabelValues(labels...).Set(1)

	stats, err := d.getContainerStats(ctx, container.ID)
	if err != nil {
		return fmt.Errorf("failed to get container stats: %w", err)
	}

	cpuUsage := d.calculateCPUUsage(stats)
	cpuUsageCores.WithLabelValues(labels...).Set(cpuUsage)

	cpuLimit := d.getCPULimit(ctx, container.ID)
	cpuLimitCores.WithLabelValues(labels...).Set(cpuLimit)

	memoryUsage.WithLabelValues(labels...).Set(float64(stats.MemoryStats.Usage))

	memLimit := float64(stats.MemoryStats.Limit)
	memoryLimit.WithLabelValues(labels...).Set(memLimit)

	var rxBytes, txBytes float64
	for _, network := range stats.Networks {
		rxBytes += float64(network.RxBytes)
		txBytes += float64(network.TxBytes)
	}
	networkReceiveBytes.WithLabelValues(labels...).Set(rxBytes)
	networkTransmitBytes.WithLabelValues(labels...).Set(txBytes)

	var blkRead, blkWrite float64
	for _, blk := range stats.BlkioStats.IoServiceBytesRecursive {
		if blk.Op == "Read" {
			blkRead += float64(blk.Value)
		} else if blk.Op == "Write" {
			blkWrite += float64(blk.Value)
		}
	}
	blockInputBytes.WithLabelValues(labels...).Set(blkRead)
	blockOutputBytes.WithLabelValues(labels...).Set(blkWrite)

	pids.WithLabelValues(labels...).Set(float64(stats.PidsStats.Current))

	return nil
}

func (d *DockerExporter) metricsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	if err := d.updateMetrics(ctx); err != nil {
		log.Printf("Error updating metrics: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	promhttp.Handler().ServeHTTP(w, r)
}

func registerMetrics() {
	prometheus.MustRegister(buildStatus)
	prometheus.MustRegister(cpuUsageCores)
	prometheus.MustRegister(cpuLimitCores)
	prometheus.MustRegister(memoryUsage)
	prometheus.MustRegister(memoryLimit)
	prometheus.MustRegister(networkReceiveBytes)
	prometheus.MustRegister(networkTransmitBytes)
	prometheus.MustRegister(blockInputBytes)
	prometheus.MustRegister(blockOutputBytes)
	prometheus.MustRegister(pids)
}

func main() {
	var (
		port        = flag.String("port", "", "Server port")
		bind        = flag.String("bind", "", "Bind address")
		configFile  = flag.String("config-file", "", "Use parameters from config file")
		showVersion = flag.Bool("version", false, "Show current version")
		extraLabels extraLabelsFlag
	)
	flag.Var(&extraLabels, "extra-label", "Add extra labels to any bitbucket_agent_build metrics")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	config, err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	finalPort := "8080"
	finalBind := "0.0.0.0"

	if config.Port != "" {
		finalPort = config.Port
	}
	if config.Bind != "" {
		finalBind = config.Bind
	}

	if *port != "" {
		finalPort = *port
	}
	if *bind != "" {
		finalBind = *bind
	}

	for key, value := range config.Labels {
		extraLabelNames = append(extraLabelNames, key)
		extraLabelValues = append(extraLabelValues, value)
	}

	for _, label := range extraLabels {
		parts := strings.SplitN(label, "=", 2)
		if len(parts) == 2 {
			found := false
			for i, name := range extraLabelNames {
				if name == parts[0] {
					extraLabelValues[i] = parts[1]
					found = true
					break
				}
			}
			if !found {
				extraLabelNames = append(extraLabelNames, parts[0])
				extraLabelValues = append(extraLabelValues, parts[1])
			}
		}
	}

	initMetrics()
	registerMetrics()

	if _, err := strconv.Atoi(finalPort); err != nil {
		log.Fatalf("Invalid port: %s", finalPort)
	}

	exporter, err := NewDockerExporter()
	if err != nil {
		log.Fatalf("Failed to create docker exporter: %v", err)
	}

	http.HandleFunc("/metrics", exporter.metricsHandler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html>
<head><title>Bitbucket Runner Exporter</title></head>
<body>
<h1>Bitbucket Runner Exporter</h1>
<p><a href="/metrics">Metrics</a></p>
</body>
</html>`)
	})

	addr := fmt.Sprintf("%s:%s", finalBind, finalPort)
	log.Printf("Starting server on %s", addr)

	server := &http.Server{
		Addr:         addr,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
