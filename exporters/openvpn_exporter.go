package exporters

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type OpenvpnServerHeader struct {
	LabelColumns []string
	Metrics      []OpenvpnServerHeaderField
}

type OpenvpnServerHeaderField struct {
	Column    string
	Desc      *prometheus.Desc
	ValueType prometheus.ValueType
}

type OpenVPNExporter struct {
	statusPaths                 []string
	openvpnUpDesc               *prometheus.Desc
	openvpnStatusUpdateTimeDesc *prometheus.Desc
	openvpnConnectedClientsDesc *prometheus.Desc
	openvpnClientDescs          map[string]*prometheus.Desc
	openvpnServerHeaders        map[string]OpenvpnServerHeader
}

func NewOpenVPNExporter(statusPaths []string, ignoreIndividuals bool) (*OpenVPNExporter, error) {
	// Metrics exported both for client and server statistics.
	openvpnUpDesc := prometheus.NewDesc(
		prometheus.BuildFQName("openvpn", "", "up"),
		"Whether scraping OpenVPN's metrics was successful.",
		[]string{"status_path"}, nil)
	openvpnStatusUpdateTimeDesc := prometheus.NewDesc(
		prometheus.BuildFQName("openvpn", "", "status_update_time_seconds"),
		"UNIX timestamp at which the OpenVPN statistics were updated.",
		[]string{"status_path"}, nil)

	// Metrics specific to OpenVPN servers.
	openvpnConnectedClientsDesc := prometheus.NewDesc(
		prometheus.BuildFQName("openvpn", "", "server_connected_clients"),
		"Number Of Connected Clients",
		[]string{"status_path"}, nil)

	// Metrics specific to OpenVPN clients.
	openvpnClientDescs := map[string]*prometheus.Desc{
		"TUN/TAP read bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "tun_tap_read_bytes_total"),
			"Total amount of TUN/TAP traffic read, in bytes.",
			[]string{"status_path"}, nil),
		"TUN/TAP write bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "tun_tap_write_bytes_total"),
			"Total amount of TUN/TAP traffic written, in bytes.",
			[]string{"status_path"}, nil),
		"TCP/UDP read bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "tcp_udp_read_bytes_total"),
			"Total amount of TCP/UDP traffic read, in bytes.",
			[]string{"status_path"}, nil),
		"TCP/UDP write bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "tcp_udp_write_bytes_total"),
			"Total amount of TCP/UDP traffic written, in bytes.",
			[]string{"status_path"}, nil),
		"Auth read bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "auth_read_bytes_total"),
			"Total amount of authentication traffic read, in bytes.",
			[]string{"status_path"}, nil),
		"pre-compress bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "pre_compress_bytes_total"),
			"Total amount of data before compression, in bytes.",
			[]string{"status_path"}, nil),
		"post-compress bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "post_compress_bytes_total"),
			"Total amount of data after compression, in bytes.",
			[]string{"status_path"}, nil),
		"pre-decompress bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "pre_decompress_bytes_total"),
			"Total amount of data before decompression, in bytes.",
			[]string{"status_path"}, nil),
		"post-decompress bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "post_decompress_bytes_total"),
			"Total amount of data after decompression, in bytes.",
			[]string{"status_path"}, nil),
	}

	var serverHeaderClientLabels []string
	var serverHeaderClientLabelColumns []string
	var serverHeaderRoutingLabels []string
	var serverHeaderRoutingLabelColumns []string
	if ignoreIndividuals {
		serverHeaderClientLabels = []string{"status_path", "common_name"}
		serverHeaderClientLabelColumns = []string{"Common Name"}
		serverHeaderRoutingLabels = []string{"status_path", "common_name"}
		serverHeaderRoutingLabelColumns = []string{"Common Name"}
	} else {
		serverHeaderClientLabels = []string{"status_path", "common_name", "connection_time", "real_address", "virtual_address", "username"}
		serverHeaderClientLabelColumns = []string{"Common Name", "Connected Since", "Real Address", "Virtual Address", "Common Name"}
		serverHeaderRoutingLabels = []string{"status_path", "common_name", "real_address", "virtual_address"}
		serverHeaderRoutingLabelColumns = []string{"Common Name", "Real Address", "Virtual Address"}
	}

	openvpnServerHeaders := map[string]OpenvpnServerHeader{
		"CLIENT_LIST": {
			LabelColumns: serverHeaderClientLabelColumns,
			Metrics: []OpenvpnServerHeaderField{
				{
					Column: "Bytes Received",
					Desc: prometheus.NewDesc(
						prometheus.BuildFQName("openvpn", "server", "client_received_bytes_total"),
						"Amount of data received over a connection on the VPN server, in bytes.",
						serverHeaderClientLabels, nil),
					ValueType: prometheus.CounterValue,
				},
				{
					Column: "Bytes Sent",
					Desc: prometheus.NewDesc(
						prometheus.BuildFQName("openvpn", "server", "client_sent_bytes_total"),
						"Amount of data sent over a connection on the VPN server, in bytes.",
						serverHeaderClientLabels, nil),
					ValueType: prometheus.CounterValue,
				},
			},
		},
		"ROUTING_TABLE": {
			LabelColumns: serverHeaderRoutingLabelColumns,
			Metrics: []OpenvpnServerHeaderField{
				{
					Column: "Last Ref (time_t)",
					Desc: prometheus.NewDesc(
						prometheus.BuildFQName("openvpn", "server", "route_last_reference_time_seconds"),
						"Time at which a route was last referenced, in seconds.",
						serverHeaderRoutingLabels, nil),
					ValueType: prometheus.GaugeValue,
				},
			},
		},
	}

	return &OpenVPNExporter{
		statusPaths:                 statusPaths,
		openvpnUpDesc:               openvpnUpDesc,
		openvpnStatusUpdateTimeDesc: openvpnStatusUpdateTimeDesc,
		openvpnConnectedClientsDesc: openvpnConnectedClientsDesc,
		openvpnClientDescs:          openvpnClientDescs,
		openvpnServerHeaders:        openvpnServerHeaders,
	}, nil
}

// Converts OpenVPN status information into Prometheus metrics. This
// function automatically detects whether the file contains server or
// client metrics. For server metrics, it also distinguishes between the
// version 2 and 3 file formats.
func (e *OpenVPNExporter) collectStatusFromReader(statusPath string, file io.Reader, ch chan<- prometheus.Metric) error {
	reader := bufio.NewReader(file)
	buf, _ := reader.Peek(18)
	if bytes.HasPrefix(buf, []byte("TITLE,")) {
		// Server statistics, using format version 2.
		return e.collectServerStatusFromReader(statusPath, reader, ch, ",")
	} else if bytes.HasPrefix(buf, []byte("TITLE\t")) {
		// Server statistics, using format version 3. The only
		// difference compared to version 2 is that it uses tabs
		// instead of spaces.
		return e.collectServerStatusFromReader(statusPath, reader, ch, "\t")
	} else if bytes.HasPrefix(buf, []byte("OpenVPN STATISTICS")) {
		// Client statistics.
		return e.collectClientStatusFromReader(statusPath, reader, ch)
	} else if bytes.HasPrefix(buf, []byte("OpenVPN CLIENT LIS")) {
		// Server statistics, using format version 3. The only
		// difference compared to version 2 is that it uses tabs
		// instead of spaces.
		return e.collectServerStatusFromReaderV4(statusPath, reader, ch)
	} else {
		return fmt.Errorf("unexpected file contents: %q", buf)
	}
}

// Converts OpenVPN server status information into Prometheus metrics.
func (e *OpenVPNExporter) collectServerStatusFromReaderV4(statusPath string, file io.Reader, ch chan<- prometheus.Metric) error {
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	var currentSection string
	headersFound := map[string][]string{}
	numberConnectedClient := 0
	recordedMetrics := map[OpenvpnServerHeaderField][]string{}

	for scanner.Scan() {
		line := scanner.Text()

		// Skip empty lines
		if len(line) == 0 {
			continue
		}

		// Handle section headers without comma separator
		if !strings.Contains(line, ",") {
			if line == "OpenVPN CLIENT LIST" {
				currentSection = "CLIENT_LIST"
				continue
			} else if line == "ROUTING TABLE" {
				currentSection = "ROUTING_TABLE"
				continue
			} else if line == "GLOBAL STATS" {
				currentSection = "GLOBAL_STATS"
				continue
			} else if line == "END" {
				break
			}
		}

		fields := strings.Split(line, ",")

		switch currentSection {
		case "CLIENT_LIST":
			if strings.HasPrefix(line, "Updated,") {
				// Handle timestamp
				timeStr := fields[1]
				timeStartStats, err := parseTime(timeStr)
				if err != nil {
					return err
				}
				ch <- prometheus.MustNewConstMetric(
					e.openvpnStatusUpdateTimeDesc,
					prometheus.GaugeValue,
					float64(timeStartStats),
					statusPath)
			} else if strings.HasPrefix(line, "Common Name,") {
				// Store headers
				headersFound["CLIENT_LIST"] = fields
			} else {
				// Handle client data
				if header, ok := e.openvpnServerHeaders["CLIENT_LIST"]; ok {
					numberConnectedClient++

					// Create column value mapping
					columnValues := make(map[string]string)
					headers := headersFound["CLIENT_LIST"]

					for i, value := range fields {
						if i < len(headers) {
							columnValues[headers[i]] = value
						}
					}

					// Extract labels
					labels := []string{statusPath}
					for _, column := range header.LabelColumns {
						labels = append(labels, columnValues[column])
					}

					log.Println("LABELS: ", labels)

					// Export metrics
					for _, metric := range header.Metrics {
						if columnValue, ok := columnValues[metric.Column]; ok {
							if l, _ := recordedMetrics[metric]; !subslice(labels, l) {
								value, err := strconv.ParseFloat(columnValue, 64)
								if err != nil {
									return err
								}
								ch <- prometheus.MustNewConstMetric(
									metric.Desc,
									metric.ValueType,
									value,
									labels...)
								recordedMetrics[metric] = append(recordedMetrics[metric], labels...)
							} else {
								log.Printf("Metric entry with same labels: %s, %s", metric.Column, labels)
							}
						}
					}
				}
			}

		case "ROUTING_TABLE":
			if strings.HasPrefix(line, "Virtual Address,") {
				headersFound["ROUTING_TABLE"] = fields
			} else if header, ok := e.openvpnServerHeaders["ROUTING_TABLE"]; ok {
				columnValues := make(map[string]string)
				headers := headersFound["ROUTING_TABLE"]

				for i, value := range fields {
					if i < len(headers) {
						columnValues[headers[i]] = value
					}
				}

				labels := []string{statusPath}
				for _, column := range header.LabelColumns {
					labels = append(labels, columnValues[column])
				}

				for _, metric := range header.Metrics {
					if columnValue, ok := columnValues[metric.Column]; ok {
						if l, _ := recordedMetrics[metric]; !subslice(labels, l) {
							value, err := strconv.ParseFloat(columnValue, 64)
							if err != nil {
								return err
							}
							ch <- prometheus.MustNewConstMetric(
								metric.Desc,
								metric.ValueType,
								value,
								labels...)
							recordedMetrics[metric] = append(recordedMetrics[metric], labels...)
						}
					}
				}
			}
		}
	}

	// Add the number of connected clients metric
	ch <- prometheus.MustNewConstMetric(
		e.openvpnConnectedClientsDesc,
		prometheus.GaugeValue,
		float64(numberConnectedClient),
		statusPath)

	return scanner.Err()
}

// Helper function to parse time string into Unix timestamp
func parseTime(timeStr string) (int64, error) {
	// Parse time string in format "2024-10-21 09:23:08"
	t, err := time.Parse("2006-01-02 15:04:05", strings.TrimSpace(timeStr))
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}

// Converts OpenVPN server status information into Prometheus metrics.
func (e *OpenVPNExporter) collectServerStatusFromReader(statusPath string, file io.Reader, ch chan<- prometheus.Metric, separator string) error {
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	headersFound := map[string][]string{}
	// counter of connected client
	numberConnectedClient := 0

	recordedMetrics := map[OpenvpnServerHeaderField][]string{}

	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), separator)
		if fields[0] == "END" && len(fields) == 1 {
			// Stats footer.
		} else if fields[0] == "GLOBAL_STATS" {
			// Global server statistics.
		} else if fields[0] == "HEADER" && len(fields) > 2 {
			// Column names for CLIENT_LIST and ROUTING_TABLE.
			headersFound[fields[1]] = fields[2:]
		} else if fields[0] == "TIME" && len(fields) == 3 {
			// Time at which the statistics were updated.
			timeStartStats, err := strconv.ParseFloat(fields[2], 64)
			if err != nil {
				return err
			}
			ch <- prometheus.MustNewConstMetric(
				e.openvpnStatusUpdateTimeDesc,
				prometheus.GaugeValue,
				timeStartStats,
				statusPath)
		} else if fields[0] == "TITLE" && len(fields) == 2 {
			// OpenVPN version number.
		} else if header, ok := e.openvpnServerHeaders[fields[0]]; ok {
			if fields[0] == "CLIENT_LIST" {
				numberConnectedClient++
			}
			// Entry that depends on a preceding HEADERS directive.
			columnNames, ok := headersFound[fields[0]]
			if !ok {
				return fmt.Errorf("%s should be preceded by HEADERS", fields[0])
			}
			if len(fields) != len(columnNames)+1 {
				return fmt.Errorf("HEADER for %s describes a different number of columns", fields[0])
			}

			// Store entry values in a map indexed by column name.
			columnValues := map[string]string{}
			for _, column := range header.LabelColumns {
				columnValues[column] = ""
			}
			for i, column := range columnNames {
				columnValues[column] = fields[i+1]
			}

			// Extract columns that should act as entry labels.
			labels := []string{statusPath}
			for _, column := range header.LabelColumns {
				labels = append(labels, columnValues[column])
			}

			// Export relevant columns as individual metrics.
			for _, metric := range header.Metrics {
				if columnValue, ok := columnValues[metric.Column]; ok {
					if l, _ := recordedMetrics[metric]; !subslice(labels, l) {
						value, err := strconv.ParseFloat(columnValue, 64)
						if err != nil {
							return err
						}
						ch <- prometheus.MustNewConstMetric(
							metric.Desc,
							metric.ValueType,
							value,
							labels...)
						recordedMetrics[metric] = append(recordedMetrics[metric], labels...)
					} else {
						log.Printf("Metric entry with same labels: %s, %s", metric.Column, labels)
					}
				}
			}
		} else {
			return fmt.Errorf("unsupported key: %q", fields[0])
		}
	}
	// add the number of connected client
	ch <- prometheus.MustNewConstMetric(
		e.openvpnConnectedClientsDesc,
		prometheus.GaugeValue,
		float64(numberConnectedClient),
		statusPath)
	return scanner.Err()
}

// Does slice contain string
func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// Is a sub-slice of slice
func subslice(sub []string, main []string) bool {
	if len(sub) > len(main) {
		return false
	}
	for _, s := range sub {
		if !contains(main, s) {
			return false
		}
	}
	return true
}

// Converts OpenVPN client status information into Prometheus metrics.
func (e *OpenVPNExporter) collectClientStatusFromReader(statusPath string, file io.Reader, ch chan<- prometheus.Metric) error {
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ",")
		if fields[0] == "END" && len(fields) == 1 {
			// Stats footer.
		} else if fields[0] == "OpenVPN STATISTICS" && len(fields) == 1 {
			// Stats header.
		} else if fields[0] == "Updated" && len(fields) == 2 {
			// Time at which the statistics were updated.
			location, _ := time.LoadLocation("Local")
			timeParser, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", fields[1], location)
			if err != nil {
				return err
			}
			ch <- prometheus.MustNewConstMetric(
				e.openvpnStatusUpdateTimeDesc,
				prometheus.GaugeValue,
				float64(timeParser.Unix()),
				statusPath)
		} else if desc, ok := e.openvpnClientDescs[fields[0]]; ok && len(fields) == 2 {
			// Traffic counters.
			value, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				return err
			}
			ch <- prometheus.MustNewConstMetric(
				desc,
				prometheus.CounterValue,
				value,
				statusPath)
		} else {
			return fmt.Errorf("unsupported key: %q", fields[0])
		}
	}
	return scanner.Err()
}

func (e *OpenVPNExporter) collectStatusFromFile(statusPath string, ch chan<- prometheus.Metric) error {
	conn, err := os.Open(statusPath)
	defer conn.Close()
	if err != nil {
		return err
	}
	return e.collectStatusFromReader(statusPath, conn, ch)
}

func (e *OpenVPNExporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.openvpnUpDesc
}

func (e *OpenVPNExporter) Collect(ch chan<- prometheus.Metric) {
	for _, statusPath := range e.statusPaths {
		err := e.collectStatusFromFile(statusPath, ch)
		if err == nil {
			ch <- prometheus.MustNewConstMetric(
				e.openvpnUpDesc,
				prometheus.GaugeValue,
				1.0,
				statusPath)
		} else {
			log.Printf("Failed to scrape showq socket: %s", err)
			ch <- prometheus.MustNewConstMetric(
				e.openvpnUpDesc,
				prometheus.GaugeValue,
				0.0,
				statusPath)
		}
	}
}
