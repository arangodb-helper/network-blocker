package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/arangodb/network-blocker/middleware"
	"github.com/arangodb/network-blocker/service"
	"github.com/juju/errgo"
	logging "github.com/op/go-logging"
	"github.com/spf13/cobra"
)

// Configuration data with defaults:

const (
	projectName = "network-blocker"
)

var (
	cmdMain = cobra.Command{
		Use:   projectName,
		Short: "Network helper for testAgent",
		Run:   cmdMainRun,
	}
	log      = logging.MustGetLogger(projectName)
	appFlags struct {
		host string
		port int
		service.ServiceConfig
		logLevel string
	}
	maskAny = errgo.MaskFunc(errgo.Any)
)

func init() {
	f := cmdMain.Flags()
	f.StringVar(&appFlags.host, "host", "0.0.0.0", "Host address to listen on")
	f.IntVar(&appFlags.port, "port", 8086, "Port to listen on")
	f.StringVar(&appFlags.logLevel, "log-level", "debug", "Minimum log level (debug|info|warning|error)")
}

// handleSignal listens for termination signals and stops this process onup termination.
func handleSignal(sigChannel chan os.Signal, stopChan chan struct{}) {
	signalCount := 0
	for s := range sigChannel {
		signalCount++
		fmt.Println("Received signal:", s)
		if signalCount > 1 {
			os.Exit(1)
		}
		stopChan <- struct{}{}
	}
}

func main() {
	cmdMain.Execute()
}

func cmdMainRun(cmd *cobra.Command, args []string) {
	level, err := logging.LogLevel(appFlags.logLevel)
	if err != nil {
		Exitf("Invalid log-level '%s': %#v", appFlags.logLevel, err)
	}
	logging.SetLevel(level, projectName)

	// Interrupt signal:
	sigChannel := make(chan os.Signal)
	stopChan := make(chan struct{}, 10)
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	go handleSignal(sigChannel, stopChan)

	// Create service
	log.Debug("creating service")
	service, err := service.NewService(appFlags.ServiceConfig, service.ServiceDependencies{
		Logger: log,
	})
	if err != nil {
		Exitf("Failed to create service: %#v", err)
	}

	// Create middleware router
	handler := middleware.SetupRoutes(log, service)
	addr := fmt.Sprintf("%s:%d", appFlags.host, appFlags.port)

	// Initialize the service
	if err := service.Initialize(); err != nil {
		Exitf("Failed to initialize service: %#v", err)
	}

	// Run the server
	log.Infof("HTTP server listening on %s", addr)
	go func() {
		if err := http.ListenAndServe(addr, handler); err != nil {
			Exitf("Failed to start listener: %#v", err)
		}
	}()

	// Wait until stop
	<-stopChan

	// Cleanup
	log.Info("Cleaning up...")
	if err := service.Cleanup(); err != nil {
		Exitf("Cleanup failed: %#v", err)
	}

	log.Infof("%s terminated", projectName)
}

// getEnvVar returns the value of the environment variable with given key of the given default
// value of no such variable exist or is empty.
func getEnvVar(key, defaultValue string) string {
	value := os.Getenv(key)
	if value != "" {
		return value
	}
	return defaultValue
}

func Exitf(format string, args ...interface{}) {
	if !strings.HasSuffix(format, "\n") {
		format = format + "\n"
	}
	fmt.Printf(format, args...)
	os.Exit(1)
}

func findLocalIP() (string, error) {
	ifas, err := net.InterfaceAddrs()
	if err != nil {
		return "", maskAny(err)
	}
	for _, ia := range ifas {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := ia.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}
	return "", maskAny(fmt.Errorf("No suitable address found"))
}
