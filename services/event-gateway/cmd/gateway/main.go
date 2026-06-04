// Command gateway is the CyberZen event gateway entrypoint.
//
// It owns HTTP webhook intake for upstream SCM and CI providers, verifies
// signatures, buffers events in-memory, and forwards them to the Convex
// HTTP endpoint configured via CONVEX_URL.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/cyberzen/event-gateway/internal/forwarder"
	"github.com/cyberzen/event-gateway/internal/handlers"
	"github.com/cyberzen/event-gateway/internal/queue"
)

// config bundles environment-driven settings. All fields have defaults.
type config struct {
	Addr           string
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	ShutdownGrace  time.Duration
	BufferCapacity int
	FlushInterval  time.Duration
	ConvexURL      string
	ConvexToken    string
	GitHubSecret   string
	GitLabSecret   string
	BitbucketSecret string
	AzureSecret    string
	JenkinsSecret  string
	CircleCISecret string
	BuildkiteSecret string
}

func loadConfig() config {
	return config{
		Addr:            envOr("ADDR", ":8081"),
		ReadTimeout:     envDuration("READ_TIMEOUT", 10*time.Second),
		WriteTimeout:    envDuration("WRITE_TIMEOUT", 15*time.Second),
		IdleTimeout:     envDuration("IDLE_TIMEOUT", 60*time.Second),
		ShutdownGrace:   envDuration("SHUTDOWN_GRACE", 15*time.Second),
		BufferCapacity:  envInt("BUFFER_CAPACITY", 1024),
		FlushInterval:   envDuration("FLUSH_INTERVAL", 2*time.Second),
		ConvexURL:       os.Getenv("CONVEX_URL"),
		ConvexToken:     os.Getenv("CONVEX_TOKEN"),
		GitHubSecret:    os.Getenv("GITHUB_WEBHOOK_SECRET"),
		GitLabSecret:    os.Getenv("GITLAB_WEBHOOK_SECRET"),
		BitbucketSecret: os.Getenv("BITBUCKET_WEBHOOK_SECRET"),
		AzureSecret:     os.Getenv("AZURE_WEBHOOK_SECRET"),
		JenkinsSecret:   os.Getenv("JENKINS_WEBHOOK_SECRET"),
		CircleCISecret:  os.Getenv("CIRCLECI_WEBHOOK_SECRET"),
		BuildkiteSecret: os.Getenv("BUILDKITE_WEBHOOK_SECRET"),
	}
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg := loadConfig()

	fwd := forwarder.NewConvex(cfg.ConvexURL, cfg.ConvexToken)
	buf := queue.NewBuffer(cfg.BufferCapacity, cfg.FlushInterval, fwd.Send)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	buf.Start(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("/webhook/github", handlers.NewGitHub(cfg.GitHubSecret, buf))
	mux.Handle("/webhook/gitlab", handlers.NewGitLab(cfg.GitLabSecret, buf))
	mux.Handle("/webhook/bitbucket", handlers.NewBitbucket(cfg.BitbucketSecret, buf))
	mux.Handle("/webhook/azuredevops", handlers.NewAzureDevOps(cfg.AzureSecret, buf))
	mux.Handle("/webhook/jenkins", handlers.NewJenkins(cfg.JenkinsSecret, buf))
	mux.Handle("/webhook/circleci", handlers.NewCircleCI(cfg.CircleCISecret, buf))
	mux.Handle("/webhook/buildkite", handlers.NewBuildkite(cfg.BuildkiteSecret, buf))

	server := &http.Server{
		Addr:         cfg.Addr,
		Handler:      mux,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	go func() {
		logger.Info("event-gateway listening", "addr", cfg.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server crashed", "err", err)
			cancel()
		}
	}()

	<-ctx.Done()
	logger.Info("shutdown signal received; draining")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
	}
	buf.Stop(shutdownCtx)
	logger.Info("event-gateway stopped")
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parsed, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(key string, fallback int) int {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parsed, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return parsed
}
