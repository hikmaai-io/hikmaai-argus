// ABOUTME: Package dbupdater provides database update management for scanners
// ABOUTME: Handles ClamAV and Trivy DB updates with coordination and observability

/*
Package dbupdater provides infrastructure for managing scanner database updates.

# Overview

The dbupdater package coordinates background updates for scanner databases
(ClamAV CVDs, Trivy vulnerability DB) with scan operations, ensuring data
consistency and providing observability.

# Core Components

Backoff implements exponential backoff with jitter for retry logic:

	b := dbupdater.NewBackoff(dbupdater.BackoffConfig{
		MaxRetries:     5,
		InitialDelay:   30 * time.Second,
		MaxDelay:       30 * time.Minute,
		Multiplier:     2.0,
		JitterFraction: 0.2,
	})

	for {
		err := doOperation()
		if err == nil {
			break
		}

		delay, ok := b.NextDelay()
		if !ok {
			return errors.New("max retries exceeded")
		}
		time.Sleep(delay)
	}

ScanCoordinator manages concurrent access between scans and database updates
using RWLock semantics:

	coordinator := dbupdater.NewScanCoordinator()

	// For scan operations (multiple can run concurrently):
	release, err := coordinator.AcquireForScan(ctx)
	if err != nil {
		return err
	}
	defer release()
	// ... perform scan ...

	// For update operations (exclusive access):
	release, err := coordinator.AcquireForUpdate(ctx)
	if err != nil {
		return err
	}
	defer release()
	// ... perform update ...

StatusTracker monitors the health and version of multiple updaters:

	tracker := dbupdater.NewStatusTracker()
	tracker.Register("clamav")
	tracker.Register("trivy")

	// Update status during operations:
	tracker.SetStatus("clamav", dbupdater.StatusUpdating)
	tracker.SetLastUpdate("clamav", time.Now())
	tracker.SetVersion("clamav", dbupdater.VersionInfo{
		Version: 12345,
		DBFiles: map[string]int{"main.cvd": 12345, "daily.cvd": 67890},
	})
	tracker.SetReady("clamav", true)
	tracker.SetStatus("clamav", dbupdater.StatusIdle)

	// Query status:
	status := tracker.Get("clamav")
	allStatuses := tracker.GetAll()

# Updater Interface

The Updater interface defines the contract for database updaters:

	type Updater interface {
		Name() string
		Update(ctx context.Context) (*UpdateResult, error)
		CheckForUpdates(ctx context.Context) (*CheckResult, error)
		GetVersionInfo() VersionInfo
		IsReady() bool
	}

# ClamAV Updater

ClamAVUpdater downloads and manages ClamAV CVD files:

	updater := dbupdater.NewClamAVUpdater(dbupdater.ClamAVUpdaterConfig{
		DatabaseDir:  "/var/lib/clamav",
		Mirrors:      []string{"https://database.clamav.net"},
		Databases:    []string{"main.cvd", "daily.cvd"},
		ClamdAddress: "unix:///var/run/clamav/clamd.ctl", // optional
	})

	result, err := updater.Update(ctx)
	if err != nil {
		log.Printf("update failed: %v", err)
	}

# Trivy Updater

TrivyUpdater downloads the Trivy vulnerability database:

	updater := dbupdater.NewTrivyUpdater(dbupdater.TrivyUpdaterConfig{
		CacheDir:   "/var/cache/trivy",
		Binary:     "trivy",
		Timeout:    10 * time.Minute,
		SkipJavaDB: true,
	})

	// Check if update is needed
	check, _ := updater.CheckForUpdates(ctx)
	if check.NeedsUpdate() {
		result, err := updater.Update(ctx)
		// ...
	}

# Thread Safety

All components in this package are thread-safe and can be used from
multiple goroutines concurrently.

# Future Components

The following components are planned for future phases:

  - DBUpdateService for orchestrating all updaters
  - Integration with circuit breakers and health checks
*/
package dbupdater
