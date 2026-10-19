package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/golang-migrate/migrate/v4"

	"github.com/JonatanGarbuyo/lds-user-service/migrations"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}

	m, err := migrations.Open(databaseURL)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = m.Close()
	}()

	switch args[0] {
	case "up":
		return up(m)
	case "down":
		return down(m, args[1:])
	case "version":
		return version(m)
	case "force":
		return force(m, args[1:])
	default:
		return usage()
	}
}

func up(m *migrate.Migrate) error {
	err := m.Up()
	if errors.Is(err, migrate.ErrNoChange) {
		fmt.Println("no pending migrations")
		return nil
	}
	if err != nil {
		return err
	}

	version, dirty, err := m.Version()
	if err != nil {
		return err
	}
	fmt.Printf("migrated to version %d (dirty=%t)\n", version, dirty)
	return nil
}

func down(m *migrate.Migrate, args []string) error {
	steps := 1
	if len(args) > 0 {
		parsed, err := strconv.Atoi(args[0])
		if err != nil || parsed <= 0 {
			return fmt.Errorf("down step count must be a positive integer, got %q", args[0])
		}
		steps = parsed
	}

	err := m.Steps(-steps)
	if errors.Is(err, migrate.ErrNoChange) {
		fmt.Println("no migrations to roll back")
		return nil
	}
	if err != nil {
		return err
	}

	version, dirty, err := m.Version()
	if err != nil {
		if errors.Is(err, migrate.ErrNilVersion) {
			fmt.Println("rolled back to before version 1")
			return nil
		}
		return err
	}
	fmt.Printf("rolled back to version %d (dirty=%t)\n", version, dirty)
	return nil
}

func version(m *migrate.Migrate) error {
	v, dirty, err := m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		fmt.Println("no version applied")
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Printf("version %d (dirty=%t)\n", v, dirty)
	return nil
}

func force(m *migrate.Migrate, args []string) error {
	if len(args) != 1 {
		return errors.New("force requires a version, for example: migrate force 1")
	}
	version, err := strconv.Atoi(args[0])
	if err != nil || version < 0 {
		return fmt.Errorf("force version must be a non-negative integer, got %q", args[0])
	}
	if err := m.Force(version); err != nil {
		return err
	}
	fmt.Printf("forced version %d\n", version)
	return nil
}

func usage() error {
	return errors.New("usage: migrate <up|down [steps]|version|force <version>>")
}
