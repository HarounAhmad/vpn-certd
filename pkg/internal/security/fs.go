package security

import (
	"fmt"
	"github.com/HarounAhmad/vpn-certd/pkg/internal/constants"
	"os"
	"path/filepath"
)

func EnsureSocketDir(sockPath string) error {
	dir := filepath.Dir(sockPath)
	if err := os.MkdirAll(dir, constants.DirPerm0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if err := os.Chmod(dir, constants.DirPerm0700); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	return nil
}
