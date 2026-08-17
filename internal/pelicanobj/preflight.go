package pelicanobj

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Preflight verifies, before anything mounts, that the prefix is reachable
// and the credential carries the scopes pelfs needs: read (and, unless
// readOnly, create/modify/delete). Failures produce actionable messages
// instead of mid-mount EIOs.
func Preflight(ctx context.Context, s Store, prefixURL string, readOnly bool) error {
	// Read probe: listing the prefix root requires storage.read. A missing
	// directory is fine (brand-new prefix); a permission error is not.
	if _, err := s.ListDir(ctx, ""); err != nil && !errors.Is(err, os.ErrNotExist) {
		if isPermission(err) {
			return fmt.Errorf(
				"cannot read %s: the credential appears to lack read permission (storage.read) on this prefix: %w",
				prefixURL, err)
		}
		return fmt.Errorf("cannot reach %s: %w", prefixURL, err)
	}
	if readOnly {
		return nil
	}

	// Write probe: create, stat, and delete a marker object.
	var b [6]byte
	_, _ = rand.Read(b[:])
	key := ".pelfs-probe-" + hex.EncodeToString(b[:])
	if err := s.Put(ctx, key, strings.NewReader("pelfs write probe")); err != nil {
		if isPermission(err) {
			return fmt.Errorf(
				"cannot write to %s: the credential appears to lack write permission (storage.modify / storage.create) on this prefix: %w",
				prefixURL, err)
		}
		return fmt.Errorf("write probe to %s failed: %w", prefixURL, err)
	}
	if _, err := s.StatKey(ctx, key); err != nil {
		return fmt.Errorf("stat of freshly written probe object under %s failed: %w", prefixURL, err)
	}
	if err := s.Delete(ctx, key); err != nil {
		if isPermission(err) {
			return fmt.Errorf(
				"cannot delete from %s: the credential appears to lack delete permission (storage.modify) on this prefix: %w",
				prefixURL, err)
		}
		return fmt.Errorf("delete probe on %s failed: %w", prefixURL, err)
	}
	return nil
}

func isPermission(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "403") || strings.Contains(msg, "401") ||
		strings.Contains(msg, "forbidden") || strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "unauthorized") || strings.Contains(msg, "credential is required")
}
