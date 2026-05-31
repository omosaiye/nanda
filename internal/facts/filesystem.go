package facts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const filesystemScheme = "fs"

type FilesystemStore struct {
	root string
}

func NewFilesystemStore(root string) (*FilesystemStore, error) {
	if root == "" {
		return nil, errors.New("filesystem facts store requires a root directory")
	}

	return &FilesystemStore{root: root}, nil
}

func (s *FilesystemStore) Put(ctx context.Context, facts []byte) (FactsPointer, error) {
	if err := ctx.Err(); err != nil {
		return FactsPointer{}, err
	}

	relativePath := deterministicPath(facts)
	fullPath := filepath.Join(s.root, relativePath)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		return FactsPointer{}, fmt.Errorf("create facts directory: %w", err)
	}
	if err := os.WriteFile(fullPath, facts, 0o644); err != nil {
		return FactsPointer{}, fmt.Errorf("write facts file: %w", err)
	}

	return FactsPointer{Scheme: filesystemScheme, Path: filepath.ToSlash(relativePath)}, nil
}

func (s *FilesystemStore) Get(ctx context.Context, pointer FactsPointer) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if pointer.Scheme != filesystemScheme {
		return nil, fmt.Errorf("unsupported facts pointer scheme %q", pointer.Scheme)
	}

	relativePath, err := cleanRelativePath(pointer.Path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(s.root, relativePath))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read facts file: %w", err)
	}

	return data, nil
}

func deterministicPath(facts []byte) string {
	sum := sha256.Sum256(facts)
	encoded := hex.EncodeToString(sum[:])
	return filepath.Join(encoded[:2], encoded[2:4], encoded+".facts")
}

func cleanRelativePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("facts pointer path is empty")
	}
	if filepath.IsAbs(path) {
		return "", errors.New("facts pointer path must be relative")
	}

	clean := filepath.Clean(filepath.FromSlash(path))
	if clean == "." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return "", errors.New("facts pointer path escapes store root")
	}

	return clean, nil
}
