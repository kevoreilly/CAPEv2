package main

import (
	"net/http"
	"runtime"
)

func IsAdmin() bool {
	return false // Simplification for non-windows or non-root
}

func ApplyMkdtempPermissions(path string) {
	// No-op for unix usually, or chmod
}

func HandleMutexPlatform(w http.ResponseWriter, r *http.Request) {
	jsonError(w, 400, "mutex feature not supported on "+runtime.GOOS)
}
