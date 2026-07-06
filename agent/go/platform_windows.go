//go:build windows

package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"syscall"
	"unsafe"
)

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procOpenMutexW          = kernel32.NewProc("OpenMutexW")
	procCreateMutexW        = kernel32.NewProc("CreateMutexW")
	procReleaseMutex        = kernel32.NewProc("ReleaseMutex")
	procWaitForSingleObject = kernel32.NewProc("WaitForSingleObject")

	shell32           = syscall.NewLazyDLL("shell32.dll")
	procIsUserAnAdmin = shell32.NewProc("IsUserAnAdmin")
)

const (
	SYNCHRONIZE          = 0x00100000
	WAIT_ABANDONED       = 0x00000080
	WAIT_OBJECT_0        = 0x00000000
	WAIT_TIMEOUT         = 0x00000102
	WAIT_FAILED          = 0xFFFFFFFF
	ERROR_FILE_NOT_FOUND = 2
	MUTEX_TIMEOUT_MS     = 500
)

func IsAdmin() bool {
	ret, _, _ := procIsUserAnAdmin.Call()
	return ret != 0
}

func ApplyMkdtempPermissions(path string) {
	// subprocess.call(["icacls", dirpath, "/inheritance:e", "/grant", "*S-1-5-32-545:(OI)(CI)(RX)"])
	cmd := exec.Command("icacls", path, "/inheritance:e", "/grant", "*S-1-5-32-545:(OI)(CI)(RX)")
	cmd.Run()
}

func openMutex(name string) (uintptr, error) {
	namePtr, _ := syscall.UTF16PtrFromString(name)
	ret, _, err := procOpenMutexW.Call(
		uintptr(SYNCHRONIZE),
		0,
		uintptr(unsafe.Pointer(namePtr)),
	)
	if ret == 0 {
		return 0, err
	}
	return ret, nil
}

func waitMutex(handle uintptr) (bool, error) {
	ret, _, err := procWaitForSingleObject.Call(handle, uintptr(MUTEX_TIMEOUT_MS))
	if ret == WAIT_ABANDONED || ret == WAIT_OBJECT_0 {
		return true, nil
	}
	if ret == WAIT_TIMEOUT {
		return false, fmt.Errorf("timeout")
	}
	return false, err
}

func releaseMutex(handle uintptr) (bool, error) {
	ret, _, err := procReleaseMutex.Call(handle)
	if ret == 0 {
		return false, err
	}
	return true, nil
}

func HandleMutexPlatform(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		mutexName := r.FormValue("mutex")
		if mutexName == "" {
			jsonError(w, 400, "no mutex provided")
			return
		}

		agentMutexesLock.Lock()
		defer agentMutexesLock.Unlock()

		if _, ok := agentMutexes[mutexName]; ok {
			jsonSuccess(w, fmt.Sprintf("have mutex: %s", mutexName), nil)
			return
		}

		h, err := openMutex(mutexName)
		if err != nil {
			// Windows error handling can be tricky to map exactly to "Not found" vs "Access denied"
			// But for now:
			jsonError(w, 404, fmt.Sprintf("mutex not found or error: %v", err))
			return
		}

		ok, err := waitMutex(h)
		if ok {
			agentMutexes[mutexName] = h
			// Success 201
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(201)
			fmt.Fprintf(w, `{"message": "got mutex: %s", "status_code": 201}`, mutexName)
			return
		}

		syscall.CloseHandle(syscall.Handle(h)) // Close if we didn't store it?
		// Wait, if we failed to wait, we might not own it.

		jsonError(w, 408, fmt.Sprintf("timeout or error waiting for mutex: %v", err))
		return
	} else if r.Method == "DELETE" {
		mutexName := r.FormValue("mutex")
		if mutexName == "" {
			jsonError(w, 400, "no mutex provided")
			return
		}

		agentMutexesLock.Lock()
		defer agentMutexesLock.Unlock()

		h, ok := agentMutexes[mutexName]
		if !ok {
			jsonError(w, 404, fmt.Sprintf("mutex does not exist: %s", mutexName))
			return
		}

		delete(agentMutexes, mutexName)

		ok, err := releaseMutex(h)
		syscall.CloseHandle(syscall.Handle(h)) // Always close handle after releasing?
		// The python code just calls ReleaseMutex. It keeps the handle open?
		// "hndl_mutex = agent_mutexes.pop(mutex_name); ok, error = release_mutex(hndl_mutex)"
		// It doesn't seem to CloseHandle explicitly in the snippet provided, but Python might GC it or it just stays open?
		// In Go/C, we must close it.

		if ok {
			jsonSuccess(w, fmt.Sprintf("released mutex: %s", mutexName), nil)
		} else {
			jsonError(w, 500, fmt.Sprintf("failed releasing mutex: %v", err))
		}
		return
	}
}
