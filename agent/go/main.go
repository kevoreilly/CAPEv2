package main

import (
	"archive/zip"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/shlex"
)

const (
	AgentVersion   = "0.20"
	Base64Encoding = "base64"
)

var (
	AgentFeatures = []string{
		"execpy",
		"execute",
		"pinning",
		"logs",
		"largefile",
		"unicodepath",
		"push",
		"update",
	}
)

var (
	authToken string
)

func init() {
	if runtime.GOOS == "windows" {
		AgentFeatures = append(AgentFeatures, "mutex", "browser_extension")
	}
}

// Status enums
const (
	StatusInit      = "init"
	StatusRunning   = "running"
	StatusComplete  = "complete"
	StatusFailed    = "failed"
	StatusException = "exception"
)

var TerminalStatuses = map[string]bool{
	StatusComplete:  true,
	StatusFailed:    true,
	StatusException: true,
}

// State holds the agent state
type State struct {
	sync.Mutex
	Status          string
	Description     string
	AsyncSubprocess *exec.Cmd
	ClientIP        string
}

var state = State{
	Status: StatusInit,
}

// AgentMutexes holds handles to Windows mutexes
var agentMutexes = make(map[string]uintptr)
var agentMutexesLock sync.Mutex

// Browser Extension
var agentBrowserExtPath string
var agentBrowserLock sync.Mutex

// Stdout/Stderr capture (simple memory buffer for now, similar to Python's StringIO approach if not verbose)
// In a real service, we might want file-based logging or ring buffers.
// For this port, we'll keep it simple or write to a global buffer if we want to support /logs
// But capturing stdout/stderr of the *agent itself* is tricky if we are inside the process.
// The Python agent redirects sys.stdout. We can't easily redirect os.Stdout globally for the http handler to read
// without pipes. We'll stick to logging to os.Stdout/Stderr and maybe capturing if requested,
// but strictly speaking, /logs in the python agent returns the *agent's* internal logs.
// We will omit complex log capturing for this MVP and just return "Not implemented" or simple buffers if needed.
// Actually, let's implement a simple log buffer.

type LogBuffer struct {
	sync.Mutex
	buf []byte
}

func (l *LogBuffer) Write(p []byte) (n int, err error) {
	l.Lock()
	defer l.Unlock()
	l.buf = append(l.buf, p...)
	return len(p), nil
}

func (l *LogBuffer) String() string {
	l.Lock()
	defer l.Unlock()
	return string(l.buf)
}

var agentLogOut = &LogBuffer{}
var agentLogErr = &LogBuffer{}

func init() {
	// If not verbose, we might want to capture.
	// For now, let's just use standard log.
}

func jsonResponse(w http.ResponseWriter, code int, message string, data map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	resp := make(map[string]interface{})
	resp["message"] = message
	resp["status_code"] = code
	for k, v := range data {
		resp[k] = v
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Error encoding JSON: %v", err)
	}
}

func jsonError(w http.ResponseWriter, code int, message string, args ...interface{}) {
	data := make(map[string]interface{})
	if len(args) > 0 {
		if m, ok := args[0].(map[string]interface{}); ok {
			data = m
		}
	}
	data["error_code"] = code
	jsonResponse(w, code, message, data)
}

func jsonSuccess(w http.ResponseWriter, message string, data map[string]interface{}) {
	jsonResponse(w, 200, message, data)
}

func main() {
	host := flag.String("host", "0.0.0.0", "Host to bind to")
	port := flag.Int("port", 8000, "Port to bind to")
	verbose := flag.Bool("v", false, "Verbose logging")
	flag.StringVar(&authToken, "auth", "", "Optional: Require this token for all requests (Authorization: Bearer <token>)")
	flag.Parse()

	if !*verbose {
		// In a real scenario, redirect stdout/stderr to our buffers
		// For now, we print to stdout.
	}

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/status", handleStatus)
	http.HandleFunc("/logs", handleLogs)
	http.HandleFunc("/system", handleSystem)
	http.HandleFunc("/environ", handleEnviron)
	http.HandleFunc("/path", handlePath)
	http.HandleFunc("/mkdir", handleMkdir)
	http.HandleFunc("/mktemp", handleMktemp)
	http.HandleFunc("/mkdtemp", handleMkdtemp)
	http.HandleFunc("/store", handleStore)
	http.HandleFunc("/retrieve", handleRetrieve)
	http.HandleFunc("/push", handlePush)
	http.HandleFunc("/update", handleUpdate)
	http.HandleFunc("/extract", handleExtract)
	http.HandleFunc("/remove", handleRemove)
	http.HandleFunc("/execute", handleExecute)
	http.HandleFunc("/execpy", handleExecPy)
	http.HandleFunc("/pinning", handlePinning)
	http.HandleFunc("/kill", handleKill)
	http.HandleFunc("/browser_extension", handleBrowserExtension)
	http.HandleFunc("/mutex", handleMutex)

	addr := fmt.Sprintf("%s:%d", *host, *port)
	fmt.Printf("Starting CAPE Agent on %s\n", addr)
	if authToken != "" {
		fmt.Println("Authentication enabled.")
	}

	server := &http.Server{Addr: addr}

	// Handle graceful shutdown via /kill
	// We can run server in a goroutine or just handle it.

	// Retry logic for binding port (useful during self-update restart)
	var err error
	for i := 0; i < 10; i++ {
		err = server.ListenAndServe()
		if err == http.ErrServerClosed {
			break
		}
		if err != nil {
			// Check for "Address already in use"
			if strings.Contains(err.Error(), "address already in use") || strings.Contains(err.Error(), "Only one usage of each socket address") {
				fmt.Printf("Port %d busy, retrying in 1s...\n", *port)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Fatalf("ListenAndServe(): %v", err)
		}
		break
	}
}

// checkSecurity middleware-ish logic
func checkSecurity(w http.ResponseWriter, r *http.Request) bool {
	// 1. IP Security (Block Localhost / Own IP)
	// This prevents malware inside the VM from driving the agent.
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}

	// Always block loopback
	if clientIP == "127.0.0.1" || clientIP == "::1" {
		// Exception: Status check might be useful locally?
		// Python agent allowed status/browser_ext from localhost.
		// Strict mode: Block all.
		// "The check seems to be preventing *malware inside the VM* (localhost) from using the Agent to escalate?"
		// Yes.
		// However, for debugging, maybe we want it. But for security, block it.
		// Let's stick to strict blocking unless specific minimal endpoints.
		if r.URL.Path != "/status" {
			http.Error(w, "Access Denied (Localhost)", http.StatusForbidden)
			return false
		}
	}

	// Check against own IP (if we can detect it easily).
	// GetLocalIP() gets the outbound IP.
	// If clientIP == GetLocalIP(), it's also a self-call.
	if clientIP == GetLocalIP() && r.URL.Path != "/status" {
		http.Error(w, "Access Denied (Self)", http.StatusForbidden)
		return false
	}

	// 2. Auth Token (Defense in depth)
	if authToken != "" {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			authHeader = r.FormValue("token")
		}

		expected := "Bearer " + authToken
		if authHeader != expected && authHeader != authToken {
			jsonError(w, 403, "Unauthorized")
			return false
		}
	}

	// 3. IP Pinning (Legacy/Standard Feature)
	state.Lock()
	defer state.Unlock()

	if state.ClientIP != "" && state.ClientIP != clientIP {
		jsonError(w, 403, "Agent pinned to different IP")
		return false
	}

	return true
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}
	isAdmin := IsAdmin()
	jsonSuccess(w, "CAPE Agent!", map[string]interface{}{
		"version":       AgentVersion,
		"features":      AgentFeatures,
		"is_user_admin": isAdmin,
	})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}

	if r.Method == "GET" {
		state.Lock()
		defer state.Unlock()

		// Check async process
		if state.Status != StatusComplete && state.AsyncSubprocess != nil {
			// Poll process
			// In Go, os/exec.Cmd.Process.Signal(syscall.Signal(0)) checks existence,
			// but waiting is the only way to get exit code.
			// However, since we started it async, we should have a goroutine waiting on it
			// that updates the state.
			// Implementation Detail: When starting async, we'll spawn a goroutine to Wait() and update state.

			// So here we just return current state.
			jsonSuccess(w, "Analysis status", map[string]interface{}{
				"status":      state.Status,
				"description": state.Description,
				"process_id":  0, // We might store PID in state if needed
			})
			return
		}

		jsonSuccess(w, "Analysis status", map[string]interface{}{
			"status":      state.Status,
			"description": state.Description,
		})
		return
	} else if r.Method == "POST" {
		status := r.FormValue("status")
		if status == "" {
			jsonError(w, 400, "No valid status has been provided")
			return
		}

		s := strings.ToLower(status)
		switch s {
		case StatusInit, StatusRunning, StatusComplete, StatusFailed, StatusException:
		default:
			jsonError(w, 400, "Invalid status value provided")
			return
		}

		state.Lock()
		defer state.Unlock()

		if _, terminal := TerminalStatuses[strings.ToLower(status)]; terminal {
			state.AsyncSubprocess = nil
		}

		state.Status = strings.ToLower(status)
		state.Description = r.FormValue("description")

		jsonSuccess(w, "Analysis status updated", nil)
	}
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}
	jsonSuccess(w, "Agent logs", map[string]interface{}{
		"stdout": agentLogOut.String(),
		"stderr": agentLogErr.String(),
	})
}

func handleSystem(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}
	jsonSuccess(w, "System", map[string]interface{}{
		"system": runtime.GOOS,
	})
}

func handleEnviron(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}
	envMap := make(map[string]string)
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		if len(pair) == 2 {
			envMap[pair[0]] = pair[1]
		}
	}
	jsonSuccess(w, "Environment variables", map[string]interface{}{
		"environ": envMap,
	})
}

func handlePath(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}
	ex, err := os.Executable()
	if err != nil {
		ex = os.Args[0]
	}
	path, _ := filepath.Abs(ex)
	jsonSuccess(w, "Agent path", map[string]interface{}{
		"filepath": path,
	})
}

func handleMkdir(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dirpath := r.FormValue("dirpath")
	if dirpath == "" {
		jsonError(w, 400, "No dirpath has been provided")
		return
	}

	// mode ignored for now, or we can parse it
	err := os.MkdirAll(dirpath, 0777)
	if err != nil {
		jsonError(w, 500, "Error creating directory", map[string]interface{}{"traceback": err.Error()})
		return
	}
	jsonSuccess(w, "Successfully created directory", nil)
}

func handleMktemp(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}
	suffix := r.FormValue("suffix")
	prefix := r.FormValue("prefix")
	dirpath := r.FormValue("dirpath")
	if dirpath == "" {
		dirpath = os.TempDir()
	}

	f, err := os.CreateTemp(dirpath, prefix+"*"+suffix)
	if err != nil {
		jsonError(w, 500, "Error creating temporary file", map[string]interface{}{"traceback": err.Error()})
		return
	}
	f.Close()
	jsonSuccess(w, "Successfully created temporary file", map[string]interface{}{"filepath": f.Name()})
}

func handleMkdtemp(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}
	suffix := r.FormValue("suffix")
	prefix := r.FormValue("prefix")
	dirpath := r.FormValue("dirpath")
	if dirpath == "" {
		dirpath = os.TempDir()
	}

	d, err := os.MkdirTemp(dirpath, prefix+"*"+suffix)
	if err != nil {
		jsonError(w, 500, "Error creating temporary directory", map[string]interface{}{"traceback": err.Error()})
		return
	}

	// Windows ICACLS equivalent
	ApplyMkdtempPermissions(d)

	jsonSuccess(w, "Successfully created temporary directory", map[string]interface{}{"dirpath": d})
}

func handleStore(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filepathStr := r.FormValue("filepath")
	if filepathStr == "" {
		jsonError(w, 400, "No filepath has been provided")
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		jsonError(w, 400, "No file has been provided")
		return
	}
	defer file.Close()

	out, err := os.Create(filepathStr)
	if err != nil {
		jsonError(w, 500, fmt.Sprintf("Error storing file: %v", err))
		return
	}
	defer out.Close()

	_, err = io.Copy(out, file)
	if err != nil {
		jsonError(w, 500, fmt.Sprintf("Error storing file: %v", err))
		return
	}

	jsonSuccess(w, "Successfully stored file", nil)
}

func handleRetrieve(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filepathStr := r.FormValue("filepath")
	if filepathStr == "" {
		jsonError(w, 400, "No filepath has been provided")
		return
	}

	// Check if file exists
	if _, err := os.Stat(filepathStr); os.IsNotExist(err) {
		jsonError(w, 404, "File not found")
		return
	}

	// Encoding
	encoding := r.FormValue("encoding")
	// Streaming
	// streaming := r.FormValue("streaming") // Not implementing full streaming for now

	f, err := os.Open(filepathStr)
	if err != nil {
		jsonError(w, 500, fmt.Sprintf("Error reading file: %v", err))
		return
	}
	defer f.Close()

	if encoding == Base64Encoding {
		// Read all and encode
		data, err := io.ReadAll(f)
		if err != nil {
			jsonError(w, 500, fmt.Sprintf("Error reading file: %v", err))
			return
		}
		w.WriteHeader(200)
		encoder := base64.NewEncoder(base64.StdEncoding, w)
		encoder.Write(data)
		encoder.Close()
	} else {
		// Just serve file
		http.ServeFile(w, r, filepathStr)
	}
}

func handleUpdate(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		jsonError(w, 400, "No file provided")
		return
	}
	defer file.Close()

	// 1. Determine paths
	currentExe, err := os.Executable()
	if err != nil {
		jsonError(w, 500, fmt.Sprintf("Cannot find own executable path: %v", err))
		return
	}

	// Check permissions/directory
	dir := filepath.Dir(currentExe)
	newExe := currentExe + ".new"
	oldExe := currentExe + ".old"

	// Clean up previous leftovers if any
	os.Remove(newExe)
	os.Remove(oldExe)

	// 2. Save new binary
	out, err := os.Create(newExe)
	if err != nil {
		jsonError(w, 500, fmt.Sprintf("Cannot create new file: %v", err))
		return
	}
	_, err = io.Copy(out, file)
	out.Close()
	if err != nil {
		jsonError(w, 500, fmt.Sprintf("Cannot save new file: %v", err))
		return
	}

	// Make executable (Linux/Mac)
	os.Chmod(newExe, 0755)

	// 3. Rename-Replace Dance
	// Windows allows renaming the running binary.
	if err := os.Rename(currentExe, oldExe); err != nil {
		jsonError(w, 500, fmt.Sprintf("Failed to move current exe: %v", err))
		os.Remove(newExe)
		return
	}

	if err := os.Rename(newExe, currentExe); err != nil {
		// Try to rollback
		os.Rename(oldExe, currentExe)
		jsonError(w, 500, fmt.Sprintf("Failed to replace exe: %v", err))
		return
	}

	// 4. Spawn new process
	// We pass the same arguments.
	cmd := exec.Command(currentExe, os.Args[1:]...)
	cmd.Dir = dir

	// Detach process logic varies by OS, but Start() usually leaves it running if we exit main.
	// On Windows, it's fine.
	if err := cmd.Start(); err != nil {
		// Rollback attempt
		os.Rename(oldExe, currentExe) // Might fail if locked now?
		jsonError(w, 500, fmt.Sprintf("Failed to restart agent: %v", err))
		return
	}

	jsonSuccess(w, "Agent updated and restarting", nil)

	// 5. Commit Suicide (Gracefully)
	go func() {
		time.Sleep(1 * time.Second) // Give the response time to flush
		os.Exit(0)
	}()
}

func handlePush(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filepathStr := r.FormValue("filepath")

	// Security: We only upload back to the Caller (Requestor).
	// We ignore "target_url" if it points to a different IP.
	// Actually, let's just use the Caller IP and a provided port (or default 8000).

	if filepathStr == "" {
		jsonError(w, 400, "No filepath provided")
		return
	}

	// Open file
	f, err := os.Open(filepathStr)
	if err != nil {
		jsonError(w, 404, fmt.Sprintf("File not found: %v", err))
		return
	}
	defer f.Close()

	// Determine target
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}

	// Allow user to specify port?
	// For simplicity, let's assume standard CAPE resultserver port or provided in "port" param.
	targetPort := r.FormValue("port")
	if targetPort == "" {
		targetPort = "8000"
	} // Default CAPE port? Usually 2042 or 8000.

	// Allow specific path?
	uploadPath := r.FormValue("upload_path")
	if uploadPath == "" {
		uploadPath = "/upload"
	} // Standard path

	targetURL := fmt.Sprintf("http://%s:%s%s", clientIP, targetPort, uploadPath)

	// Do upload
	req, err := http.NewRequest("POST", targetURL, f)
	if err != nil {
		jsonError(w, 500, fmt.Sprintf("Error creating request: %v", err))
		return
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Filename", filepath.Base(filepathStr))

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		jsonError(w, 502, fmt.Sprintf("Error uploading to %s: %v", targetURL, err))
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		jsonError(w, resp.StatusCode, fmt.Sprintf("Upload failed: %s", string(respBody)))
		return
	}

	jsonSuccess(w, "File uploaded successfully", nil)
}

func handleExtract(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dirpath := r.FormValue("dirpath")
	if dirpath == "" {
		jsonError(w, 400, "No dirpath has been provided")
		return
	}

	file, _, err := r.FormFile("zipfile")
	if err != nil {
		jsonError(w, 400, "No zip file has been provided")
		return
	}
	defer file.Close()

	// Create a temp file to store zip content because zip.NewReader needs ReaderAt
	tmpZip, err := os.CreateTemp("", "capezip-*.zip")
	if err != nil {
		jsonError(w, 500, fmt.Sprintf("Error creating temp zip: %v", err))
		return
	}
	defer os.Remove(tmpZip.Name())
	defer tmpZip.Close()

	_, err = io.Copy(tmpZip, file)
	if err != nil {
		jsonError(w, 500, fmt.Sprintf("Error saving temp zip: %v", err))
		return
	}

	// Re-open for reading
	zipReader, err := zip.OpenReader(tmpZip.Name())
	if err != nil {
		jsonError(w, 500, fmt.Sprintf("Error opening zip: %v", err))
		return
	}
	defer zipReader.Close()

	for _, zf := range zipReader.File {
		fpath := filepath.Join(dirpath, zf.Name)

		// Check for ZipSlip
		if !strings.HasPrefix(fpath, filepath.Clean(dirpath)+string(os.PathSeparator)) {
			continue // Invalid file path
		}

		if zf.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			jsonError(w, 500, fmt.Sprintf("Error creating dir: %v", err))
			return
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zf.Mode())
		if err != nil {
			jsonError(w, 500, fmt.Sprintf("Error creating file: %v", err))
			return
		}

		rc, err := zf.Open()
		if err != nil {
			outFile.Close()
			jsonError(w, 500, fmt.Sprintf("Error extracting file: %v", err))
			return
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			jsonError(w, 500, fmt.Sprintf("Error writing file: %v", err))
			return
		}
	}

	jsonSuccess(w, "Successfully extracted zip file", nil)
}

func handleRemove(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}
	path := r.FormValue("path")
	if path == "" {
		jsonError(w, 400, "No path has been provided")
		return
	}

	// Force remove
	err := os.RemoveAll(path)
	if err != nil {
		jsonError(w, 500, "Error removing file or directory")
		return
	}
	jsonSuccess(w, "Successfully deleted file/directory", nil)
}

func handleExecute(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	command := r.FormValue("command")
	if command == "" {
		jsonError(w, 400, "No command has been provided")
		return
	}

	// Security check for execute (same as Python)
	localIP := GetLocalIP()
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

	allowedCommands := map[string]bool{"date": true, "cmd /c date /t": true}

	isLocal := (clientIP == "127.0.0.1" || clientIP == "::1" || clientIP == localIP)
	if isLocal && !allowedCommands[command] {
		// In Python agent: if request.client_ip in ("127.0.0.1", local_ip) and command not in allowed: return 500
		// Wait, this logic in python agent seems to restrict LOCALHOST from executing arbitrary commands?
		// Ah, "only allow date command from localhost. Even this is just to let it be tested"
		// So remote hosts CAN execute commands?
		// Logic in python:
		// if request.client_ip in ("127.0.0.1", local_ip) and request.form["command"] not in allowed_commands:
		//    return json_error(500, "Not allowed to execute commands")
		// This implies remote IPs are fine? That's weird for a sandbox, usually it's the opposite.
		// But in a sandbox, the controller (Host) calls the Agent (Guest).
		// If the Agent is exposed to the internet, anyone can run commands.
		// But usually Agent is on a private network.
		// The check seems to be preventing *malware inside the VM* (localhost) from using the Agent to escalate?
		// Yes, that makes sense. Malware running on localhost shouldn't be able to drive the agent.

		jsonError(w, 500, "Not allowed to execute commands")
		return
	}

	asyncExec := r.FormValue("async") != ""
	// shell := r.FormValue("shell") != "" // Go exec.Command doesn't support "shell=True" directly like Python.
	// We have to wrap in cmd /c or sh -c if we want shell features.
	// But `shlex.split` in Python splits args.
	// Here we should probably just execute directly if possible or split args.
	// For simplicity, let's just attempt to split string.

	// Robust splitting for quoted arguments
	parts, err := shlex.Split(command)
	if err != nil {
		jsonError(w, 400, fmt.Sprintf("Error parsing command: %v", err))
		return
	}
	if len(parts) == 0 {
		jsonError(w, 400, "Empty command")
		return
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	cwd := r.FormValue("cwd")
	if cwd != "" {
		cmd.Dir = cwd
	}

	if asyncExec {
		err := cmd.Start()
		if err != nil {
			jsonError(w, 500, fmt.Sprintf("Error executing command: %v", err))
			return
		}
		// We need to wait for it somewhere to avoid zombies, but "async" implies fire and forget?
		// Python agent stores it in `state.async_subprocess`.
		state.Lock()
		state.Status = StatusRunning
		state.Description = ""
		state.AsyncSubprocess = cmd
		state.Unlock()

		// Spawn waiter to clean up
		go func() {
			cmd.Wait()
			// Update state on completion?
			state.Lock()
			if state.AsyncSubprocess == cmd {
				state.Status = StatusComplete
				if !cmd.ProcessState.Success() {
					state.Status = StatusFailed
					state.Description = fmt.Sprintf("Exited with code %d", cmd.ProcessState.ExitCode())
				} else {
					state.Description = ""
				}
				state.AsyncSubprocess = nil
			}
			state.Unlock()
		}()

		jsonSuccess(w, "Successfully executed command", nil)
		return
	}

	// Sync exec
	// Re-create cmd to use separate buffers
	cmd = exec.Command(parts[0], parts[1:]...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	var stdoutBuf, stderrBuf strings.Builder
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err = cmd.Run()

	stdoutBytes := []byte(stdoutBuf.String())
	stderrBytes := []byte(stderrBuf.String())

	var data map[string]interface{}
	if r.FormValue("encoding") == Base64Encoding {
		data = map[string]interface{}{
			"stdout": base64.StdEncoding.EncodeToString(stdoutBytes),
			"stderr": base64.StdEncoding.EncodeToString(stderrBytes),
		}
	} else {
		data = map[string]interface{}{
			"stdout": string(stdoutBytes),
			"stderr": string(stderrBytes),
		}
	}

	if err != nil {
		state.Lock()
		state.Status = StatusFailed
		state.Description = "Error execute command"
		state.Unlock()
		jsonError(w, 500, fmt.Sprintf("Error executing command: %v", err), data)
		return
	}

	state.Lock()
	state.Status = StatusComplete
	state.Description = ""
	state.Unlock()

	jsonSuccess(w, "Successfully executed command", data)
}

func handleExecPy(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filepathStr := r.FormValue("filepath")
	if filepathStr == "" {
		jsonError(w, 400, "No Python file has been provided")
		return
	}

	asyncExec := r.FormValue("async") != ""
	cwd := r.FormValue("cwd")

	// Determine python executable
	pythonPath := "python" // Default
	// Could use flag or env var

	cmd := exec.Command(pythonPath, filepathStr)
	if cwd != "" {
		cmd.Dir = cwd
	}

	if asyncExec {
		state.Lock()
		if state.Status == StatusRunning && state.AsyncSubprocess != nil {
			state.Unlock()
			jsonError(w, 400, "Async process already running.")
			return
		}
		state.Unlock()

		err := cmd.Start()
		if err != nil {
			jsonError(w, 500, fmt.Sprintf("Error spawning python: %v", err))
			return
		}

		state.Lock()
		state.Status = StatusRunning
		state.Description = ""
		state.AsyncSubprocess = cmd
		state.Unlock()

		go func() {
			cmd.Wait()
			state.Lock()
			if state.AsyncSubprocess == cmd {
				state.Status = StatusComplete
				if !cmd.ProcessState.Success() {
					state.Status = StatusFailed
					state.Description = "Error executing python command."
				}
				state.AsyncSubprocess = nil // Python clears it?
				// Python: "Process completed; reset async subprocess state." in get_subprocess_status
			}
			state.Unlock()
		}()

		jsonSuccess(w, "Successfully spawned command", map[string]interface{}{
			"process_id": cmd.Process.Pid,
		})
		return
	}

	// Sync
	var stdoutBuf, stderrBuf strings.Builder
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()

	stdout := stdoutBuf.String()
	stderr := stderrBuf.String()

	if r.FormValue("encoding") == Base64Encoding {
		stdout = base64.StdEncoding.EncodeToString([]byte(stdout))
		stderr = base64.StdEncoding.EncodeToString([]byte(stderr))
	}

	if err != nil {
		state.Lock()
		state.Status = StatusFailed
		state.Description = "Error executing Python command"
		state.Unlock()

		// Return error but with stdout/stderr
		jsonError(w, 400, "Error executing python command.", map[string]interface{}{
			"stdout":   stdout,
			"stderr":   stderr,
			"exitcode": cmd.ProcessState.ExitCode(),
		})
		return
	}

	state.Lock()
	state.Status = StatusComplete
	state.Description = ""
	state.Unlock()

	jsonSuccess(w, "Successfully executed command", map[string]interface{}{
		"stdout": stdout,
		"stderr": stderr,
	})
}

func handlePinning(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}
	state.Lock()
	defer state.Unlock()

	if state.ClientIP != "" {
		jsonError(w, 500, "Agent has already been pinned to an IP!")
		return
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	state.ClientIP = host

	jsonSuccess(w, "Successfully pinned Agent", map[string]interface{}{
		"client_ip": host,
	})
}

func handleKill(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}
	jsonSuccess(w, "Quit the CAPE Agent", nil)
	go func() {
		time.Sleep(100 * time.Millisecond)
		os.Exit(0)
	}()
}

func handleBrowserExtension(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}
	agentBrowserLock.Lock()
	defer agentBrowserLock.Unlock()

	if agentBrowserExtPath == "" {
		tmpDir, err := os.MkdirTemp("", "")
		if err != nil {
			jsonError(w, 500, "Error creating temp dir")
			return
		}
		// Random name
		agentBrowserExtPath = filepath.Join(tmpDir, "bext_random.json")
	}

	data := r.FormValue("networkData")
	if data != "" {
		os.WriteFile(agentBrowserExtPath, []byte(data), 0644)
	}

	jsonSuccess(w, "OK", nil)
}

func handleMutex(w http.ResponseWriter, r *http.Request) {
	if !checkSecurity(w, r) {
		return
	}
	// Wrapper to call platform specific implementation
	HandleMutexPlatform(w, r)
}

// Helpers

func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}
