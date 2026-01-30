package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go-fetcher/db"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// CAPE Task Statuses
const (
	TaskDistributed          = "distributed"
	TaskDistributedCompleted = "distributed_completed"
	TaskReported             = "reported"
)

type Config struct {
	DistDBConn     string
	MainDBConn     string
	RootDir        string
	Threads        int
	NFSMountFolder string
	IgnorePatterns []string
}

func main() {
	configPath := flag.String("config", "", "Path to JSON configuration file")
	distDB := flag.String("dist-db", "", "Distributed Database connection string")
	mainDB := flag.String("main-db", "", "Main Database connection string")
	rootDir := flag.String("root", ".", "CAPE Root directory")
	nfsMount := flag.String("nfs-mount", "", "NFS Mount folder base path (e.g. /mnt/cape_workers)")
	ignore := flag.String("ignore", "", "Comma-separated list of file/folder names to ignore (e.g. binary,memory.dmp)")
	threads := flag.Int("threads", 4, "Number of fetcher threads")
	flag.Parse()

	// 1. Load config from file if provided
	var cfg Config
	if *configPath != "" {
		file, err := os.Open(*configPath)
		if err != nil {
			log.Fatalf("Failed to open config file: %v", err)
		}
		decoder := json.NewDecoder(file)
		if err := decoder.Decode(&cfg); err != nil {
			log.Fatalf("Failed to decode config JSON: %v", err)
		}
		file.Close()
	}

	// 2. Override with CLI flags if provided (CLI takes precedence)
	if *distDB != "" {
		cfg.DistDBConn = *distDB
	}
	if *mainDB != "" {
		cfg.MainDBConn = *mainDB
	}
	if *rootDir != "." {
		cfg.RootDir = *rootDir
	}
	if *nfsMount != "" {
		cfg.NFSMountFolder = *nfsMount
	}
	if *threads != 4 {
		cfg.Threads = *threads
	}
	if *ignore != "" {
		cfg.IgnorePatterns = strings.Split(*ignore, ",")
	}

	// Default threads if 0
	if cfg.Threads == 0 {
		cfg.Threads = 4
	}
	if cfg.RootDir == "" {
		cfg.RootDir = "."
	}
	// Default ignores if empty?
	// Dist.py defaults: binary, dump_sorted.pcap, memory.dmp, logs
	if len(cfg.IgnorePatterns) == 0 {
		cfg.IgnorePatterns = []string{"binary", "dump_sorted.pcap", "memory.dmp", "logs"}
	}

	if cfg.DistDBConn == "" || cfg.MainDBConn == "" {
		log.Fatal("Both DistDBConn and MainDBConn are required (via config file or flags)")
	}

	if cfg.NFSMountFolder == "" {
		log.Fatal("NFSMountFolder is required for NFS fetching")
	}

	// Connect to Distributed DB
	distDBHandle, err := connectDB(cfg.DistDBConn)
	if err != nil {
		log.Fatalf("Failed to connect to Distributed DB: %v", err)
	}

	// Connect to Main DB
	mainDBHandle, err := connectDB(cfg.MainDBConn)
	if err != nil {
		log.Fatalf("Failed to connect to Main DB: %v", err)
	}

	log.Printf("Fast-Fetcher started with %d threads", cfg.Threads)
	log.Printf("Ignoring patterns: %v", cfg.IgnorePatterns)

	fetcher := &Fetcher{
		DistDB:         distDBHandle,
		MainDB:         mainDBHandle,
		RootDir:        cfg.RootDir,
		NFSMountFolder: cfg.NFSMountFolder,
		Threads:        cfg.Threads,
		IgnoreMap:      makeIgnoreMap(cfg.IgnorePatterns),
	}

	fetcher.Start()
}

func makeIgnoreMap(patterns []string) map[string]bool {
	m := make(map[string]bool)
	for _, p := range patterns {
		m[strings.TrimSpace(p)] = true
	}
	return m
}

func connectDB(connStr string) (*gorm.DB, error) {
	var dialector gorm.Dialector

	// Simple heuristic for dialector
	if bytes.HasPrefix([]byte(connStr), []byte("postgres")) {
		dialector = postgres.Open(connStr)
	} else if bytes.HasPrefix([]byte(connStr), []byte("mysql")) {
		dialector = mysql.Open(connStr)
	} else {
		dialector = sqlite.Open(connStr)
	}

	return gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
}

type Fetcher struct {
	DistDB         *gorm.DB
	MainDB         *gorm.DB
	RootDir        string
	NFSMountFolder string
	Threads        int
	IgnoreMap      map[string]bool
}

func (f *Fetcher) Start() {
	var wg sync.WaitGroup
	taskChan := make(chan db.Task, 100)

	// Worker threads
	for i := 0; i < f.Threads; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for task := range taskChan {
				f.ProcessTask(task)
			}
		}(i)
	}

	// Producer loop
	for {
		// Find tasks that are not retrieved and not finished in our dist db
		// We poll the nodes to see if they are "reported" there.
		// Actually, the dist.py fetcher loop looks for "reported" tasks on nodes.

		// Let's get all enabled nodes
		var nodes []db.Node
		f.DistDB.Where("enabled = ?", true).Find(&nodes)

		for _, node := range nodes {
			remoteTasks, err := f.FetchRemoteReportedTasks(node)
			if err != nil {
				log.Printf("Error fetching tasks from node %s: %v", node.Name, err)
				continue
			}

			if len(remoteTasks) == 0 {
				continue
			}

			// For each remote reported task, check if we have it in our dist db as pending retrieval
			var localTasks []db.Task
			f.DistDB.Where("node_id = ? AND task_id IN ? AND retrieved = ? AND finished = ?",
				node.ID, remoteTasks, false, false).Find(&localTasks)

			for _, t := range localTasks {
				taskChan <- t
			}
		}

		time.Sleep(10 * time.Second)
	}
}

func (f *Fetcher) FetchRemoteReportedTasks(node db.Node) ([]uint, error) {
	// GET node.URL + /tasks/list/?status=reported&ids=True
	apiURL, _ := url.Parse(node.URL)
	apiURL.Path = filepath.Join(apiURL.Path, "tasks", "list")

	q := apiURL.Query()
	q.Set("status", "reported")
	q.Set("ids", "True")
	apiURL.RawQuery = q.Encode()

	req, _ := http.NewRequest("GET", apiURL.String(), nil)
	req.Header.Set("Authorization", "Token "+node.APIKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var result struct {
		Data []struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	ids := make([]uint, len(result.Data))
	for i, d := range result.Data {
		ids[i] = d.ID
	}
	return ids, nil
}

func (f *Fetcher) ProcessTask(t db.Task) {
	log.Printf("Processing Task %d (Main: %d) from Node %d", t.TaskID, t.MainTaskID, t.NodeID)

	var node db.Node
	f.DistDB.First(&node, t.NodeID)

	// Construct NFS Source Path
	// Python: os.path.join(CUCKOO_ROOT, dist_conf.NFS.mount_folder, str(worker_name), "storage", "analyses", str(task_id))
	// f.NFSMountFolder should be the base mount path (e.g. /mnt/cape_workers or similar, or CUCKOO_ROOT/mount_folder)
	// If mount_folder in python config is relative, it is joined with CUCKOO_ROOT.
	// Here we assume f.NFSMountFolder is the absolute path to where nodes are mounted.
	// E.g. /opt/CAPE/nfs_mounts

	// Structure: <NFSMount>/<NodeName>/storage/analyses/<TaskID>
	srcDir := filepath.Join(f.NFSMountFolder, node.Name, "storage", "analyses", fmt.Sprintf("%d", t.TaskID))

	// Check if source exists (is mounted?)
	if _, err := os.Stat(srcDir); os.IsNotExist(err) {
		// Log warning but don't fail hard, maybe not synced yet?
		// dist.py logs error and returns True (skips).
		log.Printf("Source directory not found (yet?): %s", srcDir)
		return
	}

	// Destination: storage/analyses/<MainTaskID>
	destDir := filepath.Join(f.RootDir, "storage", "analyses", fmt.Sprintf("%d", t.MainTaskID))

	// Ensure dest dir doesn't exist (CopyDir requirement)
	os.RemoveAll(destDir)

	// Perform Copy
	if err := f.CopyDir(srcDir, destDir); err != nil {
		log.Printf("Failed to copy report from %s to %s: %v", srcDir, destDir, err)
		return
	}
	// 3. Update Statuses
	// Update Main DB
	f.MainDB.Table("tasks").Where("id = ?", t.MainTaskID).Update("status", TaskReported)

	// Update Dist DB
	f.DistDB.Model(&t).Updates(map[string]interface{}{
		"retrieved": true,
		"finished":  true,
	})

	// 4. Delete from worker
	f.DeleteFromWorker(node, t.TaskID)

	log.Printf("Successfully retrieved task %d (Main: %d)", t.TaskID, t.MainTaskID)
}
func (f *Fetcher) DeleteFromWorker(node db.Node, taskID uint) {
	// DELETE /tasks/delete/<task_id>/
	deleteURL := fmt.Sprintf("%s/tasks/delete/%d/", node.URL, taskID)
	req, _ := http.NewRequest("GET", deleteURL, nil) // CAPE uses GET for delete in some versions or POST?
	// In dist.py it uses DELETE method or POST to delete_many.
	// Actually dist.py: requests.post(url, data={"ids": ids, "delete_mongo": False})

	// Let's use POST delete_many for single ID to be sure
	deleteURL = fmt.Sprintf("%s/tasks/delete_many/", node.URL)
	form := url.Values{}
	form.Add("ids", fmt.Sprintf("%d", taskID))
	form.Add("delete_mongo", "False")

req, err := http.NewRequest("POST", deleteURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		log.Printf("Error creating delete request for task %d on node %s: %v", taskID, node.Name, err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Token "+node.APIKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

// CopyDir recursively copies a directory tree, attempting to preserve permissions.
func (f *Fetcher) CopyDir(src string, dst string) (err error) {
	src = filepath.Clean(src)
	dst = filepath.Clean(dst)

	si, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !si.IsDir() {
		return fmt.Errorf("source is not a directory")
	}

	_, err = os.Stat(dst)
	if err != nil && !os.IsNotExist(err) {
		return
	}
	// We allow dest to exist (merge/overwrite) or mkdirall
	err = os.MkdirAll(dst, si.Mode())
	if err != nil {
		return
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return
	}

	for _, entry := range entries {
		name := entry.Name()
		// Ignore pattern check
		if f.IgnoreMap[name] {
			continue
		}

		srcPath := filepath.Join(src, name)
		dstPath := filepath.Join(dst, name)

		if entry.IsDir() {
			err = f.CopyDir(srcPath, dstPath)
			if err != nil {
				return
			}
		} else {
			if entry.Type()&os.ModeSymlink != 0 {
				continue
			}

			err = CopyFile(srcPath, dstPath)
			if err != nil {
				return
			}
		}
	}

	return
}

func CopyFile(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		if e := out.Close(); e != nil {
			err = e
		}
	}()

	_, err = io.Copy(out, in)
	if err != nil {
		return
	}

	err = out.Sync()
	if err != nil {
		return
	}

	si, err := os.Stat(src)
	if err != nil {
		return
	}
	err = os.Chmod(dst, si.Mode())
	if err != nil {
		return
	}

	return
}
