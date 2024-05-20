package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

var (
	// IP banlist
	banlist      = make(map[string]time.Time)
	banDuration  = 1 * time.Minute // Duration for which an IP is banned
	requestLimit = 4               // Number of allowed requests per time window
	timeWindow   = 1 * time.Second // Time window for request limit
	mu           sync.Mutex        // Mutex to protect shared resources
	requests     = make(map[string][]time.Time)
)

type request struct {
	ip   string
	time time.Time
	body []byte
}

func createLog(req request, filepath string) {
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error writing log file:", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	newLine := fmt.Sprintf("IP:%s | Time:%s | Body:%s\n", req.ip, req.time.Format(time.RFC3339), string(req.body))

	_, err = writer.WriteString(newLine)
	if err != nil {
		fmt.Println("Error writing log file:", err)
		return
	}

	err = writer.Flush()
	if err != nil {
		fmt.Println("Error flushing log write buffer:", err)
		return
	}

	fmt.Println("Log successful.")
}

// getIP gets the client's real IP address from the request
func getIP(r *http.Request) string {
	// Try to get the IP from the X-Forwarded-For header (useful if the server is behind a proxy)
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		// If no X-Forwarded-For header, get the IP from RemoteAddr
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	return ip
}

// isBanned checks if an IP is in the banlist
func isBanned(ip string) bool {
	mu.Lock()
	defer mu.Unlock()
	banTime, exists := banlist[ip]
	if !exists {
		return false
	}
	if time.Now().After(banTime) {
		delete(banlist, ip)
		return false
	}
	return true
}

// addRequest records a new request from an IP and returns whether it should be banned
func addRequest(ip string) bool {
	mu.Lock()
	defer mu.Unlock()

	now := time.Now()
	requestTimes := requests[ip]

	// Filter out old requests that are outside the time window
	newRequestTimes := []time.Time{}
	for _, t := range requestTimes {
		if now.Sub(t) <= timeWindow {
			newRequestTimes = append(newRequestTimes, t)
		}
	}

	// Add the current request time
	newRequestTimes = append(newRequestTimes, now)
	requests[ip] = newRequestTimes

	// Check if the number of requests exceeds the limit
	if len(newRequestTimes) > requestLimit {
		banlist[ip] = now.Add(banDuration)
		delete(requests, ip) // Clear the request history for this IP
		return true
	}
	return false
}

// handler handles incoming HTTP POST requests
func handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the client's IP address
	clientIP := getIP(r)

	// Check if the IP is banned
	if isBanned(clientIP) {
		http.Error(w, "Forbidden access", http.StatusForbidden)
		return
	}

	// Add the request to the tracking system and check if the IP should be banned
	if addRequest(clientIP) {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	// Read the body of the request
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// Collect request data for logs and write it to file
	logFilePath := "./log.txt"
	requestData := request{ip: clientIP, time: time.Now(), body: body}
	createLog(requestData, logFilePath)

	// Log the client's IP address and the request body to the terminal
	fmt.Printf("Received request from %s: %s\n", clientIP, body)

	// Respond to the client
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Request received"))
}

func main() {
	http.HandleFunc("/", handler)

	fmt.Println("Server is listening on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
