package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type createUserRequest struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

type createUserResponse struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Username string `json:"username"`
}

type tokenRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Aud      string `json:"aud"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
}

type testUser struct {
	ID       string
	Username string
	Password string
	Email    string
}

type statusCounter struct {
	mu     sync.Mutex
	counts map[int]int64
}

func (s *statusCounter) add(code int) {
	s.mu.Lock()
	s.counts[code]++
	s.mu.Unlock()
}

func (s *statusCounter) snapshot() map[int]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[int]int64, len(s.counts))
	for k, v := range s.counts {
		result[k] = v
	}
	return result
}

type metrics struct {
	iterations          atomic.Int64
	iterationFailures   atomic.Int64
	tokenSuccesses      atomic.Int64
	tokenFailures       atomic.Int64
	meSuccesses         atomic.Int64
	meFailures          atomic.Int64
	totalLatencyNanos   atomic.Int64
	maxLatencyNanos     atomic.Int64
	tokenStatusCounters statusCounter
	meStatusCounters    statusCounter
}

func main() {
	baseURL := flag.String("base-url", "http://localhost:8080", "Base API URL")
	userCount := flag.Int("user-count", 100, "Number of users to create before load test")
	concurrency := flag.Int("concurrency", 25, "Number of concurrent workers")
	duration := flag.Duration("duration", 30*time.Second, "Load test duration")
	timeout := flag.Duration("timeout", 5*time.Second, "HTTP timeout per request")
	password := flag.String("password", "LoadTestPass123!", "Password for generated users")
	aud := flag.String("aud", "api.local", "Audience for /token requests")
	flag.Parse()

	client := &http.Client{Timeout: *timeout}
	runID := time.Now().UTC().Format("20060102t150405")

	users, err := createUsers(client, strings.TrimRight(*baseURL, "/"), *userCount, runID, *password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create users: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Created %d users. Starting load test with %d workers for %s...\n", len(users), *concurrency, duration.String())

	m := &metrics{
		tokenStatusCounters: statusCounter{counts: map[int]int64{}},
		meStatusCounters:    statusCounter{counts: map[int]int64{}},
	}

	deadline := time.Now().Add(*duration)
	var userCursor atomic.Int64
	var wg sync.WaitGroup

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				idx := int(userCursor.Add(1)-1) % len(users)
				u := users[idx]
				iterStart := time.Now()

				token, tokenStatus, err := issueToken(client, *baseURL, u, *aud)
				m.tokenStatusCounters.add(tokenStatus)
				if err != nil {
					m.tokenFailures.Add(1)
					m.iterationFailures.Add(1)
					m.iterations.Add(1)
					continue
				}
				m.tokenSuccesses.Add(1)

				meStatus, err := callMe(client, *baseURL, token)
				m.meStatusCounters.add(meStatus)
				if err != nil {
					m.meFailures.Add(1)
					m.iterationFailures.Add(1)
					m.iterations.Add(1)
					continue
				}
				m.meSuccesses.Add(1)

				iterLatency := time.Since(iterStart).Nanoseconds()
				m.totalLatencyNanos.Add(iterLatency)
				updateMax(&m.maxLatencyNanos, iterLatency)
				m.iterations.Add(1)
			}
		}()
	}

	wg.Wait()

	totalIterations := m.iterations.Load()
	durationSeconds := duration.Seconds()
	if durationSeconds == 0 {
		durationSeconds = 1
	}
	iterationRPM := float64(totalIterations) / durationSeconds * 60
	avgMs := 0.0
	if totalIterations > 0 {
		avgMs = float64(m.totalLatencyNanos.Load()) / float64(totalIterations) / float64(time.Millisecond)
	}
	maxMs := float64(m.maxLatencyNanos.Load()) / float64(time.Millisecond)

	fmt.Println("\nLoad test summary")
	fmt.Printf("  users_created: %d\n", len(users))
	fmt.Printf("  concurrency: %d\n", *concurrency)
	fmt.Printf("  duration: %s\n", duration.String())
	fmt.Printf("  iterations: %d\n", totalIterations)
	fmt.Printf("  iteration_failures: %d\n", m.iterationFailures.Load())
	fmt.Printf("  iteration_rpm: %.1f\n", iterationRPM)
	fmt.Printf("  token_successes: %d\n", m.tokenSuccesses.Load())
	fmt.Printf("  token_failures: %d\n", m.tokenFailures.Load())
	fmt.Printf("  me_successes: %d\n", m.meSuccesses.Load())
	fmt.Printf("  me_failures: %d\n", m.meFailures.Load())
	fmt.Printf("  avg_iteration_latency_ms: %.1f\n", avgMs)
	fmt.Printf("  max_iteration_latency_ms: %.1f\n", maxMs)
	fmt.Printf("  token_status_counts: %v\n", m.tokenStatusCounters.snapshot())
	fmt.Printf("  me_status_counts: %v\n", m.meStatusCounters.snapshot())
}

func createUsers(client *http.Client, baseURL string, count int, runID, password string) ([]testUser, error) {
	users := make([]testUser, 0, count)
	for i := 0; i < count; i++ {
		username := fmt.Sprintf("lt_%s_%03d", runID, i)
		email := fmt.Sprintf("%s@example.com", username)
		req := createUserRequest{
			FirstName: fmt.Sprintf("Load%d", i),
			LastName:  "Tester",
			Email:     email,
			Username:  username,
			Password:  password,
		}

		status, body, err := postJSON(client, baseURL+"/user/create", req, nil)
		if err != nil {
			return nil, fmt.Errorf("create user %s request failed: %w", username, err)
		}
		if status != http.StatusCreated {
			return nil, fmt.Errorf("create user %s failed with status %d: %s", username, status, strings.TrimSpace(string(body)))
		}

		var created createUserResponse
		if err := json.Unmarshal(body, &created); err != nil {
			return nil, fmt.Errorf("decode create user response for %s: %w", username, err)
		}

		users = append(users, testUser{
			ID:       created.ID,
			Username: username,
			Password: password,
			Email:    email,
		})
	}
	return users, nil
}

func issueToken(client *http.Client, baseURL string, user testUser, aud string) (string, int, error) {
	payload := tokenRequest{
		Username: user.Username,
		Password: user.Password,
		Aud:      aud,
	}

	status, body, err := postJSON(client, strings.TrimRight(baseURL, "/")+"/token", payload, nil)
	if err != nil {
		return "", status, err
	}
	if status != http.StatusCreated {
		return "", status, fmt.Errorf("token status %d: %s", status, strings.TrimSpace(string(body)))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", status, err
	}
	if strings.TrimSpace(tokenResp.AccessToken) == "" {
		return "", status, errorsNew("empty access token")
	}

	return tokenResp.AccessToken, status, nil
}

func callMe(client *http.Client, baseURL, token string) (int, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(baseURL, "/")+"/me", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("/me status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return resp.StatusCode, nil
}

func postJSON(client *http.Client, url string, payload any, headers map[string]string) (int, []byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return resp.StatusCode, nil, readErr
	}

	return resp.StatusCode, body, nil
}

func updateMax(maxVal *atomic.Int64, candidate int64) {
	for {
		current := maxVal.Load()
		if candidate <= current {
			return
		}
		if maxVal.CompareAndSwap(current, candidate) {
			return
		}
	}
}

func errorsNew(msg string) error {
	return fmt.Errorf("%s", msg)
}
