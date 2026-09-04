package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// ScheduledPost represents a post scheduled for future publication
type ScheduledPost struct {
	ID           string       `json:"id"`
	UserPubkey   string       `json:"user_pubkey"`
	Kind         int          `json:"kind"`
	SignedEvent  *nostr.Event `json:"signed_event"`
	Relays       []string     `json:"relays"`
	ScheduledFor time.Time    `json:"scheduled_for"`
	Status       string       `json:"status"` // pending, processing, published, failed
	PublishedAt  *time.Time   `json:"published_at,omitempty"`
	ErrorMessage string       `json:"error_message,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
}

// copy returns a deep copy of the ScheduledPost to prevent data races
func (p *ScheduledPost) copy() *ScheduledPost {
	copy := *p
	if copy.SignedEvent != nil {
		eventCopy := *p.SignedEvent
		copy.SignedEvent = &eventCopy
	}
	if copy.PublishedAt != nil {
		t := *p.PublishedAt
		copy.PublishedAt = &t
	}
	if copy.Relays != nil {
		copy.Relays = make([]string, len(p.Relays))
		copyRelays(copy.Relays, p.Relays)
	}
	return &copy
}

func copyRelays(dst, src []string) {
	copy(dst, src)
}

// SchedulerStore handles persistence of scheduled posts
type SchedulerStore struct {
	mu       sync.RWMutex
	filePath string
	posts    map[string]*ScheduledPost
}

func NewSchedulerStore(dataDir string) (*SchedulerStore, error) {
	filePath := filepath.Join(dataDir, "scheduled_posts.json")
	store := &SchedulerStore{
		filePath: filePath,
		posts:    make(map[string]*ScheduledPost),
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, err
	}

	// Load existing data
	if err := store.load(); err != nil {
		return nil, err
	}

	// Crash recovery: reset any posts stuck in "processing" back to "pending".
	// If the process crashed after ListPending transitioned them to "processing"
	// but before publishPost could update the status, they would be stranded
	// forever. Re-publication is idempotent — events have fixed IDs and relays
	// dedup by event ID. (Bug 6 fix)
	recovered := 0
	for _, post := range store.posts {
		if post.Status == "processing" {
			post.Status = "pending"
			recovered++
		}
	}
	if recovered > 0 {
		log.Printf("Scheduler: recovered %d posts stuck in 'processing' state", recovered)
		if err := store.save(); err != nil {
			log.Printf("Scheduler: failed to persist recovery: %v", err)
		}
	}

	return store, nil
}

func (s *SchedulerStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // New file
		}
		return err
	}

	return json.Unmarshal(data, &s.posts)
}

// saveLocked writes the posts map to disk atomically.
// Caller MUST hold s.mu (write lock). (Bug 1 fix: crash-safe persistence)
func (s *SchedulerStore) saveLocked() error {
	data, err := json.MarshalIndent(s.posts, "", "  ")
	if err != nil {
		return err
	}

	return atomicWriteFile(s.filePath, data, 0644)
}

// save is a wrapper that acquires the lock before calling saveLocked.
// Used by callers that do not already hold the lock (e.g. NewSchedulerStore).
func (s *SchedulerStore) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *SchedulerStore) Add(post *ScheduledPost) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Save previous state for rollback (Bug 2 fix)
	prev, existed := s.posts[post.ID]
	s.posts[post.ID] = post

	if err := s.saveLocked(); err != nil {
		// Rollback on persistence failure
		if existed {
			s.posts[post.ID] = prev
		} else {
			delete(s.posts, post.ID)
		}
		return err
	}
	return nil
}

func (s *SchedulerStore) Get(id string) (*ScheduledPost, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if post, ok := s.posts[id]; ok {
		return post.copy(), nil
	}
	return nil, fmt.Errorf("post not found")
}

func (s *SchedulerStore) Update(post *ScheduledPost) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Save previous state for rollback (Bug 2 fix)
	prev, existed := s.posts[post.ID]
	s.posts[post.ID] = post

	if err := s.saveLocked(); err != nil {
		// Rollback on persistence failure
		if existed {
			s.posts[post.ID] = prev
		} else {
			delete(s.posts, post.ID)
		}
		return err
	}
	return nil
}

func (s *SchedulerStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Save previous state for rollback (Bug 2 fix)
	prev, existed := s.posts[id]
	delete(s.posts, id)

	if err := s.saveLocked(); err != nil {
		// Rollback on persistence failure
		if existed {
			s.posts[id] = prev
		}
		return err
	}
	return nil
}

// DeleteIfNotProcessing atomically checks ownership and status, then deletes
// the post — all under a single write lock. Returns an error if the post is
// not found, belongs to a different user, or is currently being published.
// (Bug 3 fix: eliminates check-then-delete race)
func (s *SchedulerStore) DeleteIfNotProcessing(id string, ownerPubkey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	post, ok := s.posts[id]
	if !ok {
		return fmt.Errorf("post not found")
	}

	if post.UserPubkey != ownerPubkey {
		return fmt.Errorf("not allowed")
	}

	if post.Status == "processing" {
		return fmt.Errorf("cannot delete post while it is being published")
	}

	// Save previous state for rollback
	prev := post
	delete(s.posts, id)

	if err := s.saveLocked(); err != nil {
		// Rollback on persistence failure
		s.posts[id] = prev
		return err
	}
	return nil
}

func (s *SchedulerStore) ListByUser(pubkey string) []*ScheduledPost {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*ScheduledPost
	for _, post := range s.posts {
		if post.UserPubkey == pubkey {
			result = append(result, post.copy())
		}
	}
	return result
}

func (s *SchedulerStore) ListPending() []*ScheduledPost {
	s.mu.Lock()
	defer s.mu.Unlock()

	var result []*ScheduledPost
	now := time.Now()

	for _, post := range s.posts {
		if post.Status == "pending" &&
			(post.ScheduledFor.Before(now) || post.ScheduledFor.Equal(now)) {
			// Atomically transition to "processing" to prevent duplicate work
			post.Status = "processing"
			result = append(result, post.copy())
		}
	}

	// Persist status changes while still holding the lock (Bug 1/2 fix)
	if err := s.saveLocked(); err != nil {
		log.Printf("Scheduler: failed to persist processing transitions: %v", err)
	}

	return result
}

// validateRelayURL performs SSRF protection by validating relay URLs.
// Only ws:// and wss:// schemes are allowed (scheduler only publishes to relays).
// Hosts are resolved to IP addresses and checked against private/non-public ranges. (Bug 7 fix)
func validateRelayURL(relayURL string) error {
	// Parse URL to ensure it's well-formed
	u, err := url.Parse(relayURL)
	if err != nil {
		return fmt.Errorf("invalid relay URL: %w", err)
	}

	// Only allow ws:// and wss:// schemes — the scheduler publishes to Nostr relays
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return fmt.Errorf("unsupported relay scheme: %s (only ws/wss allowed)", u.Scheme)
	}

	host := u.Hostname()

	// Reject if the host is an IP literal that is private/loopback/etc.
	if ip := net.ParseIP(host); ip != nil {
		if !isPublicIP(ip) {
			return fmt.Errorf("blocked relay address: %s", host)
		}
		return nil
	}

	// Resolve hostname to IP addresses and validate each
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("failed to resolve relay host %s: %w", host, err)
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return fmt.Errorf("blocked relay address: %s resolves to private IP %s", host, ip.String())
		}
	}

	return nil
}

// isPublicIP returns true if the IP is a public, routable address.
// Rejects loopback, private, link-local, multicast, unspecified, and
// CGNAT (100.64.0.0/10) ranges. (V-PRE-2 fix: hardens SSRF protection)
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	// Block CGNAT range 100.64.0.0/10 (RFC 6598)
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return false
	}
	return true
}

// Scheduler handles the background processing of scheduled posts
type Scheduler struct {
	store *SchedulerStore
}

func NewScheduler(dataDir string) (*Scheduler, error) {
	store, err := NewSchedulerStore(dataDir)
	if err != nil {
		return nil, err
	}
	return &Scheduler{store: store}, nil
}

// logWithFields is a simple structured logging helper
func logWithFields(level, message string, fields map[string]interface{}) {
	fieldStrs := make([]string, 0, len(fields))
	for k, v := range fields {
		fieldStrs = append(fieldStrs, fmt.Sprintf("%s=%v", k, v))
	}
	log.Printf("[%s] %s %s", level, message, strings.Join(fieldStrs, " "))
}

func (s *Scheduler) Start() {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			s.processPendingPosts()
		}
	}()
	logWithFields("info", "Scheduler started", map[string]interface{}{
		"interval": "1 minute",
	})
}

func (s *Scheduler) processPendingPosts() {
	posts := s.store.ListPending()

	for _, post := range posts {
		go s.publishPost(post)
	}
}

func (s *Scheduler) publishPost(post *ScheduledPost) {
	logWithFields("info", "Publishing scheduled post", map[string]interface{}{
		"post_id":     post.ID,
		"user_pubkey": post.UserPubkey,
	})

	ctx := context.Background()
	successCount := 0
	var lastErr error

	// Publish to local relay first.
	// khatru Relay.AddEvent returns (skipBroadcast, writeError):
	//   (false, nil) = new event stored and broadcast
	//   (true,  nil) = duplicate (ErrDupEvent), already on relay
	//   (false, err) = rejected or store error
	// Both nil-error cases mean the event is on the relay, so count as
	// success. Previously only `added=true` was counted, which inverted the
	// semantics: every brand-new local publish was marked as failure while
	// only duplicates were marked success. (B8 fix)
	if relay != nil {
		_, err := relay.AddEvent(ctx, post.SignedEvent)
		if err != nil {
			logWithFields("error", "Failed to add event to local relay", map[string]interface{}{
				"post_id": post.ID,
				"error":   err.Error(),
			})
			lastErr = err
		} else {
			successCount++
			logWithFields("info", "Event present on local relay", map[string]interface{}{
				"post_id": post.ID,
			})
		}
	}

	// Validate and publish to external relays
	for _, relayURL := range post.Relays {
		// SSRF protection: validate relay URL
		if err := validateRelayURL(relayURL); err != nil {
			logWithFields("warn", "Skipping invalid relay URL", map[string]interface{}{
				"post_id":   post.ID,
				"relay_url": relayURL,
				"error":     err.Error(),
			})
			if lastErr == nil {
				lastErr = err
			}
			continue
		}

		r, err := nostr.RelayConnect(ctx, relayURL)
		if err != nil {
			logWithFields("error", "Failed to connect to relay", map[string]interface{}{
				"post_id":   post.ID,
				"relay_url": relayURL,
				"error":     err.Error(),
			})
			lastErr = err
			continue
		}

		err = r.Publish(ctx, *post.SignedEvent)
		r.Close()

		if err != nil {
			logWithFields("error", "Failed to publish to relay", map[string]interface{}{
				"post_id":   post.ID,
				"relay_url": relayURL,
				"error":     err.Error(),
			})
			lastErr = err
			continue
		}

		successCount++
		logWithFields("info", "Published to relay", map[string]interface{}{
			"post_id":   post.ID,
			"relay_url": relayURL,
		})
	}

	// Update status based on actual publish results
	post.Status = "published"
	if successCount == 0 {
		post.Status = "failed"
		if lastErr != nil {
			post.ErrorMessage = "Publish failed"
		} else {
			post.ErrorMessage = "No valid relays specified"
		}
	}

	now := time.Now()
	post.PublishedAt = &now

	if err := s.store.Update(post); err != nil {
		logWithFields("error", "Failed to update post status", map[string]interface{}{
			"post_id": post.ID,
			"status":  post.Status,
			"error":   err.Error(),
		})
	}

	logWithFields("info", "Finished publishing scheduled post", map[string]interface{}{
		"post_id":       post.ID,
		"final_status":  post.Status,
		"success_count": successCount,
	})
}

// HTTP Handlers

// enableCORS sets same-origin CORS headers. Only echoes the Origin if it
// matches the expected request origin, preventing cross-origin access to
// scheduled drafts. Handles reverse proxies via X-Forwarded-Host/Proto.
// (Bug 9 fix + B-INT-1/2/F-INT-1 fixes: proxy-aware, full-origin comparison)
func (s *Scheduler) enableCORS(w http.ResponseWriter, r *http.Request) {
	// Always set Vary: Origin to prevent cache poisoning (F-INT-1 fix)
	w.Header().Add("Vary", "Origin")

	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}

	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return
	}

	// Reconstruct the expected origin using proxy headers when available.
	// X-Forwarded-Host is only trusted when DOCKER_ENV is set (behind a proxy)
	// to prevent spoofing when the relay is directly exposed. (B-INT-1 fix)
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if fwdProto := r.Header.Get("X-Forwarded-Proto"); fwdProto == "http" || fwdProto == "https" {
		scheme = fwdProto
	}
	host := r.Host
	if os.Getenv("DOCKER_ENV") == "true" {
		if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
			host = fwdHost
		}
	}
	expectedOrigin := scheme + "://" + host

	// Compare full origin (scheme + host + port) not just host. (B-INT-2 fix)
	if origin == expectedOrigin {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	}
}

func (s *Scheduler) HandleSchedule(w http.ResponseWriter, r *http.Request) {
	s.enableCORS(w, r)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Auth Check (NIP-98)
	userPubkey, err := checkAuth(r)
	if err != nil {
		logWithFields("warn", "Unauthorized schedule attempt", map[string]interface{}{
			"error": err.Error(),
		})
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse Body
	var req struct {
		SignedEvent  nostr.Event `json:"signed_event"`
		Relays       []string    `json:"relays"`
		ScheduledFor time.Time   `json:"scheduled_for"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logWithFields("warn", "Invalid JSON in schedule request", map[string]interface{}{
			"user_pubkey": userPubkey,
			"error":       err.Error(),
		})
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate scheduled_for. A zero/past time would publish immediately on
	// the next tick (B12 fix); a date far in the future would be stored
	// indefinitely. Require a future time within one year.
	now := time.Now()
	if req.ScheduledFor.IsZero() || !req.ScheduledFor.After(now) {
		logWithFields("warn", "Invalid scheduled_for: must be a future time", map[string]interface{}{
			"user_pubkey":    userPubkey,
			"scheduled_for":  req.ScheduledFor,
		})
		http.Error(w, "scheduled_for must be a future time", http.StatusBadRequest)
		return
	}
	if req.ScheduledFor.After(now.AddDate(1, 0, 0)) {
		logWithFields("warn", "Invalid scheduled_for: more than one year ahead", map[string]interface{}{
			"user_pubkey":    userPubkey,
			"scheduled_for":  req.ScheduledFor,
		})
		http.Error(w, "scheduled_for cannot be more than one year in the future", http.StatusBadRequest)
		return
	}

	// Validate User (must match signed event pubkey)
	if req.SignedEvent.PubKey != userPubkey {
		logWithFields("warn", "Event pubkey mismatch", map[string]interface{}{
			"user_pubkey":     userPubkey,
			"event_pubkey":    req.SignedEvent.PubKey,
		})
		http.Error(w, "Event pubkey mismatch", http.StatusBadRequest)
		return
	}

	// Validate signature
	ok, err := req.SignedEvent.CheckSignature()
	if !ok || err != nil {
		logWithFields("warn", "Invalid event signature", map[string]interface{}{
			"user_pubkey": userPubkey,
		})
		http.Error(w, "Invalid event signature", http.StatusBadRequest)
		return
	}

	// Validate relay URLs (SSRF protection)
	for _, relayURL := range req.Relays {
		if err := validateRelayURL(relayURL); err != nil {
			logWithFields("warn", "Invalid relay URL in request", map[string]interface{}{
				"user_pubkey": userPubkey,
				"relay_url":   relayURL,
				"error":       err.Error(),
			})
			http.Error(w, "Invalid relay URL", http.StatusBadRequest)
			return
		}
	}

	// Create ScheduledPost
	post := &ScheduledPost{
		ID:           nostr.GeneratePrivateKey(),
		UserPubkey:   userPubkey,
		Kind:         req.SignedEvent.Kind,
		SignedEvent:  &req.SignedEvent,
		Relays:       req.Relays,
		ScheduledFor: req.ScheduledFor,
		Status:       "pending",
		CreatedAt:    time.Now(),
	}

	if err := s.store.Add(post); err != nil {
		logWithFields("error", "Failed to save scheduled post", map[string]interface{}{
			"user_pubkey": userPubkey,
			"post_id":     post.ID,
			"error":       err.Error(),
		})
		http.Error(w, "Failed to save schedule", http.StatusInternalServerError)
		return
	}

	logWithFields("info", "Scheduled post created", map[string]interface{}{
		"user_pubkey":    userPubkey,
		"post_id":        post.ID,
		"scheduled_for":  req.ScheduledFor,
		"relay_count":    len(req.Relays),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(post)
}

func (s *Scheduler) HandleList(w http.ResponseWriter, r *http.Request) {
	s.enableCORS(w, r)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userPubkey, err := checkAuth(r)
	if err != nil {
		logWithFields("warn", "Unauthorized list attempt", map[string]interface{}{
			"error": err.Error(),
		})
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	posts := s.store.ListByUser(userPubkey)

	// Build a sanitized list response that omits SignedEvent to avoid
	// exposing unpublished Nostr events to cross-origin readers. (Bug 9 fix)
	type scheduledPostSummary struct {
		ID           string     `json:"id"`
		UserPubkey   string     `json:"user_pubkey"`
		Kind         int        `json:"kind"`
		Relays       []string   `json:"relays"`
		ScheduledFor time.Time  `json:"scheduled_for"`
		Status       string     `json:"status"`
		PublishedAt  *time.Time `json:"published_at,omitempty"`
		ErrorMessage string     `json:"error_message,omitempty"`
		CreatedAt    time.Time  `json:"created_at"`
	}
	summaries := make([]scheduledPostSummary, len(posts))
	for i, p := range posts {
		summaries[i] = scheduledPostSummary{
			ID:           p.ID,
			UserPubkey:   p.UserPubkey,
			Kind:         p.Kind,
			Relays:       p.Relays,
			ScheduledFor: p.ScheduledFor,
			Status:       p.Status,
			PublishedAt:  p.PublishedAt,
			ErrorMessage: p.ErrorMessage,
			CreatedAt:    p.CreatedAt,
		}
	}

	logWithFields("info", "Listed scheduled posts", map[string]interface{}{
		"user_pubkey":  userPubkey,
		"post_count":   len(posts),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summaries)
}

func (s *Scheduler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	s.enableCORS(w, r)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userPubkey, err := checkAuth(r)
	if err != nil {
		logWithFields("warn", "Unauthorized delete attempt", map[string]interface{}{
			"error": err.Error(),
		})
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing id", http.StatusBadRequest)
		return
	}

	// Atomically check ownership + status + delete under a single lock.
	// (Bug 3 fix: eliminates check-then-delete race)
	err = s.store.DeleteIfNotProcessing(id, userPubkey)
	if err != nil {
		errMsg := err.Error()
		switch {
		case errMsg == "post not found":
			logWithFields("warn", "Post not found for deletion", map[string]interface{}{
				"user_pubkey": userPubkey,
				"post_id":     id,
			})
			http.Error(w, "Post not found", http.StatusNotFound)
		case errMsg == "not allowed":
			logWithFields("warn", "Forbidden deletion attempt", map[string]interface{}{
				"user_pubkey": userPubkey,
				"post_id":     id,
			})
			http.Error(w, "Not allowed", http.StatusForbidden)
		case errMsg == "cannot delete post while it is being published":
			http.Error(w, "Cannot delete post while it is being published", http.StatusConflict)
		default:
			logWithFields("error", "Failed to delete scheduled post", map[string]interface{}{
				"user_pubkey": userPubkey,
				"post_id":     id,
				"error":       errMsg,
			})
			http.Error(w, "Failed to delete", http.StatusInternalServerError)
		}
		return
	}

	logWithFields("info", "Deleted scheduled post", map[string]interface{}{
		"user_pubkey": userPubkey,
		"post_id":     id,
	})

	w.WriteHeader(http.StatusOK)
}

// CheckAuth verifies NIP-98 header and checks if user is allowed in nostr.json
func checkAuth(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing Authorization header")
	}

	// Parse NIP-98 token inline (no nip98 subpackage available)
	prefix := "Nostr "
	if !strings.HasPrefix(authHeader, prefix) || len(authHeader) <= len(prefix) {
		return "", fmt.Errorf("invalid header format")
	}
	token := authHeader[len(prefix):]

	// Decode base64 event
	eventJSON, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", fmt.Errorf("invalid base64 token: %w", err)
	}

	var event nostr.Event
	if err := json.Unmarshal(eventJSON, &event); err != nil {
		return "", fmt.Errorf("invalid event JSON: %w", err)
	}

	// Validate NIP-98 requirements
	if event.Kind != 27235 {
		return "", fmt.Errorf("invalid event kind for NIP-98: %d", event.Kind)
	}

	ok, err := event.CheckSignature()
	if !ok || err != nil {
		return "", fmt.Errorf("invalid event signature")
	}

	// Reconstruct full request URL for comparison. Uses the shared helper so
	// scheduler auth, dashboard login and Blossom auth agree on the expected
	// URL behind reverse proxies. (F8 fix)
	fullURL := getRequestURL(r)

	// Check u tag matches request URL (fix potential panic)
	uTag := event.Tags.GetFirst([]string{"u", ""})
	if uTag == nil || len(*uTag) < 2 {
		return "", fmt.Errorf("missing or malformed u tag in NIP-98 token")
	}
	if (*uTag)[1] != fullURL {
		return "", fmt.Errorf("URL mismatch in NIP-98 token")
	}

	// Check method tag
	methodTag := event.Tags.GetFirst([]string{"method", ""})
	if methodTag == nil || len(*methodTag) < 2 {
		return "", fmt.Errorf("missing or malformed method tag in NIP-98 token")
	}
	if !strings.EqualFold((*methodTag)[1], r.Method) {
		return "", fmt.Errorf("method mismatch in NIP-98 token")
	}

	// Verify the auth event is fresh — reject tokens older than 60 seconds
	// or with an expired expiration tag. Prevents indefinite token replay. (Flag 6 fix)
	now := nostr.Now()
	if event.CreatedAt > now+60 {
		return "", fmt.Errorf("auth event created in the future")
	}
	if now-event.CreatedAt > 60 {
		return "", fmt.Errorf("auth event too old")
	}

	expirationTag := event.Tags.GetFirst([]string{"expiration"})
	if expirationTag != nil && len(*expirationTag) >= 2 {
		expiration, _ := strconv.ParseInt((*expirationTag)[1], 10, 64)
		if nostr.Timestamp(expiration) < now {
			return "", fmt.Errorf("auth event expired")
		}
	}

	pubkey := event.PubKey

	// Check against allowed list (data.Names)
	// Access the global 'data' variable
	allowed := false

	// Check if user is in data.Names
	for _, pk := range data.Names {
		if pk == pubkey {
			allowed = true
			break
		}
	}

	if !allowed {
		return "", fmt.Errorf("pubkey not allowed in nostr.json")
	}

	return pubkey, nil
}
