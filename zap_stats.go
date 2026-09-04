package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// ---------------------------------------------------------------------------
// Types — mirror the frontend AnalyticsData shape so the existing card
// components can consume the server response without changes.
// ---------------------------------------------------------------------------

type ZapStatsSnapshot struct {
	LastUpdated int64          `json:"lastUpdated"`
	Range       string         `json:"range"`
	Aggregate   AggregateStats `json:"aggregate"`
	Members     []MemberStats  `json:"members"`
}

// parsedZap is a parsed kind 9735 zap receipt destined to a community member.
type parsedZap struct {
	amount      int64
	createdAt   int64
	zapper      string
	recipient   string
	zappedEvent string // event ID from 'e' tag, if present
}

// eventInfoEntry holds cached content/metadata for a zapped event.
type eventInfoEntry struct {
	kind    int
	author  string
	content string
	created int64
}

// profileInfo holds a fetched kind 0 profile (name + picture).
type profileInfo struct {
	name    string
	picture string
}

type AggregateStats struct {
	TotalEarnings   int64                `json:"totalEarnings"`
	TotalZaps       int                  `json:"totalZaps"`
	UniqueZappers   int                  `json:"uniqueZappers"`
	EarningsByPeriod []EarningsByPeriod  `json:"earningsByPeriod"`
	TopContent      []EarningsByContent  `json:"topContent"`
	EarningsByKind  []EarningsByKind     `json:"earningsByKind"`
	TopZappers      []ZapperStats        `json:"topZappers"`
	TemporalPatterns TemporalPatterns    `json:"temporalPatterns"`
	ZapperLoyalty   LoyaltyStats         `json:"zapperLoyalty"`
}

type MemberStats struct {
	Pubkey            string            `json:"pubkey"`
	Name              string            `json:"name"`
	TotalEarnings     int64             `json:"totalEarnings"`
	TotalZaps         int               `json:"totalZaps"`
	UniqueZappers     int               `json:"uniqueZappers"`
	TopContentSats    int64             `json:"topContentSats"`
	TopContentPreview string            `json:"topContentPreview"`
	EarningsByPeriod  []EarningsByPeriod `json:"earningsByPeriod,omitempty"`
	TopZappers        []ZapperStats      `json:"topZappers,omitempty"`
}

type EarningsByPeriod struct {
	Period   string `json:"period"`
	TotalSats int64  `json:"totalSats"`
	ZapCount  int    `json:"zapCount"`
	Date      string `json:"date"`
}

type EarningsByContent struct {
	EventID   string `json:"eventId"`
	EventKind int    `json:"eventKind"`
	Content   string `json:"content"`
	Author    string `json:"author"`
	TotalSats int64  `json:"totalSats"`
	ZapCount  int    `json:"zapCount"`
	CreatedAt int64  `json:"created_at"`
}

type EarningsByKind struct {
	Kind       int    `json:"kind"`
	KindName   string `json:"kindName"`
	TotalSats  int64  `json:"totalSats"`
	ZapCount   int    `json:"zapCount"`
	Percentage float64 `json:"percentage"`
}

type ZapperStats struct {
	Pubkey    string `json:"pubkey"`
	Name      string `json:"name,omitempty"`
	Picture   string `json:"picture,omitempty"`
	TotalSats int64  `json:"totalSats"`
	ZapCount  int    `json:"zapCount"`
}

type TemporalPatterns struct {
	EarningsByHour       []EarningsByHour      `json:"earningsByHour"`
	EarningsByDayOfWeek  []EarningsByDayOfWeek `json:"earningsByDayOfWeek"`
}

type EarningsByHour struct {
	Hour         int   `json:"hour"`
	TotalSats    int64 `json:"totalSats"`
	ZapCount     int   `json:"zapCount"`
	AvgZapAmount int64 `json:"avgZapAmount"`
}

type EarningsByDayOfWeek struct {
	DayOfWeek    int    `json:"dayOfWeek"`
	DayName      string `json:"dayName"`
	TotalSats    int64  `json:"totalSats"`
	ZapCount     int    `json:"zapCount"`
	AvgZapAmount int64  `json:"avgZapAmount"`
}

type LoyaltyStats struct {
	NewZappers           int           `json:"newZappers"`
	ReturningZappers     int           `json:"returningZappers"`
	RegularSupporters    int           `json:"regularSupporters"`
	AverageLifetimeValue int64         `json:"averageLifetimeValue"`
	TopLoyalZappers      []ZapperStats `json:"topLoyalZappers"`
}

// ---------------------------------------------------------------------------
// In-memory cache + persistence
// ---------------------------------------------------------------------------

var (
	zapStatsMu        sync.RWMutex
	zapStatsCache     map[string]*ZapStatsSnapshot // keyed by range: "24h", "7d", "30d", "all"
	zapStatsCachePath = "db/zap-stats.json"
)

// kindNames mirrors the frontend KIND_NAMES map for the most common kinds.
var kindNames = map[int]string{
	0:     "Profiles",
	1:     "Notes",
	3:     "Contact Lists",
	6:     "Reactions",
	9734:  "Zap Requests",
	9735:  "Zap Receipts",
	30023: "Long-form Articles",
	30078: "App Data",
	31922: "Date-Based Calendar Event",
	31923: "Time-Based Calendar Event",
}

var dayNames = []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}

// ---------------------------------------------------------------------------
// Background goroutine — computes snapshots every 10 minutes
// ---------------------------------------------------------------------------

// startZapStatsBackground starts a goroutine that periodically computes
// community zap analytics and caches the result in memory + on disk.
func startZapStatsBackground(config Config) {
	// Try to load a persisted snapshot on startup so the endpoint
	// can serve immediately before the first computation finishes.
	loadZapStatsFromDisk()

	// Kick off the first computation immediately in the background.
	go func() {
		computeAndCacheZapStats(config)
	}()

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		computeAndCacheZapStats(config)
	}
}

func loadZapStatsFromDisk() {
	zapStatsMu.Lock()
	defer zapStatsMu.Unlock()
	body, err := os.ReadFile(zapStatsCachePath)
	if err != nil {
		return // no cached file — fine, will compute shortly
	}
	var snapshots map[string]*ZapStatsSnapshot
	if err := json.Unmarshal(body, &snapshots); err != nil {
		log.Printf("zap-stats: failed to parse cached snapshots: %v", err)
		return
	}
	zapStatsCache = snapshots
	// Log the "all" range's lastUpdated as representative
	if snap, ok := snapshots["all"]; ok {
		log.Printf("zap-stats: loaded cached snapshots from disk (lastUpdated: %s, ranges: %d)",
			time.Unix(snap.LastUpdated, 0).Format(time.RFC3339), len(snapshots))
	}
}

func saveZapStatsToDisk(snapshots map[string]*ZapStatsSnapshot) {
	body, err := json.MarshalIndent(snapshots, "", "  ")
	if err != nil {
		log.Printf("zap-stats: failed to marshal snapshots: %v", err)
		return
	}
	// Ensure the directory exists
	dir := zapStatsCachePath[:strings.LastIndex(zapStatsCachePath, "/")]
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("zap-stats: failed to create cache dir: %v", err)
		return
	}
	if err := os.WriteFile(zapStatsCachePath, body, 0644); err != nil {
		log.Printf("zap-stats: failed to write cache file: %v", err)
	}
}

// computeAndCacheZapStats queries the DB for all zap receipts destined to
// community members, computes aggregate + per-member analytics, and stores
// the result in the in-memory cache and on disk.
func computeAndCacheZapStats(config Config) {
	// Gather community pubkeys from nostr.json
	communityPubkeys := make(map[string]bool) // lowercase hex → true
	for _, pk := range data.Names {
		communityPubkeys[strings.ToLower(strings.TrimSpace(pk))] = true
	}
	if len(communityPubkeys) == 0 {
		log.Printf("zap-stats: no community pubkeys in nostr.json, skipping")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// ---- Collect zap receipts from both local DB and external relays ----

	// Track which event IDs were already in the local DB (so we only save
	// truly new ones from external relays)
	localIDs := make(map[string]bool)
	allReceipts := make(map[string]*nostr.Event)

	// 1. Query local DB for kind 9735 zap receipts
	localCh, err := db.QueryEvents(ctx, nostr.Filter{
		Kinds: []int{9735},
		Limit: 0, // no limit — get everything
	})
	if err != nil {
		log.Printf("zap-stats: local QueryEvents error: %v", err)
	} else {
		for evt := range localCh {
			allReceipts[evt.ID] = evt
			localIDs[evt.ID] = true
		}
	}
	log.Printf("zap-stats: local DB has %d kind 9735 receipts", len(allReceipts))

	// 2. Discover NIP-65 relays from kind 10002 events in the local DB
	relayURLs := discoverNip65Relays(ctx, communityPubkeys)
	log.Printf("zap-stats: discovered %d NIP-65 relays: %v", len(relayURLs), relayURLs)

	// 3. Fan out to external relays and fetch zap receipts for community pubkeys
	communityPubkeyList := make([]string, 0, len(communityPubkeys))
	for pk := range communityPubkeys {
		communityPubkeyList = append(communityPubkeyList, pk)
	}

	externalReceipts := fetchZapReceiptsFromRelays(ctx, relayURLs, communityPubkeyList)
	newFromExternal := 0
	for _, evt := range externalReceipts {
		if !localIDs[evt.ID] {
			// This is a new receipt we didn't have locally — save it
			if err := db.SaveEvent(ctx, evt); err == nil {
				newFromExternal++
			}
		}
		allReceipts[evt.ID] = evt
	}
	log.Printf("zap-stats: fetched %d receipts from external relays (%d new saved, %d already local)",
		len(externalReceipts), newFromExternal, len(externalReceipts)-newFromExternal)

	zaps := make([]parsedZap, 0, 500)
	zappedEventIDs := make(map[string]bool)

	// Parse all receipts (local + external, deduplicated)
	for _, evt := range allReceipts {
		parsed := parseZapReceiptEvent(evt, communityPubkeys)
		if parsed == nil {
			continue
		}
		zaps = append(zaps, *parsed)
		if parsed.zappedEvent != "" {
			zappedEventIDs[parsed.zappedEvent] = true
		}
	}

	log.Printf("zap-stats: parsed %d community zap receipts (zapped events: %d)",
		len(zaps), len(zappedEventIDs))

	// Fetch zapped event content for top-content and kind breakdown.
	// Query in chunks to avoid overly large filters.
	eventInfo := make(map[string]eventInfoEntry)

	eventIDs := make([]string, 0, len(zappedEventIDs))
	for id := range zappedEventIDs {
		eventIDs = append(eventIDs, id)
	}

	// First pass: fetch the zapped events themselves
	const chunkSize = 500
	for i := 0; i < len(eventIDs); i += chunkSize {
		end := i + chunkSize
		if end > len(eventIDs) {
			end = len(eventIDs)
		}
		chunk := eventIDs[i:end]

		ech, err := db.QueryEvents(ctx, nostr.Filter{
			IDs:   chunk,
			Limit: len(chunk),
		})
		if err != nil {
			log.Printf("zap-stats: error fetching zapped events chunk %d: %v", i/chunkSize, err)
			continue
		}
		for evt := range ech {
			content := evt.Content
			if len(content) > 200 {
				content = content[:200] + "..."
			}
			eventInfo[evt.ID] = eventInfoEntry{
				kind:    evt.Kind,
				author:  strings.ToLower(evt.PubKey),
				content: content,
				created: int64(evt.CreatedAt),
			}
		}
	}

	// Second pass: follow q tags (NIP-18 quote reposts) to fetch
	// quoted event content and prepend it to the zapped event's preview.
	// We need the raw tags, so re-query the events we found in the first pass.
	foundIDs := make([]string, 0, len(eventInfo))
	for id := range eventInfo {
		foundIDs = append(foundIDs, id)
	}

	quotedIDs := make(map[string]bool)
	type quoteRef struct {
		quotedID  string
		quotedBy  string // the zapped event ID that contains the q tag
	}
	var quoteRefs []quoteRef

	for i := 0; i < len(foundIDs); i += chunkSize {
		end := i + chunkSize
		if end > len(foundIDs) {
			end = len(foundIDs)
		}
		chunk := foundIDs[i:end]

		ech, err := db.QueryEvents(ctx, nostr.Filter{
			IDs:   chunk,
			Limit: len(chunk),
		})
		if err != nil {
			continue
		}
		for evt := range ech {
			for _, tag := range evt.Tags {
				if len(tag) >= 2 && tag[0] == "q" {
					quotedIDs[tag[1]] = true
					quoteRefs = append(quoteRefs, quoteRef{
						quotedID: tag[1],
						quotedBy: evt.ID,
					})
				}
			}
		}
	}

	// Fetch quoted events from DB
	quotedInfo := make(map[string]struct {
		author  string
		content string
	}) // keep as anonymous struct — only used locally
	if len(quotedIDs) > 0 {
		quotedIDList := make([]string, 0, len(quotedIDs))
		for id := range quotedIDs {
			quotedIDList = append(quotedIDList, id)
		}
		for i := 0; i < len(quotedIDList); i += chunkSize {
			end := i + chunkSize
			if end > len(quotedIDList) {
				end = len(quotedIDList)
			}
			chunk := quotedIDList[i:end]

			qch, err := db.QueryEvents(ctx, nostr.Filter{
				IDs:   chunk,
				Limit: len(chunk),
			})
			if err != nil {
				continue
			}
			for evt := range qch {
				qContent := evt.Content
				if len(qContent) > 200 {
					qContent = qContent[:200] + "..."
				}
				quotedInfo[evt.ID] = struct {
					author  string
					content string
				}{
					author:  strings.ToLower(evt.PubKey),
					content: qContent,
				}
			}
		}
	}

	// Fetch profile names for quoted event authors
	quotedAuthorPubkeys := make(map[string]bool)
	for _, qi := range quotedInfo {
		quotedAuthorPubkeys[qi.author] = true
	}
	quotedAuthorNames := make(map[string]string)
	if len(quotedAuthorPubkeys) > 0 {
		pkList := make([]string, 0, len(quotedAuthorPubkeys))
		for pk := range quotedAuthorPubkeys {
			pkList = append(pkList, pk)
		}
		// Use the same profile fetch as zappers, but only from local DB
		// (quoted authors may not be on external relays, and we don't want
		// to slow down the job with external queries for non-community members)
		localProfiles := fetchZapperProfiles(ctx, pkList, nil)
		for pk, prof := range localProfiles {
			if prof.name != "" {
				quotedAuthorNames[pk] = prof.name
			}
		}
	}

	// Prepend quoted content to the zapped event's content
	for _, ref := range quoteRefs {
		info, ok := eventInfo[ref.quotedBy]
		if !ok {
			continue
		}
		qInfo, ok := quotedInfo[ref.quotedID]
		if !ok {
			continue
		}
		// Build the quoted prefix
		authorLabel := quotedAuthorNames[qInfo.author]
		if authorLabel == "" {
			authorLabel = qInfo.author[:8] + "..."
		}
		quotedPrefix := "Quoting @" + authorLabel + ": " + qInfo.content
		if len(quotedPrefix) > 150 {
			quotedPrefix = quotedPrefix[:150] + "..."
		}
		// Prepend to existing content, cap total at 400 chars
		newContent := quotedPrefix + "\n" + info.content
		if len(newContent) > 400 {
			newContent = newContent[:400] + "..."
		}
		info.content = newContent
		eventInfo[ref.quotedBy] = info
	}

	log.Printf("zap-stats: fetched %d zapped events, %d quoted events, %d quote refs",
		len(eventInfo), len(quotedInfo), len(quoteRefs))

	// ---- Build shared data for all range computations ----

	// Build a pubkey → name lookup from nostr.json
	pubkeyToName := make(map[string]string)
	for name, pk := range data.Names {
		pubkeyToName[strings.ToLower(strings.TrimSpace(pk))] = name
	}

	// Fetch profiles for ALL unique zappers (shared across all ranges)
	allZapperPubkeys := make(map[string]bool)
	for _, zap := range zaps {
		allZapperPubkeys[strings.ToLower(strings.TrimSpace(zap.zapper))] = true
	}
	pubkeyList := make([]string, 0, len(allZapperPubkeys))
	for pk := range allZapperPubkeys {
		pubkeyList = append(pubkeyList, pk)
	}
	zapperProfiles := fetchZapperProfiles(ctx, pubkeyList, relayURLs)
	log.Printf("zap-stats: fetched %d zapper profiles total", len(zapperProfiles))

	// ---- Compute snapshots for each time range ----

	now := time.Now().Unix()
	timeRanges := []struct {
		name  string
		since int64 // 0 = no filter (all time)
	}{
		{"24h", now - 24*60*60},
		{"7d", now - 7*24*60*60},
		{"30d", now - 30*24*60*60},
		{"all", 0},
	}

	snapshots := make(map[string]*ZapStatsSnapshot, len(timeRanges))
	for _, r := range timeRanges {
		var filteredZaps []parsedZap
		if r.since == 0 {
			filteredZaps = zaps
		} else {
			for _, zap := range zaps {
				if zap.createdAt >= r.since {
					filteredZaps = append(filteredZaps, zap)
				}
			}
		}
		snap := computeSnapshotForRange(filteredZaps, eventInfo, zapperProfiles, pubkeyToName, communityPubkeys, r.name)
		snapshots[r.name] = snap
		log.Printf("zap-stats: computed '%s' snapshot — %d zaps, %d sats, %d members, %d zappers",
			r.name, snap.Aggregate.TotalZaps, snap.Aggregate.TotalEarnings, len(snap.Members), snap.Aggregate.UniqueZappers)
	}

	zapStatsMu.Lock()
	zapStatsCache = snapshots
	zapStatsMu.Unlock()

	saveZapStatsToDisk(snapshots)
}

// computeSnapshotForRange aggregates a time-filtered set of zaps into a
// ZapStatsSnapshot. All the expensive data fetching (receipts, event content,
// profiles) is done by the caller; this function only does in-memory aggregation.
func computeSnapshotForRange(
	zaps []parsedZap,
	eventInfo map[string]eventInfoEntry,
	zapperProfiles map[string]profileInfo,
	pubkeyToName map[string]string,
	communityPubkeys map[string]bool,
	rangeName string,
) *ZapStatsSnapshot {
	var totalEarnings int64
	totalZaps := len(zaps)
	zapperSet := make(map[string]bool)

	earningsByDay := make(map[string]*EarningsByPeriod)
	contentAgg := make(map[string]*EarningsByContent)
	kindAgg := make(map[int]*struct {
		totalSats int64
		zapCount  int
	})
	zapperAgg := make(map[string]*ZapperStats)

	hourAgg := make(map[int]*struct {
		totalSats int64
		zapCount  int
	})
	for h := 0; h < 24; h++ {
		hourAgg[h] = &struct {
			totalSats int64
			zapCount  int
		}{}
	}
	dowAgg := make(map[int]*struct {
		totalSats int64
		zapCount  int
	})
	for d := 0; d < 7; d++ {
		dowAgg[d] = &struct {
			totalSats int64
			zapCount  int
		}{}
	}

	type zapperLoyaltyData struct {
		zaps      []int64
		totalSats int64
		zapCount  int
	}
	zapperLoyalty := make(map[string]*zapperLoyaltyData)

	type memberData struct {
		totalEarnings int64
		totalZaps     int
		zappers       map[string]bool
		contentAgg    map[string]int64
		earningsByDay map[string]*EarningsByPeriod
		zapperAgg     map[string]*ZapperStats
	}
	members := make(map[string]*memberData)
	for pk := range communityPubkeys {
		members[pk] = &memberData{
			zappers:       make(map[string]bool),
			contentAgg:    make(map[string]int64),
			earningsByDay: make(map[string]*EarningsByPeriod),
			zapperAgg:     make(map[string]*ZapperStats),
		}
	}

	for _, zap := range zaps {
		totalEarnings += zap.amount
		zapperSet[zap.zapper] = true

		t := time.Unix(zap.createdAt, 0).UTC()
		dayKey := t.Format("2006-01-02")

		if md, ok := members[zap.recipient]; ok {
			md.totalEarnings += zap.amount
			md.totalZaps++
			md.zappers[zap.zapper] = true
			if zap.zappedEvent != "" {
				md.contentAgg[zap.zappedEvent] += zap.amount
			}
			if _, ok := md.earningsByDay[dayKey]; !ok {
				md.earningsByDay[dayKey] = &EarningsByPeriod{Period: dayKey, Date: dayKey + "T00:00:00Z"}
			}
			md.earningsByDay[dayKey].TotalSats += zap.amount
			md.earningsByDay[dayKey].ZapCount++
			if _, ok := md.zapperAgg[zap.zapper]; !ok {
				md.zapperAgg[zap.zapper] = &ZapperStats{Pubkey: zap.zapper}
			}
			md.zapperAgg[zap.zapper].TotalSats += zap.amount
			md.zapperAgg[zap.zapper].ZapCount++
		}

		if _, ok := earningsByDay[dayKey]; !ok {
			earningsByDay[dayKey] = &EarningsByPeriod{Period: dayKey, Date: dayKey + "T00:00:00Z"}
		}
		earningsByDay[dayKey].TotalSats += zap.amount
		earningsByDay[dayKey].ZapCount++

		if zap.zappedEvent != "" {
			info, hasInfo := eventInfo[zap.zappedEvent]
			if _, ok := contentAgg[zap.zappedEvent]; !ok {
				content := ""
				kind := 1
				author := ""
				var created int64
				if hasInfo {
					content = info.content
					kind = info.kind
					author = info.author
					created = info.created
				}
				contentAgg[zap.zappedEvent] = &EarningsByContent{
					EventID: zap.zappedEvent, EventKind: kind, Content: content, Author: author, CreatedAt: created,
				}
			}
			contentAgg[zap.zappedEvent].TotalSats += zap.amount
			contentAgg[zap.zappedEvent].ZapCount++
		}

		if zap.zappedEvent != "" {
			if info, ok := eventInfo[zap.zappedEvent]; ok {
				if _, ok := kindAgg[info.kind]; !ok {
					kindAgg[info.kind] = &struct {
						totalSats int64
						zapCount  int
					}{}
				}
				kindAgg[info.kind].totalSats += zap.amount
				kindAgg[info.kind].zapCount++
			}
		}

		if _, ok := zapperAgg[zap.zapper]; !ok {
			zapperAgg[zap.zapper] = &ZapperStats{Pubkey: zap.zapper}
		}
		zapperAgg[zap.zapper].TotalSats += zap.amount
		zapperAgg[zap.zapper].ZapCount++

		hourAgg[t.Hour()].totalSats += zap.amount
		hourAgg[t.Hour()].zapCount++
		dowAgg[int(t.Weekday())].totalSats += zap.amount
		dowAgg[int(t.Weekday())].zapCount++

		if _, ok := zapperLoyalty[zap.zapper]; !ok {
			zapperLoyalty[zap.zapper] = &zapperLoyaltyData{}
		}
		zapperLoyalty[zap.zapper].zaps = append(zapperLoyalty[zap.zapper].zaps, zap.createdAt)
		zapperLoyalty[zap.zapper].totalSats += zap.amount
		zapperLoyalty[zap.zapper].zapCount++
	}

	// ---- Build sorted slices ----

	earningsByPeriodList := make([]EarningsByPeriod, 0, len(earningsByDay))
	for _, e := range earningsByDay {
		earningsByPeriodList = append(earningsByPeriodList, *e)
	}
	sort.Slice(earningsByPeriodList, func(i, j int) bool { return earningsByPeriodList[i].Period < earningsByPeriodList[j].Period })

	topContentList := make([]EarningsByContent, 0, len(contentAgg))
	for _, c := range contentAgg {
		if c.Content == "" && c.CreatedAt == 0 {
			continue
		}
		topContentList = append(topContentList, *c)
	}
	sort.Slice(topContentList, func(i, j int) bool { return topContentList[i].TotalSats > topContentList[j].TotalSats })
	if len(topContentList) > 10 {
		topContentList = topContentList[:10]
	}

	earningsByKindList := make([]EarningsByKind, 0, len(kindAgg))
	for kind, agg := range kindAgg {
		name, ok := kindNames[kind]
		if !ok {
			name = "Kind " + strconv.Itoa(kind)
		}
		var pct float64
		if totalEarnings > 0 {
			pct = float64(agg.totalSats) / float64(totalEarnings) * 100
		}
		earningsByKindList = append(earningsByKindList, EarningsByKind{
			Kind: kind, KindName: name, TotalSats: agg.totalSats, ZapCount: agg.zapCount, Percentage: pct,
		})
	}
	sort.Slice(earningsByKindList, func(i, j int) bool { return earningsByKindList[i].TotalSats > earningsByKindList[j].TotalSats })

	topZappersList := make([]ZapperStats, 0, len(zapperAgg))
	for _, z := range zapperAgg {
		topZappersList = append(topZappersList, *z)
	}
	sort.Slice(topZappersList, func(i, j int) bool { return topZappersList[i].TotalSats > topZappersList[j].TotalSats })
	if len(topZappersList) > 10 {
		topZappersList = topZappersList[:10]
	}

	earningsByHourList := make([]EarningsByHour, 0, 24)
	for h := 0; h < 24; h++ {
		agg := hourAgg[h]
		var avg int64
		if agg.zapCount > 0 {
			avg = agg.totalSats / int64(agg.zapCount)
		}
		earningsByHourList = append(earningsByHourList, EarningsByHour{
			Hour: h, TotalSats: agg.totalSats, ZapCount: agg.zapCount, AvgZapAmount: avg,
		})
	}

	earningsByDowList := make([]EarningsByDayOfWeek, 0, 7)
	for d := 0; d < 7; d++ {
		agg := dowAgg[d]
		var avg int64
		if agg.zapCount > 0 {
			avg = agg.totalSats / int64(agg.zapCount)
		}
		earningsByDowList = append(earningsByDowList, EarningsByDayOfWeek{
			DayOfWeek: d, DayName: dayNames[d], TotalSats: agg.totalSats, ZapCount: agg.zapCount, AvgZapAmount: avg,
		})
	}

	var newZappers, returningZappers, regularSupporters int
	loyalZappers := make([]ZapperStats, 0)
	for pk, ld := range zapperLoyalty {
		if ld.zapCount == 1 {
			newZappers++
		} else {
			returningZappers++
			sort.Slice(ld.zaps, func(i, j int) bool { return ld.zaps[i] < ld.zaps[j] })
			avgDays := 0.0
			if ld.zapCount > 1 {
				span := float64(ld.zaps[len(ld.zaps)-1]-ld.zaps[0]) / 86400.0
				avgDays = span / float64(ld.zapCount-1)
			}
			if ld.zapCount >= 5 || (ld.zapCount >= 3 && avgDays <= 7) {
				regularSupporters++
			}
			loyalZappers = append(loyalZappers, ZapperStats{Pubkey: pk, TotalSats: ld.totalSats, ZapCount: ld.zapCount})
		}
	}
	sort.Slice(loyalZappers, func(i, j int) bool { return loyalZappers[i].TotalSats > loyalZappers[j].TotalSats })
	if len(loyalZappers) > 10 {
		loyalZappers = loyalZappers[:10]
	}
	var avgLifetime int64
	if len(zapperLoyalty) > 0 {
		avgLifetime = totalEarnings / int64(len(zapperLoyalty))
	}

	enrichZapperStats(topZappersList, zapperProfiles)
	enrichZapperStats(loyalZappers, zapperProfiles)

	memberList := make([]MemberStats, 0, len(communityPubkeys))
	for pk, md := range members {
		if md.totalZaps == 0 {
			continue
		}
		name := pubkeyToName[pk]
		if name == "" || name == "_" {
			name = pk[:12] + "..."
		}

		var topContentSats int64
		var topContentPreview string
		for eventID, sats := range md.contentAgg {
			if sats > topContentSats {
				topContentSats = sats
				if info, ok := eventInfo[eventID]; ok {
					preview := info.content
					if len(preview) > 80 {
						preview = preview[:80] + "..."
					}
					topContentPreview = preview
				}
			}
		}

		memberEarningsByPeriod := make([]EarningsByPeriod, 0, len(md.earningsByDay))
		for _, e := range md.earningsByDay {
			memberEarningsByPeriod = append(memberEarningsByPeriod, *e)
		}
		sort.Slice(memberEarningsByPeriod, func(i, j int) bool { return memberEarningsByPeriod[i].Period < memberEarningsByPeriod[j].Period })

		memberTopZappers := make([]ZapperStats, 0, len(md.zapperAgg))
		for _, z := range md.zapperAgg {
			memberTopZappers = append(memberTopZappers, *z)
		}
		sort.Slice(memberTopZappers, func(i, j int) bool { return memberTopZappers[i].TotalSats > memberTopZappers[j].TotalSats })
		if len(memberTopZappers) > 20 {
			memberTopZappers = memberTopZappers[:20]
		}
		enrichZapperStats(memberTopZappers, zapperProfiles)

		memberList = append(memberList, MemberStats{
			Pubkey: pk, Name: name,
			TotalEarnings: md.totalEarnings, TotalZaps: md.totalZaps, UniqueZappers: len(md.zappers),
			TopContentSats: topContentSats, TopContentPreview: topContentPreview,
			EarningsByPeriod: memberEarningsByPeriod, TopZappers: memberTopZappers,
		})
	}
	sort.Slice(memberList, func(i, j int) bool { return memberList[i].TotalEarnings > memberList[j].TotalEarnings })

	return &ZapStatsSnapshot{
		LastUpdated: time.Now().Unix(),
		Range:       rangeName,
		Aggregate: AggregateStats{
			TotalEarnings:    totalEarnings,
			TotalZaps:        totalZaps,
			UniqueZappers:    len(zapperSet),
			EarningsByPeriod: earningsByPeriodList,
			TopContent:       topContentList,
			EarningsByKind:   earningsByKindList,
			TopZappers:       topZappersList,
			TemporalPatterns: TemporalPatterns{
				EarningsByHour:      earningsByHourList,
				EarningsByDayOfWeek: earningsByDowList,
			},
			ZapperLoyalty: LoyaltyStats{
				NewZappers:           newZappers,
				ReturningZappers:     returningZappers,
				RegularSupporters:    regularSupporters,
				AverageLifetimeValue: avgLifetime,
				TopLoyalZappers:      loyalZappers,
			},
		},
		Members: memberList,
	}
}

// ---------------------------------------------------------------------------
// NIP-65 relay discovery + external relay fanout
// ---------------------------------------------------------------------------

// blockedRelays are relays excluded from fanout (unreliable or deprecated).
var blockedRelays = map[string]bool{
	"wss://relay.snort.social":  true,
	"wss://relay.nostr.band":    true,
}

// discoverNip65Relays reads kind 10002 (Relay List) events from the local DB
// authored by community members, and extracts the unique set of relay URLs
// marked for reading. Always includes a set of well-known public relays as
// a baseline, since zap receipts may live on relays not listed in any
// community member's NIP-65 relay list. Also checks the ZAP_STATS_EXTRA_RELAYS
// env var for additional relays to query.
func discoverNip65Relays(ctx context.Context, communityPubkeys map[string]bool) []string {
	relaySet := make(map[string]bool)

	// Always include baseline public relays. These are popular relays where
	// zap receipts commonly live, even if they're not in anyone's NIP-65 list.
	// This mirrors the frontend's DEFAULT_RELAYS behavior.
	baselineRelays := []string{
		"wss://relay.damus.io",
		"wss://nos.lol",
		"wss://relay.primal.net",
	}
	for _, url := range baselineRelays {
		relaySet[url] = true
	}

	// Also check ZAP_STATS_EXTRA_RELAYS env var for additional relays
	extraRelaysStr, _ := os.LookupEnv("ZAP_STATS_EXTRA_RELAYS")
	if extraRelaysStr != "" {
		for _, url := range strings.Split(extraRelaysStr, ",") {
			url = strings.TrimSpace(url)
			if url != "" {
				relaySet[strings.ToLower(url)] = true
			}
		}
	}

	// Query kind 10002 events from all community members
	authors := make([]string, 0, len(communityPubkeys))
	for pk := range communityPubkeys {
		authors = append(authors, pk)
	}

	// Query in chunks to avoid overly large author filters
	const chunkSize = 100
	for i := 0; i < len(authors); i += chunkSize {
		end := i + chunkSize
		if end > len(authors) {
			end = len(authors)
		}
		chunk := authors[i:end]

		ch, err := db.QueryEvents(ctx, nostr.Filter{
			Kinds:   []int{10002},
			Authors: chunk,
			Limit:   0,
		})
		if err != nil {
			log.Printf("zap-stats: error querying kind 10002: %v", err)
			continue
		}

		for evt := range ch {
			for _, tag := range evt.Tags {
				if len(tag) >= 2 && tag[0] == "r" {
					url := strings.TrimSpace(tag[1])
					if url == "" {
						continue
					}
					// NIP-65: a third element "read" or "write" marks the
					// relay's usage. If no marker, it's both read+write.
					if len(tag) >= 3 && tag[2] == "write" {
						continue // skip write-only relays
					}
					url = strings.ToLower(url)
					if !blockedRelays[url] {
						relaySet[url] = true
					}
				}
			}
		}
	}

	result := make([]string, 0, len(relaySet))
	for url := range relaySet {
		result = append(result, url)
	}
	sort.Strings(result) // deterministic order for logging
	return result
}

// fetchZapReceiptsFromRelays connects to each external relay via WebSocket
// and queries kind 9735 zap receipts where the #p tag matches any community
// pubkey. Results from all relays are merged and deduplicated by event ID.
//
// Relays are queried concurrently with a per-relay timeout. Failures on
// individual relays are logged but don't affect the overall result.
func fetchZapReceiptsFromRelays(ctx context.Context, relayURLs []string, communityPubkeys []string) []*nostr.Event {
	if len(relayURLs) == 0 || len(communityPubkeys) == 0 {
		return nil
	}

	type relayResult struct {
		url     string
		events  []*nostr.Event
		success bool
	}

	results := make(chan relayResult, len(relayURLs))

	// Query each relay concurrently
	for _, url := range relayURLs {
		go func(relayURL string) {
			result := relayResult{url: relayURL}

			// Per-relay timeout — don't let one slow relay block the cycle
			relayCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()

			relay, err := nostr.RelayConnect(relayCtx, relayURL)
			if err != nil {
				log.Printf("zap-stats: failed to connect to %s: %v", relayURL, err)
				results <- result
				return
			}
			defer relay.Close()

			// Query kind 9735 with #p filter for community pubkeys.
			// We query in batches of pubkeys to avoid overly large filters
			// that some relays reject.
			const pubkeyBatchSize = 50
			var allEvents []*nostr.Event

			for i := 0; i < len(communityPubkeys); i += pubkeyBatchSize {
				end := i + pubkeyBatchSize
				if end > len(communityPubkeys) {
					end = len(communityPubkeys)
				}
				batch := communityPubkeys[i:end]

				// Paginated fetch: keep querying until a batch returns fewer
				// than the limit, indicating no more results. (Flag 8 fix)
				const pageLimit = 1000
				var untilCursor *nostr.Timestamp
				for {
					filter := nostr.Filter{
						Kinds: []int{9735},
						Tags:  nostr.TagMap{"p": batch},
						Limit: pageLimit,
					}
					if untilCursor != nil {
						filter.Until = untilCursor
					}

					events, err := relay.QuerySync(relayCtx, filter)
					if err != nil {
						log.Printf("zap-stats: query error on %s (batch %d): %v", relayURL, i/pubkeyBatchSize, err)
						break
					}
					allEvents = append(allEvents, events...)

					// If fewer than pageLimit returned, no more pages
					if len(events) < pageLimit {
						break
					}

					// Find the oldest timestamp in this batch to use as the
					// cursor for the next page
					var oldest nostr.Timestamp
					for _, e := range events {
						if oldest == 0 || e.CreatedAt < oldest {
							oldest = e.CreatedAt
						}
					}
					if oldest == 0 {
						break
					}
					// Subtract 1 to avoid re-fetching the oldest event
					ts := oldest - 1
					untilCursor = &ts
				}
			}

			result.events = allEvents
			result.success = true
			log.Printf("zap-stats: fetched %d receipts from %s", len(allEvents), relayURL)
			results <- result
		}(url)
	}

	// Collect results
	seen := make(map[string]bool)
	var merged []*nostr.Event

	for i := 0; i < len(relayURLs); i++ {
		r := <-results
		if !r.success {
			continue
		}
		for _, evt := range r.events {
			if !seen[evt.ID] {
				seen[evt.ID] = true
				merged = append(merged, evt)
			}
		}
	}

	return merged
}

// parseZapReceiptEvent extracts the relevant fields from a kind 9735 zap
// receipt event. Returns nil if the event is not a valid community zap
// (missing bolt11, zero amount, or not destined to a community member).
func parseZapReceiptEvent(evt *nostr.Event, communityPubkeys map[string]bool) *struct {
	amount      int64
	createdAt   int64
	zapper      string
	recipient   string
	zappedEvent string
} {
	// Verify the zap receipt's signature to prevent forged receipts. (Flag 7 fix)
	ok, err := evt.CheckSignature()
	if !ok || err != nil {
		return nil
	}

	var recipient string
	var bolt11 string
	var zappedEventID string
	var description string

	for _, tag := range evt.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "p":
			recipient = strings.ToLower(strings.TrimSpace(tag[1]))
		case "bolt11":
			bolt11 = tag[1]
		case "e":
			zappedEventID = tag[1]
		case "description":
			description = tag[1]
		}
	}

	// Only keep zaps destined to community members
	if recipient == "" || !communityPubkeys[recipient] {
		return nil
	}

	// Decode amount from bolt11 invoice
	amount, err := parseBolt11Amount(bolt11)
	if err != nil || amount == 0 {
		return nil
	}

	// Extract zapper pubkey from the description (zap request) event
	zapper := evt.PubKey // fallback to receipt pubkey
	if description != "" {
		var zapReq struct {
			PubKey string `json:"pubkey"`
		}
		if json.Unmarshal([]byte(description), &zapReq) == nil && zapReq.PubKey != "" {
			zapper = strings.ToLower(strings.TrimSpace(zapReq.PubKey))
		}
	}

	return &struct {
		amount      int64
		createdAt   int64
		zapper      string
		recipient   string
		zappedEvent string
	}{
		amount:      int64(amount),
		createdAt:   int64(evt.CreatedAt),
		zapper:      strings.ToLower(strings.TrimSpace(zapper)),
		recipient:   recipient,
		zappedEvent: zappedEventID,
	}
}

// fetchZapperProfiles fetches kind 0 (profile metadata) events for the given
// pubkeys. It first checks the local DB, then falls back to querying external
// NIP-65 relays for any pubkeys not found locally. Returns a map of
// pubkey → {name, picture}.
func fetchZapperProfiles(ctx context.Context, pubkeys []string, relayURLs []string) map[string]profileInfo {
	profiles := make(map[string]profileInfo)

	if len(pubkeys) == 0 {
		return profiles
	}

	// Helper: parse a kind 0 event into profile fields
	parseProfile := func(evt *nostr.Event) (string, string) {
		var p struct {
			Name        string `json:"name"`
			DisplayName string `json:"display_name"`
			Picture     string `json:"picture"`
		}
		if json.Unmarshal([]byte(evt.Content), &p) != nil {
			return "", ""
		}
		name := p.Name
		if name == "" {
			name = p.DisplayName
		}
		return name, p.Picture
	}

	// 1. Query local DB first
	missingPubkeys := make([]string, 0, len(pubkeys))
	const chunkSize = 100
	for i := 0; i < len(pubkeys); i += chunkSize {
		end := i + chunkSize
		if end > len(pubkeys) {
			end = len(pubkeys)
		}
		chunk := pubkeys[i:end]

		ch, err := db.QueryEvents(ctx, nostr.Filter{
			Kinds:   []int{0},
			Authors: chunk,
			Limit:   0,
		})
		if err != nil {
			log.Printf("zap-stats: error querying kind 0 profiles: %v", err)
			missingPubkeys = append(missingPubkeys, chunk...)
			continue
		}

		// Keep only the most recent kind 0 per pubkey
		latestByPubkey := make(map[string]*nostr.Event)
		for evt := range ch {
			pk := strings.ToLower(strings.TrimSpace(evt.PubKey))
			if existing, ok := latestByPubkey[pk]; !ok || evt.CreatedAt > existing.CreatedAt {
				latestByPubkey[pk] = evt
			}
		}

		for pk, evt := range latestByPubkey {
			name, picture := parseProfile(evt)
			if name != "" || picture != "" {
				profiles[pk] = struct {
					name    string
					picture string
				}{name: name, picture: picture}
			}
		}

		// Track which pubkeys weren't found locally
		chunkSet := make(map[string]bool)
		for _, pk := range chunk {
			chunkSet[pk] = true
		}
		for pk := range chunkSet {
			if _, found := profiles[pk]; !found {
				missingPubkeys = append(missingPubkeys, pk)
			}
		}
	}

	log.Printf("zap-stats: fetched %d profiles from local DB, %d missing", len(profiles), len(missingPubkeys))

	// 2. Fetch missing profiles from external relays
	if len(missingPubkeys) > 0 && len(relayURLs) > 0 {
		externalProfiles := fetchProfilesFromRelays(ctx, relayURLs, missingPubkeys)
		for pk, evt := range externalProfiles {
			name, picture := parseProfile(evt)
			if name != "" || picture != "" {
				profiles[pk] = struct {
					name    string
					picture string
				}{name: name, picture: picture}
			}
			// Save to local DB for future use
			if err := db.SaveEvent(ctx, evt); err == nil {
				// saved successfully
			}
		}
		log.Printf("zap-stats: fetched %d profiles from external relays", len(externalProfiles))
	}

	return profiles
}

// fetchProfilesFromRelays queries external relays for kind 0 events from the
// given pubkeys. Returns a map of pubkey → event (most recent per pubkey).
func fetchProfilesFromRelays(ctx context.Context, relayURLs []string, pubkeys []string) map[string]*nostr.Event {
	result := make(map[string]*nostr.Event)
	if len(relayURLs) == 0 || len(pubkeys) == 0 {
		return result
	}

	type relayResult struct {
		events  []*nostr.Event
		success bool
	}

	results := make(chan relayResult, len(relayURLs))

	for _, url := range relayURLs {
		go func(relayURL string) {
			res := relayResult{}
			relayCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()

			relay, err := nostr.RelayConnect(relayCtx, relayURL)
			if err != nil {
				results <- res
				return
			}
			defer relay.Close()

			// Query in chunks of 100 pubkeys
			var allEvents []*nostr.Event
			const chunkSize = 100
			for i := 0; i < len(pubkeys); i += chunkSize {
				end := i + chunkSize
				if end > len(pubkeys) {
					end = len(pubkeys)
				}
				events, err := relay.QuerySync(relayCtx, nostr.Filter{
					Kinds:   []int{0},
					Authors: pubkeys[i:end],
					Limit:   len(pubkeys[i:end]),
				})
				if err != nil {
					continue
				}
				allEvents = append(allEvents, events...)
			}

			res.events = allEvents
			res.success = true
			results <- res
		}(url)
	}

	// Collect and merge, keeping the most recent event per pubkey
	for i := 0; i < len(relayURLs); i++ {
		r := <-results
		if !r.success {
			continue
		}
		for _, evt := range r.events {
			pk := strings.ToLower(strings.TrimSpace(evt.PubKey))
			if existing, ok := result[pk]; !ok || evt.CreatedAt > existing.CreatedAt {
				result[pk] = evt
			}
		}
	}

	return result
}

// enrichZapperStats fills in Name and Picture fields on a slice of ZapperStats
// using the provided profile map.
func enrichZapperStats(stats []ZapperStats, profiles map[string]profileInfo) {
	for i := range stats {
		if p, ok := profiles[strings.ToLower(strings.TrimSpace(stats[i].Pubkey))]; ok {
			stats[i].Name = p.name
			stats[i].Picture = p.picture
		}
	}
}

// parseBolt11Amount extracts the satoshi amount from a BOLT11 invoice's
// human-readable part. It replicates the logic from go-nostr/nip60's
// GetSatoshisAmountFromBolt11 without pulling in the cashu dependency.
//
// Format: lnbc<amount><unit>1...
// Examples: lnbc1000u1... (1000 µsat = 100 sats), lnbc1m1... (1 msat = 100k sats)
func parseBolt11Amount(bolt11 string) (uint64, error) {
	if len(bolt11) < 50 {
		return 0, fmt.Errorf("invalid invoice, too short")
	}
	// Only need the HRP (up to the last '1' in the first 50 chars)
	prefix := bolt11[:50]
	idx := strings.LastIndex(prefix, "1")
	if idx == -1 {
		return 0, fmt.Errorf("invalid invoice")
	}
	hrp := prefix[:idx]
	amount, ok := strings.CutPrefix(hrp, "lnbc")
	if !ok {
		return 0, fmt.Errorf("invalid invoice")
	}
	if len(amount) < 1 {
		return 0, nil
	}

	// Last character may be a unit multiplier or a digit
	char := amount[len(amount)-1]
	digit := char - '0'
	isDigit := digit >= 0 && digit <= 9

	cutPoint := len(amount) - 1
	if isDigit {
		cutPoint++
	}

	num := amount[:cutPoint]
	if len(num) < 1 {
		return 0, nil
	}

	am, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		return 0, err
	}

	switch char {
	case 'm':
		return am * 100000, nil
	case 'u':
		return am * 100, nil
	case 'n':
		return am / 10, nil
	case 'p':
		return am / 10000, nil
	default:
		return am * 100000000, nil
	}
}

// ---------------------------------------------------------------------------
// HTTP handler — GET /api/zap-stats
// ---------------------------------------------------------------------------

// handleZapStats serves the cached community zap analytics snapshot.
// It is gated to team members via requireTeamSession, following the same
// pattern as the other dashboard API endpoints.
func handleZapStats(requireTeamSession func(http.ResponseWriter, *http.Request) bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireTeamSession(w, r) {
			return
		}

		// Determine the requested time range (default: "all")
		rangeName := r.URL.Query().Get("range")
		if rangeName == "" {
			rangeName = "all"
		}

		zapStatsMu.RLock()
		snapshots := zapStatsCache
		zapStatsMu.RUnlock()

		if snapshots == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Computing zap stats — please try again in a moment.",
			})
			return
		}

		snapshot, ok := snapshots[rangeName]
		if !ok {
			// Fall back to "all" if the requested range doesn't exist
			snapshot, ok = snapshots["all"]
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "No zap stats available yet.",
				})
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(snapshot)
	}
}
