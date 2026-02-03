package main

import (
	"encoding/json"
	"log"
	"math"
	"net/http"
	"os"
	"time"
)

type ScoreRequest struct {
	Amount      int64  `json:"amount"`
	Currency    string `json:"currency"`
	CardCountry string `json:"card_country"`
	MerchantID  string `json:"merchant_id"`
}

type ScoreResponse struct {
	RiskScore int    `json:"risk_score"`
	RiskLevel string `json:"risk_level"`
}

func main() {
	port := envOr("PORT", "8082")

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("/v1/score", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var req ScoreRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}

		score := scoreRisk(req)
		writeJSON(w, http.StatusOK, score)
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           logRequests(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("fraud service listening on :%s", port)
	log.Fatal(srv.ListenAndServe())
}

func scoreRisk(req ScoreRequest) ScoreResponse {
	base := float64(req.Amount) / 100.0
	if req.CardCountry != "US" {
		base *= 1.5
	}
	if req.Currency != "USD" {
		base *= 1.2
	}
	score := int(math.Min(base, 100.0))
	level := "low"
	if score >= 70 {
		level = "high"
	} else if score >= 40 {
		level = "medium"
	}

	return ScoreResponse{RiskScore: score, RiskLevel: level}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
