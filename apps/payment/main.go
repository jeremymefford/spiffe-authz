package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

type ChargeRequest struct {
	Amount      int64  `json:"amount"`
	Currency    string `json:"currency"`
	CardCountry string `json:"card_country"`
	MerchantID  string `json:"merchant_id"`
	UserID      string `json:"user_id"`
}

type FraudScoreRequest struct {
	Amount      int64  `json:"amount"`
	Currency    string `json:"currency"`
	CardCountry string `json:"card_country"`
	MerchantID  string `json:"merchant_id"`
	UserID      string `json:"user_id"`
}

type FraudScoreResponse struct {
	RiskScore int    `json:"risk_score"`
	RiskLevel string `json:"risk_level"`
}

type ChargeResponse struct {
	Approved   bool              `json:"approved"`
	Reason     string            `json:"reason"`
	FraudScore *FraudScoreResponse `json:"fraud_score,omitempty"`
}

func main() {
	port := envOr("PORT", "8081")
	fraudURL := envOr("FRAUD_URL", "http://127.0.0.1:15001")

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("/v1/charge", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var req ChargeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}

		score, err := fetchFraudScore(r, fraudURL+"/v1/score", FraudScoreRequest(req))
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}

		resp := ChargeResponse{
			Approved:   score.RiskLevel != "high",
			Reason:     "approved",
			FraudScore: score,
		}
		if !resp.Approved {
			resp.Reason = "risk_too_high"
		}

		writeJSON(w, http.StatusOK, resp)
	})

	mux.HandleFunc("/v1/refund", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "refund_queued"})
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           logRequests(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("payment service listening on :%s", port)
	log.Fatal(srv.ListenAndServe())
}

func fetchFraudScore(r *http.Request, url string, payload FraudScoreRequest) (*FraudScoreResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	// propagate context headers for OPA decisions
	copyHeader(r, req, "x-user-role")
	copyHeader(r, req, "x-merchant-tier")
	copyHeader(r, req, "x-transaction-id")

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, errStatus(resp.StatusCode)
	}

	var score FraudScoreResponse
	if err := json.NewDecoder(resp.Body).Decode(&score); err != nil {
		return nil, err
	}

	return &score, nil
}

func copyHeader(from *http.Request, to *http.Request, key string) {
	if v := from.Header.Get(key); v != "" {
		to.Header.Set(key, v)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errStatus(code int) error {
	return &httpError{code: code}
}

type httpError struct {
	code int
}

func (e *httpError) Error() string {
	return "upstream status " + http.StatusText(e.code)
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
