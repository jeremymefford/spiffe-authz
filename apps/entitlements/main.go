package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type CheckRequest struct {
	SpiffeID    string `json:"spiffe_id"`
	Token       string `json:"token"`
}

type CheckResponse struct {
	Entitlements []string `json:"entitlements"`
}

type Claims struct {
	Sub          string   `json:"sub"`
	Roles        []string `json:"roles"`
	Tenant       string   `json:"tenant"`
	MerchantTier string   `json:"merchant_tier"`
	MFA          bool     `json:"mfa"`
	Exp          int64    `json:"exp"`
}

func main() {
	port := envOr("PORT", "8083")

	spiffeEntitlements := map[string][]string{
		// Service-level entitlements (who can call what).
		"spiffe://example.org/ns/lab/sa/payment": {
			"svc.charge",
			"svc.fraud.score",
		},
		"spiffe://example.org/ns/lab/sa/fraud": {},
	}


	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("/v1/check", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var req CheckRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}

		requestID := r.Header.Get("x-request-id")
		if req.Token == "" {
			log.Printf("entitlements denied request_id=%s spiffe_id=%s error=missing_token", requestID, req.SpiffeID)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing token"})
			return
		}

		claims, err := verifyJWT(req.Token, []byte("lab-secret"))
		if err != nil {
			log.Printf("entitlements denied request_id=%s spiffe_id=%s error=%s token_len=%d", requestID, req.SpiffeID, err.Error(), len(req.Token))
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			return
		}

		entitlements := mergeEntitlements(spiffeEntitlements[req.SpiffeID], roleEntitlementsFor(claims.Roles))
		entitlements = unique(entitlements)

		log.Printf("entitlements request_id=%s spiffe_id=%s sub=%s tenant=%s roles=%v entitlements=%v",
			requestID, req.SpiffeID, claims.Sub, claims.Tenant, claims.Roles, entitlements)

		writeJSON(w, http.StatusOK, CheckResponse{Entitlements: entitlements})
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           logRequests(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("entitlements service listening on :%s", port)
	log.Fatal(srv.ListenAndServe())
}

func roleEntitlementsFor(roles []string) []string {
	entitlements := make([]string, 0)
	roleEntitlements := map[string][]string{
		"payments": {"user.charge.basic", "user.fraud.score.basic"},
		"payments_admin": {"user.charge.high", "user.fraud.score.high", "user.refunds"},
		"risk": {"user.fraud.score.high"},
	}
	for _, role := range roles {
		entitlements = append(entitlements, roleEntitlements[role]...)
	}
	return entitlements
}

func mergeEntitlements(sets ...[]string) []string {
	out := make([]string, 0)
	for _, set := range sets {
		out = append(out, set...)
	}
	return out
}

func unique(values []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func verifyJWT(token string, secret []byte) (Claims, error) {
	var claims Claims
	parts := splitToken(token)
	if len(parts) != 3 {
		return claims, errInvalidToken
	}

	if !verifyHS256(parts[0], parts[1], parts[2], secret) {
		return claims, errInvalidToken
	}

	payload, err := decodeSegment(parts[1])
	if err != nil {
		return claims, errInvalidToken
	}

	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, errInvalidToken
	}

	if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
		return claims, errExpiredToken
	}

	return claims, nil
}

func splitToken(token string) []string {
	out := make([]string, 0, 3)
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			out = append(out, token[start:i])
			start = i + 1
		}
	}
	out = append(out, token[start:])
	return out
}

func verifyHS256(header, payload, sig string, secret []byte) bool {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(header))
	mac.Write([]byte("."))
	mac.Write([]byte(payload))
	expected := mac.Sum(nil)
	decoded, err := decodeSegment(sig)
	if err != nil {
		return false
	}
	return hmac.Equal(decoded, expected)
}

func decodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}
	return base64.URLEncoding.DecodeString(seg)
}

var errInvalidToken = errors.New("invalid token")
var errExpiredToken = errors.New("expired token")

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
