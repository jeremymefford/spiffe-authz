package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type CheckRequest struct {
	SpiffeID string `json:"spiffe_id"`
	Token    string `json:"token"`
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
	jwt.RegisteredClaims
}

func main() {
	port := envOr("PORT", "127.0.0.1:8083")
	jwtCert := mustEnv("JWT_CERT")
	pubKey, err := publicKeyFromCert(jwtCert)
	if err != nil {
		log.Fatalf("invalid JWT_CERT: %v", err)
	}

	spiffeEntitlements := map[string][]string{
		// Service-level entitlements (who can call what).
		"spiffe://example.org/ns/lab/sa/payment": {
			"svc.charge",
			"svc.fraud.score",
		},
		"spiffe://example.org/ns/lab/sa/fraud": {},
	}
	allowedDelegates := map[string][]string{
		"spiffe://example.org/ns/lab/sa/opa-payment": {"spiffe://example.org/ns/lab/sa/payment"},
		"spiffe://example.org/ns/lab/sa/opa-fraud":   {"spiffe://example.org/ns/lab/sa/payment"},
	}
	if raw := os.Getenv("ENTITLEMENTS_DELEGATES"); raw != "" {
		var overrides map[string][]string
		if err := json.Unmarshal([]byte(raw), &overrides); err != nil {
			log.Fatalf("invalid ENTITLEMENTS_DELEGATES: %v", err)
		}
		allowedDelegates = overrides
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
		callerSpiffeID := spiffeIDFromXFCC(r.Header.Get("x-forwarded-client-cert"))
		if callerSpiffeID == "" {
			log.Printf("entitlements denied request_id=%s spiffe_id=%s error=missing_spiffe_id",
				requestID, req.SpiffeID)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing spiffe id"})
			return
		}
		effectiveSpiffeID, err := resolveSpiffeID(callerSpiffeID, req.SpiffeID, allowedDelegates)
		if err != nil {
			log.Printf("entitlements denied request_id=%s spiffe_id=%s error=%s caller_spiffe_id=%s",
				requestID, req.SpiffeID, err.Error(), callerSpiffeID)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "spiffe id mismatch"})
			return
		}
		token := req.Token
		if token == "" {
			token = bearerToken(r.Header.Get("authorization"))
		}
		if token == "" {
			log.Printf("entitlements denied request_id=%s spiffe_id=%s error=missing_token", requestID, req.SpiffeID)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing token"})
			return
		}

		claims, err := verifyJWT(token, pubKey)
		if err != nil {
			log.Printf("entitlements denied request_id=%s spiffe_id=%s error=%s token_len=%d", requestID, req.SpiffeID, err.Error(), len(token))
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			return
		}

		entitlements := mergeEntitlements(spiffeEntitlements[effectiveSpiffeID], roleEntitlementsFor(claims.Roles))
		entitlements = unique(entitlements)

		log.Printf("entitlements request_id=%s spiffe_id=%s sub=%s tenant=%s roles=%v entitlements=%v",
			requestID, effectiveSpiffeID, claims.Sub, claims.Tenant, claims.Roles, entitlements)

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
		"finance-admin":      {"user.charge.basic", "user.charge.high", "user.fraud.score.basic", "user.fraud.score.high", "user.refunds"},
		"finance-data-entry": {"user.charge.basic", "user.fraud.score.basic"},
		"risk":               {"user.fraud.score.high"},
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

func verifyJWT(token string, key *ecdsa.PublicKey) (Claims, error) {
	claims := Claims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}))
	parsed, err := parser.ParseWithClaims(token, &claims, func(t *jwt.Token) (any, error) {
		return key, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return Claims{}, errExpiredToken
		}
		return Claims{}, errInvalidToken
	}
	if !parsed.Valid {
		return Claims{}, errInvalidToken
	}
	return claims, nil
}

func publicKeyFromCert(certPEM string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("invalid pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("certificate does not contain ecdsa public key")
	}
	return key, nil
}

func bearerToken(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return ""
	}
	if strings.ToLower(parts[0]) != "bearer" {
		return ""
	}
	return parts[1]
}

func spiffeIDFromXFCC(header string) string {
	if header == "" {
		return ""
	}
	// Look for URI=spiffe://... in the XFCC header.
	parts := strings.Split(header, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "URI=") {
			uri := strings.TrimPrefix(part, "URI=")
			if strings.HasPrefix(uri, "spiffe://") {
				return uri
			}
		}
	}
	return ""
}

func resolveSpiffeID(caller, requested string, allowedDelegates map[string][]string) (string, error) {
	if requested == "" || requested == caller {
		return caller, nil
	}

	if delegates, ok := allowedDelegates[caller]; ok {
		for _, allowed := range delegates {
			if requested == allowed {
				return requested, nil
			}
		}
	}

	return "", errors.New("spiffe_mismatch")
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

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("missing required env var: %s", key)
	}
	return v
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
