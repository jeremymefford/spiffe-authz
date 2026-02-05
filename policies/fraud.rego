package envoy.authz

default allow = false

response := {
  "allowed": allow,
  "http_status": status,
  "body": body,
}

status := 200 {
  allow
}
status := 401 {
  not allow
}

body := "" {
  allow
}
body := "unauthorized" {
  not allow
}

allow {
  is_health
}

allow {
  is_score
  require_payment_spiffe
  valid_claims
  claims := jwt_claims
  claims.merchant_tier != ""
  req := req_body
  req.merchant_id != "m-gambling"
  req.amount <= 2000
  has_entitlement("svc.fraud.score")
  has_entitlement("user.fraud.score.basic")
}

allow {
  is_score
  require_payment_spiffe
  valid_claims
  claims := jwt_claims
  claims.merchant_tier == "gold"
  req := req_body
  req.merchant_id != "m-gambling"
  req.amount <= 5000
  has_entitlement("svc.fraud.score")
  has_entitlement("user.fraud.score.high")
}

allow {
  is_score
  require_payment_spiffe
  valid_claims
  claims := jwt_claims
  req := req_body
  req.merchant_id == "m-gambling"
  req.amount <= 500
  has_entitlement("svc.fraud.score")
  has_entitlement("user.fraud.score.basic")
}

allow {
  is_score
  require_payment_spiffe
  valid_claims
  claims := jwt_claims
  claims.merchant_tier == "gold"
  req := req_body
  req.merchant_id == "m-gambling"
  req.amount <= 500
  has_entitlement("svc.fraud.score")
  has_entitlement("user.fraud.score.high")
}

is_health {
  input.attributes.request.http.method == "GET"
  input.attributes.request.http.path == "/v1/health"
}

is_score {
  input.attributes.request.http.method == "POST"
  input.attributes.request.http.path == "/v1/score"
}

require_payment_spiffe {
  input.attributes.source.principal == payment_spiffe_id
}

valid_claims {
  jwt_valid
  c := jwt_claims
  c.tenant == "acme"
  token_not_expired(c)
}

token_not_expired(c) {
  exp := c.exp
  exp != 0
  time.now_ns() < exp * 1000000000
}

req_body := json.unmarshal(input.attributes.request.http.body)

payment_spiffe_id := "spiffe://example.org/ns/lab/sa/payment"

jwt_cert := opa.runtime().env.JWT_CERT

token := t {
  auth := input.attributes.request.http.headers["authorization"]
  parts := split(auth, " ")
  count(parts) == 2
  lower(parts[0]) == "bearer"
  t := parts[1]
}

jwt := io.jwt.decode_verify(token, {"cert": jwt_cert, "alg": "ES256"})

jwt_valid {
  jwt_cert != ""
  jwt[0]
}

jwt_claims := jwt[2]

has_entitlement(entitlement) {
  entitlement_allowed(payment_spiffe_id, entitlement)
}

entitlement_allowed(spiffe_id, entitlement) {
  resp := http.send({
    "method": "POST",
    "url": "http://127.0.0.1:15002/v1/check",
    "headers": {
      "content-type": "application/json",
    },
    "body": {"spiffe_id": spiffe_id, "token": token},
    "timeout": "1s",
    "force_cache": true,
    "force_cache_duration_seconds": 30,
  })
  resp.status_code == 200
  entitlements := resp.body.entitlements
  entitlements[_] == entitlement
}
