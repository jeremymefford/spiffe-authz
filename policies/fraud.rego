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
  input.attributes.request.http.method == "GET"
  input.attributes.request.http.path == "/v1/health"
}

allow {
  input.attributes.request.http.method == "POST"
  input.attributes.request.http.path == "/v1/score"
  input.attributes.source.principal == "spiffe://example.org/ns/lab/sa/payment"
  jwt_valid
  claims := jwt_claims
  claims.tenant == "acme"
  claims.merchant_tier != ""
  body := json.unmarshal(input.attributes.request.http.body)
  body.merchant_id != "m-gambling"
  body.amount <= 2000
  entitlement_allowed(payment_spiffe_id, claims, "svc.fraud.score")
  entitlement_allowed(payment_spiffe_id, claims, "user.fraud.score.basic")
}

allow {
  input.attributes.request.http.method == "POST"
  input.attributes.request.http.path == "/v1/score"
  input.attributes.source.principal == "spiffe://example.org/ns/lab/sa/payment"
  jwt_valid
  claims := jwt_claims
  claims.tenant == "acme"
  claims.merchant_tier == "gold"
  body := json.unmarshal(input.attributes.request.http.body)
  body.merchant_id != "m-gambling"
  body.amount <= 5000
  entitlement_allowed(payment_spiffe_id, claims, "svc.fraud.score")
  entitlement_allowed(payment_spiffe_id, claims, "user.fraud.score.high")
}

allow {
  input.attributes.request.http.method == "POST"
  input.attributes.request.http.path == "/v1/score"
  input.attributes.source.principal == "spiffe://example.org/ns/lab/sa/payment"
  jwt_valid
  claims := jwt_claims
  claims.tenant == "acme"
  body := json.unmarshal(input.attributes.request.http.body)
  body.merchant_id == "m-gambling"
  body.amount <= 500
  entitlement_allowed(payment_spiffe_id, claims, "svc.fraud.score")
  entitlement_allowed(payment_spiffe_id, claims, "user.fraud.score.basic")
}

allow {
  input.attributes.request.http.method == "POST"
  input.attributes.request.http.path == "/v1/score"
  input.attributes.source.principal == "spiffe://example.org/ns/lab/sa/payment"
  jwt_valid
  claims := jwt_claims
  claims.tenant == "acme"
  claims.merchant_tier == "gold"
  body := json.unmarshal(input.attributes.request.http.body)
  body.merchant_id == "m-gambling"
  body.amount <= 500
  entitlement_allowed(payment_spiffe_id, claims, "svc.fraud.score")
  entitlement_allowed(payment_spiffe_id, claims, "user.fraud.score.high")
}

payment_spiffe_id := "spiffe://example.org/ns/lab/sa/payment"

jwt_secret := opa.runtime().env.JWT_SECRET

token := t {
  auth := input.attributes.request.http.headers["authorization"]
  parts := split(auth, " ")
  count(parts) == 2
  lower(parts[0]) == "bearer"
  t := parts[1]
}

jwt := io.jwt.decode_verify(token, {"secret": jwt_secret, "alg": "HS256"})

jwt_valid {
  jwt_secret != ""
  jwt[0]
}

jwt_claims := jwt[2]

entitlement_allowed(spiffe_id, claims, entitlement) {
  resp := http.send({
    "method": "POST",
    "url": "http://127.0.0.1:15002/v1/check",
    "headers": {
      "content-type": "application/json",
      "authorization": sprintf("Bearer %s", [token]),
    },
    "body": {"spiffe_id": spiffe_id, "token": token},
    "timeout": "1s",
  })
  resp.status_code == 200
  entitlements := resp.body.entitlements
  entitlements[_] == entitlement
}
