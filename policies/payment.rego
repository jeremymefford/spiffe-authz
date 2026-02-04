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
  is_refund
  valid_claims
  claims := jwt_claims
  claims.mfa == true
  has_entitlement("svc.charge")
  has_entitlement("user.refunds")
}

allow {
  is_charge
  valid_claims
  claims := jwt_claims
  req := req_body
  req.currency == "USD"
  req.amount <= basic_limit(claims)
  has_entitlement("svc.charge")
  has_entitlement("user.charge.basic")
}

allow {
  is_charge
  valid_claims
  claims := jwt_claims
  claims.merchant_tier == "gold"
  req := req_body
  req.currency == "USD"
  req.amount <= 5000
  has_entitlement("svc.charge")
  has_entitlement("user.charge.high")
}

basic_limit(claims) := 100 {
  is_data_entry(claims)
}

basic_limit(claims) := 1000 {
  not is_data_entry(claims)
}

is_data_entry(claims) {
  roles := claims.roles
  roles[_] == "finance-data-entry"
}

is_health {
  input.attributes.request.http.method == "GET"
  input.attributes.request.http.path == "/v1/health"
}

is_refund {
  input.attributes.request.http.method == "POST"
  input.attributes.request.http.path == "/v1/refund"
}

is_charge {
  input.attributes.request.http.method == "POST"
  input.attributes.request.http.path == "/v1/charge"
}

valid_claims {
  jwt_valid
  c := jwt_claims
  c.tenant == "acme"
  c.merchant_tier != ""
}

req_body := json.unmarshal(input.attributes.request.http.body)

service_spiffe_id := "spiffe://example.org/ns/lab/sa/payment"

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
  entitlement_allowed(service_spiffe_id, entitlement)
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
  })
  resp.status_code == 200
  entitlements := resp.body.entitlements
  entitlements[_] == entitlement
}
