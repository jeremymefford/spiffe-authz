package envoy.authz

default allow = false

allow {
  input.attributes.request.http.method == "GET"
  input.attributes.request.http.path == "/v1/health"
}

allow {
  input.attributes.request.http.method == "POST"
  input.attributes.request.http.path == "/v1/refund"
  input.attributes.request.http.headers["x-approver-role"] == "refunds"
  entitlement_allowed("refunds")
}

allow {
  input.attributes.request.http.method == "POST"
  input.attributes.request.http.path == "/v1/charge"
  input.attributes.request.http.headers["x-user-role"] == "payments"
  body := json.unmarshal(input.attributes.request.http.body)
  body.currency == "USD"
  body.amount <= 1000
  entitlement_allowed("charge.basic")
}

allow {
  input.attributes.request.http.method == "POST"
  input.attributes.request.http.path == "/v1/charge"
  input.attributes.request.http.headers["x-user-role"] == "payments"
  input.attributes.request.http.headers["x-merchant-tier"] == "gold"
  body := json.unmarshal(input.attributes.request.http.body)
  body.currency == "USD"
  body.amount <= 5000
  entitlement_allowed("charge.high")
}

entitlement_allowed(entitlement) {
  resp := http.send({
    "method": "POST",
    "url": "http://127.0.0.1:15002/v1/check",
    "headers": {"content-type": "application/json"},
    "body": {"spiffe_id": input.attributes.source.principal, "entitlement": entitlement},
    "timeout": "1s",
  })
  resp.status_code == 200
  resp.body.allow == true
}
