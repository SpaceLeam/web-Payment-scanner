#  Attack Vectors & Vulnerabilities

This document details the specific vulnerabilities detected by the Web Payment Scanner.

## 1. Race Conditions 

**Description:**
Occurs when a system performs an action (like checking a balance or inventory) and then updates the state, but fails to lock the resource during the process. Concurrent requests can exploit this gap.

**How we test:**
- **Technique:** Concurrent Request Flooding
- **Method:** We send 50+ simultaneous requests to endpoints like "claim coupon", "transfer funds", or "checkout".
- **Detection:** If multiple requests succeed where only one should (e.g., claiming a one-time coupon 5 times), a race condition is flagged.

**Remediation:**
- Use database transactions with `FOR UPDATE` locking.
- Implement optimistic locking (versioning).
- Use atomic operations (e.g., Redis `DECR`).

---

## 2. Price Manipulation 

**Description:**
Occurs when the server trusts the price or amount sent by the client without validating it against the backend source of truth.

**How we test:**
- **Technique:** Parameter Tampering
- **Method:** We intercept checkout requests and modify the `amount`, `price`, or `cost` fields.
- **Payloads:**
  - Negative values (`-100`)
  - Zero values (`0`)
  - Tiny values (`0.01`)
  - String formats (`"0.00"`)
- **Detection:** If the server processes a transaction with a manipulated price (HTTP 200 OK), it is flagged.

**Remediation:**
- Never trust client-side prices.
- Always fetch the price from the database using the Product ID.
- Validate that the total amount matches `price * quantity`.

---

## 3. IDOR (Insecure Direct Object References) 

**Description:**
Occurs when an application exposes a reference to an internal implementation object (like a database key) without access control checks.

**How we test:**
- **Technique:** ID Enumeration
- **Method:** We identify numeric IDs in URLs (e.g., `/orders/1001`) and attempt to access adjacent IDs (`1000`, `1002`).
- **Detection:** If we can successfully access a resource ID that wasn't originally discovered or belongs to another user context, it is flagged.

**Remediation:**
- Implement proper Access Control Lists (ACLs).
- Use indirect references (UUIDs) instead of sequential IDs.
- Verify ownership of the object before returning data.

---

## 4. OTP/2FA Bypass 

**Description:**
Weaknesses in One-Time Password implementations, such as lack of rate limiting or predictable codes.

**How we test:**
- **Technique:** Rate Limit Testing
- **Method:** We send 20+ invalid OTPs in rapid succession.
- **Detection:** If the server does not return HTTP 429 (Too Many Requests) or block the IP, it is flagged as missing rate limiting.

**Remediation:**
- Implement strict rate limiting (e.g., 3 attempts per minute).
- Implement exponential backoff.
- Invalidate OTPs after failed attempts.

---

## 5. Webhook/Callback Bypass 

**Description:**
Payment gateways (Stripe, PayPal, etc.) send webhooks to notify your server of payment status. If these are not verified, an attacker can fake a successful payment.

**How we test:**
- **Technique:** Signature Stripping & Spoofing
- **Method:** We send fake "payment.success" webhooks to callback endpoints.
  1. Without any signature header.
  2. With an invalid signature.
- **Detection:** If the server accepts the webhook (HTTP 200) without a valid signature, it is flagged.

**Remediation:**
- Always verify the cryptographic signature provided by the payment gateway.
- Check the timestamp to prevent replay attacks.

---

## 6. Amount Validation Issues 🔢

**Description:**
Issues with how numbers are handled, including precision errors and overflows.

**How we test:**
- **Technique:** Precision & Overflow Injection
- **Payloads:**
  - High precision (`10.123456789`)
  - Large numbers (Overflow)
- **Detection:** Checks for 500 errors or acceptance of invalid formats.

**Remediation:**
- Use appropriate data types for currency (e.g., Decimal, not Float).
- Validate input format strictly.

---

## 7. Idempotency Bypass 🔄

**Description:**
Failure to handle duplicate requests correctly, potentially leading to double charging or duplicate orders.

**How we test:**
- **Technique:** Replay Attacks
- **Method:** We send the same request twice, once with an Idempotency Key and once without (or reusing the key).
- **Detection:** Checks if the server processes the request as a new operation instead of returning the cached result.

**Remediation:**
- Implement Idempotency Keys for all state-changing operations.
- Cache the response for a processed key and return it for subsequent requests.
