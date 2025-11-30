# 🧪 Manual Testing Guide

This guide provides step-by-step instructions for manually testing the Web Payment Scanner and verifying its findings.

## 📋 Prerequisites

1.  **Target Application**: A web application with payment functionality (e.g., checkout, cart, wallet).
2.  **Scanner Binary**: Ensure you have built the scanner (`make build`).
3.  **Browser**: Firefox (installed via Playwright) or Chrome.

---

##  Step 1: Basic Connectivity Test

Before running a full scan, verify the scanner can connect to your target.

```bash
./bin/scanner --target https://example.com --crawl=false --scanners=false
```
*Note: The `--scanners=false` flag isn't a real flag in our current CLI, but you can disable individual scanners or just let it run discovery and exit.*

**Better approach:**
Run a quick discovery scan:
```bash
./bin/scanner --target https://example.com --race=false --price=false --idor=false --otp=false --callback=false --amount=false --idempotency=false
```

**Verify:**
- [ ] Scanner starts successfully.
- [ ] Browser launches (if not headless).
- [ ] "Discovery complete" message appears.
- [ ] Endpoints are listed in the output.

---

##  Step 2: Authenticated Scan

Most payment flaws require being logged in.

1.  **Identify Login URL**: e.g., `https://example.com/login`
2.  **Run Scanner with Login**:
    ```bash
    ./bin/scanner --target https://example.com/dashboard --login https://example.com/login
    ```
3.  **Manual Action**:
    - The browser will open and navigate to the login page.
    - **Manually type** your username and password.
    - Click "Login".
    - Wait for the scanner to detect the redirect/dashboard.
4.  **Verify**:
    - [ ] Console shows "Login detected!".
    - [ ] Console shows "Session extracted".
    - [ ] Cookies count is > 0.

---

##  Step 3: Testing Race Conditions

**Scenario**: Trying to use a single-use coupon multiple times.

1.  **Find Endpoint**: Look for the "Apply Coupon" or "Checkout" button endpoint in the discovery list.
2.  **Run Scan**:
    ```bash
    ./bin/scanner --target https://example.com/checkout --race=true --price=false --idor=false
    ```
3.  **Verify Results**:
    - Check the report (`reports/scan_report_....html`).
    - Look for "Race Condition" vulnerabilities.
    - **Manual Verification**:
        - Use Burp Suite or Postman.
        - Send 10 concurrent requests to the endpoint using Turbo Intruder (Burp) or a script.
        - Check if multiple requests succeeded (HTTP 200/201).

---

##  Step 4: Testing Price Manipulation

**Scenario**: Changing the price of an item in the cart.

1.  **Run Scan**:
    ```bash
    ./bin/scanner --target https://example.com/api/cart --price=true
    ```
2.  **Verify Results**:
    - Look for "Price Manipulation" in the report.
    - **Manual Verification**:
        - Intercept the checkout request in browser DevTools (Network tab).
        - Right-click -> "Copy as cURL".
        - Edit the cURL command, changing `"price": 100` to `"price": 1`.
        - Run the command.
        - Check if the server accepts it.

---

##  Step 5: Testing IDOR

**Scenario**: Viewing another user's order.

1.  **Run Scan**:
    ```bash
    ./bin/scanner --target https://example.com/api/orders/1005 --idor=true
    ```
2.  **Verify Results**:
    - Look for "IDOR" vulnerabilities.
    - **Manual Verification**:
        - Create two accounts (User A and User B).
        - Log in as User A.
        - Try to access User B's order ID (e.g., `/api/orders/1006`).
        - If you see the order details, it's vulnerable.

---

##  Troubleshooting

**Browser closes too fast?**
- The scanner closes the browser after session extraction.
- To keep it open longer for debugging, you might need to modify `internal/browser/browser.go` to add a `time.Sleep()` or use a debug flag if implemented.

**Login not detected?**
- Ensure the URL changes after login. The scanner waits for the URL to change from the login URL.
- If it's a Single Page App (SPA) that doesn't change URL, the scanner might time out.

**No endpoints found?**
- Try increasing depth: `--max-depth=5` (if configurable in code, currently hardcoded or via config).
- Ensure `payment_paths.txt` has relevant paths.

---

##  Safety Warning

- **DO NOT** run this against production systems without explicit permission.
- **DO NOT** use your main personal account; you might get banned due to "hacking attempts" (race conditions, brute force).
- **ALWAYS** use test accounts.
