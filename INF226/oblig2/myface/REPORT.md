# MyFace Report for *NAME*
## Tasks
### a) SQL Injection

> How did you do the SQL injection and what did you do to fix it?
- I injected the SQL by submitting a username that closed the expected quoted value and appended an INSERT statement, which caused the database to execute both the original and my injected SQL. Because the app concatenated raw user input into query strings, characters like '; changed the SQL grammar and allowed creation of accounts. 
I fixed this by converting all statements to parameterized queries (using ? placeholders and passing values separately) so input is always treated as data, not SQL. The query to "hack" looked like this: ' ; INSERT INTO users (username, password, info) VALUES ('HACKER2', 'GGez', '{"name": "Bob", "color": "red"}'); 

### b) JS Code Injection

> How did you inject JS code?
- I edited Profile → About and saved HTML/JS. The code i added was ```<button onclick="alert('GGez')">gethacked</button>```, but you could also add something like: ```<img src=x onerror=alert(1)>```.

> Could we solve it with`CSP
- we could block inline JavaScript and event handlers (e.g. onclick=), so some payloads would stop working.
However, CSP alone is not enough, because the vulnerability comes from the JavaScript code inserting user-controlled strings directly into the DOM with innerHTML. If attacker HTML is injected into the page, CSP will not stop all DOM-based XSS vectors.A CSP is good defense-in-depth, but the correct fix is to stop injecting untrusted HTML and instead build DOM elements safely.

> Does it work on `/users/me`? Why not?
- When you visit /users/me in a browser, the request’s Accept header prefers text/html, so the server renders the _users.html template. Jinja auto-escaping prints user fields as text (no |safe). Also on the home page, the JS fetches /users/<id> as JSON and then injects the fields into the DOM using innerHTML. That path does execute attacker HTML because it bypasses template escaping.
> How did you fix the problem?
- The XSS happened because the client-side code inserted user data into the page using innerHTML. That allowed attacker-controlled HTML and JavaScript (e.g. <img onerror=alert(1)>) to execute. I fixed this by rewriting format_field() and format_profile() to build the UI using safe DOM APIs (createElement, textContent) instead of concatenating HTML strings. I also enabled a nonce-based Content-Security-Policy (the nonce was already generated in before_request). I added the CSP in an after_request handler so only scripts with the correct nonce run, and inline event handlers like onclick= are blocked.

### c) Access Control

> What do you think about how passwords are currently stored?
- In the original code, passwords were stored in plaintext in the database and compared directly during login. There was also no validation preventing an empty password, and users could set weak passwords (e.g., "a"). This is not aligned with security best practices. Modern applications must never store plaintext credentials; if the database leaks, all accounts are immediately compromised.
> How did you improve it?
- I replaced plaintext password storage with salted password hashing using Werkzeug:generate_password_hash(password) when storing a password check_password_hash(stored_hash, password) when verifying login. This ensures that even if the database is leaked, attackers cannot read user passwords directly. I also added password complexity checks before allowing updates. For example:Minimum length Must include letters and numbers. Attempting to set a weak/empty password results in a validation error.
> Explain your access control scheme
- Originally, all users could view full profiles of every other user, which violates the principle of least privilege. I implemented a simple buddy-based access control policy: By default, users only see username. If user A adds user B as a buddy, then B may view A's full profile. If both users add each other, both can see each others full profile.
> Did you add buddies?
- yes
> Can a user change another users profile info?
- No, /profile/ route always edits the logged-in user, not a user ID provided by the client.There is no parameter like /profile/<user_id> and the client can't choose who is updated. That means: The server never trusts a user-supplied ID. The edit always applies to the session’s user only. So even if someone crafts a malicious POST request, it will update their own profile only.
 
### d) Security Analysis

> Which project did you review? (Full URL to repository)
- https://git.app.uib.no/inf226/25h/proj/Andreas.Farup_myface
> Write you analysis in the [Security Analysis](#security-analysis) section below.



### e) OpenId Connect

> Did you implement OIDC?
> Yes
> How did you do it?
> I follwed the guide to get the token, then i checked if that user already existed. If it did log it in to that. If not create a new user and log into that.
> Does it work? (it might be difficult for the TAs to test this on their own computers)
Yes


## z) Improvements (bonus)

> Did you make any improvements after the main deadline? Make a list of exactly what changes you made.


## å) Chat log (bonus)

> Include your AI chat log in [`AI_LOG.txt`](./AI_LOG.txt)

## MyFace Security Analysis
### Threat model
* **Actors** – The primary threats come from unauthenticated internet users, authenticated but malicious users, and curious developers with repository access. Attackers can send crafted HTTP requests, operate a browser while authenticated, or inspect the repository contents.
* **Assets** – User profiles (names, colours, biographies), password hashes, bearer tokens, session cookies, and the availability of the buddy feature are the main assets. Protecting session integrity and confidential profile data is critical.
* **Trust boundaries** – Browser <→ Flask server, Flask <→ SQLite database, and application logs written to disk are the main boundaries. Any data coming from users (profile fields, colour values, uploaded URLs) crosses these boundaries and must be sanitised.
* **Attacker goals** – Steal or forge sessions, inject code into profiles, perform CSRF to add buddies without consent, harvest credentials from logs, or disable token-based features.

1. **Secret key management is incomplete.** `load_or_generate_secrets` never generates a random key, and debug mode falls back to the hard-coded string `"mY s3kritz"`, making sessions predictable and enabling tampering or CSRF token forgery.
2. **Session cookie hardening is left TODO.** Important flags such as `Secure`, `HttpOnly`, `SameSite`, and a custom cookie name are commented out, so default Flask settings apply even in production, missing defence-in-depth against cookie theft and CSRF.
3. **Sensitive data is written to logs.** The login request handler logs the entire session and form payload, including submitted passwords, while the authentication helpers also log decoded Basic credentials and bearer tokens, leaking secrets to anyone with log access.
4. **CSRF protections are missing for JSON endpoints.** The buddy API accepts POST requests without any CSRF token, and the front-end helper simply calls `fetch` with default cookies, allowing an external site to trigger buddy additions for logged-in users
5. **Security headers are unused.** Although `before_request` sets a nonce, the `after_request` hook leaves CSP and related headers commented out, missing an easy defence against inline script abuse.
6. **Form validation gaps.** The login form does not require a password field, permitting unnecessary error states and making brute-force detection harder; profile fields such as colour and URLs are not validated beyond basic type checks, compounding the injection risk
