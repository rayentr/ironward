// JWT decode, cookie samesite, password-in-url, basic-auth, timing-unsafe, hmac.

// jwt-decode-not-verify
const payload = jwt.decode(token);

// cookie-no-samesite
res.cookie("session", sid, { httpOnly: true, secure: true });

// password-in-url-query
const url = `https://api.example.com/login?password=${pw}&user=${u}`;
const url2 = "https://api.example.com/act?api_key=deadbeef1234";

// basic-auth-over-http
const r = await fetch("http://api.legacy.com/auth?authorization=abc");
const h = { Authorization: "Basic YWRtaW46aHVudGVyMg==" };

// timing-unsafe-comparison
if (password === req.body.password) { return true; }
if (token !== req.query.token) { return false; }

// hmac-no-timing-safe
if (hmac.digest("hex") === sig) return true;
