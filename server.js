const express = require("express");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = "mock-enterprise-secret"; // Only for mock

function decodeBasicAuth(authHeader) {
  if (!authHeader || !authHeader.startsWith("Basic ")) {
    return null;
  }

  const base64Credentials = authHeader.split(" ")[1];
  const credentials = Buffer.from(base64Credentials, "base64").toString("utf-8");
  const [appId, appKey] = credentials.split(":");

  return { appId, appKey };
}

app.get("/api/v3/auth/app-token", (req, res) => {
  try {
    const authHeader = req.headers["authorization"];
    const creds = decodeBasicAuth(authHeader);

    if (!creds || !creds.appId || !creds.appKey) {
      return res.status(401).json({
        error: "invalid_app_credentials",
        message: "Missing or invalid Basic Authorization header",
      });
    }

    const now = Math.floor(Date.now() / 1000);
    const expiresIn = 900; // 15 minutes

    const payload = {
      type: "app-token",
      jti: uuidv4().slice(0, 10),
      iss: "https://sapientaiproducts.com",
      industry: "087c0f33-da00-416e-9701-ce27f3adbcd9",
      appKey: creds.appKey.slice(0,10),
      appId: creds.appId,
      services: ["llm", "projects", "state"],
      appName: "Mock Enterprise App",
      iat: now,
      exp: now + expiresIn,
    };

    const token = jwt.sign(payload, JWT_SECRET, {
      algorithm: "HS256",
    });

    return res.json({
      app_token: token,
      token_type: "Bearer",
      expires_in: expiresIn,
    });
  } catch (err) {
    console.error("Mock App Token Error:", err);
    return res.status(500).json({
      error: "internal_mock_error",
    });
  }
});

app.listen(PORT, () => {
  console.log(`Mock App Token Server running on port ${PORT}`);
});
