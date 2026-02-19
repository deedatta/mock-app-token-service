const express = require("express");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

const app = express();

const PORT = process.env.PORT || 3000;
const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC3eX0IDafFuUl+
a/FSBQ/fwhfgkkNdHjjlfNvpIPNDEufAiOAvqywQdhAxUdRlicgJZsT8f9S761jU
djV7zOj4hHWMnA3NN3GPygjUuxo5HC3AxbL6TAbnRVT6ZV/HNbTW0vryYaqPHt5V
qcskNRG9g7JbdnaSPoAZl731Eni22RKEfFA8+iQGH6oDOJ95UkEjUpGpNeI+ouBL
+dbzpA1R4am5RCTX7Av/gEegGd/Lsgpa+l1N+Jh7glJ/WuJsz/waYl+1VxPISvFC
HVYL5jc9CqWksbh6YtMym2kRkURKgrpSzBpHDwTZ434njcOreEtZkqIFgPAo3BqL
jcghPYcZAgMBAAECggEBALcChLfyvwXX0zo6O4U/rVzZgu2rl2wbyE8Io2bASkX+
ZpLDNTP3PsXQrkgzwnPh4lmWXCks7SrhD0MmAiVR+JRjs8kkpBOuGSV/Nh3T381V
kUG3Mda+3Sf1HVWCpu3TYWXjHxOEXhfSh53U9t9P3Dk4U0EuQgmQNEDS/lSlLyna
W3b+8o4js5gquH7FuAxkfb7KMpiCuDRDciZrs88X3Yl45oy/yYJDCw1FXjvwDeUR
JpniXP9Csx9FUZl/vhmeQuFHzA5/frLvwD1yzFCMLU4DW6d36jBo6V3e8yv90DlB
bRZzNu/FqPJSqfhhsf1iovnkPnuG0nhBchRct7QChv0CgYEA83pF+keuyI0Mytu+
OWXmH7MDHBxusp7RXilH9RdU83SuqdDpcjXKx+xKnWXehBLK8bebVUGcdhbVsJsu
pL/tYEgwop1V/qfORrPoz5uK/Ti/+6mERwBBGwt9OEruQ9IWD+rMvNzHexWIr1UE
K4lhP2G1VpqbNOj3+3+04+8gRPcCgYEAwOkwo7xWY9maxhXTzuHcpdJatWo7mvIB
1N4m2gV180X9GiWd2KeWOyYkcqAWuEZvRb1n2NlQiYkuuN4qBqYO2NX6gCdueW+1
Rt3Awg9wRLoBHum3nuER9zj8Y/KtZvVpkxIUr8Vfp5eYWTGtP74J7yfD8rTzJ+fY
dTGQZ2j1YG8CgYEAtRYBC+faqFC37fzHm1sdcAAtVPAUqQcUQwtC+Jf01+m1qpm1
tvspKc6lpDFK8UIk7OiZQCy/WNkc7/BLHb+dplmqypdoiTF3awCOLDLMig92Qo/O
0RvwUFQYOxEH6ytKu2XwBpvSRco7UeRSaKsRyBk8zP/KZezL26Mc/9YvUvsCgYBY
3NJACmjNNBb8ul9IRHislfqc6OOuG17GnNLOyYcs2geePMe6XnBwrMBLYP02Q5PM
T1R/6pMT1/KCzCwVxfa+4cqzr/ZO0Ct0CoBZpFz1+6y6fbTM5iateD2jGM3RyKiq
S8Dluwi2HbnbFGwXGcZfuTSlH7+GmWD3ky5OxGWL1wKBgQDIdjiC8UYzHWRhHFIl
qXSSWdHP4xhg/vBRORlCvhBdo6fneSIsuBocUDMFuJfkm2qMzoD1AnMUQ4S+rc8g
/1vW+wmOTqovpVgcStwxvnvWh0wgzRjwNXVn2Demy2U6EIWL8eHpNcStPaFf7Lqy
LlmuBDyecU3UCJRxSOJdeUOu4Q==
-----END PRIVATE KEY-----`

const notFoundAppIds = ['a5edde6f-01f1-49c7-a969-d819b916e4d3'];

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

    if (notFoundAppIds.includes(creds.appId)) {
      return res.status(401).json({
        error: "invalid_app_credentials",
        message: "App authentication failed",
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

    const token = jwt.sign(payload, PRIVATE_KEY, {
      algorithm: "RS256", expiresIn, keyid: '_FrxfQVSlPUlvGZ5HvdkNSugQsyrdn0uqlWJGIMY_Yw'
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
