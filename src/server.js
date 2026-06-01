const http = require("http");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "127.0.0.1";
const JWT_SECRET = "local-development-jwt-secret";
const TOKEN_TTL_SECONDS = 60 * 60;

function base64UrlEncode(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function base64UrlDecode(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(base64, "base64").toString("utf8");
}

function signToken(payload) {
  const header = {
    alg: "HS256",
    typ: "JWT"
  };
  const now = Math.floor(Date.now() / 1000);
  const body = {
    ...payload,
    iat: now,
    exp: now + TOKEN_TTL_SECONDS
  };
  const unsignedToken = [
    base64UrlEncode(JSON.stringify(header)),
    base64UrlEncode(JSON.stringify(body))
  ].join(".");
  const signature = crypto
    .createHmac("sha256", JWT_SECRET)
    .update(unsignedToken)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  return `${unsignedToken}.${signature}`;
}

function verifyToken(token) {
  const parts = token.split(".");

  if (parts.length !== 3) {
    return null;
  }

  const [encodedHeader, encodedPayload, signature] = parts;
  const unsignedToken = `${encodedHeader}.${encodedPayload}`;
  const expectedSignature = crypto
    .createHmac("sha256", JWT_SECRET)
    .update(unsignedToken)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  if (
    signature.length !== expectedSignature.length ||
    !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))
  ) {
    return null;
  }

  try {
    const header = JSON.parse(base64UrlDecode(encodedHeader));
    const payload = JSON.parse(base64UrlDecode(encodedPayload));
    const now = Math.floor(Date.now() / 1000);

    if (header.alg !== "HS256" || payload.exp <= now) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

const routes = {
  "GET /users": () => ({
    subpath: "users",
    endpoint: "list",
    data: [
      { id: 1, name: "Ada Lovelace" },
      { id: 2, name: "Grace Hopper" }
    ]
  }),
  "GET /users/status": () => ({
    subpath: "users",
    endpoint: "status",
    status: "users service is running"
  }),
  "GET /products": () => ({
    subpath: "products",
    endpoint: "list",
    data: [
      { id: 1, name: "Notebook" },
      { id: 2, name: "Pencil" }
    ]
  }),
  "GET /products/status": () => ({
    subpath: "products",
    endpoint: "status",
    status: "products service is running"
  }),
  "GET /orders": () => ({
    subpath: "orders",
    endpoint: "list",
    data: [
      { id: 1, total: 29.99 },
      { id: 2, total: 74.5 }
    ]
  }),
  "GET /orders/status": () => ({
    subpath: "orders",
    endpoint: "status",
    status: "orders service is running"
  })
};

const publicRoutes = {
  "POST /getToken": createToken,
  "POST /token": createToken
};

function sendJson(res, statusCode, body) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8"
  });
  res.end(JSON.stringify(body, null, 2));
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", (chunk) => {
      body += chunk;

      if (body.length > 1_000_000) {
        req.destroy();
        reject(new Error("Request body is too large"));
      }
    });
    req.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("Request body must be valid JSON"));
      }
    });
    req.on("error", reject);
  });
}

async function createToken(req, res) {
  if (req.headers.secret !== "secret") {
    sendJson(res, 401, {
      error: "Invalid secret"
    });
    return;
  }

  let body;

  try {
    body = await readJsonBody(req);
  } catch (error) {
    sendJson(res, 400, {
      error: error.message
    });
    return;
  }

  const { username, role } = body;

  if (!username || !role) {
    sendJson(res, 400, {
      error: "username and role are required"
    });
    return;
  }

  sendJson(res, 200, {
    accessToken: signToken({ username, role })
  });
}

function authenticate(req) {
  const authorization = req.headers.authorization || "";
  const [scheme, token] = authorization.split(" ");

  if (scheme !== "Bearer" || !token) {
    return null;
  }

  return verifyToken(token);
}

async function handleRequest(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const routeKey = `${req.method} ${url.pathname}`;
  const publicHandler = publicRoutes[routeKey];

  if (publicHandler) {
    await publicHandler(req, res);
    return;
  }

  const handler = routes[routeKey];

  if (!handler) {
    sendJson(res, 404, {
      error: "Not found",
      availableEndpoints: Object.keys(routes)
    });
    return;
  }

  const currentUser = authenticate(req);

  if (!currentUser) {
    sendJson(res, 401, {
      error: "Missing or invalid access token"
    });
    return;
  }

  sendJson(res, 200, handler());
}

const server = http.createServer(handleRequest);

server.listen(PORT, HOST, () => {
  console.log(`API server listening at http://${HOST}:${PORT}`);
});
