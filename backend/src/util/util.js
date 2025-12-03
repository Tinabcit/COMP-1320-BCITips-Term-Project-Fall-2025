// backend/util/util.js
import jwt from "jsonwebtoken";

const JWT_SECRET = "secret"; // MUST match authService

const DEFAULT_HEADER = {
  "content-type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
};

function verifyToken(token) {
  try {
    // returns payload: { userId, username, iat, exp }
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    console.error("JWT verify error:", err.message);
    return null;
  }
}

function getUserFromRequest(req, res) {
  const authHeader = req.headers["authorization"];

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.writeHead(401, DEFAULT_HEADER);
    res.end(
      JSON.stringify({ error: "Missing or invalid Authorization header" })
    );
    return null;
  }

  const token = authHeader.slice("Bearer ".length);
  const payload = verifyToken(token);

  if (!payload) {
    res.writeHead(401, DEFAULT_HEADER);
    res.end(JSON.stringify({ error: "Invalid token" }));
    return null;
  }

  // payload has { userId, username, iat, exp }
  return payload;
}

export { DEFAULT_HEADER, getUserFromRequest };
