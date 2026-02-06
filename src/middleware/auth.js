function authMiddleware(req, res, next) {
  const expectedToken = process.env.BEARER_TOKEN;
  if (!expectedToken) {
    res.status(500).json({ error: "server_not_configured" });
    return;
  }

  const authHeader = req.get("authorization") || "";
  const [scheme, token] = authHeader.split(" ");

  if (!authHeader || scheme !== "Bearer" || !token) {
    res.status(401).json({ error: "missing_bearer_token" });
    return;
  }

  if (token !== expectedToken) {
    res.status(403).json({ error: "invalid_bearer_token" });
    return;
  }

  next();
}

module.exports = authMiddleware;
