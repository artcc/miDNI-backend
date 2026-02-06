const express = require("express");
const pinoHttp = require("pino-http");
const logger = require("./logger");
const authMiddleware = require("./middleware/auth");
const verifyRouter = require("./routes/verify");

const app = express();

app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));
app.use(pinoHttp({ logger, autoLogging: { ignore: (req) => req.url === "/health" } }));

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.use(authMiddleware);
app.use("/verify", verifyRouter);

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => {
  logger.info({ port }, "miDNI backend listening");
});
