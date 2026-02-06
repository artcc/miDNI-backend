const express = require("express");
const authMiddleware = require("./middleware/auth");
const verifyRouter = require("./routes/verify");

const app = express();

app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.use(authMiddleware);
app.use("/verify", verifyRouter);

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => {
  console.log(`miDNI backend listening on port ${port}`);
});
