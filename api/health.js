module.exports = (req, res) => {
  if (req.method && req.method !== "GET") {
    res.setHeader("Allow", "GET");
    res.status(405).end("Method Not Allowed");
    return;
  }

  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store, max-age=0");
  res.status(200).end(
    JSON.stringify({
      ok: true,
      time: new Date().toISOString(),
    })
  );
};
