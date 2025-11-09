import express from "express";

const router = express.Router();

router.get("/messages", (req, res) => {
  res.send("Messages endpoint");
});

export default router;
