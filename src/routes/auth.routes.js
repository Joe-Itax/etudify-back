const { Router } = require("express");
const authRouter = Router();
const {
  signupUser,
  loginUser,
  logoutUser,
} = require("../controllers/auth.controller");
const { authMiddleware } = require("../middlewares/auth.middleware");

authRouter.post("/signup", signupUser);
authRouter.post("/login", loginUser);
authRouter.post("/logout", authMiddleware, logoutUser);

module.exports = authRouter;
