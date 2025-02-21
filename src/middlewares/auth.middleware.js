const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const { user } = new PrismaClient();

async function refreshTokenMiddleware(req, res, next) {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res
      .status(403)
      .json({ message: "Aucun token de rafraîchissement fourni !" });
  }

  try {
    // Vérifier le refreshToken
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    // Vérifier si l'utilisateur existe et si le refreshToken est valide
    const userData = await user.findUnique({
      where: { id: decoded.id, refreshToken: refreshToken },
    });

    if (!userData) {
      console.log("");

      return res.status(403).json({ message: "Token invalide ou expiré !" });
    }

    // Générer un nouveau Access Token
    const newAccessToken = jwt.sign(
      { email: userData.email, id: userData.id },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    // Attacher le token à la requête pour que les routes suivantes puissent l'utiliser
    req.newAccessToken = newAccessToken;

    next();
  } catch (error) {
    return res.status(403).json({ message: "Token invalide !" });
  }
}

async function authMiddleware(req, res, next) {
  let accessToken = req.headers.authorization?.split(" ")[1];

  if (!accessToken) {
    return res
      .status(401)
      .json({ message: "Accès refusé ! Aucun token fourni." });
  }

  try {
    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
    req.user = decoded; // Ajouter l'utilisateur à la requête
    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      // Si le token a expiré, on appelle le middleware de refresh
      return refreshTokenMiddleware(req, res, () => {
        // Une fois que le refreshToken est validé, on passe au middleware suivant

        req.headers.authorization = `Bearer ${req.newAccessToken}`;
        next();
      });
    }
    return res.status(403).json({ message: "Token invalide !" });
  }
}

module.exports = {
  authMiddleware,
  //   authenticateUser,
};
