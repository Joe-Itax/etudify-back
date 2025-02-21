const { PrismaClient } = require("@prisma/client");
const { user } = new PrismaClient();
const jwt = require("jsonwebtoken");
const passport = require("passport");
const { hashPassword, comparePassword } = require("../utils/helper");

// verification si l'email est valide
const emailValid = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

//Verification password (au moins 8 caractères, une majuscule, une minuscule, un chiffre)
const passwordValid = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;

async function signupUser(req, res) {
  const userReq = req.body;

  if (Object.keys(userReq).length > 4) {
    return res.status(500).json({
      message: `Veuillez ne saisir uniquement les entrées requis à savoir le firstname, lastname, l'email et le password`,
    });
  }

  if (
    !userReq.firstname ||
    !userReq.lastname ||
    !userReq.email ||
    !userReq.password
  ) {
    return res.status(403).json({
      message: `Les champs firstname, lastname, email et password sont obligatoire`,
    });
  }

  //Verifie si l'email est valide
  if (!emailValid.test(userReq.email)) {
    return res.status(403).json({
      message: `Veuillez saisir une adresse mail valide.`,
    });
  }

  // Verifie si le password repond aux critères
  if (!passwordValid.test(userReq.password)) {
    return res.status(403).json({
      message: `Veuillez saisir un mot de passe selon les critères (Au moins 8 caractères, une majuscule, une minuscule, un chiffre, un caractère spécial).`,
    });
  }

  //Hasher le password avant de l'enregistrer dans la BD
  userReq.password = await hashPassword(userReq.password);
  try {
    const searchUserInDB = await user.findUnique({
      where: {
        email: userReq.email,
      },
    });

    if (searchUserInDB) {
      return res.status(400).json({
        message: "Un utilisateur avec cet email est déjà enregistré",
      });
    }

    const signupNewUserInDB = await user.create({
      data: {
        ...userReq,
        tokenRevokedAt: null, // Indique que le token n'a pas été révoqué
      },
      include: {
        resources: true,
        comment: true,
        like: true,
        favorite: true,
        questions: true,
        answers: true,
      },
    });

    // **Access Token (expire en 15 min)**
    const accessToken = await jwt.sign(
      { email: signupNewUserInDB.email, id: signupNewUserInDB.id },
      process.env.JWT_SECRET,
      { expiresIn: "1m" }
    );

    // **Refresh Token (expire en 7 jours)**
    const refreshToken = jwt.sign(
      { email: signupNewUserInDB.email, id: signupNewUserInDB.id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "7d" }
    );

    // Stocker le Refresh Token en base de données
    await user.update({
      where: { email: signupNewUserInDB.email },
      data: { refreshToken: refreshToken },
    });

    // res.cookie("jwt", token, {
    //   //Set the cookie duration to 3 days
    //   maxAge: 1000 * 60 * 60 * 24 * 3,
    //   sameSite: "None",
    //   httpOnly: false, //Mettre à true en prod
    //   secure: true,
    // });

    // Envoyer les tokens au client
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true, // Empêche l'accès par JS (protection XSS)
      secure: false, // Activer en HTTPS (prod)
      sameSite: "None",
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 jours
    });

    // Suppression des données sensibles avant de retourner l'utilisateur
    delete signupNewUserInDB.password;
    delete signupNewUserInDB.isDeleted;
    delete signupNewUserInDB.role;
    delete signupNewUserInDB.updatedAt;
    delete signupNewUserInDB.tokenRevokedAt;

    return res.status(200).json({
      isLoggedIn: true,
      message: `Compte créé et connecté avec succès en tant que ${signupNewUserInDB.email}`,
      user: signupNewUserInDB,
      accessToken: accessToken, // Envoyer le token d'accès au frontend
    });
  } catch (error) {
    return res.status(500).json({
      message: error.message,
    });
  }
}

async function loginUser(req, res) {
  const userReq = req.body;

  if (Object.keys(userReq).length > 2) {
    return res.status(500).json({
      message: `Veuillez ne saisir uniquement les entrées requis à savoir l'email et le password`,
    });
  }

  if (!userReq.email || !userReq.password) {
    return res.status(403).json({
      message: `Les entrées email et password sont obligatoire`,
    });
  }

  if (!emailValid.test(userReq.email)) {
    return res.status(403).json({
      message: `Veuillez saisir une adresse mail valide.`,
    });
  }

  try {
    // Vérification de l'existence de l'utilisateur
    const searchUserInDB = await user.findUnique({
      where: {
        email: userReq.email,
      },
    });
    if (!searchUserInDB) {
      return res.status(404).json({
        message: `Aucun compte n'a été trouvé avec cet email !`,
      });
    }

    // Vérification du mot de passe
    const passwordIsCorrect = await comparePassword(
      userReq.password,
      searchUserInDB.password
    );
    if (!passwordIsCorrect) {
      return res.status(400).json({ message: "Mot de passe incorrect !" });
    }

    // Mise à jour de tokenRevokedAt à null pour permettre l'accès
    await user.update({
      where: {
        email: searchUserInDB.email,
      },
      data: {
        tokenRevokedAt: null, // Réinitialisation pour permettre l'accès avec ce token
      },
    });

    // **Access Token (expire en 15 min)**
    const accessToken = await jwt.sign(
      { email: searchUserInDB.email, id: searchUserInDB.id },
      process.env.JWT_SECRET,
      { expiresIn: "1m" }
    );

    // **Refresh Token (expire en 7 jours)**
    const refreshToken = jwt.sign(
      { email: searchUserInDB.email, id: searchUserInDB.id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "7d" }
    );

    // Stocker le Refresh Token en base de données (optionnel mais recommandé)
    await user.update({
      where: { email: userReq.email },
      data: { refreshToken: refreshToken },
    });

    // Stockage du token dans un cookie
    // res.cookie("jwt", token, {
    //   maxAge: 1000 * 60 * 60 * 24 * 3, //3 jours
    //   sameSite: "None",
    //   httpOnly: false, //Mettre à true en prod
    //   secure: true,
    // });

    // Envoyer les tokens au client
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true, // Empêche l'accès par JS (protection XSS)
      secure: false, // Activer en HTTPS (prod)
      sameSite: "None",
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 jours
    });

    // Suppression des données sensibles avant de retourner l'utilisateur
    delete searchUserInDB.password;
    delete searchUserInDB.isDeleted;
    delete searchUserInDB.role;
    delete searchUserInDB.updatedAt;
    delete searchUserInDB.refreshToken;
    delete searchUserInDB.tokenRevokedAt;

    return res.status(200).json({
      isLoggedIn: true,
      message: `Connecté en tant que '${searchUserInDB.email} - ${searchUserInDB.firstname} ${searchUserInDB.lastname}'`,
      user: searchUserInDB,
      accessToken: accessToken, // Envoyer le token d'accès au frontend
    });
  } catch (error) {
    return res.status(500).json({
      message: error.message,
    });
  }
}

// async function logout(req, res) {
//   try {
//     const token = req.cookies.jwt;
//     if (!token) {
//       return res.status(400).json({ message: "Aucun token trouvé" });
//     }

//     const decoded = jwt.verify(token, process.env.JWT_SECRET);

//     await user.update({
//       where: {
//         email: decoded.email,
//       },
//       data: {
//         tokenRevokedAt: new Date(),
//       },
//     });

//     res.clearCookie("jwt");
//     return res.status(200).json({ message: "Déconnexion réussie" });
//   } catch (error) {
//     return res.status(500).json({ message: "Erreur lors de la déconnexion" });
//   }
// }
async function logoutUser(req, res) {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(200).json({ message: "Déjà déconnecté" });
    }

    // Supprimer le refreshToken de la DB
    await user.updateMany({
      where: { refreshToken: refreshToken },
      data: { refreshToken: null },
    });

    // Supprimer le cookie
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: false, // Mettre à true en prod
      sameSite: "None",
    });

    return res
      .status(200)
      .json({ isLoggedIn: false, message: "Déconnexion réussie" });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
}

module.exports = {
  signupUser,
  loginUser,
  logoutUser,
};
