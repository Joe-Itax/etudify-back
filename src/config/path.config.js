const authBaseURI = "/api/auth"; /** Authentification **/

const userBaseURI = "/api/user"; /** Profile D'UN Utilisateur **/

const usersBaseURI = "/api/users"; /** All users **/

const ressoucesBaseURI = "/api/ressources"; /** Gestion des Ressources **/

const questionBaseURI =
  "/api/questions"; /** Les questions posté dans le forum **/

const contactBaseURI = "/api/contact";
/** Gestion des messages envoyé par les users **/

const adminBaseURI = "/api/admin"; /** Back-office d'administration **/
const paths = {
  authBaseURI: authBaseURI,
  usersBaseURI: usersBaseURI,
  userBaseURI: userBaseURI,
  ressoucesBaseURI: ressoucesBaseURI,
  questionBaseURI: questionBaseURI,
  contactBaseURI: contactBaseURI,
  adminBaseURI: adminBaseURI,
};

module.exports = paths;
