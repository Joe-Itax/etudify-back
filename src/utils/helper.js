const bcrypt = require("bcrypt");
const { PrismaClient } = require("@prisma/client");
const { user } = new PrismaClient();

const hashPassword = async (password) => {
  return bcrypt.hashSync(password, 10);
};

const comparePassword = async (password, passwordHashed) => {
  return bcrypt.compareSync(password, passwordHashed);
};

const serialiseDeserialiseUser = async (passport) => {
  passport.serializeUser(async (user, done) => {
    done(null, user.email);
  });

  passport.deserializeUser(async (email, done) => {
    try {
      const userReq = user.findUnique({
        where: {
          email: email,
        },
      });
      done(null, userReq.email);
    } catch (error) {
      done(error);
    }
  });
};

module.exports = {
  hashPassword,
  comparePassword,
  serialiseDeserialiseUser,
};
