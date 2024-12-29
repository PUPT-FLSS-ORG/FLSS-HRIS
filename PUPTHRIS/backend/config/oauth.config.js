const config = {
  token: {
    expiresIn: "24h",
    algorithm: "HS256",
  },

  clients: {
    [process.env.FLSS_CLIENT_ID]: {
      clientId: process.env.FLSS_CLIENT_ID,
      clientSecret: process.env.FLSS_CLIENT_SECRET,
      redirectUris: ["http://fallback-url-here"],
    },
  },

  allowedOrigins: ["*"],

  facultyDataFields: [
    "UserID",
    "Fcode",
    "FirstName",
    "Surname",
    "MiddleName",
    "NameExtension",
    "Email",
    "EmploymentType",
    "isActive",
  ],
};

module.exports = config;
