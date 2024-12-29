const { AuthorizationCode, ClientCredentials } = require("simple-oauth2");
const jwt = require("jsonwebtoken");
const oauthConfig = require("../config/oauth.config");

class OAuth2Service {
  constructor() {
    this.tokenSecret = process.env.JWT_SECRET_KEY;
    this.employmentTypeMapping = {
      fulltime: "Full-Time",
      parttime: "Part-Time",
      temporary: "Temporary",
      designee: "Designee",
    };

    // Simple-oauth2 Configuration
    this.oauth2 = new ClientCredentials({
      client: {
        id: process.env.FLSS_CLIENT_ID,
        secret: process.env.FLSS_CLIENT_SECRET,
      },
      auth: {
        tokenHost: process.env.TOKEN_HOST || "http://localhost:3000",
        tokenPath: "/oauth/token",
        revokePath: "/oauth/revoke",
      },
    });
  }

  // Validate client credentials using simple-oauth2
  async validateClient(clientId, clientSecret) {
    try {
      const client = oauthConfig.clients[clientId];
      if (!client || client.clientSecret !== clientSecret) {
        return false;
      }
      return true;
    } catch (error) {
      console.error("Client validation error:", error);
      return false;
    }
  }

  // Generate access token with faculty data
  async generateToken(userData) {
    try {
      const payload = {
        sub: userData.UserID,
        type: "access_token",
        ...this._filterFacultyData(userData),
      };

      // Generate JWT token to maintain compatibility
      const accessToken = jwt.sign(payload, this.tokenSecret, {
        expiresIn: oauthConfig.token.expiresIn,
        algorithm: oauthConfig.token.algorithm,
      });

      // Create OAuth2-compatible token response
      return {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: this._getExpiresInSeconds(oauthConfig.token.expiresIn),
        faculty_data: payload,
      };
    } catch (error) {
      console.error("Token generation error:", error);
      throw error;
    }
  }

  // Validate access token - maintains compatibility
  validateToken(token) {
    try {
      return jwt.verify(token, this.tokenSecret);
    } catch (error) {
      return null;
    }
  }

  // Helper method to convert JWT expiry to seconds
  _getExpiresInSeconds(expiresIn) {
    const units = {
      h: 3600,
      d: 86400,
      w: 604800,
    };
    const match = expiresIn.match(/(\d+)([hdw])/);
    if (match) {
      const [_, number, unit] = match;
      return parseInt(number) * (units[unit] || 1);
    }
    return 86400; // Default to 24 hours
  }

  // Filter and format faculty data - maintains compatibility
  _filterFacultyData(userData) {
    const filtered = {};
    oauthConfig.facultyDataFields.forEach((field) => {
      if (userData[field] !== undefined) {
        switch (field) {
          case "isActive":
            filtered.status = userData[field] ? "Active" : "Inactive";
            break;
          case "EmploymentType":
            filtered.faculty_type =
              this.employmentTypeMapping[userData[field].toLowerCase()] ||
              userData[field].toLowerCase();
            break;
          case "Surname":
            filtered.last_name = userData[field];
            break;
          case "FirstName":
            filtered.first_name = userData[field];
            break;
          case "MiddleName":
            filtered.middle_name = userData[field] || null;
            break;
          case "NameExtension":
            filtered.name_extension = userData[field] || null;
            break;
          case "Fcode":
            filtered.faculty_code = userData[field];
            break;
          default:
            filtered[field] = userData[field];
        }
      }
    });
    return filtered;
  }
}

module.exports = new OAuth2Service();
