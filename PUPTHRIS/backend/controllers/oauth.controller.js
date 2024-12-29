const User = require("../models/userModel");
const bcrypt = require("bcrypt");
const oauth2Service = require("../services/oauth2.service");

class OAuthController {
  /**
   * Generates an access token for a user given valid credentials.
   * @param {Object} req - The request object.
   * @param {Object} res - The response object.
   * @returns {Promise<void>}
   */
  async generateToken(req, res) {
    try {
      const { username, password, client_id, client_secret } = req.body;

      // Validate client credentials
      const isValidClient = await oauth2Service.validateClient(
        client_id,
        client_secret
      );
      if (!isValidClient) {
        return res.status(401).json({
          error: "invalid_client",
          error_description: "Invalid client credentials",
        });
      }

      // Find user by username/email
      const user = await User.findOne({
        where: { Email: username },
      });

      if (!user) {
        return res.status(401).json({
          error: "invalid_grant",
          error_description: "Invalid credentials",
        });
      }

      // Verify password
      const validPassword = await bcrypt.compare(password, user.PasswordHash);
      if (!validPassword) {
        return res.status(401).json({
          error: "invalid_grant",
          error_description: "Invalid credentials",
        });
      }

      // Generate token response
      const tokenResponse = await oauth2Service.generateToken(user);
      res.json(tokenResponse);
    } catch (error) {
      console.error("OAuth token generation error:", error);
      res.status(500).json({
        error: "server_error",
        error_description: "An internal server error occurred",
      });
    }
  }

  /**
   * Validates an access token and returns user data if the token is valid.
   * @param {Object} req - The request object.
   * @param {Object} res - The response object.
   * @returns {Promise<void>}
   */
  async validateToken(req, res) {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
          error: "invalid_token",
          error_description: "Token is missing",
        });
      }

      const token = authHeader.split(" ")[1];
      const decoded = oauth2Service.validateToken(token);

      if (!decoded) {
        return res.status(401).json({
          error: "invalid_token",
          error_description: "Token is invalid or expired",
        });
      }

      res.json({
        active: true,
        faculty_data: decoded,
      });
    } catch (error) {
      console.error("Token validation error:", error);
      res.status(500).json({
        error: "server_error",
        error_description: "An internal server error occurred",
      });
    }
  }
}

module.exports = new OAuthController();
