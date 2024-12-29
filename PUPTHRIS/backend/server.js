/**
 * Configuration
 */
const express = require("express");
const dotenv = require("dotenv");
dotenv.config();

const { sequelize } = require("./config/db.config");
const oauthConfig = require("./config/oauth.config");

/**
 * Middleware
 */
const bodyParser = require("body-parser");
const cors = require("cors");
const checkDatabaseConnection = require("./middleware/databaseConnectionCheck");

/**
 * Application Setup
 */
const app = express();
const port = process.env.PORT || 3000;

/**
 * Middleware Initialization
 */
app.use(cors(oauthConfig.allowedOrigins));
app.use(bodyParser.json());
app.use(checkDatabaseConnection);

/**
 * Route Imports
 */
const basicDetailsRoutes = require("./routes/basicDetailsRoutes");
const personalDetailsRoutes = require("./routes/personalDetailsRoutes");
const trainingsRoutes = require("./routes/trainingsRoute");
const educationRoutes = require("./routes/educationRoutes");
const voluntaryworkRoutes = require("./routes/voluntaryworkRoutes");
const userRoutes = require("./routes/userRoutes");
const authRoutes = require("./routes/authRoutes");
const dashboardRoutes = require("./routes/dashboardRoutes");
const specialSkillRoutes = require("./routes/specialSkillRoutes");
const achievementAwardsRoutes = require("./routes/achievementAwardsRoutes");
const officershipMembershipRoutes = require("./routes/officerMembershipRoutes");
const departmentRoutes = require("./routes/departmentRoutes");
const profileImageRoutes = require("./routes/profileImageRoutes");
const roleRoutes = require("./routes/roleRoutes");
const userManagementRoutes = require("./routes/userManagementRoutes");
const coordinatorRoutes = require("./routes/coordinatorRoute");
const academicRanksRoutes = require("./routes/academicRanksRoute");
const excelImportRoutes = require("./routes/excelImportRoute");
const collegeCampusRoutes = require("./routes/collegeCampusRoutes");
const evaluationRoutes = require("./routes/evaluationRoutes");
const apiRoutes = require("./routes/apiRoutes");
const researchPaperRoutes = require("./routes/researchPaperRoutes");
const bookRoutes = require("./routes/bookRoutes");
const lectureMaterialRoutes = require("./routes/lectureMaterialRoutes");
const configRoutes = require("./routes/configRoutes");
const professionalLicenseRoutes = require("./routes/professionalLicenseRoutes");
const employmentInformationRoutes = require("./routes/employmentInformationRoutes");
const certificationRoutes = require("./routes/certificationRoutes");
const oauthRoutes = require("./routes/oauth.routes");

/**
 * Route Definitions
 */

app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok" });
});

app.use("/api/users", userRoutes);
app.use("/api/auth", authRoutes);
app.use("/oauth", oauthRoutes);
app.use("/api/roles", roleRoutes);

app.use("/api/basic-details", basicDetailsRoutes);
app.use("/api/personaldetails", personalDetailsRoutes);
app.use("/api/profile-image", profileImageRoutes);

app.use("/api/trainings", trainingsRoutes);
app.use("/api/education", educationRoutes);
app.use("/api/voluntarywork", voluntaryworkRoutes);
app.use("/api/specialskills", specialSkillRoutes);
app.use("/api/achievement-awards", achievementAwardsRoutes);
app.use("/api/officership-membership", officershipMembershipRoutes);
app.use("/api/research-papers", researchPaperRoutes);
app.use("/api/books", bookRoutes);
app.use("/api/lecture-materials", lectureMaterialRoutes);
app.use("/api/professional-licenses", professionalLicenseRoutes);
app.use("/api/employment-information", employmentInformationRoutes);
app.use("/api/certifications", certificationRoutes);

app.use("/api/user-management", userManagementRoutes);
app.use("/api/coordinators", coordinatorRoutes);
app.use("/api/academic-ranks", academicRanksRoutes);
app.use("/api/department", departmentRoutes);
app.use("/api/college-campuses", collegeCampusRoutes);
app.use("/api/evaluation", evaluationRoutes);

app.use("/api/dashboard", dashboardRoutes);
app.use("/api/excel-import", excelImportRoutes);
app.use("/api/external", apiRoutes);
app.use("/api/config", configRoutes);

/**
 * Database and Server Initialization
 */
async function startServer() {
  try {
    require("./models/associations");
    require("./utils/databaseCleanup");

    await sequelize.sync();
    console.log("Database synced successfully");

    app.listen(port, () => {
      console.log(`Server running at http://localhost:${port}/`);
    });
  } catch (err) {
    console.error("Unable to start the server:", err);
  }
}

startServer();