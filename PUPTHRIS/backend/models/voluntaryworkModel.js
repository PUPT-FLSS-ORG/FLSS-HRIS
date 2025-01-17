const { Sequelize, DataTypes } = require('sequelize');
const { sequelize } = require('../config/db.config');

const VoluntaryWork = sequelize.define('VoluntaryWork', {
  VoluntaryWorkID: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  userID: {
    type: DataTypes.INTEGER,
    references: {
      model: 'users',
      key: 'UserID',
    },
  },
  OrganizationNameAddress: {
    type: DataTypes.STRING(255),
  },
  InclusiveDatesFrom: {
    type: DataTypes.DATE,
  },
  InclusiveDatesTo: {
    type: DataTypes.DATE,
  },
  NumberOfHours: {
    type: DataTypes.INTEGER,
  },
  PositionNatureOfWork: {
    type: DataTypes.STRING(100),
  },
}, {
  tableName: 'voluntarywork',
  timestamps: false,
});

module.exports = VoluntaryWork;
