const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Employee = sequelize.define('Employee', {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
    },
    firstName: {
        type: DataTypes.STRING(50),
        allowNull: false
    },
    lastName: {
        type: DataTypes.STRING(50),
        allowNull: false
    },
    email: {
        type: DataTypes.STRING(100),
        allowNull: false,
        unique: true
    },
    department: {
        type: DataTypes.ENUM('HR', 'Finance', 'IT', 'Sales', 'Operations'),
        allowNull: false
    },
    position: {
        type: DataTypes.STRING(100)
    },
    salary: {
        type: DataTypes.DECIMAL(10, 2),
        allowNull: false
    },
    hireDate: {
        type: DataTypes.DATEONLY,
        allowNull: false
    },
    isActive: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
    }
});

module.exports = Employee;