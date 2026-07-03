const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Invoice = sequelize.define('Invoice', {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
    },
    invoiceNumber: {
        type: DataTypes.STRING(20),
        allowNull: false,
        unique: true
    },
    clientName: {
        type: DataTypes.STRING(100),
        allowNull: false
    },
    amount: {
        type: DataTypes.DECIMAL(12, 2),
        allowNull: false
    },
    tax: {
        type: DataTypes.DECIMAL(12, 2),
        defaultValue: 0
    },
    status: {
        type: DataTypes.ENUM('draft', 'sent', 'paid', 'overdue', 'cancelled'),
        defaultValue: 'draft'
    },
    dueDate: {
        type: DataTypes.DATEONLY,
        allowNull: false
    },
    paidDate: {
        type: DataTypes.DATEONLY,
        allowNull: true
    }
});

module.exports = Invoice;