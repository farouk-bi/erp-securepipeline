const express = require('express');
const router = express.Router();
const Invoice = require('../models/invoice.model');
const { authMiddleware, requireRole } = require('../middlewares/auth.middleware');
const { Op } = require('sequelize');

router.use(authMiddleware);

// GET /api/finance/invoices
router.get('/invoices', async (req, res) => {
    try {
        const { status, from, to } = req.query;
        const where = {};
        if (status) where.status = status;
        if (from || to) {
            where.dueDate = {};
            if (from) where.dueDate[Op.gte] = from;
            if (to) where.dueDate[Op.lte] = to;
        }

        const invoices = await Invoice.findAll({ where, order: [['createdAt', 'DESC']] });
        const totalAmount = invoices.reduce((sum, inv) => sum + parseFloat(inv.amount), 0);

        res.json({ data: invoices, total: invoices.length, totalAmount });
    } catch (error) {
        res.status(500).json({ error: { message: error.message } });
    }
});

// POST /api/finance/invoices
router.post('/invoices', requireRole('admin', 'manager'), async (req, res) => {
    try {
        // Générer le numéro de facture automatiquement
        const count = await Invoice.count();
        const invoiceNumber = `INV-${new Date().getFullYear()}-${String(count + 1).padStart(5, '0')}`;

        const invoice = await Invoice.create({ ...req.body, invoiceNumber });
        res.status(201).json({ message: 'Invoice created', data: invoice });
    } catch (error) {
        res.status(400).json({ error: { message: error.message } });
    }
});

// PATCH /api/finance/invoices/:id/status
router.patch('/invoices/:id/status', requireRole('admin', 'manager'), async (req, res) => {
    try {
        const invoice = await Invoice.findByPk(req.params.id);
        if (!invoice) {
            return res.status(404).json({ error: { message: 'Invoice not found' } });
        }

        const { status } = req.body;
        const updateData = { status };
        if (status === 'paid') updateData.paidDate = new Date();

        await invoice.update(updateData);
        res.json({ message: 'Invoice status updated', data: invoice });
    } catch (error) {
        res.status(400).json({ error: { message: error.message } });
    }
});

module.exports = router;