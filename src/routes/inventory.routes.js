const express = require('express');
const router = express.Router();
const Product = require('../models/product.model');
const { authMiddleware, requireRole } = require('../middlewares/auth.middleware');
const { Op } = require('sequelize');
const { sequelize } = require('../config/database');

router.use(authMiddleware);

// GET /api/inventory/products
router.get('/products', async (req, res) => {
    try {
        const { category, search } = req.query;
        const where = {};
        if (category) where.category = category;
        if (search) where.name = { [Op.iLike]: `%${search}%` };

        const products = await Product.findAll({ where, order: [['name', 'ASC']] });
        res.json({ data: products, total: products.length });
    } catch (error) {
        res.status(500).json({ error: { message: error.message } });
    }
});

// GET /api/inventory/alerts — Produits en sous-stock
router.get('/alerts', async (req, res) => {
    try {
        const products = await Product.findAll({
            where: { quantity: { [Op.lte]: sequelize.col('minStock') } },
            order: [['quantity', 'ASC']]
        });
        res.json({ data: products, alertCount: products.length });
    } catch (error) {
        res.status(500).json({ error: { message: error.message } });
    }
});

// POST /api/inventory/products
router.post('/products', requireRole('admin', 'manager'), async (req, res) => {
    try {
        const product = await Product.create(req.body);
        res.status(201).json({ message: 'Product created', data: product });
    } catch (error) {
        res.status(400).json({ error: { message: error.message } });
    }
});

// PATCH /api/inventory/products/:id/stock
router.patch('/products/:id/stock', requireRole('admin', 'manager'), async (req, res) => {
    try {
        const product = await Product.findByPk(req.params.id);
        if (!product) {
            return res.status(404).json({ error: { message: 'Product not found' } });
        }

        const { adjustment } = req.body; // +10 ou -5
        const newQuantity = product.quantity + adjustment;

        if (newQuantity < 0) {
            return res.status(400).json({ error: { message: 'Insufficient stock' } });
        }

        await product.update({ quantity: newQuantity });
        res.json({ message: 'Stock updated', data: product });
    } catch (error) {
        res.status(400).json({ error: { message: error.message } });
    }
});

module.exports = router;