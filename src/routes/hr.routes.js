const express = require('express');
const router = express.Router();
const Employee = require('../models/employee.model');
const { authMiddleware, requireRole } = require('../middlewares/auth.middleware');

// Toutes les routes HR nécessitent une authentification
router.use(authMiddleware);

// GET /api/hr/employees
router.get('/employees', async (req, res) => {
    try {
        const employees = await Employee.findAll({
            where: { isActive: true },
            attributes: { exclude: ['salary'] } // Masquer le salaire par défaut
        });
        res.json({ data: employees, total: employees.length });
    } catch (error) {
        res.status(500).json({ error: { message: error.message } });
    }
});

// GET /api/hr/employees/:id
router.get('/employees/:id', async (req, res) => {
    try {
        const employee = await Employee.findByPk(req.params.id);
        if (!employee) {
            return res.status(404).json({ error: { message: 'Employee not found' } });
        }
        res.json({ data: employee });
    } catch (error) {
        res.status(500).json({ error: { message: error.message } });
    }
});

// POST /api/hr/employees (admin/manager uniquement)
router.post('/employees', requireRole('admin', 'manager'), async (req, res) => {
    try {
        const employee = await Employee.create(req.body);
        res.status(201).json({ message: 'Employee created', data: employee });
    } catch (error) {
        res.status(400).json({ error: { message: error.message } });
    }
});

// PUT /api/hr/employees/:id (admin/manager uniquement)
router.put('/employees/:id', requireRole('admin', 'manager'), async (req, res) => {
    try {
        const employee = await Employee.findByPk(req.params.id);
        if (!employee) {
            return res.status(404).json({ error: { message: 'Employee not found' } });
        }
        await employee.update(req.body);
        res.json({ message: 'Employee updated', data: employee });
    } catch (error) {
        res.status(400).json({ error: { message: error.message } });
    }
});

// DELETE /api/hr/employees/:id (admin uniquement — soft delete)
router.delete('/employees/:id', requireRole('admin'), async (req, res) => {
    try {
        const employee = await Employee.findByPk(req.params.id);
        if (!employee) {
            return res.status(404).json({ error: { message: 'Employee not found' } });
        }
        await employee.update({ isActive: false });
        res.json({ message: 'Employee deactivated' });
    } catch (error) {
        res.status(500).json({ error: { message: error.message } });
    }
});

module.exports = router;