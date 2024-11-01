import express from "express";

import libroRoutes from '../routes/libro.routes.js';
import reseniaRoutes from '../routes/resenia.routes.js';
import usuarioRoutes from '../routes/usuario.routes.js';
import filtroRoutes from '../routes/filtro.routes.js';

const router = express.Router();


router.use('/', libroRoutes);
router.use('/', reseniaRoutes);
router.use('/', usuarioRoutes);
router.use('/', filtroRoutes);

export default router;
