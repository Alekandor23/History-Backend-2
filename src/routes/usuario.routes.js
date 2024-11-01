import { Router } from "express";
import { createUsuario, logIn } from '../controllers/usuario.controllers.js';

const router = Router();

// Ruta para crear usuario
router.post('/registrar/usuario', createUsuario);

// Ruta para iniciar sesion

router.post('/iniciarSesion', logIn);

export default router;
