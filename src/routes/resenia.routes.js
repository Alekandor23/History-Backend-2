import { Router } from "express";
import { createResenia, deleteResenia, getResenias, getReseniaTuUsuario } from "../controllers/resenia.controllers.js";

const router = Router();

// Ruta para obtener las resenias
router.get('/libros/:id_libro/resenias', getResenias);

// Ruta para obtener las resenia de un libro de tu usuario
router.get('/libros/:id_libro/resenias/:id_usuario', getReseniaTuUsuario);

// Ruta para que un usuario escriba la resenia de un libro en especifico
router.post('/libros/:id_libro/resenias/:id_usuario', createResenia);

// Ruta para que un usuario elimine la resenia de un libro en especifico
router.delete('/libros/:id_libro/resenias/:id_usuario', deleteResenia);
export default router;