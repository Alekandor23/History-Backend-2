import { Router } from "express";
import { getCategorias, getPaises, getLibrosPorPais, getLibrosPorCategoria } from "../controllers/filtro.controller.js";

const router = Router();

//Ruta para obtener todas las categorias disponibles
router.get('/libros/categorias', getCategorias);

//Ruta para obtener todos los paises disponibles 
router.get('/libros/paises', getPaises);

//Ruta para obtener todos los libros asociados a una categoria
router.get('/libros/paises/:id_pais', getLibrosPorPais);

//Ruta para obtener todos los libros asociados a un pais
router.get('/libros/categorias/:id_categoria', getLibrosPorCategoria);

export default router; 