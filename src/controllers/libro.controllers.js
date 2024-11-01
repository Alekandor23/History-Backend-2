
import { PrismaClient } from "@prisma/client"

const prisma = new PrismaClient();

export const getLibros = async (req, res) => {
    const libros = await prisma.libro.findMany({
        select:{
            titulo: true,
            portada: true,
            id: true
        }
    });
    res.json(libros);
};

export const getDescripcion = async (req, res) => {
    const { id_libro } = req.params;

    const libros = await prisma.libro.findUnique({
        select:{
            sinopsis: true,
            objetivos: true
        },

        where:{
            id: parseInt(id_libro, 10)
        }
    });

    if (libros.length === 0){
        return res.status(404).json({message: "Libro no encontrado" });
    }

    res.json(libros);
};

export const getDetalles = async (req, res) => {
    const { id_libro } = req.params;

    const libro = await prisma.libro.findUnique({
        where: {
            id: parseInt(id_libro, 10)
          },
          select: {
            autor: {
              select: {
                nombre: true,
              },
            },
            editorial: {
              select: {
                nombre: true,
              },
            },
            numero_paginas: true,
            fecha_publicacion: true
          },
    });

    if (libro.length === 0){
        return res.status(404).json({message: "Libro no encontrado" });
    }

    res.json(libro);
};

export const getTitulo = async (req, res) => {
    const { id_libro } = req.params;

    const libro = await prisma.libro.findUnique({
        where: {
            id: parseInt(id_libro, 10)
          },
          select: {
            titulo: true,
            portada: true
          },
    });

    if (libro.length === 0){
        return res.status(404).json({message: "Libro no encontrado" });
    }

    res.json(libro);
};

export const getCategorias = async (req, res) => {
    const { id_libro } = req.params;

    const libroConCategorias = await prisma.libro.findUnique({
        where:{
            id: parseInt(id_libro, 10)
        },

        include:{
            categorias:{
                select:{
                    nombre: true
                }
            }
        }
    });

    const categorias = libroConCategorias.categorias.map(categoria => categoria.nombre);


    if (categorias.length === 0){
        return res.status(404).json({message: "Categorias no encontradas" });
    }
    
    res.json(categorias);
};

export const getResumen = async (req, res) => {
    const { id_libro } = req.params;

    const libro = await prisma.libro.findUnique({
        where: {
            id: parseInt(id_libro, 10)
          },
          select: {
            resumen: true
          },
    });

    if (libro.length === 0){
        return res.status(404).json({message: "Libro no encontrado" });
    }

    res.json(libro);
};

export const getBusquedaTitulo = async (req, res) => {
    const query = req.query.query;

    try {
        const results = await prisma.libro.findMany({
            where:{
                titulo:{
                    contains: query, 
                    mode: 'insensitive',
                },
            },

            select:{
                titulo: true,
                portada: true, 
                id: true
            }
        });
        res.json(results);
    } catch (error) {
        console.error('Error en la búsqueda:', error);
        res.status(500).json({ error: 'Error en la búsqueda' });    
    }
}