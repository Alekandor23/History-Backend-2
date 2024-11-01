import { PrismaClient } from "@prisma/client"

const prisma = new PrismaClient();

export const getCategorias = async (req, res) => {
    const categorias = await prisma.categoria.findMany({
        select:{
            nombre: true,
            id: true
        }
    });

    res.status(200).json(categorias);
};

export const getPaises = async (req, res) => {
    const categorias = await prisma.pais.findMany({
        select:{
            nombre: true,
            id: true
        }
    });

    res.status(200).json(categorias);
};

export const getLibrosPorPais = async (req, res) => {
    const { id_pais } = req.params;

    const libros = await prisma.libro.findMany({
        where: {
            paisId: parseInt(id_pais, 10)
          },
          select: {
            titulo: true,
            portada: true,
            id: true
          },
    });
    
    res.json(libros);
};

export const getLibrosPorCategoria = async (req, res) => {
    try {
        const { id_categoria } = req.params;

        if (!id_categoria) {
            return res.status(400).json({ error: "id_categoria es requerido" });
        }

        const categoria = await prisma.categoria.findMany({
            where: {
                id: parseInt(id_categoria, 10)
              },
              select: {
                libros: {
                  select: {
                    nombre: true,
                  },
                },
                nombre: true
              },
        });

        if (!categoria) {
            return res.status(404).json({ error: "Categoría no encontrada" });
        }

        res.json(categoria);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error al obtener la categoría" });
    }
};
