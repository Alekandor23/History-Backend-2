import { PrismaClient } from "@prisma/client"

const prisma = new PrismaClient();


export const getResenias = async (req, res) => {
  const { id_libro } = req.params;

  const resenias = await prisma.resenia.findMany({
    where: {
      libroId: parseInt(id_libro, 10)
    },
    select: {
      descripcion: true,
      calificacion: true,
      usuario: {
        select: {
          nombreUsuario: true
        }
      }
    }
  });

  if (resenias.length === 0){
    return res.status(404).json({message: "Resenias no encontradas" });
  };

  res.json(resenias);
};

export const getReseniaTuUsuario = async (req, res) => {
  const { id_libro, id_usuario } = req.params;

  const resenias = await prisma.resenia.findFirst({
    where: {
      libroId: parseInt(id_libro, 10),
      usuarioId: parseInt(id_usuario, 10)
    },
    select: {
      descripcion: true,
      calificacion: true,
      usuario: {
        select: {
          nombreUsuario: true
        }
      }
    }
  });

  if (resenias.length === 0){
    return res.status(404).json({message: "Resenia no encontrada" });
  };

  res.json(resenias);
};

export const createResenia = async (req, res) => {
  const { id_libro, id_usuario } = req.params;
  const { descripcionI, calificacionI } = req.body;

  try{
    const reseniaExistente = await prisma.resenia.findFirst({
      where: {
          libroId: parseInt(id_libro, 10),
          usuarioId: parseInt(id_usuario, 10)
      },
      include:{
        usuario: true,
        libro:true 
      }
    });

    if (reseniaExistente) {
      return res.status(400).json({ 
        message: `El usuario ${reseniaExistente.usuario.nombreUsuario} ya tiene una resenia para ${reseniaExistente.libro.titulo}` 
      });
    }

    const nuevaResenia = await prisma.resenia.create({
      data: {
        descripcion: descripcionI,
        calificacion: calificacionI, 
        usuarioId: parseInt(id_usuario, 10),
        libroId: parseInt(id_libro, 10)
      }
    });

  res.status(201).json({ message: "Resenia creada exitosamente", resenia: nuevaResenia });
  }catch(error){
    res.status(500).json({ message: "Error al crear resenia", error: error.message });
  }
};

export const deleteResenia = async (req, res) => {
  const { id_libro, id_usuario } = req.params;

  try{
    const reseniaAEliminar = await prisma.resenia.findFirst({
      where: {
          libroId: parseInt(id_libro, 10),
          usuarioId: parseInt(id_usuario, 10)
      }
    });

    if(!reseniaAEliminar){
      return res.status(404).json({ message: "Resenia no encontrada"});
    }

    const reseniaEliminada = await prisma.resenia.delete({
      where:{
        id: reseniaAEliminar.id
      }
    })

    res.status(200).json({message: "Resenia eliminada con exito", resenia: reseniaEliminada});

  }catch(error){
    if(error.code === "P2025"){
      return res.status(404).json({ message: "Resenia no encontrada"});
    }
    res.status(500).json({ message: "Error al eliminar la resenia", error: error.message });
  }
};



