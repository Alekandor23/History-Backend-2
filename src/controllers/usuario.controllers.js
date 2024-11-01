import { PrismaClient } from "@prisma/client"
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const prisma = new PrismaClient();

export const createUsuario = async (req, res) => {
    const { nombreUsuarioI, nombreI, apellidoI, correoI, contraseniaI } = req.body;

    if(!nombreUsuarioI, !nombreI, !apellidoI, !correoI, !contraseniaI){
        return res.send({message: 'Datos Incompletos'});
    }

    try {
        const usuarioExistente = await prisma.usuario.findFirst({
            where: {
                OR: [
                    { nombreUsuario: nombreUsuarioI },
                    { correo: correoI }
                ]
            }
        });

        if (usuarioExistente) {
            const conflictField = usuarioExistente.nombreUsuario === nombreUsuarioI ? 'nombre de usuario' : 'correo';
            return res.status(400).json({ message: `El usuario ya existe con este ${conflictField}` });
        }

        const saltRounds = 8;
        const hashedPassword = await bcrypt.hash(contraseniaI, saltRounds);

        const nuevoUsuario = await prisma.usuario.create({
            data: {
                nombreUsuario: nombreUsuarioI,
                nombre: nombreI,
                apellido: apellidoI,
                correo: correoI,
                contrasenia: hashedPassword
            }
        });

        res.status(201).json({ message: "Usuario creado exitosamente", usuario: nuevoUsuario });
    } catch (error) {
        res.status(500).json({ message: "Error al crear usuario", error: error.message });
    }
};

export const logIn = async (req, res) => {
    const { nombreUsuarioI, contraseniaI } = req.body;

    try {
        // Verificar si existe el usuario
        const usuario = await prisma.usuario.findFirst({
            where: {
                nombreUsuario: nombreUsuarioI
            }
        });

        if (!usuario) {
            return res.status(404).json({ message: "Usuario no encontrado" });
        }

        // Comparar la contraseña ingresada con el hash almacenado
        const esContraseniaCorrecta = await bcrypt.compare(contraseniaI, usuario.contrasenia);

        if (!esContraseniaCorrecta) {
            return res.status(401).json({ message: "Contraseña incorrecta" });
        }

        // Respuesta exitosa con los datos del usuario (sin contraseña)
        res.status(200).json({
            message: "Sesión iniciada",
            usuario: {
                id: usuario.id,
                nombreUsuario: usuario.nombreUsuario,
                correo: usuario.correo
            }
        });
        
        // Si quieres usar JSON Web Token (JWT) para la autenticación, agrega lo siguiente
        // const token = jwt.sign({ userId: usuario.id }, 'tu_secreto', { expiresIn: '1h' });
        // res.json({ usuario, token });
    } catch (error) {
        console.error('Error al iniciar sesión:', error);  // Agregar un console.error para ver detalles en la consola
        res.status(500).json({ message: 'Error al iniciar sesión', error: error.message });
    }
};