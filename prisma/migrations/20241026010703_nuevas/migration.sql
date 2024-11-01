-- CreateTable
CREATE TABLE "Usuario" (
    "id" SERIAL NOT NULL,
    "nombre" TEXT NOT NULL,
    "apellido" TEXT NOT NULL,
    "nombreUsuario" TEXT NOT NULL,
    "correo" TEXT NOT NULL,
    "contrasenia" TEXT NOT NULL,

    CONSTRAINT "Usuario_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Resenia" (
    "id" SERIAL NOT NULL,
    "descripcion" TEXT NOT NULL,
    "calificacion" INTEGER NOT NULL,
    "usuarioID" INTEGER NOT NULL,

    CONSTRAINT "Resenia_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Usuario_correo_key" ON "Usuario"("correo");

-- AddForeignKey
ALTER TABLE "Resenia" ADD CONSTRAINT "Resenia_usuarioID_fkey" FOREIGN KEY ("usuarioID") REFERENCES "Usuario"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
