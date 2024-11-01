/*
  Warnings:

  - Added the required column `paisId` to the `Libro` table without a default value. This is not possible if the table is not empty.
  - Added the required column `resumen` to the `Libro` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "Libro" ADD COLUMN     "paisId" INTEGER NOT NULL,
ADD COLUMN     "resumen" TEXT NOT NULL;

-- CreateTable
CREATE TABLE "Categoria" (
    "id" SERIAL NOT NULL,
    "nombre" TEXT NOT NULL,

    CONSTRAINT "Categoria_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Pais" (
    "id" SERIAL NOT NULL,
    "nombre" TEXT NOT NULL,

    CONSTRAINT "Pais_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "_CategoriaToLibro" (
    "A" INTEGER NOT NULL,
    "B" INTEGER NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "_CategoriaToLibro_AB_unique" ON "_CategoriaToLibro"("A", "B");

-- CreateIndex
CREATE INDEX "_CategoriaToLibro_B_index" ON "_CategoriaToLibro"("B");

-- AddForeignKey
ALTER TABLE "Libro" ADD CONSTRAINT "Libro_paisId_fkey" FOREIGN KEY ("paisId") REFERENCES "Pais"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_CategoriaToLibro" ADD CONSTRAINT "_CategoriaToLibro_A_fkey" FOREIGN KEY ("A") REFERENCES "Categoria"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_CategoriaToLibro" ADD CONSTRAINT "_CategoriaToLibro_B_fkey" FOREIGN KEY ("B") REFERENCES "Libro"("id") ON DELETE CASCADE ON UPDATE CASCADE;
