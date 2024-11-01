/*
  Warnings:

  - Added the required column `autorId` to the `Libro` table without a default value. This is not possible if the table is not empty.
  - Added the required column `editorialId` to the `Libro` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "Libro" ADD COLUMN     "autorId" INTEGER NOT NULL,
ADD COLUMN     "editorialId" INTEGER NOT NULL;

-- CreateTable
CREATE TABLE "Editorial" (
    "id" SERIAL NOT NULL,
    "nombre" TEXT NOT NULL,

    CONSTRAINT "Editorial_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "Libro" ADD CONSTRAINT "Libro_autorId_fkey" FOREIGN KEY ("autorId") REFERENCES "Autor"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Libro" ADD CONSTRAINT "Libro_editorialId_fkey" FOREIGN KEY ("editorialId") REFERENCES "Editorial"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
