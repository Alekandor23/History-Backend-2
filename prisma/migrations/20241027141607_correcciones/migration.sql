/*
  Warnings:

  - You are about to drop the column `usuarioID` on the `Resenia` table. All the data in the column will be lost.
  - Added the required column `libroId` to the `Resenia` table without a default value. This is not possible if the table is not empty.
  - Added the required column `usuarioId` to the `Resenia` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE "Resenia" DROP CONSTRAINT "Resenia_usuarioID_fkey";

-- AlterTable
ALTER TABLE "Resenia" DROP COLUMN "usuarioID",
ADD COLUMN     "libroId" INTEGER NOT NULL,
ADD COLUMN     "usuarioId" INTEGER NOT NULL;

-- AddForeignKey
ALTER TABLE "Resenia" ADD CONSTRAINT "Resenia_usuarioId_fkey" FOREIGN KEY ("usuarioId") REFERENCES "Usuario"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Resenia" ADD CONSTRAINT "Resenia_libroId_fkey" FOREIGN KEY ("libroId") REFERENCES "Libro"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
