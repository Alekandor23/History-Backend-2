/*
  Warnings:

  - Added the required column `portada` to the `Libro` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "Libro" ADD COLUMN     "portada" TEXT NOT NULL;
