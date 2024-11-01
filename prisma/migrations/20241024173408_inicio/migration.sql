-- CreateTable
CREATE TABLE "Libro" (
    "id" SERIAL NOT NULL,
    "titulo" TEXT NOT NULL,
    "decripcion" TEXT NOT NULL,
    "fecha_publicacion" TIMESTAMP(3) NOT NULL,
    "numero_paginas" INTEGER NOT NULL,
    "sinopsis" TEXT NOT NULL,
    "objetivos" TEXT NOT NULL,

    CONSTRAINT "Libro_pkey" PRIMARY KEY ("id")
);
