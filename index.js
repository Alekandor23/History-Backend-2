import express from 'express'
//import libroRoutes from "./routes/libro.routes.js"
import cors from 'cors';
import route from './src/api/endPoints.js'


const PORT = 3000;
const app = express()

app.use(express.json())
//app.use(libroRoutes);

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('No permitido por CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE']
}));


app.use('/', route);

app.listen(PORT);
console.log("Server on port", PORT);
