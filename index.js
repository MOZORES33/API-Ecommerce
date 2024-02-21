// Importa el módulo 'express' para facilitar la creación de un servidor web.
const express = require("express");
// Importa el módulo 'body-parser' para analizar el cuerpo de las solicitudes HTTP.
const bodyParse = require("body-parser");

// Importa el módulo 'jsonwebtoken' para gestionar la creación y verificación de tokens JWT.
const jwt = require('jsonwebtoken');
// Importa el módulo 'cors' para permitir solicitudes entre dominios diferentes (CORS).
const cors = require('cors');
// Importa el módulo 'mysql' para interactuar con una base de datos MySQL.
const mysql = require('mysql2');

const multer = require('multer');
const path = require('path');
const fs = require('fs');
// Crea una instancia de la aplicación Express.
const app = express();
// Habilita el middleware 'cors' para permitir solicitudes desde cualquier origen.
app.use(cors());
// Habilita el middleware 'body-parser' para analizar el cuerpo de las solicitudes en formato JSON con un límite de 10 MB.
app.use(bodyParse.json({ limit: '10mb' }));
app.use(bodyParse.urlencoded({ extended: true }));
// Importa el módulo 'moment' para trabajar con fechas y horas de manera sencilla.
const moment = require('moment');
// Importa el módulo 'dotenv' para cargar variables de entorno desde un archivo '.env'.
require('dotenv').config();
// Obtiene el valor de la variable de entorno 'SECRET' desde el archivo '.env'.
const PORT = process.env.PORT || 3977;
const secret = process.env.SECRET;


// Configuración de multer para la carga de archivos
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'imagenes/'); // Carpeta donde se guardarán las imágenes
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, file.fieldname + '-' + uniqueSuffix + ext);
    },
});

function eliminarImagen(rutaDeLaImagen) {
    // Verifica si el archivo existe
    if (fs.existsSync(rutaDeLaImagen)) {
      // Elimina el archivo
      fs.unlinkSync(rutaDeLaImagen);
      return "imagen_eliminada"
    } else {
      return "inexistente"
    }
  }

const upload = multer({ storage: storage });

// Define una ruta GET en la raíz ("/") de la aplicación Express.
app.get('/', function(req, res){
    // Envía la respuesta "Primera ruta de la Api" al cliente que realiza la solicitud.
    res.send('Primera ruta de la Api')
})

// Define un objeto 'credentials' que contiene la información de conexión a la base de datos MySQL.
const credentials = {
    host: 'localhost',      // Dirección del servidor de la base de datos.
    user: 'root2',           // Nombre de usuario de la base de datos.
    password: '',           // Contraseña de la base de datos (en este caso, está vacía).
    database: 'tienda_web'  // Nombre de la base de datos que se va a utilizar.
}

// Define una ruta GET para la ruta '/token'. Esta servirá para verificar la validez de un token.
app.get('/token', (req, res) => {
    try{
        // Almacena el token enviado por el usuario en la constante token
        const token = req.headers.authorization.split(' ')[1]
        // Verifica si la constante token esta vacia.
        if (token === undefined)
            // Envia un mensaje de error
            return res.send('error');
        // Verifica que la firma del token sea correcta
        const payload = jwt.verify(token, secret)
        // Verifica la fecha de expiración del token
        if(Date.now() > payload.exp){
            // Envia un mensaje de error
            return res.send("error")
        }
        // Envia un mensaje indicando que el token es valido
        res.send('existe')
    } catch (error) {
        // Envia un mensaje de error
        res.send("error")
    }
})

// Define una ruta GET para la ruta '/token'. Esta servirá para verificar la validez de un token.
app.get('/token_administrador', (req, res) => {
    try{
        // Almacena el token enviado por el usuario en la constante token
        const token = req.headers.authorization.split(' ')[1]
        // Verifica si la constante token esta vacia.
        if (token === undefined)
            // Envia un mensaje de error
            return res.send('error');
        // Verifica que la firma del token sea correcta
        const payload = jwt.verify(token, secret)
        // Verifica la fecha de expiración del token
        if(Date.now() > payload.exp){
            // Envia un mensaje de error
            return res.send("error")
        }
        if (payload.username === 'admin')
            // Envia un mensaje indicando que el token es valido
            res.send('existe')
        else
            res.send('error')
    } catch (error) {
        // Envia un mensaje de error
        res.send("error")
    }
})

// Define una ruta POST para la ruta '/login'. Esta servirá para iniciar sesión.
app.post('/login', (req, res) => {
    try{
        // Obtiene el username y el password que envió el usuario
        const {username, password} = req.body
        if(!username || !password)
            return res.send('error');
        // Almacena los datos obtenidos en la constante values
        const values = [username, password]
        // Crea una conexión a la base de datos MySQL utilizando las credenciales definidas anteriormente.
        let connection = mysql.createConnection(credentials)
        try{
            // Realiza una consulta MySql para verificar si el usuario y la contraseña almacenados en la constante values son validos
            connection.query("call login_client(?,?)", values, (err, result) => {
                // Cerramos la conexión
                connection.end()
                // Verifica si ocurrió un error al realizar la consulta
                if(err){
                    // Envia un mensaje de error
                    res.send('error')
                }
                else if (result[0][0].mensaje === 'error')
                    res.send('error')
                else if (result[0][0].mensaje === 'false')
                    res.send('false')
                else if (result[0][0].mensaje === 'existe'){
                        // Crea un token para enviar al usuario
                        const token = jwt.sign({
                            // Almacenamos en el token el nombre de usuario
                            username,
                            // Añadimos una fecha de expiración
                            exp: Date.now() + 86400 * 1000
                            // Utilizamos la clave secreta para firmar el token
                        }, secret)
                        // Enviamos un token al usuario
                        res.send({token})
                }
            })
        }
        catch{
            res.send('error');
        }
    }
    catch{
        res.send('error');
    }
})

// Define una ruta POST para la ruta '/updateUser'. Esta servirá para Actualizar la contraseña de un usuario.
app.post('/updateUser', (req, res) => {
    // Utilizamos try and catch para manejar los errores
    try{
        try{
            // Almacena el token enviado por el usuario en la constante token
            const token = req.headers.authorization.split(' ')[1]
            // Verifica si la constante token esta vacia.
            if (token === undefined)
                // Envia un mensaje de error
                return res.send('error1');
            // Verifica que la firma del token sea correcta
            const payload = jwt.verify(token, secret)
            // Verifica la fecha de expiración del token
            if(Date.now() > payload.exp)
                // Envia un mensaje de error
                return res.send("error1");
        }
        catch{
            return res.send('error1');
        }
        // Obtiene los datos que envió el usuario
        const { newPassword, passwordActual } = req.body;

        if(!newPassword || !passwordActual)
            return res.send('error2');

        // Almacena los datos obtenidos y el username almacenado en el token en la constante values
        const values = [newPassword, payload.username, passwordActual];
        // Crea una conexión a la base de datos MySQL utilizando las credenciales definidas anteriormente.
        let connection = mysql.createConnection(credentials);
        // Utilizamos try and catch para manejar los errores
        try{
            // Realizamos una consulta a la base de datos para actualizar la contraseña del usuario
            connection.query('call update_client(?,?,?)', values, (err, result) => {
                // Cerramos la conexión
                connection.end();
                // Verificamos si ocurrieron errores al realizar la consulta
                if (err)
                    // Enviamos un mensaje de error al usuario
                    res.send('error2');
                else if (result[0][0].mensaje === 'error')
                    res.send('error2')
                else if (result[0][0].mensaje === 'exito')
                    res.send('exito');
            })
        }
        catch{
            // En caso de error envia un mensaje de error
            res.send('error2');
        }
    } catch{
        // En caso de error envia un mensaje de error
        res.send('error2');
    }
});

// Define una ruta POST para la ruta '/register'. Esta servirá para registrar un nuevo usuario
app.post('/register', (req, res) => {
    try{
        // Obtenemos los datos que envió el usuario
        const { username, password } = req.body;
        if(!username || !password)
            return res.send('error');
        // Almacenamos los datos obtenidos en la constante values
        const values = [username, password];
        // Creamos una conexión a la base de datos MySQL utilizando las credenciales definidas anteriormente.
        let connection = mysql.createConnection(credentials);
        // Realizamos una consulta para registrar un nuevo usuario utilizando el procedimiento almacenado new_client, enviando como parametro los datos almacenados en la constante values
        connection.query('call new_client(?,?);', values, (err, result) => {
            // Cerramos la conexión
            connection.end();
            // Verificamos si ocurrió un error
            if (err)
                // Enviamos un mensaje de error
                res.send('error');
            // Verificamos si el nombre de usuario que intentamos registrar ya existe
            else if (result[0][0].mensaje === 'existe')
                // Enviamos un mensaje indicando que el nombre de usuario no está disponible
                res.send('existe');
            else if (result[0][0].mensaje === 'error')
                // Enviamos un mensaje indicando que el nombre de usuario no está disponible
                res.send('error');
            else{
                // Si el nuevo usuario fue añadido correctamente, creamos un token para enviarlo al usuario
                const token = jwt.sign({
                    // Almacenamos en el token el nombre de usuario
                    username,
                    // Añadimos una fecha de expiración
                    exp: Date.now() + 86400 * 1000
                    // Utilizamos la clave secreta para firmar el token
                }, secret);
                // Enviamos un token al usuario
                res.send({ token });
            }
        });
    }
    catch{
        res.send('error');
    }
});

// Define una ruta POST para la ruta '/deleteUser'. Esta servirá para eliminar un usuario.
app.post('/deleteUser', (req, res) => {
    // Utilizamos try and catch para manejar los errores
    try{
        try{
            // Almacena el token enviado por el usuario en la constante token
            const token = req.headers.authorization.split(' ')[1]
            // Verifica si la constante token esta vacia.
            if (token === undefined)
                // Envia un mensaje de error
                return res.send('error1');
            // Verifica que la firma del token sea correcta
            const payload = jwt.verify(token, secret)
            // Verifica la fecha de expiración del token
            if(Date.now() > payload.exp)
                // Envia un mensaje de error
                return res.send("error1");
            if (payload.username === 'admin')
                // Envia un mensaje indicando que el token es valido
                return res.send('error2');
        }
        catch{
            return res.send('error1');
        }
        // Obtenemos los datos que envió el usuario
        const { password } = req.body;
        if(!password)
            return res.send('error2')
        // Almacena los datos obtenidos y el username almacenado en el token en la constante values
        const values = [payload.username, password];
        // Crea una conexión a la base de datos MySQL utilizando las credenciales definidas anteriormente.
        let connection = mysql.createConnection(credentials);
        // Utilizamos try and catch para manejar los errores
        try{
            // Realizamos una consulta para actualizar la contraseña del usuario utilizando el procedimiento almacenado delete_client, enviando como parametro los datos almacenados en la constante values
            connection.query('call delete_client(?,?);', values, (err, result) => {
                // Cerramos la conexión
                connection.end();
                // Verificamos si ocurrió un error
                if (err)
                    // Enviamos un mensaje de error
                    res.send('error2');
                // Verificamos si el usuario existe en la base de datos
                else if (result[0][0].mensaje === 'inexistente')
                    // Enviamos un mensaje indicando que el usuario no existe en la base de datos
                    res.send('inexistente');
                else if (result[0][0].mensaje === 'error')
                    // Enviamos un mensaje indicando que el nombre de usuario no está disponible
                    res.send('error2');
                // Verificamos si la contraseña del usuario fue actualizada correctamente
                else if (result[0][0].mensaje === 'correcto')
                    // Enviamos un mensaje indicando que la contraseña fue modificada correctamente
                    res.send('correcto');
            })
        }
        catch{
            // Enviamos un mensaje de error
            res.send('error2');
        }

    } catch{
        // Enviamos un mensaje de error
        res.send('error2');
    }
});

// Define una ruta GET para la ruta '/get_purchases'. Esta servirá para obtener el historial de compras realizadas por el usuario sin detalles de productos
app.get('/get_purchases', (req, res) => {
    try{
        try{
            // Almacena el token enviado por el usuario en la constante token
            const token = req.headers.authorization.split(' ')[1]
            // Verifica si la constante token esta vacia.
            if (token === undefined)
                // Envia un mensaje de error
                return res.send('inexistente');
            // Verifica que la firma del token sea correcta
            const payload = jwt.verify(token, secret)
            // Verifica la fecha de expiración del token
            if(Date.now() > payload.exp)
                // Envia un mensaje de error
                return res.send("inexistente");
        }
        catch{
            return res.send('inexistente')
        }
        // Crea una conexión a la base de datos MySQL utilizando las credenciales definidas anteriormente.
        let connection = mysql.createConnection(credentials)
        try{
            // Realizamos una consulta para obtener todas las compras del usuario utilizando el procedimiento almacenado get_purchases, enviando como parametro username almacenado en el token
            connection.query('call get_purchases(?)', payload.username,(err, result) => {
                // Cerramos la conexión
                connection.end()
                // Verificamos si ocurrió un error
                if (err)
                    // Enviamos un mensaje de error
                    res.send('error')
                // Verificamos si desde el procedimiento almacenado se obtuvo un mensaje de error o los datos de las compras realizadas por el usuario
                else if(result[0][0])
                    // Verificamos si el usuario existe
                    if(result[0][0].mensaje === 'inexistente')
                        // Enviamos un mensaje indicando que el usuario no existe en la base de datos
                        res.send("inexistente")
                    else if (result[0][0].mensaje === 'error')
                        // Enviamos un mensaje indicando que el nombre de usuario no está disponible
                        res.send('error');
                else{
                    // Enviamos los datos de las compras realizadas por el usuario
                    res.send(result)
                }
            })
        }
        catch{
            return res.send('error');
        }
    }
    catch{
        res.send('error');
    }
});

// Define una ruta POST para la ruta '/get_purchasing_details'. Esta servirá para obtener los detalles de una de las compras realizada por el usuario
app.post('/get_purchasing_details', (req, res) => {
    // Utilizamos try and catch para manejar los errores
    try{
        try{

            // Almacena el token enviado por el usuario en la constante token
            const token = req.headers.authorization.split(' ')[1]
            // Verifica si la constante token esta vacia.
            if (token === undefined)
            // Envia un mensaje de error
            return res.send('inexistente');
            // Verifica que la firma del token sea correcta
            const payload = jwt.verify(token, secret)
            // Verifica la fecha de expiración del token
            if(Date.now() > payload.exp)
            // Envia un mensaje de error
            return res.send("inexistente");
        }
        catch{
            return res.send("inexistente");
        }
        // Crea una conexión a la base de datos MySQL utilizando las credenciales definidas anteriormente.
        let connection = mysql.createConnection(credentials)
        try{
            // Realizamos una consulta para obtener los detalles de una de las compras realizadas por el usuario utilizando el procedimiento almacenado get_purchasing_details, enviando como parametro id_venta enviado por el usuario
            connection.query('call get_purchasing_details(?)', req.body.id_venta, (err, result) => {
                // Cerramos la conexión
                connection.end()
                // Verificamos si ocurrió un error
                if (err)
                    // Enviamos un mensaje de error
                    res.send('error')
                // Verificamos si desde el procedimiento almacenado se obtuvo un mensaje de error o los detalles de la compra
                else if(result[0][0])
                    // Verificamos si la compra existe
                    if(result[0][0].mensaje === 'inexistente')
                        // Enviamos un mensaje indicando que la compra no existe en la base de datos
                        res.send("inexistente")
                    if(result[0][0].mensaje === 'error')
                        // Enviamos un mensaje indicando que la compra no existe en la base de datos
                        res.send("error")
                else{
                    // Enviamos los detalles de la compra
                    res.send(result)
                }
            })
        }
        catch{
            res.send('error')
        }
    }
    catch{
        // Enviamos un mensaje de error
        res.send('error')
    }
});

// Define una ruta POST para la ruta '/cargar-venta'. Esta servirá para añadir una nueva compra realizada por el usuario
app.post('/cargar-venta', (req, res) => {
    // Utilizamos try and catch para manejar los errores
    try{
        try{
            // Almacena el token enviado por el usuario en la constante token
            const token = req.headers.authorization.split(' ')[1]
            // Verifica si la constante token esta vacia.
            if (token === undefined)
                // Envia un mensaje de error
                return res.send('error1');
            // Verifica que la firma del token sea correcta
            const payload = jwt.verify(token, secret)
            // Verifica la fecha de expiración del token
            if(Date.now() > payload.exp)
                // Envia un mensaje de error
                return res.send('error1');
        }
        catch{
            return res.send('error1');
        }
        // Obtenemos los datos que envió el usuario
        const { shoppingHistory, total } = req.body;
        // Creamos una conexión a la base de datos MySQL utilizando las credenciales definidas anteriormente.
        let connection1 = mysql.createConnection(credentials);

        // Obtenemos la fecha y hora actual
        const fechaHoraActual = moment().format('YYYY-MM-DD HH:mm:ss');
        // Almacena los datos obtenidos y el username almacenado en el token en la constante values
        const values = [payload.username, fechaHoraActual, total, shoppingHistory];
        try{
            // Realizamos una consulta para cargar la compra realizada por el usuario utilizando el procedimiento almacenado cargar_venta, enviando como parametro los datos almacenados en la constante values
            connection1.query('call cargar_venta(?,?,?,?)', values, (err, result) => {
                // Cerramos la conexión
                connection1.end();
                // Verificamos si ocurrió un error
                if (err)
                    // Enviamos un mensaje de error
                    res.send("error2");
                // Verificamos si ocurrió un error
                else if (result[0][0].mensaje === 'error')
                    // Enviamos un mensaje de error
                    res.send('error2');
                // Verificamos si el usuario existe en la base de datos
                else if (result[0][0].mensaje === 'inexistente')
                    // Enviamos un mensaje indicando que el usuario no existe en la base de datos
                    res.send('inexistente');
                // Verificamos si la compra realizada por el usuario fue añadida correctamente
                else if (result[0][0].mensaje === 'correcto')
                    // Enviamos un mensaje indicando que la compra fue añadida correctamente
                    res.send('correcto');
            });
        }
        catch{
            res.send('error2');
        }
        
    }catch{
        // Enviamos un mensaje de error
        res.send('error2');
    }
});

// Define una ruta GET para la ruta '/productos'. Esta servirá para obtener los datos de todos los productos
app.get('/productos', (req, res) => {
    // Crea una conexión a la base de datos MySQL utilizando las credenciales definidas anteriormente.
    let connection = mysql.createConnection(credentials)

    // Realizamos una consulta para obtener los datos de todos los productos
    connection.query('call get_products()', (err, result) => {
        // Cerramos la conexión
        connection.end()
        // Verificamos si ocurrió un error
        if (err)
            // Enviamos un mensaje de error
            res.send('error')
        else
            // Enviamos los datos de todos los productos
            res.send(result)
    })
})

// Define una ruta GET para la ruta '/productos'. Esta servirá para obtener los datos de todos los productos
app.get('/get_categories', (req, res) => {
    // Crea una conexión a la base de datos MySQL utilizando las credenciales definidas anteriormente.
    let connection = mysql.createConnection(credentials)

    // Realizamos una consulta para obtener los datos de todos los productos
    connection.query('call get_categories()', (err, result) => {
        // Cerramos la conexión
        connection.end()
        // Verificamos si ocurrió un error
        if (err)
            // Enviamos un mensaje de error
            res.send('error')
        else
            // Enviamos los datos de todos los productos
            res.send(result)
    })
})


app.post('/new_category', (req, res) => {
    // Añadir verificacion del token y verificacion del usuario administrador tanto 
    // aqui como en la pagina para agregar el boton en la barra de navegación para 
    // realizar las tareas de administracion
    // Tambien ver la manera de prohibir eliminar el usuario administrador.
    try
    {
        try{
            // Almacena el token enviado por el usuario en la constante token
            const token = req.headers.authorization.split(' ')[1]
            // Verifica si la constante token esta vacia.
            if (token === undefined)
                // Envia un mensaje de error
                return res.send('error1');
            // Verifica que la firma del token sea correcta
            const payload = jwt.verify(token, secret)
            // Verifica la fecha de expiración del token
            if(Date.now() > payload.exp)
                // Envia un mensaje de error
                return res.send('error1');
            else if(payload.username !== 'admin')
                // Envia un mensaje de error
                return res.send('error1');
        }
        catch{
            return res.send('error1');
        }
        
        const {valor} = req.body
        
        if(!valor)
            return res.send('error2');

        // Crea una conexión a la base de datos MySQL utilizando las credenciales definidas anteriormente.
        let connection = mysql.createConnection(credentials)

        // Realizamos una consulta para obtener los datos de todos los productos
        connection.query('call add_category(?)', valor, (err, result) => {
            // Cerramos la conexión
            connection.end()

            // Verificamos si ocurrió un error
            if (err)
            // Enviamos un mensaje de error
                res.send("error2");
            // Verificamos si el usuario existe en la base de datos
            else if (result[0][0].mensaje === 'existe')
                // Enviamos un mensaje indicando que el usuario no existe en la base de datos
                res.send('error3');
            else if (result[0][0].mensaje === 'error')
                // Enviamos un mensaje indicando que el usuario no existe en la base de datos
                res.send('error2');
            // Verificamos si la compra realizada por el usuario fue añadida correctamente
            else if (result[0][0].mensaje === 'correcto')
                // Enviamos un mensaje indicando que la compra fue añadida correctamente
                res.send('correcto');
        })
    }
    catch{
        res.send('error2');
    }    
});

app.post('/upload_product', upload.single('inputFile'), (req, res) => {
    // Añadir verificacion del token y verificacion del usuario administrador tanto 
    // aqui como en la pagina para agregar el boton en la barra de navegación para 
    // realizar las tareas de administracion
    // Tambien ver la manera de prohibir eliminar el usuario administrador.
    try
    {
        try{
            // Almacena el token enviado por el usuario en la constante token
            const token = req.headers.authorization.split(' ')[1]
            // Verifica si la constante token esta vacia.
            if (token === undefined)
                // Envia un mensaje de error
                return res.send('error1');
            // Verifica que la firma del token sea correcta
            const payload = jwt.verify(token, secret)
            // Verifica la fecha de expiración del token
            if(Date.now() > payload.exp)
                // Envia un mensaje de error
                return res.send('error1');
            else if(payload.username !== 'admin')
                // Envia un mensaje de error
                return res.send('error1');
        }
        catch{
            return res.send('error1');
        }

        const { nombre, descripcion, categoria, precio } = req.body;

        if(!nombre || !descripcion || !categoria || !precio)
            return res.send('error')

        const values = [ categoria, nombre, descripcion, precio, req.file.filename ];

        let connection = mysql.createConnection(credentials);
        try{
            // Realizamos una consulta para obtener los detalles de una de las compras realizadas por el usuario utilizando el procedimiento almacenado get_purchasing_details, enviando como parametro id_venta enviado por el usuario
            connection.query('call new_product(?,?,?,?,?)', values, (err, result) => {
                // Cerramos la conexión
                connection.end()
                // Verificamos si ocurrió un error
                if (err)
                    // Enviamos un mensaje de error
                    res.send('error')
                // Verificamos si desde el procedimiento almacenado se obtuvo un mensaje de error o los detalles de la compra
                else if(result[0][0].mensaje === 'correcto')
                    res.send('correcto')
                else if(result[0][0].mensaje === 'error')
                    res.send('error')
            })
        }
        catch{
            res.send('error');
        }
    }
    catch{
        res.send('error');
    }    
});

app.post('/delete_product', (req, res) => {
    try{
        try{
            // Almacena el token enviado por el usuario en la constante token
            const token = req.headers.authorization.split(' ')[1]
            // Verifica si la constante token esta vacia.
            if (token === undefined)
                // Envia un mensaje de error
                return res.send('error1');
            // Verifica que la firma del token sea correcta
            const payload = jwt.verify(token, secret)
            // Verifica la fecha de expiración del token
            if(Date.now() > payload.exp)
                // Envia un mensaje de error
                return res.send('error1');
            else if(payload.username !== 'admin')
                // Envia un mensaje de error
                return res.send('error1');
        }
        catch{
            return res.send('error1')
        }
        
        // Añadir verificacion de token del usuario administrador
        const { id, urlImage } = req.body;
        
        if(!id || !urlImage)
            return res.send('error2');

        let connection = mysql.createConnection(credentials);
        try{
            // Realizamos una consulta para obtener los detalles de una de las compras realizadas por el usuario utilizando el procedimiento almacenado get_purchasing_details, enviando como parametro id_venta enviado por el usuario
            connection.query('call delete_product(?)', id, (err, result) => {
                // Cerramos la conexión
                connection.end()
                // Verificamos si ocurrió un error
                if (err)
                    // Enviamos un mensaje de error
                    res.send('error2')
                // Verificamos si desde el procedimiento almacenado se obtuvo un mensaje de error o los detalles de la compra
                else if(result[0][0].mensaje === 'error')
                    res.send('error2')
                else if(result[0][0].mensaje === 'correcto'){
                    if(eliminarImagen('imagenes/' + urlImage) === 'imagen_eliminada')
                        res.send('correcto')
                    else
                        res.send('error3')
                }
            })
        }
        catch{
            res.send('error2')
        }
    }
    catch{
        res.send('error2')
    }
});


app.get('/products_categories_token', async (req, res) => {
    try{
        let admin;
        // Almacena el token enviado por el usuario en la constante token
        const token = req.headers.authorization.split(' ')[1]
        // Verifica si la constante token esta vacia.
        if (token === undefined)
            // Envia un mensaje de error
            admin = false;
        else{
            try{
                // Verifica que la firma del token sea correcta
                const payload = jwt.verify(token, secret)
                // Verifica la fecha de expiración del token
                if(Date.now() > payload.exp)
                    // Envia un mensaje de error
                    admin = false;
                else if(payload.username === 'admin')
                    // Envia un mensaje de error
                    admin = true;
                else
                    admin = false;
            }
            catch{
                admin = false;
            }
        }
        
        let products;
        let categories;

        // Crea una conexión a la base de datos MySQL utilizando las credenciales definidas anteriormente.
        let connection = mysql.createConnection(credentials)

        // Realizamos una consulta para obtener los datos de todos los productos
        products = await queryDatabase(connection, 'call get_products()');
        connection.end()

        // Crea una conexión a la base de datos MySQL utilizando las credenciales definidas anteriormente.
        let connection2 = mysql.createConnection(credentials)

        // Realizamos una consulta para obtener los datos de todos los productos
        categories = await queryDatabase(connection2, 'call get_categories()');
        connection2.end()

        const response = [products, categories, admin];

        res.send(response);
    }
    catch{
        res.send('error');
    }
})

function queryDatabase(connection, query) {
    return new Promise((resolve, reject) => {
        connection.query(query, (err, result) => {
            if (err) {
                reject(err);
            } else {
                resolve(result);
            }
        });
    });
}

// Define una ruta USE para la ruta '/imagenes de manera que se pueda acceder a las imagenes almacenadas en la carpeta con dicho nombre'.
app.use('/imagenes', express.static('./imagenes'));

app.listen(PORT, () =>{
    console.log(`Aplicación iniciada en el puerto ${PORT}`)
})
