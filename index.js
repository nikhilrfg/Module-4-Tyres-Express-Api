const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

// Allows us to access the .env
require('dotenv').config();

const app = express();
const port = process.env.PORT; // default port to listen

const corsOptions = {
   origin: '*', 
   credentials: true,  
   'access-control-allow-credentials': true,
   optionSuccessStatus: 200,
}

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

app.use(cors(corsOptions));

// Makes Express parse the JSON body of any requests and adds the body to the req object
app.use(bodyParser.json());

app.use(async (req, res, next) => {
  try {
    // Connecting to our SQL db. req gets modified and is available down the line in other middleware and endpoint functions
    req.db = await pool.getConnection();
    req.db.connection.config.namedPlaceholders = true;

    // Traditional mode ensures not null is respected for unsupplied fields, ensures valid JavaScript dates, etc.
    await req.db.query('SET SESSION sql_mode = "TRADITIONAL"');
    await req.db.query(`SET time_zone = '-8:00'`);

    // Moves the request on down the line to the next middleware functions and/or the endpoint it's headed for
    await next();

    // After the endpoint has been reached and resolved, disconnects from the database
    req.db.release();
  } catch (err) {
    // If anything downstream throw an error, we must release the connection allocated for the request
    console.log(err)
    // If an error occurs, disconnects from the database
    if (req.db) req.db.release();
    throw err;
  }
});

// These endpoints can be reached without needing a JWT
// app.get('/tyres', async (req, res) => {
//   const [tyres] = await req.db.query(`SELECT * FROM tyres`);

//   console.log('/tyres endpoint reached');

//   res.json(tyres);
// });

// app.put('/tyres', async (req, res) => {
//   const { 
//     newBrandValue,
//     newMakeValue,
//     newModelValue,
//     newSizeValue
//   } = req.body;

//   const [insert] = await req.db.query(`
//     INSERT INTO tyres (brand, make, model, size, date_created, user_id, deleted_flag)
//     VALUES (:newBrandValue, :newMakeValue, :newModelValue, :newSizeValue, NOW(), :user_id, :deleted_flag);
//   `, { 
//     newBrandValue,
//     newMakeValue, 
//     newModelValue,
//     newSizeValue,
//     user_id: 1, 
//     deleted_flag: 0
//   });

//   // Attaches JSON content to the response
//   res.json({
//     id: insert.insertId,
//     newBrandValue,
//     newMakeValue,
//     newModelValue,
//     newSizeValue,
//     userId: 1
//    });
// })

// app.delete('/tyres/:id', async (req, res) => {
//   console.log(req.params);
//   const { id } = req.params;
//   await req.db.query(`UPDATE tyres SET deleted_flag = 1 WHERE id = :tyreId`, { tyreId: id });

//   res.json('Success!');
// });

// Hashes the password and inserts the info into the `user` table
app.post('/register', async function (req, res) {
  try {
    console.log('req.body', req.body)
    const { password, username, userIsAdmin } = req.body;

    const isAdmin = userIsAdmin ? 1 : 0;

    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('username', username)
    const [user] = await req.db.query(
      `INSERT INTO tyres_data.user (user_name, password, admin_flag) 
      VALUES (:username, :hashedPassword, :userIsAdmin);`,
      { 
        username,
        hashedPassword,
        userIsAdmin: isAdmin
      }
    );

    const jwtEncodedUser = jwt.sign(
      { userId: user.insertId, ...req.body, userIsAdmin: isAdmin },
      process.env.JWT_KEY
    );

    console.log('jwtEncodedUser', jwtEncodedUser);

    res.json({ jwt: jwtEncodedUser, success: true });
  } catch (err) {
    console.log('error', err);
    res.json({ err, success: false });
  }
});

app.post('/log-in', async function (req, res) {
  try {
    const { username, password: userEnteredPassword } = req.body;

    const [[user]] = await req.db.query(`SELECT * FROM tyres_data.user WHERE user_name = :username`, { username });

    if (!user) res.json('Username not found');
  
    const hashedPassword = `${user.password}`
    const passwordMatches = await bcrypt.compare(userEnteredPassword, hashedPassword);

    if (passwordMatches) {
      const payload = {
        userId: user.id,
        username: user.username,
        userIsAdmin: user.admin_flag
      }
      
      const jwtEncodedUser = jwt.sign(payload, process.env.JWT_KEY);

      res.json({ jwt: jwtEncodedUser, success: true });
    } else {
      res.json({ err: 'Password is wrong', success: false });
    }
  } catch (err) {
    console.log('Error in /authenticate', err);
  }
});

// Jwt verification checks to see if there is an authorization header with a valid jwt in it.
app.use(async function verifyJwt(req, res, next) {
  const { authorization: authHeader } = req.headers;
  
  if (!authHeader) res.json('Invalid authorization, no authorization headers');

  const [scheme, jwtToken] = authHeader.split(' ');

  if (scheme !== 'Bearer') res.json('Invalid authorization, invalid authorization scheme');

  try {
    const decodedJwtObject = jwt.verify(jwtToken, process.env.JWT_KEY);

    req.user = decodedJwtObject;
  } catch (err) {
    console.log(err);
    if (
      err.message && 
      (err.message.toUpperCase() === 'INVALID TOKEN' || 
      err.message.toUpperCase() === 'JWT EXPIRED')
    ) {

      req.status = err.status || 500;
      req.body = err.message;
      req.app.emit('jwt-error', err, req);
    } else {

      throw((err.status || 500), err.message);
    }
  }

  await next();
});

app.post('/tyres', async (req, res) => {
  const { 
    newBrandValue,
    newMakeValue,
    newModelValue,
    newSizeValue
  } = req.body;

  const { userId } = req.user;

  const [insert] = await req.db.query(`
    INSERT INTO tyres (brand, make, model, size, date_created, user_id, deleted_flag)
    VALUES (:newBrandValue, :newMakeValue, :newModelValue, :newSizeValue, NOW(), :user_id, :deleted_flag);
  `, { 
    newBrandValue,
    newMakeValue, 
    newModelValue,
    newSizeValue,
    user_id: userId,
    deleted_flag: 0
  });

  // Attaches JSON content to the response
  res.json({
    id: insert.insertId,
    newBrandValue,
    newMakeValue,
    newModelValue,
    newSizeValue,
    userId
   });
});

app.put('/tyres', async (req, res) => {
  const { id, brand, make, model, size } = req.body;

  const [cars] = await req.db.query(
    `UPDATE tyres SET brand = :brand, make = :make, model = :model, size = :size WHERE id = :id;`, 
    { 
      id,
      brand,
      make,
      model,
      size
     });

  // Attaches JSON content to the response
  res.json({ id, brand, make, model, size, success: true });
})

// Creates a GET endpoint at <WHATEVER_THE_BASE_URL_IS>/car
app.get('/tyres', async (req, res) => {
  const { userId } = req.user;

  const [tyres] = await req.db.query(`SELECT * FROM tyres WHERE user_id = :userId AND deleted_flag = 0;`, { userId });

  // Attaches JSON content to the response
  res.json({ tyres });
});

// http://localhost:3001/car/1
app.delete('/tyres/:id', async (req, res) => {
  const { id: tyreId } = req.params;

  await req.db.query(`UPDATE tyres SET deleted_flag = 1 WHERE id = :tyreId`, { tyreId });

  res.json({ success: true });
})

// Start the Express server
app.listen(port, () => {
  console.log(`server started at http://localhost:${port}`);
});