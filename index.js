//  import modules

const express = require('express');
const mysql = require('mysql');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();

// function middleware intégrée par express , analyse requete

app.use(express.urlencoded({ extended : true}));

// connexion bdd 

const connection = mysql.createConnection({
    host : 'localhost',
    user : 'root',
    password : '',
    database : 'auth_node_olivet_db',
});

connection.connect((err) => {
    if(err) throw err;
    console.log('connect bdd YESSSSSS')
})

// configuration ejs moteur de templates

app.set('view engine', 'ejs');

// config express session

app.use(
    session({
        secret : 'secret',
        resave : true,
        saveUninitialized : true
    })
);

// middleware verifier connexion du user

const requireLogin = (req, res, next) => {
    if (!req.session.userId) {
      res.redirect('/login');
    } else {
      next();
    }
};

// routes 

app.get('/admin', requireLogin, (req, res)=>{
    const isAdmin = req.session.isAdmin;
    res.render('admin' , {isAdmin});
})

app.get('/boutique', (req, res)=>{
    const isAdmin = req.session.isAdmin;
    const getProductsQuery = "SELECT * FROM boutiques"
    connection.query(getProductsQuery, (err, result)=>{
        if(err) throw err;
        else res.render('boutique', {isAdmin}, {boutiques: result})
    });
    res.render('boutique' , {isAdmin});
})


app.get('/dashboard', requireLogin, (req, res) => {
    const isAdmin = req.session.isAdmin;
    const username = req.session.username;
    const getUserQuery = "SELECT * FROM users WHERE username = ?";
    
    connection.query(getUserQuery, [username], (err, results) => {
      if (err) throw err;
      else res.render('dashboard', {isAdmin, results: results });
    });
  });
  

app.get('/', requireLogin, (req, res) => {
    const isAdmin = req.session.isAdmin;
    const username = req.session.username;
    res.render('home' , {isAdmin , username});
});

// register 
app.get('/register', (req, res) => {
    res.render('register');
})


app.post('/register' , (req , res) => {
    const {username ,email , password , role } = req.body;
    // verifiez si users existe deja dans la bdd 
    const checkUserQuery = 'SELECT COUNT(*) AS count FROM users WHERE username = ? ';
    connection.query(checkUserQuery, [username], (err, results) => {
        if(err) throw err;
        const count = results[0].count;
        if(count > 0) {
            res.redirect('/register?error=user_exists');
        } else {
            // hash mdp 
            bcrypt.hash(password, 10, (err, hashedpassword) => {
                if(err) throw err;
                // insert users dans bdd 
                const insertUserQuery = 'INSERT INTO users(username , email, password , role) VALUES (? , ?, ? , ?)';
                connection.query(insertUserQuery, [username , email, hashedpassword , role] , (err, results) => {
                    if(err) throw err;
                    res.redirect('/login');
                });
            });
        }

    });

});

// login

app.get('/login', (req, res) => {
    res.render('login');
})

app.post('/login' , (req, res) => {
    const {username , password} = req.body;
    // recup les informations du users 
    const getUserQuery = 'SELECT id , username , password , role FROM users WHERE username = ? ';
    connection.query(getUserQuery, [username], (err, results) => {
        if(err) throw err;

        if(results.length === 1) {
            const user = results[0];
            
            // verif le mdp 

            bcrypt.compare(password, user.password, (err, isMatch ) => {
                if(err) throw err;

                if(isMatch) {
                    req.session.userId = user.id;
                    req.session.username = user.username;
                    req.session.isAdmin = user.role === 'admin';
                    res.redirect('/');
                } else {
                    res.redirect('/login');
                }
            }); 
        } else {
            res.redirect('/login');
        }
    });

});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});





// server

const port = 8080;
app.listen(port, () => {
    console.log("marche bien ")
})