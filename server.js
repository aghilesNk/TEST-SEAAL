if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

//ajouter tous les modules que nous allons utiliser
//passport pour choisir une stratégie d'authentification des utilisateurs de manière sécurisée et efficace.
//expres-session pour crée une session distinct pour chaque utilisateur qui se connecte à l’application
//bycrypt pour le hashage de mot de passe
//flash pour enregistrer des message pour ensuite les afficher a l'utilisateur
//methodOverride est utiliser pour le logout et la suppression de la session
//path est utiliser pour inclure le CSS a l'EJS
const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const methodOverride = require('method-override');
const path = require('path');

//initialiser le passport avec l'email et l'id du user
const initializePassport = require('./passport-config');
initializePassport(
  passport,
  (email) => users.find((user) => user.email === email),
  (id) => users.find((user) => user.id === id)
);

//stocker les utilisateur dans une liste en local, cella doit etre remplacé par une base de données en production
const users = [];

//utiliser les modules que nous avons ajouter au paravant
//configurer session
app.set('view-engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));
app.use(express.static(path.join(__dirname, 'css')));

//pour aller a la page index
app.get('/', checkAuthenticated, (req, res) => {
  res.render('index.ejs', { name: req.user.name });
});

//aller a la page login si nous ne somme pas déja connecter sinon rester sur la page d'acceuil de l'utilisateur
app.get('/login', checkNotAuthenticated, (req, res) => {
  res.render('login.ejs');
});

//transmettre les information avec post aux passport pour verifier l'authentification
app.post(
  '/login',
  checkNotAuthenticated,
  passport.authenticate('login', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true,
  })
);

//aller a la page register si nous ne somme pas déja connecter sinon rester sur la page d'acceuil de l'utilisateur
app.get('/register', checkNotAuthenticated, (req, res) => {
  res.render('register.ejs');
});

//transmettre les information avec post aux passport pour enregister l'inscription et utiliser un mot de passe hasher avec bcrypt
app.post('/register', checkNotAuthenticated, async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    users.push({
      id: Date.now().toString(),
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
    });
    res.redirect('/login');
  } catch {
    res.redirect('/register');
  }
  console.log(users);
});

//supprimer la session en cours lors du logout
app.delete('/logout', (req, res, next) => {
  req.logOut((err) => {
    if (err) {
      return next(err);
    }
    res.redirect('/login');
  });
});

//verifier si l'utilisateur et bien connecter et qu'il ce trouve sur la page d'acceuil
function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

//verifier si l'utilisateur et n'est pas connecter et qu'il ce trouve sur la page login ou register
function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  next();
}

app.listen(3000);
