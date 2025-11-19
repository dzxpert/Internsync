const express = require('express');
const session = require('express-session');
const path = require("path");
const { pool, sessionStore } = require('./database');
const { CHECK_AUTH } = require('./middleware');
const routes = require('./routes');

const app = express();
const publicDir = path.join(__dirname, './public');
app.use(express.static(publicDir));
app.use(express.urlencoded({ extended: 'false' }));
app.use(express.json());
app.use(session({
  secret: 'OMMPPH',
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000 // 1 day in milliseconds
  }
}));
app.set('view engine', 'hbs');

app.use('/', routes);

const port = 3000;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
