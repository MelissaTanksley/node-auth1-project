const express = require('express')
const bcrypt = require('bcryptjs')
const session = require('express-session')
const users = require('./dbhelper')

const server = express()
server.use(express.json())

server.use(
    session({
        name: 'nonsession',
        secret: 'Cheese is optional in a quesadilla',
        cookie:{
            maxAge: 1*24*60*60*1000,
            secure: true
        },
        httpOnly: true,
        resave: false,
        saveUninitialized: false,
    })
)
server.post('/api/login', (req, res) => {
    const credentials = req.body;

    users.findBy(credentials.username)
      .first()
      .then(user => {
        // check that passwords match
        if (user && bcrypt.compareSync(credentials.password, user.password)) {
          res.status(200).json({ message: `Welcome ${user.username}!` });
        } else {
          // we will return 401 if the password or username are invalid
          // we don't want to let attackers know when they have a good username
          res.status(401).json({ message: 'Invalid Credentials' });
        }
      })
      .catch(error => {
        res.status(500).json(error);
      });
  });

  server.post('/api/register', (req, res)=>{
      const credentials = req.body;
      const hash = bcrypt.hashSync(credentials.password, 14);
      credentials.password = hash;

      users.register(credentials)
      .then(user => {
        if(user.length){
          res.status(201).json(user).end()
        }else{
          res.status(500).json({message: "Could not be added."}).end()
        }
      })
      .catch(err => {
        res.status(500).json({message: "Something went fucky"}).end()
      })
  })

  server.get('/api/users', protected, (req, res) => {
    users.get()
      .then(users => {
        if(users.length){
          res.status(200).json(users)}
          else{
            res.status(404).json({message: "No users to be found!"})
          }
        })
      .catch(err => res.status(500).json({message: err}));
  });

server.get('/api/logout', (req, res) =>{
    if (req.session){
        req.session.destroy(err=>{
            if(err){
                res.send("Error Logging Out").end()
            }else{
                res.send("Bye Bye")
            }
        })
    }
})

function protected(req, res, next) {
    if (req.session && req.session.userId) {
      next();
    } else {
      res.status(401).json({ message: 'you shall not pass!!' });
    }
  }



const port = process.env.PORT || 4004;

server.listen(port, ()=> console.log(`I am listening: ${port}`)) 