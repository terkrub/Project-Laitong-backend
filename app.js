const express = require('express')
const cors = require('cors')
const app = express()
const bodyParser = require('body-parser')
const jsonParser = bodyParser.json()
const connection = require('./database')
const jwt = require('jsonwebtoken')
const secret = 'username-login'
const bcrypt = require('bcrypt')
const saltBounds = 10;

app.use(cors())

app.post('/register',jsonParser,function (req, res, next){
    bcrypt.hash(req.body.password, saltBounds,function (err, hashPw){
        connection.execute(
            'INSERT INTO users (username,password,สาขา) VALUES  (?, ?, ?)',[req.body.username,hashPw,req.body.branch],
            function (err, result, fields){
                if (err) {
                    res.json({status: 'error', message: err.message})
                    return
                }
                res.json({status:'Success'})
            }
        )
    })
})

app.post('/login',jsonParser,function (req, res, next){
    connection.execute(
        'SELECT * FROM users WHERE username=?',[req.body.username],
        function (err, result, fields){
            if (err){
                res.json({status: 'error', message: err.message})
                return
            }

            if (result.length === 0){
                res.json({status:'fail',message:"No user found"})
                return
            }

            bcrypt.compare(req.body.password,result[0].password,function (err,isLogin){

                if (err){
                    res.json({status: 'error', message: err.message})
                    return
                }
                if (isLogin) {

                    const token = jwt.sign({ username: result[0].username }, secret,{ expiresIn: '7d' });
                    res.json({status: 'Success',token})
                }
                else
                    res.json({status:'fail', message:"Password incorrect"})
            })
        }
    )
})

app.post('/authen',jsonParser,function (req, res, next) {
    try {
        const token = req.headers.authorization
        const decoded = jwt.verify(token.split(' ')[1], secret)
        res.json({status: 'Success', decoded})
    }catch (err){
        res.json({status:'error', message: err.message})
    }
})

app.listen(3333,function (){
    console.log('CORS-enable web server listening on port 3333')
})