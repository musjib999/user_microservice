const express = require('express');
const bcrypt = require('bcrypt');
const jsonwebtoken = require('jsonwebtoken');
const SmsServiceDao = require('../dao/dao.sms.service');

const { secretKey, expiresIn } = require('../configs').webToken;
const UserDao = require('../dao/dao.user');

module.exports = () => {
    const api = express.Router();

    /**
     * @swagger
     * /api/v1/auth/login:
     *  post:
     *      description: "Logs in a registered user and returns a token"
     *      tags:
     *          - Auth Routines
     *      parameters:
     *          - name: reqBody
     *            description: 'The body of the request in json format consisting of username and password'
     *            in: body
     *            schema:
     *               type: object
     *               properties:
     *                   username:
     *                      type: string
     *                   password:
     *                      type: string
     *               required:
     *                   - username
     *                   - password
     *      responses:
     *          '200':
     *              description: 'Request is successful'
     *          '500':
     *              description: 'Request Failed'
     */
    api.post('/login', async (req, res) => {
        const { username, password } = req.query;
        try {
            let user = await UserDao.getOneByUsername(username);
            let dbUserPass = user.password;
            let flag = await comparePasswordsPromisified(password, dbUserPass);
            if (flag) {
                user.password = '************';
                let token = await generateToken(user._id, user.userType);
                let refToken = await refreshToken(user._id, user.userId, token);
                const payload = { user: user, token: token, rToken: refToken };
                res.status(200).json({ status: 'success', payload: payload, message: 'User Logged In successfully!' });
            } else {
                res.status(500).json({ status: 'failed', payload: null, message: 'Invalid username or password' });
            }
        } catch (err) {
            res.status(500).json({ status: 'failed', payload: null, message: err });
        }
    });

    /**
     * @swagger
     * /api/v1/auth/register:
     *  post:
     *      description: "Registers a new user and return user info"
     *      tags:
     *          - Auth Routines
     *      parameters:
     *          - name: reqBody
     *            description: 'The body of the request consisting of fname, lname, username and password'
     *            in: body
     *            schema:
     *               type: object
     *               properties:
     *                   fname:
     *                      type: string
     *                   lname:
     *                      type: string
     *                   username:
     *                      type: string
     *                   password:
     *                      type: string
     *               required:
     *                   - fname
     *                   - lname
     *                   - username
     *                   - password
     *      responses:
     *          '200':
     *              description: 'Request is successful'
     *          '500':
     *              description: 'Request Failed'
     */
    api.post('/register', async (req, res) => {
        try {
            const savedUser = await UserDao.addNew(req.body);
            res.status(200).json({ status: 'success', payload: savedUser, message: 'User created successfully!' });
        } catch (err) {
            res.status(500).json({ status: 'failed', payload: null, message: err });
        }
    });

    return api;
}

function comparePasswordsPromisified(sent, existing) {
    return new Promise((resolve, reject) => {
        bcrypt.compare(sent, existing, (err, same) => {
            if (err) {
                reject(err);
            }
            resolve(same);
        });
    });
}

//token
function generateToken(userId, userType) {
    return new Promise((resolve, reject) => {
        jsonwebtoken.sign({ userId: userId, userType: userType }, secretKey, { expiresIn }, (err, token) => {
            if (err) {
                reject(err);
            }
            resolve(token);
        });
    });
}


//refreshToken
function refreshToken(userId, userType, token) {
    return new Promise((resolve, reject) => {
        jsonwebtoken.sign({ userId: userId, userType: userType, token: token }, secretKey, { expiresIn }, (err, token) => {
            if (err) {
                reject(err);
            }
            resolve(token);
        });
    });
}