require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const AWS = require('aws-sdk');
const checkAuth = require('./middleware/auth');

const app = express();

app.use(bodyParser.json());
app.use(cors({
    // origin: 'http://localhost:3000',
    credentials: true,
}));
app.use(cookieParser());

AWS.config.update({ region: process.env.AWS_REGION });
const cognito = new AWS.CognitoIdentityServiceProvider();

const generateSecretHash = (username) => {
    if (!process.env.CLIENT_SECRET) {
        return undefined
    }
    return crypto
        .createHmac("sha256", process.env.CLIENT_SECRET)
        .update(username + process.env.CLIENT_ID)
        .digest("base64");
}

app.post('/signup', async (req, res) => {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
        return res.status(400).json({ error: "Username, Email and Password are required" })
    }

    const params = {
        ClientId: process.env.CLIENT_ID,
        SecretHash: generateSecretHash(username),
        Username: username,
        Password: password,
        UserAttributes: [{
            Name: 'email',
            Value: email
        }]
    };

    try {
        const data = await cognito.signUp(params).promise();
        res.json({ message: "User sign up is successful.", data });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
})

app.post("/confirmEmail", async (req, res) => {
    const { username, confirmationCode } = req.body;

    if (!username || !confirmationCode) {
        return res.status(400).json({ error: "Username and Confirmation Code are required" })
    }

    const params = {
        ClientId: process.env.CLIENT_ID,
        SecretHash: generateSecretHash(username),
        Username: username,
        ConfirmationCode: confirmationCode
    }

    try {
        const data = await cognito.confirmSignUp(params).promise();
        res.json({ message: "User confirmation is successful.", data });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
})

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Username and Password are required" })
    }

    const params = {
        AuthFlow: 'USER_PASSWORD_AUTH',
        ClientId: process.env.CLIENT_ID,
        AuthParameters: {
            USERNAME: username,
            PASSWORD: password,
            SECRET_HASH: generateSecretHash(username),
        }
    };

    try {
        const data = await cognito.initiateAuth(params).promise();
        const token = jwt.sign({ username: data.AuthenticationResult.AccessToken }, process.env.JWT_SECRET_KEY, { expiresIn: '15min' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            // sameSite: 'Lax',
            sameSite: 'Strict',
            maxAge: 900000,
        });

        res.json({ message: 'User authenticated successfully' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
})

app.post('/logout', checkAuth, async (req, res) => {
    const token = req.cookies.token;

    const params = {
        AccessToken: token
    }

    try {
        await cognito.globalSignOut(params).promise();

        res.cookie('token', '', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            expires: new Date(0),
        });
        res.status(200).json({ message: 'Successfully logged out' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.use((req, res) => {
    res.status(404).json({ message: 'Page not found' });
})

app.listen(process.env.PORT, () => {
    console.log(`Server running on port ${process.env.PORT}`);
});