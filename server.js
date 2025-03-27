// server.js

const express = require('express');
const bodyParser = require('body-parser');
const AWS = require('aws-sdk');
const { CognitoUserPool, CognitoUser, AuthenticationDetails } = require('amazon-cognito-identity-js');
const path = require('path');
const cors = require('cors');


// AWS Cognito config
const poolData = {
  UserPoolId: 'us-east-2_CfIuQw9Ai', // replace with your User Pool ID
  ClientId: '17m8e3s0o2iovp0c044nmmb8np' // replace with your App Client ID
};

const userPool = new CognitoUserPool(poolData);

const app = express();
app.use(bodyParser.json()); // parse JSON payloads
app.use(cors());

app.get('/', (req, res) => {
    res.status(200).json({ message: 'Request Recieved' });
})
// Route to authenticate a user
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  console.log(`username, password`, username, password);
  const authenticationData = {
    Username: username,
    Password: password,
  };

  const authenticationDetails = new AuthenticationDetails(authenticationData);
  const userData = {
    Username: username,
    Pool: userPool,
  };

  const cognitoUser = new CognitoUser(userData);

  cognitoUser.authenticateUser(authenticationDetails, {
    onSuccess: (result) => {
      // Successful authentication, return the JWT token
      const idToken = result.getIdToken().getJwtToken();
      const accessToken = result.getAccessToken().getJwtToken();
      const refreshToken = result.getRefreshToken().getToken();

      // Respond with the tokens
      res.json({
        idToken,
        accessToken,
        refreshToken,
      });
    },
    onFailure: (err) => {
      // Authentication failed
      res.status(401).json({ message: 'Authentication failed', error: err });
    }
  });
});

// // Serve React frontend (if static files are built)
// app.use(express.static('client/build'));

// Fallback to index.html for React SPA routing
// app.get('*', (req, res) => {
//   res.sendFile(path.join(__dirname, 'client', 'build', 'index.html'));
// });

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
