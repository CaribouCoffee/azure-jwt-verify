const jwt = require('jsonwebtoken');
const axios = require('axios');
// TODO: this module is also not being maintained and the code itself is kind of hacky 
// we might want to bring the solution into this one and tidy it up a little
const getPem = require('rsa-pem-from-mod-exp');

const publicKeys = {};

// Validate the jwt Token with the audience and the issuer
const verifyJwt = function verifyJwt(jwtToken, publicKey, aud, iss) {
  return new Promise(function (resolve, reject) {
    jwt.verify(jwtToken, publicKey, { algorithms: ['RS256'], audience: aud, issuer: iss },
      function (error, decoded) {
        if (!error) {
          resolve(decoded);
        } else {
          reject(error);
        }
      });
  });
};

// fetch publicKeys (mod and exp) from jwks_uri if there are no current kid matching
const getPublicKeys = function getPublicKeys(JWK_URI, jwtKid) {
  if (hasPublicKey(jwtKid)) {
    return new Promise(function (resolve, _reject) {
      resolve(publicKeys);
    });
  } else {
    return new Promise(function (resolve, reject) {
      axios.get(JWK_URI).then(function(response) {
        console.log(response);
        let keys = JSON.parse(response).keys;
        updatePublicKeys(keys);
        resolve(publicKeys);
      })
      .catch(function(error) {
        console.log(error);
        reject(error)
      })
    });
  }
};

// generate and cache the rsa public key from modulus exponent
const updatePublicKeys = function (b2cKeys) {
  b2cKeys.forEach(function (value) {
    publicKeys[value.kid] = getPem(value.n, value.e)
  });
};

// retunrs the public key for the given kid from the cached keys
const getPublicKey = function (jwtKid) {
  if (publicKeys.hasOwnProperty(jwtKid)) {
    return publicKeys[jwtKid];
  } else {
    return false;
  }
};

// check if the kid has a public key 
const hasPublicKey = function (jwtKid) {
  return publicKeys.hasOwnProperty(jwtKid);
};

// verify the jwtToken against the given configuration
exports.verify = function (jwtToken, config) {
  return new Promise(function (resolve, reject) {
    let decoded = jwt.decode(jwtToken, { complete: true });
    if (!decoded) {
      reject('{ "status":"error", "message":"Error Decoding JWT Token" }');
    } else {
      let jwtKid = decoded.header.kid;
      if (!jwtKid) {
        reject('{ "status":"error", "message":"Invalid JWT Token" }');
      } else {
        getPublicKeys(config.JWK_URI, jwtKid).then(function (response) {
          if (hasPublicKey(jwtKid)) {
            let publicKey = getPublicKey(jwtKid);
            return verifyJwt(jwtToken, publicKey, config.AUD, config.ISS).then(function (response) {
              resolve(JSON.stringify({ "status": "success", "message": response }));
            }).catch(function (error) {
              reject(JSON.stringify({ "status": "error", "message": error }));
            });
          } else {
            reject('{ "status":"error", "message":"Invalid jwt kid" }');
          }
        }).catch(function (error) {
          reject('{ "status":"error", "message":"Cannot fetch data from JWK_URI" }');
        })
      }
    }
  });
};
