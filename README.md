# DpopTrial
Trial implementation of DPoP auth. Very basic. 

Follows the explanation here: [Illustrated DPoP (OAuth Access Token Security Enhancement)](https://darutk.medium.com/illustrated-dpop-oauth-access-token-security-enhancement-801680d761ff)

Info on building JWT here: [jwt.io](https://jwt.io/introduction)

## The project contains two APIs:
1. DPoP Trial: this is the API that hands out access tokens and special resources
2. DPoP Client: this is the client application that requests access tokens and tries to access resources.

This is a very basic implementation to understand the principles. There is no fancy middlewares handling the auth, and the Client uses a singleton to remember the RSA used to generate the DPoP proof token between calls. This singleton also keeps the access token for later use. 

## How to use
1. Start up both APIs
1. Open Postman (or the like) and do the following GET request:
   
   `GET https://localhost:7261/Auth`
   
   This will return a 200 OK (fingers crossed)
1. After the Auth request run the following GET request:
   
   `GET https://localhost:7261/Resource`
  
   A succesful response will look like this:

   200 OK - "DPoP proof seems legit"

1. To test a failed DPoP test you can use the following GET request:
   
   `GET https://localhost:7261/Resource/invalid`

   This will respond with the following:

   200 OK - "Access Token thumbprint invalid"

   This happens because the _invalid_ endpoint instantiates a new RSA for creating the DPoP proof JWT. This results in the public key thumbprint  on the access token not matching that of the DPoP Proof JWT
  
There is also a Nunit test project that ended up containing the shared Token implementations. It showcases some of my failed attempts at using BouncyCastle to make use of the EdDSA algorithm instead of PS RSA.
