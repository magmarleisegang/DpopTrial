# DpopTrial
Trial implementation of DPoP auth. Very basic. 
Follows the explanation here: https://darutk.medium.com/illustrated-dpop-oauth-access-token-security-enhancement-801680d761ff
Info on building JWT from jwt.io

The project contains two APIs:
1. DPoP Trial: this is the API that hands out access tokens and special resources
2. DPoP Client: this is the client application that requests access tokens and tries to access resources.

This is a very basic implementation to understand the principles. There is no fancy middlewares handling the auth, and the Client uses a singleton to remember the RSA used to generate the DPoP proof token between calls. This singleton also keeps the access token for later use. 

There is also a Nunit test project that ended up containing the shared Token implementations. It showcases some of my failed attempts at using BouncyCastle to make use of the EdDSA algorithm instead of PS RSA.
