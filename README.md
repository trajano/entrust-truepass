Entrust TruePass JASPIC implementation
======================================

This is a simplistic implementation of [HttpHeaderAuthModule](https://github.com/trajano/server-auth-modules/blob/master/src/main/java/net/trajano/auth/HttpHeaderAuthModule.java) from [Server Auth Modules](https://site.trajano.net/server-auth-modules/) which has been hard coded for Entrust TruePass implementations and uses Java EE 6 to support older versions of WebSphere Application Server.

It provides a sample EAR and web app that can be deployed to WebSphere Application Server based on [Utility JSPs](https://github.com/trajano/util).

This is implemented with [JASPIC embedded inside the application](https://trajano.net/2014/11/implementing-jaspic-in-the-application/).