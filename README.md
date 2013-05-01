Session-Binding-Proxy
=====================

An Nginx module capable of binding the application session to the SSL session by encrypting the application cookie with a secret key and the SSL master key

This module is a session hijacking prevention method.
By binding the application session to the SSL session, it makes it a bit harder to just capture the cookie by whatever means and pretend that you are logged in to a web application.

Configuration
=====================
An example conf file for Session-Binding-Proxy is given.
The session_binding_proxy directive takes at least 1 argument.
This first argument is the private encryption/decryption key.
It is a key that only resides in Nginx, such that the end user cannot decrypt the given cookie.
Furthermore, the directive takes cookie names as arguments.
Say you want to encrypt the cookie "s_session_id", then you can specifiy $s_session_id as argument.
You can encrypt as many cookies as you want.
Keep in mind though that some cookies can not be encrypted, because the JavaScript code in the application might depend on the cookie value.

If your application resides on a different server in the backend, you can use the reverse proxy in Nginx with the proxy_pass directive.
To make sure your application does not break with static redirects (full domain specified in the redirect), you can add the sub_filter directive to clean up the responses from your backend server.