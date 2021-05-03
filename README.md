Session-Binding-Proxy
=====================
An Nginx module capable of binding the application session to the SSL session by encrypting the application cookie with a secret key and the SSL master key

This module is a session hijacking prevention method.
By binding the application session to the SSL session, it makes it a bit harder to just capture the cookie by whatever means and pretend that you are logged in to a web application.

Build/Compile
=====================
There are two ways to compile and inlcude nginx modules.
First off you can compile nginx from source with this module included.
Download the latest nginx source to your local folder and run the following:

```
cd nginx-<version>
./configure --with-debug \
        --with-http_ssl_module \
        --add-module=path/to/Session-Binding-Proxy/nginx_session_binding_proxy_module \
make
make install
```

Alternatively you can compile Session-Binding-Proxy as a dynamic module.
Again download the latest nginx source to your local folder and run the following:

```
cd nginx-<version>
./configure --with-debug \
        --with-http_ssl_module \
        --add-module=path/to/Session-Binding-Proxy/nginx_session_binding_proxy_module \
make modules
sudo cp objs/nginx_session_binding_proxy_module.so /etc/nginx/modules/
```

Note that you need the http_ssl_module to compile the Session-Binding-Proxy module.

Configuration
=====================
An example conf file for Session-Binding-Proxy is given.
The session_binding_proxy directive takes 0 or more arguments.
The arguments are cookies that you want encrypted.
Say you want to encrypt the cookie "s_session_id", then you can specifiy $s_session_id as argument.
You can encrypt as many cookies as you want.
Keep in mind though that some cookies can not be encrypted, because the JavaScript code in the application might depend on the cookie value.
Encrypting them will break the application functionality.

The session_binding_proxy_key directive takes only 1 argument, namely the private system key.
It is a key that only resides in Nginx, such that the end user cannot decrypt the given cookie.
This is an optional directive. A random key is generated on every startup of Nginx.
This directive overwrites the random key.
(When multiple Session Binding Proxy servers are used in a larger network, implementing the same key can be usefull.)
Make sure you use 64 hexadecimal characters.

If your application resides on a different server in the backend, you can use the reverse proxy in Nginx with the proxy_pass directive.
To make sure your application does not break with static redirects (full domain specified in the redirect), you can add the sub_filter directive to clean up the responses from your backend server.

You can extend the SSL connection time, such that the timeout of SSL will not influence the application session timeout.
I've set it to 120m. Please note that the browser can also cut the SSL session...

Donate
=====================
This project was made for my bachelor thesis years ago. I do not have much time to work on this anymore.
If you like the project and want to help me out, please consider donating.

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://paypal.me/WillemBurgers/5)