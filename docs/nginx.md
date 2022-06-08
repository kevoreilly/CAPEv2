# NGINX Guide

In this guide we'll be using the NGINX web server as a secure reverse proxy for Cuckoo.

    sudo apt-get install nginx apache2-utils

Add yourself to the `cuckoo` group:

    sudo usermod -a -G cuckoo $USER

## Create a SSL certificate

 It is very important that communications between the sandbox and its users are secure for a couple of reasons:

- Prevents credentials from being sniffed
- Prevents triggering IDS alarms in your network while uploading malware

You can use a self-signed certificate, or one that has been signed by an internal or external Certificate Authority (CA). Using a CA will allow browsers and other HTTPS clients that trust the CA to trust that the connection is secure. Self signed certificates will generate browser warnings.

If you are accessing your sandbox directly via in internal/private IP address, you must use a self signed certificate.

Create a directory to store the certificates and keys:

    mkdir ~/ssl
    cd ~/ssl

To create a self-signed certificate, run:

    openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout cuckoo.key -out cuckoo.crt

**Or**, to create a Certificate Signing Request (CSR) for a CA, run:

    openssl req -newkey rsa:4096-nodes -keyout cuckoo.key -out cuckoo.csr

Fill in the prompts. **Watch out** for `Common Name (e.g. server FQDN or YOUR domain name)`, which is the IP address or domain name that you will be hosting Cuckoo web services on. it is the most important field.

Remove the CSR after you have your certs

    rm cuckoo.csr

Move the keys into place:

    cd
    sudo mv ssl /etc/nginx

Secure the keys:

    sudo chown -R root:www-data /etc/nginx/ssl
    sudo chmod -R u=rX,g=rX,o= /etc/nginx/ssl

## Configure NGINX

Disable the default nginx configuration:

    sudo rm /etc/nginx/sites-enabled/default

Create the Cuckoo web server configuration

    sudo nano /etc/nginx/sites-available/cuckoo

**Note**: In both the SSL and non-SSL server blocks below, replace `IP_Address` with the IP address of the interface you will access web services through. This is done so that the webserver cannot be accessed by sandbox VMs.

```nginx
server {
    # SSL best practices from https://mozilla.github.io/server-side-tls/ssl-config-generator/
    listen IP_Address:443 ssl http2;
    ssl_certificate /etc/nginx/ssl/cuckoo.crt;
    ssl_certificate_key /etc/nginx/ssl/cuckoo.key;
    ssl_protocols TLSv1.2;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256';
    ssl_prefer_server_ciphers on;
    # Uncomment this next line if you are using a signed, trusted cert
    #add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    root /usr/share/nginx/html;
    index index.html index.htm;
    client_max_body_size 101M;
    auth_basic "Login required";
    auth_basic_user_file /etc/nginx/htpasswd;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /storage/analysis {
       alias /opt/cuckoo/storage/analyses/;
       autoindex on;
       autoindex_exact_size off;
       autoindex_localtime on;
    }

    location /static {
      alias /opt/cuckoo/web/static/;
    }
}

server {
    listen IP_Address:80;
    return 301 https://$server_name$request_uri;
}
```

Enable the nginx Cuckoo configuration:

    sudo ln -s /etc/nginx/sites-available/cuckoo /etc/nginx/sites-enabled/cuckoo

Setup basic authentication:

Cuckoo's web interface has no authentication mechanism of its own, so we'll use use `nginx`'s basic auth. To create a user, use

    sudo htpasswd -c /etc/nginx/htpasswd exampleuser

Where `exampleuser` is the name of the user you want to add.

Secure the permissions of the `httpasswd` file:

    sudo chown root:www-data /etc/nginx/htpasswd
    sudo chmod u=rw,g=r,o= /etc/nginx/htpasswd
