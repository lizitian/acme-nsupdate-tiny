# acme-nsupdate-tiny

This is a tiny, auditable script that issues and renews
[Let's Encrypt](https://letsencrypt.org/) certificates. Since it has access to
your private Let's Encrypt account key and nsupdate TSIG key, I tried to make it
as tiny as possible (currently less than 100 lines).
The only prerequisites are python, openssl and nsupdate.

**PLEASE READ THE SOURCE CODE! YOU MUST TRUST IT WITH YOUR PRIVATE ACCOUNT KEY!**

## Donate

If this script is useful to you, please donate to the EFF. I don't work there,
but they do fantastic work.

[https://eff.org/donate/](https://eff.org/donate/)

## How to use this script

If you already have a Let's Encrypt issued certificate and just want to renew,
you should only have to do Steps 3 and 6.

### Step 1: Create a Let's Encrypt account private key (if you haven't already)

You must have a public key registered with Let's Encrypt and sign your requests
with the corresponding private key. If you don't understand what I just said,
this script likely isn't for you! Please use the official Let's Encrypt
[client](https://github.com/letsencrypt/letsencrypt).
To accomplish this you need to initially create a key, that can be used by
acme-nsupdate-tiny, to register an account for you and sign all following requests.

```
openssl genrsa 4096 > account.key
```

#### Use existing Let's Encrypt key

Alternatively you can convert your key, previously generated by the original
Let's Encrypt client.

The private account key from the Let's Encrypt client is saved in the
[JWK](https://tools.ietf.org/html/rfc7517) format. `acme-nsupdate-tiny` is using the PEM
key format. To convert the key, you can use the tool
[conversion script](https://gist.github.com/JonLundy/f25c99ee0770e19dc595) by JonLundy:

```sh
# Download the script
wget -O - "https://gist.githubusercontent.com/JonLundy/f25c99ee0770e19dc595/raw/6035c1c8938fae85810de6aad1ecf6e2db663e26/conv.py" > conv.py

# Copy your private key to your working directory
cp /etc/letsencrypt/accounts/acme-v01.api.letsencrypt.org/directory/<id>/private_key.json private_key.json

# Create a DER encoded private key
openssl asn1parse -noout -out private_key.der -genconf <(python2 conv.py private_key.json)

# Convert to PEM
openssl rsa -in private_key.der -inform der > account.key
```

### Step 2: Create a certificate signing request (CSR) for your domains.

The ACME protocol (what Let's Encrypt uses) requires a CSR file to be submitted
to it, even for renewals. You can use the same CSR for multiple renewals. NOTE:
you can't use your account private key as your domain private key!

```
# Generate a domain private key (if you haven't already)
openssl genrsa 4096 > domain.key
```

```
# For a single domain
openssl req -new -sha256 -key domain.key -subj "/CN=yoursite.com" > domain.csr

# For multiple domains (use this one if you want both www.yoursite.com and yoursite.com)
openssl req -new -sha256 -key domain.key -subj "/" -addext "subjectAltName = DNS:yoursite.com, DNS:www.yoursite.com" > domain.csr

# For multiple domains (same as above but works with openssl < 1.1.1)
openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:yoursite.com,DNS:www.yoursite.com")) > domain.csr
```

### Step 3: Make your DNS server accept nsupdate requests

You must prove you own the domains you want a certificate for, so Let's Encrypt
requires you add a TXT record to your domain. This script will issue nsupdate
requests to your domain, so all you need to do is make sure that your DNS server
accepts nsupdate requests. You can use a TSIG key in your DNS server, so
unauthorized DNS update requests will be denied.

```
# Example for bind
key "default" {
    algorithm hmac-sha256;
    secret "SECRET";
};
zone "_acme-challenge.example.com" {
    type master;
    file "/etc/bind/zones/acme.zone";
    allow-update {
        key "default";
    };
};
```

### Step 4: Get a signed certificate!

Now that you have setup your server and generated all the needed files, run this
script with the permissions needed to read your private account key and CSR.

```
# Run the script
python acme_nsupdate_tiny.py --account-key ./account.key --csr ./domain.csr --tsig-key "hmac-sha256:default SECRET"
```

### Step 5: Install the certificate

The download URL of signed https certificate chain that is output by this script
can be used along with your private key to run an https server. You need to
download and include them in the https settings in your web server's configuration.
Here's an example on how to configure an nginx server:

```nginx
server {
    listen 443 ssl;
    server_name yoursite.com www.yoursite.com;

    ssl_certificate /path/to/signed_chain.crt;
    ssl_certificate_key /path/to/domain.key;
    ssl_session_timeout 5m;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA;
    ssl_session_cache shared:SSL:50m;
    ssl_dhparam /path/to/server.dhparam;
    ssl_prefer_server_ciphers on;

    ...the rest of your config
}

server {
    listen 80;
    server_name yoursite.com www.yoursite.com;

    ...the rest of your config
}
```

### Step 6: Setup an auto-renew cronjob

Congrats! Your website is now using https! Unfortunately, Let's Encrypt
certificates only last for 90 days, so you need to renew them often. No worries!
It's automated! Just make a bash script and add it to your crontab (see below
for example script).

Example of a `renew_cert.sh`:
```sh
#!/usr/bin/sh
CRT=$(python /path/to/acme_nsupdate_tiny.py --account-key /path/to/account.key --csr /path/to/domain.csr --production || exit)
wget "$CRT" -O /path/to/signed_chain.crt
service nginx reload
```

```
# Example line in your crontab (runs once per month)
0 0 1 * * /path/to/renew_cert.sh 2>> /var/log/acme_tiny.log
```

NOTE: Since Let's Encrypt's ACME v2 release, the intermediate certificate is
included in the issued certificate download, so you no longer have to independently
download the intermediate certificate and concatenate it to your signed certificate.

## Permissions

The biggest problem you'll likely come across while setting up and running this
script is permissions. You want to limit access to your account private key and
DNS update requests as much as possible.

**BE SURE TO:**
* Backup your account private key (e.g. `account.key`)
* Don't allow this script to be able to read your domain private key!
* Don't allow this script to be run as root!

## Feedback/Contributing

This project has a very, very limited scope and codebase. I'm happy to receive
bug reports and pull requests, but please don't add any new features.

**This script must stay under 100 lines of code to ensure it can be easily
audited by anyone who wants to run it. The number of characters in a line
must be less than 120 characters.**

If you want to add features for your own setup to make things easier for you,
please do! It's open source, so feel free to fork it and modify as necessary.
