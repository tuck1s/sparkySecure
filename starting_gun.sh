#!/usr/bin/env bash
# Example of how to start gunicorn from the command line
#  - specify the public and private keys that will be used when serving https:// requests
#  - bind to a port number that's available on this server, accepting any incoming requests
#  - log access requests to a local file
#  - run as a process attached to console, for debugging

# Note: for Production use, Gunicorn should be hosted behind a proxy such as Nginx
# see http://docs.gunicorn.org/en/stable/deploy.html

# To start as a daemon process, add --daemon

gunicorn webapp:app --certfile=/etc/pki/tls/certs/ca.crt --keyfile=/etc/pki/tls/private/ca.key --bind=0.0.0.0:8855 --access-logfile gunicorn.log