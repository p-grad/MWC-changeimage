# Gunicorn config
bind = ":8443"
workers = 2
threads = 2
certfile = "/tls/cert.pem"
keyfile = "/tls/key.pem"
