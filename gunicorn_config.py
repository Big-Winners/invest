# gunicorn_config.py
import multiprocessing

# Server socket
bind = "0.0.0.0:10000"
backlog = 2048

# Worker processes
workers = 2
worker_class = "sync"
worker_connections = 1000
timeout = 120  # Increased timeout for image processing
keepalive = 5
max_requests = 1000
max_requests_jitter = 50

# Debugging
reload = False
spew = False

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Process naming
proc_name = "bigwinners_app"

# SSL (if needed)
# keyfile = ""
# certfile = ""