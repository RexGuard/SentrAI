"""What a machine's own agent key may reach, in one place with no imports.

main.py checks machine keys against AGENT_ROUTES, serve.py's agents' port answers only these plus AGENT_OPEN,
and the hosted gateway (mvp/web/gateway.py) loads this file by path to apply the same list in front of every
company's core, without importing the core.
"""

# What a machine's own agent key may do (fleet.py): send its events and heartbeat, read its block list.
# It reports what runs there and how its hardware is doing, picks up the jobs the panel queued for its own machine
# and reports how they went (jobs.py).
AGENT_ROUTES = frozenset({("POST", "/events"), ("POST", "/heartbeat"), ("GET", "/blocklist"), ("GET", "/fleet/me"),
                          ("POST", "/fleet/services"), ("POST", "/fleet/hardware"), ("GET", "/fleet/jobs/next"),
                          ("POST", "/fleet/jobs/result"), ("POST", "/fleet/offline-report"),
                          # the file watch (lab/agent/watch.py): send what it found, fetch the shared fingerprint list
                          ("POST", "/fleet/threats"), ("GET", "/fleet/signatures"),
                          # backup copies kept on other machines (backup_copies.py): send its key and its own sealed
                          # copies, fetch the copies it was picked to keep, say what it holds
                          ("POST", "/fleet/backup-key"), ("POST", "/fleet/backup-copies"),
                          ("GET", "/fleet/backup-copies/wanted"), ("GET", "/fleet/backup-copies/file"),
                          ("POST", "/fleet/backup-copies/held")})

# Open on the agents' port without a machine key: a new machine swapping its join code for a key, and the health check.
AGENT_OPEN = frozenset({("POST", "/fleet/enrol"), ("GET", "/health")})
