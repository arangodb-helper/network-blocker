# Network blocker

The ArangoDB network blocker is a sidekick for the ArangoDB test agent, used to block/unblock
network traffic on a machine.
It is the software equivalent of "unplug a network cable".

# Usage 

```
make docker 
docker run -it --net=host --privileged -v /var/run:/var/run arangodb/network-blocker
```

The volume mapping to `/var/run` is needed to allow network-blocker to lock on the iptables
lock file (`/var/run/xtables.lock`)

# API

## GET `/ping` 

Results with `OK` (status 200) when the service is up an running. 

## POST `/api/v1/reject/tcp/<port>`

Actively block all traffic to the given TCP port for all local IP addresses.

## POST `/api/v1/drop/tcp/<port>`

Silently block all traffic to the given TCP port for all local IP addresses.

## POST `/api/v1/allow/tcp/<port>`

Allow all traffic to the given TCP port for all local IP addresses.

## GET `/api/v1/rules`

Return all rules applies by this process.
