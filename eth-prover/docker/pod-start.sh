#!/usr/bin/env bash
# Container entry for rented GPU pods: sshd if a public key was provided, then idle forever.
if [ -n "${PUBLIC_KEY:-}" ]; then
  echo "$PUBLIC_KEY" > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
  /usr/sbin/sshd -p 22 && echo "sshd started"
fi
exec sleep infinity
