#!/bin/bash

cd /workspaces/hyperlight

# Change ownership of /dev/$HYPERVISOR so the user can have access
# NOTE: This can be only done here as the /dev/$HYPERVISOR is passed as a runtime
# argument
sudo chown -R "${HYPERVISOR}:${HYPERVISOR}" /dev/${HYPERVISOR}
sudo chmod g+rw /dev/$HYPERVISOR

# Install targets needed for Hyperlight - it takes into account the version
# needed
#rustup target add x86_64-unknown-none
#rustup target add x86_64-pc-windows-msvc
