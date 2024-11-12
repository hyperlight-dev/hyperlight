#!/bin/bash

ENV_FILE=.devcontainer/.env

DEVICE="/dev/kvm"  
DEVICE_GROUP=$(ls -l $DEVICE | awk '{print $4}')
DEVICE_GID=$(getent group $DEVICE_GROUP | cut -d: -f3)
 
echo "USER=vscode" > $ENV_FILE
echo "GROUP=vscode" >> $ENV_FILE
echo "DEVICE_GID=$DEVICE_GID" >> $ENV_FILE
echo "DEVICE_GROUP=$DEVICE_GROUP" >> $ENV_FILE
