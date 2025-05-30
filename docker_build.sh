#!/bin/bash

SNMP_TEST_APP_VERSION=${SNMP_TEST_APP_VERSION:-latest}
VERSION=$(echo $SNMP_TEST_APP_VERSION)
# Check if the version is provided
if [ -z "$VERSION" ]; then
  echo "Error: SNMP_TEST_APP_VERSION is not set. Please set it to the desired version."
  exit 1
fi

# Check if the Dockerfile exists
if [ ! -f Dockerfile ]; then
  echo "Error: Dockerfile not found in the current directory."
  exit 1
fi
# Build the Docker image with the specified version
echo "Building SNMP Test App version $VERSION..."
sudo docker build -t snmp-test-app-$VERSION .
