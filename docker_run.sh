#!/bin/bash

SNMP_TEST_APP_VERSION=${SNMP_TEST_APP_VERSION:-latest}
VERSION=$(echo $SNMP_TEST_APP_VERSION)
# Check if the version is provided
if [ -z "$VERSION" ]; then
  echo "Error: SNMP_TEST_APP_VERSION is not set. Please set it to the desired version."
  exit 1
fi
# Check if the Docker image exists
if ! sudo docker image inspect snmp-test-app-$VERSION > /dev/null 2>&1; then
  echo "Error: Docker image snmp-test-app-$VERSION does not exist. Please build the image first."
  exit 1
fi
# Run the Docker container with the specified version
echo "Running SNMP Test App version $VERSION..."
sudo docker run -p 3000:3000 -p 161:161/udp -p 162:162/udp snmp-test-app-$VERSION
