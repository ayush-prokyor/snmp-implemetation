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

# Save the Docker image to a tar file
echo "Saving SNMP Test App version $VERSION to snmp-test-app-$VERSION.tar..."
mkdir -p releases
if [ -f releases/snmp-test-app-$VERSION.tar ]; then
  echo "Removing existing snmp-test-app-$VERSION.tar..."
  rm releases/snmp-test-app-$VERSION.tar
fi
sudo docker save -o snmp-test-app-$VERSION.tar snmp-test-app-$VERSION
mv snmp-test-app-$VERSION.tar releases/
sudo chown sunny:sunny releases/snmp-test-app-$VERSION.tar
