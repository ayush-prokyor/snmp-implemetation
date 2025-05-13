#!/bin/bash

VERSION=v5p0

sudo docker save -o snmp-test-app-$VERSION.tar snmp-test-app-$VERSION
mv snmp-test-app-$VERSION.tar releases/
sudo chown sunny:sunny releases/snmp-test-app-$VERSION.tar
