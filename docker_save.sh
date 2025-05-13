#!/bin/bash

VERSION=v4p0

sudo docker save -o snmp-test-app-$VERSION.tar snmp-test-app-$VERSION
mv snmp-test-app-$VERSION.tar releases/
sudo chown sunny:sunny releases/snmp-test-app-$VERSION.tar
