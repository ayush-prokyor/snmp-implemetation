#!/bin/bash

VERSION=v5p0

sudo docker run -p 3000:3000 -p 161:161/udp -p 162:162/udp snmp-test-app-$VERSION
