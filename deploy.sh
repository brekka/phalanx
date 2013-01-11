#!/bin/bash
mvn clean install
rsync -av web/target/phalanx-web-*.war dogma:/tmp/
