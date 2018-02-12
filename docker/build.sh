#!/bin/bash
git clone https://github.com/elixir-europe/ega-data-api-v3-cipher.git
mvn -f /ega-data-api-v3-cipher/pom.xml install
git clone https://github.com/elixir-europe/ega-data-api-v3-res_mvc.git
mvn -f /ega-data-api-v3-res_mvc/pom.xml install
mv /ega-data-api-v3-res_mvc/target/ReEncryptionMVC-0.0.1-SNAPSHOT.jar /EGA_build
mv /ega-data-api-v3-res_mvc/docker/resd.sh /EGA_build
mv /ega-data-api-v3-res_mvc/docker/Dockerfile_Deploy /EGA_build
