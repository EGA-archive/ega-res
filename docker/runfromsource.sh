#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
sudo docker run --rm --name build -v $DIR:/EGA_build -it alexandersenf/ega_build sh -c 'exec /EGA_build/build.sh'
sudo docker build -t ega_resmvc -f Dockerfile_Deploy .
sudo rm ReEncryptionMVC-0.0.1-SNAPSHOT.jar
sudo rm Dockerfile_Deploy
sudo rm resd.sh
sudo docker run -d -p 9090:9090 ega_resmvc
