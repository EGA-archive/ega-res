#!/bin/bash
SERVICE_NAME=ReEncryptionService
PATH_TO_JAR=/ReEncryptionMVC-0.0.1-SNAPSHOT.jar
PROCESSCNT=$(ps x | grep -v grep | grep -c "ReEncryptionMVC-0.0.1-SNAPSHOT.jar")
#PID=$(ps aux | grep "ReEncryptionMVC-0.0.1-SNAPSHOT.jar" | grep -v grep | awk '{print $2}')
if [ $PROCESSCNT == 0 ]; then
    echo "Starting $SERVICE_NAME ..."
    nohup java -jar $PATH_TO_JAR 2>> /dev/null >> /dev/null &
    echo "$SERVICE_NAME started ..."
#else
#    echo "$SERVICE_NAME is already running ..."
fi
