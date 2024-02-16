#!/bin/sh

count=0
while [ $count -lt 5 ]
do
    java -javaagent:./src/datadogjar/dd-java-agent.jar -XX:FlightRecorderOptions=stackdepth=256 -Ddd.service=authservice -Ddd.version=1.0 -Ddd.profiling.enabled=true -jar app.jar
    if [ $? -ne 0 ]
    then
        count=`expr $count + 1`
        echo "application failed! retrying in 30 seconds"
        sleep 30
    fi
done

echo "Too many restarts. Something is wrong!"

exit 1
