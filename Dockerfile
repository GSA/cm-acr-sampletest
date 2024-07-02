ARG image_version="20240616"

FROM 752281881774.dkr.ecr.us-east-1.amazonaws.com/odp_openjdk17:${image_version} as builder

COPY src src
COPY pom.xml ./

RUN mvn -B -DskipTests clean install verify


# --- copy jar file from previous stage
ARG image_version
FROM 752281881774.dkr.ecr.us-east-1.amazonaws.com/odp_openjdk17:${image_version}

RUN mkdir -p ./external-libs/datadogjar/
ADD --chown=gsa-user:gsa-user 'https://dtdg.co/latest-java-tracer' ./external-libs/datadogjar/dd-java-agent.jar

COPY startup.sh ./
COPY --from=builder /home/gsa-user/app/target/auth-service.jar app.jar

CMD [ "sh", "startup.sh" ]
