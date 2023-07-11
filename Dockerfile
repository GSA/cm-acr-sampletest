
# --- create the jar file
#FROM maven:3.6.3-openjdk-11 as java-builder
FROM adoptopenjdk/maven-openjdk11 as java-builder
RUN apt-get update && apt-get -y upgrade
RUN mkdir -p /app
WORKDIR /app
COPY ./src /app/src
COPY ./pom.xml /app/
RUN mvn -DskipTests clean install verify

# --- copy jar file from previous stage
#FROM openjdk:8-jre-alpine
FROM adoptopenjdk/openjdk11:jre-11.0.6_10-alpine
RUN apk update && apk upgrade --available
RUN adduser -D -s /bin/sh acr
WORKDIR /home/acr
COPY --from=java-builder /app/target/*.jar app.jar
RUN chown acr app.jar
USER acr
COPY startup.sh /home/acr
CMD [ "sh", "startup.sh" ]