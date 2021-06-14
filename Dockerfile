# --- create the jar file
FROM maven:3.6.3-openjdk-11 as java-builder
RUN mkdir -p /app
WORKDIR /app
COPY ./src /app/src
COPY ./pom.xml /app/
RUN mvn -DskipTests clean install verify

# --- copy jar file from previous stage
FROM openjdk:8-jre-alpine
RUN adduser -D -s /bin/sh acr
WORKDIR /home/acr
COPY --from=java-builder /app/target/*.jar app.jar
RUN chown acr app.jar
USER acr
ENTRYPOINT ["java","-jar","app.jar"]
