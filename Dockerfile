#FROM openjdk:8-jdk-alpine
#ARG JAR_FILE=target/*.jar
#COPY ${JAR_FILE} TokenService.jar
#ENTRYPOINT ["java","-jar","/TokenService.jar"]

FROM openjdk:8-jdk-alpine
ADD target/auth-service.jar auth-service.jar
EXPOSE 8083
ENTRYPOINT ["java","-jar","auth-service.jar"]
