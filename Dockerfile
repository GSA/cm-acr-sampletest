FROM 752281881774.dkr.ecr.us-east-1.amazonaws.com/odp_openjdk17:20230924
RUN mkdir -p ./src 
COPY ./src ./src
COPY ./pom.xml ./
RUN mvn -DskipTests clean install verify
RUN find $M2_HOME/ -iname '*.jar'
RUN find /home/gsa-user/.m2/ -iname '*.jar'
RUN rm -rf /home/gsa-user/.m2/repository
RUN find /home/gsa-user/.m2/ -iname '*.jar'
RUN /usr/bin/jar tvf /home/gsa-user/target/auth-service.jar

# --- copy jar file from previous stage
RUN cp ./target/*.jar app.jar
COPY startup.sh ./
CMD [ "sh", "startup.sh" ]






