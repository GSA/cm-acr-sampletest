FROM 752281881774.dkr.ecr.us-east-1.amazonaws.com/odp_openjdk17:20230827
RUN mkdir -p ./src 
COPY ./src ./src
COPY ./pom.xml ./
RUN mvn -DskipTests clean install verify

# --- copy jar file from previous stage
RUN cp ./target/*.jar app.jar
COPY startup.sh ./
CMD [ "sh", "startup.sh" ]






