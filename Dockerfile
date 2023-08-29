FROM 752281881774.dkr.ecr.us-east-1.amazonaws.com/odp_openjdk17:20230728
RUN mkdir -p ./src 
COPY ./src ./src
COPY ./pom.xml ./
RUN mvn -DskipTests clean install verify
#RUN rm -rf /root/.m2/repository/org/apache/maven/shared/maven-shared-utils/3.1.0/maven-shared-utils-3.1.0.jar
#RUN rm -rf /root/.m2/repository/com/google/guava/guava/28.2-android/guava-28.2-android.jar
RUN find $M2_HOME/ -iname '*.jar'
Run rm -rf /home/gsa-user/.m2/repository
RUN find /home/gsa-user/.m2/ -iname '*.jar'
#Run rm -rf /root/.m2/repository
RUN find /root/.m2/ -iname '*.jar'

# --- copy jar file from previous stage
RUN cp ./target/*.jar app.jar
COPY startup.sh ./
CMD [ "sh", "startup.sh" ]






