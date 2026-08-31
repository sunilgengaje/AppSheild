# Use OpenJDK for the runtime
FROM openjdk:17-jdk-slim

# Set the working directory
WORKDIR /app

# Copy the build artifact (assuming a fat JAR is built)
COPY build/libs/backend-all.jar /app/appshield-backend.jar

# Expose the telemetry and license port
EXPOSE 8080

# Run the backend
ENTRYPOINT ["java", "-jar", "/app/appshield-backend.jar"]
