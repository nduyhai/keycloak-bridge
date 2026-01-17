# syntax=docker/dockerfile:1.7

# =========================
# 1) Build stage (Maven)
# =========================
FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /workspace

# Cache dependencies
COPY pom.xml .
RUN --mount=type=cache,target=/root/.m2 \
    mvn -q -DskipTests dependency:go-offline

# Build app (use Maven profile "cds" if you have it; otherwise drop -Pcds)
COPY src ./src
RUN --mount=type=cache,target=/root/.m2 \
    mvn -q -DskipTests -Pcds package


# =========================
# 2) CDS training stage
#    (start app once, then exit)
# =========================
FROM eclipse-temurin:25-jre AS cds-train
WORKDIR /app

COPY --from=build /workspace/target/*.jar /app/app.jar

# Use Spring profile "cds" to avoid hanging during training.
# You should have src/main/resources/application-cds.yml (or .properties) with:
#   spring.main.web-application-type=none
#   spring.main.keep-alive=false
#   spring.task.scheduling.enabled=false
ENV SPRING_PROFILES_ACTIVE=cds

# (Optional) extra safety flags to avoid port binding and ensure eager init
ENV JAVA_TOOL_OPTIONS="-Dspring.main.web-application-type=none -Dspring.main.keep-alive=false -Dspring.main.lazy-initialization=false"

# 2.1) Dump loaded class list
RUN java -Xshare:off \
    -XX:DumpLoadedClassList=/app/classlist.txt \
    -jar /app/app.jar || true

# 2.2) Build the app CDS archive
RUN java -Xshare:dump \
    -XX:SharedClassListFile=/app/classlist.txt \
    -XX:SharedArchiveFile=/app/app-cds.jsa


# =========================
# 3) Runtime stage
# =========================
FROM eclipse-temurin:25-jre
WORKDIR /app

# non-root user
RUN useradd -r -u 10001 appuser
USER appuser

COPY --from=build /workspace/target/*.jar /app/app.jar
COPY --from=cds-train /app/app-cds.jsa /app/app-cds.jsa

EXPOSE 8080

# Show CDS usage in logs + force using our app archive
ENV JAVA_OPTS="-Xlog:cds"
ENTRYPOINT ["sh", "-c", "java -Xshare:on -XX:SharedArchiveFile=/app/app-cds.jsa $JAVA_OPTS -jar /app/app.jar"]
