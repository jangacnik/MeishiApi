FROM eclipse-temurin:21-jdk AS build
WORKDIR /app

COPY gradlew ./
COPY gradle gradle
COPY build.gradle.kts settings.gradle.kts gradle.properties ./
RUN ./gradlew --no-daemon dependencies

COPY src src
RUN ./gradlew --no-daemon installDist

FROM eclipse-temurin:21-jre
RUN useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin meishi
WORKDIR /app
COPY --from=build --chown=meishi:meishi /app/build/install/MeishiApi ./
USER 10001

ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=70"

EXPOSE 8080
ENTRYPOINT ["./bin/MeishiApi"]
