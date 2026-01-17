# Spring Boot Template

Minimal **Spring Boot 4** project template with **Java 25**, Docker support, and CI-ready setup.

This repository is intended to be used as a **GitHub Template** to quickly bootstrap new Spring Boot services.

---

## ✨ Features

- Spring Boot **4.x**
- Java **25**
- Minimal dependencies (Web + Actuator)
- Docker support:
    - JVM
    - AOT
    - CDS
    - GraalVM Native
- Docker Compose profiles
- GitHub Actions CI
- No Lombok (pure Java, native-friendly)

---

## 🚀 Quick Start

### Prerequisites

- Docker (recommended)
- Java 25 (only if running without Docker)
- Maven 3.9+

---

### Run with Docker (recommended)

#### Default JVM mode

```bash
make compose-up
```

App runs at:

```
http://localhost:8080
```

Health check:

```
http://localhost:8080/actuator/health
```

---

### Run with Docker profiles

| Mode   | Command             | Port |
|--------|---------------------|------|
| JVM    | make compose-up     | 8080 |
| AOT    | make compose-aot    | 8081 |
| CDS    | make compose-cds    | 8082 |
| Native | make compose-native | 8083 |

Stop containers:

```bash
make compose-down
```

---

## 🐳 Docker Images

Build images directly:

```bash
make docker-build
make docker-build-aot
make docker-build-cds
make docker-build-native
```

Resulting images:

- spring-boot-template:latest
- spring-boot-template:aot
- spring-boot-template:cds
- spring-boot-template:native

---

## 🧪 Run Tests

```bash
mvn test
```

---

## 📁 Project Structure

```
.
├─ docker/
│  ├─ Dockerfile
│  ├─ Dockerfile.aot
│  ├─ Dockerfile.cds
│  ├─ Dockerfile.native
│  └─ docker-compose.yml
├─ src/
│  ├─ main/java
│  └─ test/java
├─ .github/workflows/ci.yml
├─ Makefile
├─ pom.xml
└─ README.md
```

---

## 🧩 Native Build Notes

- Native build is handled via Dockerfile.native
- No Lombok to avoid native/AOT issues
- Image name defaults to Maven artifactId

---

## 🛠️ Customization After Using Template

After clicking **Use this template**, you should:

1. Rename:
    - groupId
    - artifactId
    - package name
2. Update:
    - spring.application.name
    - Docker image name (if desired)
3. Add dependencies as needed:
    - JPA / Mongo
    - Security
    - Kafka / Redis
    - Observability

We can use the script to quickly rename:

```bash
chmod +x scripts/init-project.sh

./scripts/init-project.sh new-project-name
```

---

## 📌 Design Principles

- Minimal by default
- No opinionated libraries
- Docker-first
- Native-ready
- Easy to extend

---

## 📄 License

[MIT](LICENSE)
