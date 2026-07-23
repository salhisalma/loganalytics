# Intelligent Log Analytics & Threat Detection Engine

A SIEM-style (Security Information and Event Management) cybersecurity monitoring platform.
It collects application logs in real time, parses them into structured data, runs rule-based
threat detection over them, raises alerts, stores everything in a relational database, and
presents it all on a live analyst dashboard.

Built as part of a 4-week internship project, following the *Intelligent Log Analytics &
Threat Detection Engine* internship guide.

---

## 1. What This System Does

| Capability | What it does |
|---|---|
| Real-time log collection | A scheduled service continuously reads application logs produced by Log4j2. |
| Log parsing engine | Extracts timestamp, IP address, request URL, HTTP method, status code, and severity from each line. |
| Threat detection engine | Applies rules for brute-force logins, SQL injection payloads, suspicious URLs, request flooding, and repeated failed access. |
| Alert management | Creates a security alert whenever activity crosses a defined threshold; alerts can be marked as resolved from the dashboard. |
| Dashboard analytics | Shows a live log stream, alerts, threat statistics, log distribution, and top source IPs. |
| Persistence | Stores logs, alerts, and users in a relational database (MySQL) via JPA/Hibernate. |

### User roles
- **Regular user** — registers, logs in, and performs activity (including simulated attacks) from a user panel. Their actions generate the logs the engine analyzes.
- **Analyst / admin** — signs in to an admin dashboard to watch the live log stream, review threat alerts, resolve them, and read security metrics.

---

## 2. Tech Stack

| Layer | Technology |
|---|---|
| Language | Java 17 |
| Framework | Spring Boot 3.1.5, Spring MVC |
| Security | Spring Security (BCrypt password hashing, role-based route protection) |
| Logging | Log4j2 (SLF4J API) |
| Persistence | Spring Data JPA + Hibernate |
| Database | **MySQL** (via XAMPP) — migrated from the H2 in-memory default so data survives restarts |
| View | Thymeleaf, HTML, CSS, Bootstrap |
| Client logic | JavaScript (fetch/polling), Chart.js-free custom bar/pie visualizations |
| Build | Maven |

---

## 3. System Architecture

```
BROWSER (client)
  index / login / register / user & admin dashboards
  dashboard.js / user-dashboard.js -> poll REST API every few seconds
        |
        v
CONTROLLER LAYER
  PageController      -> serves Thymeleaf HTML pages
  AuthController       -> register / login / logout
  ActivityController    -> user activity + attack simulation
  DashboardController    -> JSON APIs for the admin dashboard + alert resolution
        |
        v
SERVICE LAYER
  UserService   LogService   ThreatAlertService
        |                          |
        v                          v
THREAT DETECTION ENGINE      REPOSITORY LAYER
(rule-based, in-memory        Spring Data JPA interfaces
 sliding-window state)        LogEntry / ThreatAlert / AppUser
        |                          |
        | raises alerts            v
        +----------------->  DATABASE (MySQL)
                             logs · alerts · users
                                    ^
                                    | reads log files (scheduled poller)
                             LOGGING SUBSYSTEM
                             (Log4j2 writes logs/app.log to disk)
```

### Request lifecycle (end to end)
1. A user performs an action in the browser (e.g. a login attempt or a simulated SQL-injection request).
2. The relevant controller handles the request; `ActivityLogger` writes a structured line to `logs/app.log` via Log4j2.
3. On its schedule (every 5 seconds), `LogCollectionService` reads the new log lines.
4. `LogParser` turns each raw line into a `LogEntry` (IP, URL, method, status, timestamp, severity).
5. `ThreatDetectionEngine` evaluates the entry against every rule.
6. If a rule matches, a `ThreatAlert` is created and saved to the database.
7. The `LogEntry` (and any alert) is persisted via the repositories.
8. The admin dashboard polls the `DashboardController` API and displays the newest logs, alerts, and metrics — updating without a page refresh.

---

## 4. Detection Rules

| Rule | Trigger | Severity |
|---|---|---|
| Brute force | ≥ 5 failed logins (401 on `/login`) from one IP | HIGH |
| SQL injection | Known SQLi tokens in the URL (`OR 1=1`, `UNION SELECT`, `DROP TABLE`...) | CRITICAL |
| Suspicious URL | Path traversal, `/etc/passwd`, `<script>`, `.php`, etc. | MEDIUM |
| Request flood | ≥ 20 requests from one IP within 10 seconds | MEDIUM |
| Repeated failed access | ≥ 10 non-2xx responses from one IP within 60 seconds | MEDIUM |

All five rules from the guide's detection table are implemented (the guide's own reference
implementation only covers four; this project implements all five, including *repeated failed
access*).

---

## 5. Project Structure

```
src/main/java/com/loganalytics/
├── LogAnalyticsApplication.java     # Spring Boot entry point (@EnableScheduling)
├── model/                            # JPA entities
│   ├── LogEntry.java
│   ├── ThreatAlert.java              # includes `resolved` flag
│   └── AppUser.java
├── repository/                       # Spring Data JPA interfaces
│   ├── LogEntryRepository.java
│   ├── ThreatAlertRepository.java
│   └── AppUserRepository.java
├── service/                          # business logic
│   ├── LogService.java
│   ├── ThreatAlertService.java
│   ├── UserService.java
│   ├── ActivityLogger.java
│   ├── AppUserDetailsService.java
│   └── LogCollectionService.java     # scheduled log-file poller
├── engine/
│   ├── LogParser.java                 # regex extraction
│   └── ThreatDetectionEngine.java     # 5 detection rules
├── controller/
│   ├── AuthController.java
│   ├── ActivityController.java        # incl. 5 attack-simulation endpoints
│   ├── DashboardController.java       # incl. alert-resolve endpoint
│   └── PageController.java
├── dto/
│   ├── LoginRequest.java
│   ├── RegisterRequest.java
│   └── ApiResponse.java
└── config/
    ├── SecurityConfig.java
    ├── CustomAuthenticationSuccessHandler.java
    └── DataInitializer.java           # seeds demo admin + user

src/main/resources/
├── application.properties             # MySQL connection config
├── log4j2.xml
├── templates/                          # Thymeleaf pages
│   ├── index.html, login.html, register.html
│   ├── user-dashboard.html, admin-dashboard.html
└── static/
    ├── css/dashboard.css, css/user-dashboard.css
    └── js/dashboard.js, js/user-dashboard.js

src/test/java/com/loganalytics/engine/
├── LogParserTest.java
└── ThreatDetectionEngineTest.java
```

---

## 6. Before You Start

### Tools required
- JDK 17 (Temurin/OpenJDK) — verify with `java -version`
- Apache Maven 3.9+ — verify with `mvn -version`
- MySQL (this project uses **XAMPP**'s bundled MySQL) — verify XAMPP's MySQL service is running
- Git

### Database setup (XAMPP / MySQL)
1. Open the XAMPP control panel, start **MySQL** (Apache is only needed if you want to browse via phpMyAdmin).
2. Go to `http://localhost/phpmyadmin`, create a database named `loganalytics`.
   (Not strictly required — `application.properties` uses `createDatabaseIfNotExist=true`, so the app will create it automatically on first run if it doesn't already exist.)
3. Hibernate creates the three tables (`app_users`, `log_entries`, `threat_alerts`) automatically on startup via `spring.jpa.hibernate.ddl-auto=update`.

---

## 7. Running the Project

```bash
mvn clean package
java -jar target/loganalytics-0.0.1-SNAPSHOT.jar
```

Then open **http://localhost:8080**

### Default seeded accounts
| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | ROLE_ADMIN |
| `user` | `user123` | ROLE_USER |

---

## 8. How to Demo & Verify the System

1. Start the app and open the admin dashboard (`admin` / `admin123`) — note the baseline counts.
2. Log in and out a few times as `user` — watch the log stream grow on the admin dashboard.
3. From the user dashboard, trigger each simulated attack (or via curl):
   ```bash
   curl -X POST http://localhost:8080/api/activity/simulate/bruteforce
   curl -X POST http://localhost:8080/api/activity/simulate/sqli
   curl -X POST http://localhost:8080/api/activity/simulate/flood
   curl -X POST http://localhost:8080/api/activity/simulate/suspicious
   curl -X POST http://localhost:8080/api/activity/simulate/failedaccess
   ```
4. Within one poll cycle (~5 seconds), the corresponding alert appears on the admin dashboard:
   - Brute force → **HIGH**
   - SQL injection → **CRITICAL**
   - Suspicious URL → **MEDIUM**
   - Request flood → **MEDIUM**
   - Repeated failed access → **MEDIUM**
5. Click **Resolve** on an alert in the admin dashboard and confirm the "Active Threats" count decreases.
6. Open phpMyAdmin (`http://localhost/phpmyadmin`) → `loganalytics` database → confirm rows exist in `log_entries` and `threat_alerts`.
7. Restart the application and confirm the data is still there (proves persistence via MySQL, unlike the default in-memory H2 setup).

---

## 9. Running Tests

```bash
mvn test
```

Covers:
- **`LogParserTest`** — regex extraction of timestamp, IP (including IPv6, e.g. Windows'
  loopback `0:0:0:0:0:0:0:1`), method, URL, status, severity; rejects malformed lines.
- **`ThreatDetectionEngineTest`** — all five detection rules, including negative cases
  (e.g. normal traffic and 4/5 failed logins must **not** raise an alert).

---

## 10. Screenshots

*(Add screenshots here: login page, user dashboard with simulator, admin dashboard with live
alerts and charts, phpMyAdmin showing persisted data.)*

---

## 11. Stretch Goals Attempted

- ✅ **Switched the database from H2 to MySQL** (`application.properties` + `mysql-connector-j`
  dependency; no other code changes needed, exactly as the guide describes).
- ✅ **Alert resolution workflow** — beyond the base spec: alerts can be marked resolved from
  the dashboard, with an "Active Threats" counter that reflects only unresolved alerts.
- ✅ **5th detection rule (repeated failed access)** implemented in full, including its own
  simulation endpoint and dedicated tests.

Not yet attempted: Docker/docker-compose, Geo-IP lookups, email alerting, MITRE ATT&CK mapping.

---

## 12. Deliverables Checklist

- [x] Git repository with commit history
- [x] This README (setup steps, architecture summary, screenshots section)
- [x] Runnable JAR (`mvn clean package`) and run instructions
- [ ] Short demo video/recording triggering each detection rule

---

## Glossary

| Term | Meaning |
|---|---|
| SIEM | Security Information and Event Management — centralizes logs, detects events, and raises alerts. |
| SOC | Security Operations Center — the team/room that monitors and responds to security events. |
| Blue team | Defenders who monitor and protect systems (vs. red team attackers). |
| Brute force | Repeated login guesses to crack credentials. |
| SQL injection (SQLi) | Injecting SQL through inputs to manipulate a database query. |
| Log4j2 | A Java logging framework used to emit structured application logs. |
| JPA / Hibernate | Java Persistence API and its most common implementation for mapping objects to tables. |
| Thymeleaf | A server-side template engine that renders HTML from Java model data. |
| Repository | A Spring Data interface that provides database access with minimal code. |
| Threshold | A configured limit that, when crossed, triggers a detection rule. |

---

Based on the *Intelligent Log Analytics and Threat Detection Engine* internship project guide.
Use only in authorized, local environments — attack simulation endpoints only ever write
representative log lines locally; they never perform real attacks.
