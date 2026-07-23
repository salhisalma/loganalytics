package com.loganalytics.service;

import com.loganalytics.engine.LogParser;
import com.loganalytics.engine.ThreatDetectionEngine;
import com.loganalytics.model.LogEntry;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import java.io.File;
import java.io.RandomAccessFile;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@Service
public class LogCollectionService {

    private final LogParser parser;
    private final LogService logService;
    private final ThreatDetectionEngine detectionEngine;

    @Value("${app.log.file}")
    private String logFile;

    private long lastPosition = 0;

    // FIX: lastPosition used to live only in memory, so it reset to 0 on every
    // app restart. That made the collector re-read the ENTIRE app.log from byte 0
    // each time, re-inserting old log lines and re-triggering already-fired alerts
    // with a fresh LocalDateTime.now() — which is why alert/log timestamps looked
    // like they kept jumping to "now" instead of keeping their original date.
    // We now persist the position to a small sidecar file next to app.log.
    private Path positionMarkerPath;

    public LogCollectionService(LogParser parser, LogService logService,
                                ThreatDetectionEngine detectionEngine) {
        this.parser = parser;
        this.logService = logService;
        this.detectionEngine = detectionEngine;
    }

    @PostConstruct
    public void init() {
        positionMarkerPath = Path.of(logFile + ".pos");
        if (Files.exists(positionMarkerPath)) {
            try {
                String content = Files.readString(positionMarkerPath).trim();
                if (!content.isEmpty()) {
                    lastPosition = Long.parseLong(content);
                }
            } catch (IOException | NumberFormatException e) {
                lastPosition = 0;
            }
        }
    }

    @Scheduled(fixedDelayString = "${app.log.poll-ms:5000}")
    public void collect() {
        File file = new File(logFile);
        if (!file.exists()) {
            return;
        }

        // FIX: if app.log was cleared/rotated since last run, the saved position
        // would now be past the end of the (smaller) file. Reset to 0 instead of
        // letting raf.seek() land past EOF.
        if (lastPosition > file.length()) {
            lastPosition = 0;
        }

        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            raf.seek(lastPosition);

            String line;
            while ((line = raf.readLine()) != null) {
                String logLine = new String(line.getBytes("ISO-8859-1"), "UTF-8");

                LogEntry entry = parser.parse(logLine);
                if (entry != null) {
                    logService.save(entry);
                    detectionEngine.analyze(entry);
                }
            }

            lastPosition = raf.getFilePointer();
            persistPosition();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void persistPosition() {
        try {
            Files.writeString(positionMarkerPath, String.valueOf(lastPosition));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}