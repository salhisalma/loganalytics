package com.loganalytics.service;

import com.loganalytics.model.LogEntry;
import com.loganalytics.repository.LogEntryRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;  // ← ADD THIS IMPORT
import java.time.LocalDateTime;
import java.util.List;

@Service
public class LogService {
    private final LogEntryRepository logRepository;
    
    public LogService(LogEntryRepository logRepository) {
        this.logRepository = logRepository;
    }
    
    @Transactional  // ← ADD THIS ANNOTATION
    public LogEntry save(LogEntry entry) {
        LogEntry saved = logRepository.save(entry);
        logRepository.flush();  // ← ADD THIS LINE TO FORCE SAVE
        return saved;
    }
    
    public List<LogEntry> recent() { 
        return logRepository.findTop50ByOrderByTimestampDesc(); 
    }
    
    public long total() { 
        return logRepository.count(); 
    }
    
    public long failedRequests() { 
        return logRepository.countByStatusCode(401); 
    }
    
    public long countSince(LocalDateTime since) { 
        return logRepository.countSince(since); 
    }
}