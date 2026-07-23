package com.loganalytics.repository;

import com.loganalytics.model.LogEntry;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface LogEntryRepository extends JpaRepository<LogEntry, Long> {

    List<LogEntry> findTop50ByOrderByTimestampDesc();

    long countByStatusCode(int statusCode);

    List<LogEntry> findByIpAddressAndStatusCode(String ip, int statusCode);

    @Query("SELECT COUNT(l) FROM LogEntry l WHERE l.timestamp >= :since")
    long countSince(@Param("since") LocalDateTime since);

    // Dashboard Statistics

    @Query("""
            SELECT l.ipAddress, COUNT(l)
            FROM LogEntry l
            GROUP BY l.ipAddress
            ORDER BY COUNT(l) DESC
            """)
    List<Object[]> getTopSourceIPs();

    @Query("""
            SELECT l.httpMethod, COUNT(l)
            FROM LogEntry l
            GROUP BY l.httpMethod
            """)
    List<Object[]> getMethodDistribution();

    @Query("""
            SELECT l.statusCode, COUNT(l)
            FROM LogEntry l
            GROUP BY l.statusCode
            ORDER BY l.statusCode
            """)
    List<Object[]> getStatusDistribution();

    @Query("""
            SELECT l.severity, COUNT(l)
            FROM LogEntry l
            GROUP BY l.severity
            """)
    List<Object[]> getSeverityDistribution();

    @Query("""
            SELECT DATE(l.timestamp), COUNT(l)
            FROM LogEntry l
            GROUP BY DATE(l.timestamp)
            ORDER BY DATE(l.timestamp)
            """)
    List<Object[]> getLogsPerDay();

}