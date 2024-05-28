-- Script to create JOBS and EVENTS tables in SQLite3
-- Run in root mode to access db in /etc/yalt/yalt.db

-- Create the JOBS table
CREATE TABLE JOBS (
    jobid INTEGER UNSIGNED,
    uid INTEGER,
    gid INTEGER,
    PRIMARY KEY (jobid)
);

-- Create the EVENTS table
CREATE TABLE EVENTS (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    jobid INTEGER UNSIGNED,
    ts BIGINT,
    pid INTEGER,
    uid INTEGER,
    ret INTEGER,
    flags INTEGER,
    comm VARCHAR(16),
    file_path TEXT,
    keep BOOLEAN,
    mime_type VARCHAR(255) DEFAULT NULL,
    link_path VARCHAR(255) DEFAULT NULL,
    FOREIGN KEY (jobid) REFERENCES JOBS(jobid)
);
