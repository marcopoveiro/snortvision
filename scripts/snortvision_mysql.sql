-- SnortVision v0.1 — MySQL 8.0+ Schema
-- Run: mysql -u root -p < snortvision_mysql.sql
-- ──────────────────────────────────────────────────────────────────

CREATE DATABASE IF NOT EXISTS snortvision
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'snortvision'@'%'
  IDENTIFIED BY 'StrongPass123!';    -- ← CHANGE THIS

GRANT ALL PRIVILEGES ON snortvision.* TO 'snortvision'@'%';
FLUSH PRIVILEGES;
USE snortvision;

-- Alerts
CREATE TABLE IF NOT EXISTS alerts (
  id         BIGINT UNSIGNED    AUTO_INCREMENT PRIMARY KEY,
  ts         DATETIME(3)        NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  rule_id    VARCHAR(32),
  msg        VARCHAR(512),
  category   ENUM('DDOS','EXPLOIT','TROJAN','MALWARE','SCAN','POLICY','HUNTING') DEFAULT 'HUNTING',
  severity   ENUM('critical','high','medium','low','info') DEFAULT 'medium',
  src_ip     VARCHAR(45)        NOT NULL,
  dst_ip     VARCHAR(45),
  src_port   SMALLINT UNSIGNED,
  dst_port   SMALLINT UNSIGNED,
  proto      VARCHAR(8),
  country    CHAR(2),
  city       VARCHAR(128),
  action     ENUM('BLOCKED','ALERT') DEFAULT 'ALERT',
  raw        TEXT,
  INDEX idx_ts    (ts),
  INDEX idx_srcip (src_ip),
  INDEX idx_sev   (severity),
  INDEX idx_cat   (category)
) ENGINE=InnoDB ROW_FORMAT=COMPRESSED;

-- Blocklist
CREATE TABLE IF NOT EXISTS blocklist (
  id       INT UNSIGNED   AUTO_INCREMENT PRIMARY KEY,
  ip       VARCHAR(45)    NOT NULL UNIQUE,
  reason   VARCHAR(255),
  added    DATETIME       DEFAULT CURRENT_TIMESTAMP,
  hits     INT UNSIGNED   DEFAULT 0,
  active   TINYINT(1)     DEFAULT 1,
  source   ENUM('Manual','Auto','DDoS') DEFAULT 'Manual',
  INDEX idx_active (active)
) ENGINE=InnoDB;

-- Snort rules (managed by Rules Manager)
CREATE TABLE IF NOT EXISTS rules (
  id       INT UNSIGNED   AUTO_INCREMENT PRIMARY KEY,
  sid      VARCHAR(16),
  gid      TINYINT UNSIGNED DEFAULT 1,
  rev      SMALLINT UNSIGNED DEFAULT 1,
  enabled  TINYINT(1)     DEFAULT 1,
  action   VARCHAR(16)    DEFAULT 'alert',
  proto    VARCHAR(8)     DEFAULT 'TCP',
  src      VARCHAR(64)    DEFAULT 'any',
  sport    VARCHAR(32)    DEFAULT 'any',
  dir      VARCHAR(4)     DEFAULT '->',
  dst      VARCHAR(64)    DEFAULT '$HOME_NET',
  dport    VARCHAR(32)    DEFAULT 'any',
  msg      VARCHAR(512),
  cat      VARCHAR(16),
  sev      VARCHAR(16),
  hits     INT UNSIGNED   DEFAULT 0
) ENGINE=InnoDB;

-- iptables audit log
CREATE TABLE IF NOT EXISTS iptables_log (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ts         DATETIME DEFAULT CURRENT_TIMESTAMP,
  op         VARCHAR(8),
  rule       VARCHAR(128),
  applied_by VARCHAR(64)
) ENGINE=InnoDB;

-- Default rules
INSERT IGNORE INTO rules (sid,gid,rev,enabled,action,proto,src,sport,dir,dst,dport,msg,cat,sev) VALUES
('2001219',1,20,1,'alert','TCP','any','any','->','$HOME_NET','22',   'ET SCAN Potential SSH Scan',          'SCAN',   'medium'),
('2021001',1,5, 1,'drop', 'TCP','any','any','->','any',      '80',  'ET DOS LOIC HTTP Flood',              'DDOS',   'critical'),
('2013028',1,8, 1,'drop', 'TCP','any','any','->','$HOME_NET','any', 'ET TROJAN Win32/Zbot Checkin',        'TROJAN', 'critical'),
('2008435',1,3, 1,'drop', 'TCP','any','any','->','any',      '80',  'ET EXPLOIT CVE-2014-6271 Shellshock', 'EXPLOIT','critical'),
('2019714',1,12,1,'alert','TCP','any','any','->','$HOME_NET','any', 'ET SCAN Nmap Detected',               'SCAN',   'low'),
('2030171',1,2, 1,'drop', 'TCP','any','any','->','$HOME_NET','443', 'ET MALWARE Win32/Dridex SSL',         'MALWARE','critical');

-- ── Useful queries ──────────────────────────────────────────────────────────
-- Top attackers (last 24h):
-- SELECT src_ip, country, COUNT(*) hits, SUM(action='BLOCKED') blocked
-- FROM alerts WHERE ts > NOW() - INTERVAL 24 HOUR
-- GROUP BY src_ip, country ORDER BY hits DESC LIMIT 20;
--
-- Alert volume by severity (last 7 days):
-- SELECT severity, COUNT(*) n FROM alerts
-- WHERE ts > NOW() - INTERVAL 7 DAY GROUP BY severity;
--
-- Active blocklist:
-- SELECT ip, reason, source, hits FROM blocklist WHERE active=1 ORDER BY hits DESC;
