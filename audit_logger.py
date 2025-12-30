"""
SecureIT - Audit Logger Module
Handles audit logging to SQLite database
"""

import sqlite3
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import getpass


class AuditLogger:
    """
    Manages audit logging for all encryption/decryption operations
    """
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize audit logger
        
        Args:
            db_path: Path to SQLite database (defaults to AppData folder)
        """
        if db_path is None:
            # Use AppData folder
            appdata = os.getenv('APPDATA')
            secureit_dir = os.path.join(appdata, 'SecureIT')
            os.makedirs(secureit_dir, exist_ok=True)
            db_path = os.path.join(secureit_dir, 'audit.db')
            
        self.db_path = db_path
        self._initialize_database()
        
    def _initialize_database(self):
        """Create database and tables if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS AuditLog (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                operation_type TEXT NOT NULL CHECK(operation_type IN ('ENCRYPT', 'DECRYPT')),
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('SUCCESS', 'FAILED')),
                error_message TEXT,
                secure_delete INTEGER NOT NULL DEFAULT 0
            )
        ''')
        
        # Create indexes for faster queries
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp ON AuditLog(timestamp)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_operation ON AuditLog(operation_type)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_status ON AuditLog(status)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_username ON AuditLog(username)
        ''')
        
        conn.commit()
        conn.close()
        
    def log_operation(self, operation: str, filename: str, filepath: str,
                     file_size: int, status: str, error_message: Optional[str] = None,
                     secure_delete: bool = False) -> int:
        """
        Log an encryption/decryption operation
        
        Args:
            operation: 'ENCRYPT' or 'DECRYPT'
            filename: Name of the file
            filepath: Full path to the file
            file_size: Size of file in bytes
            status: 'SUCCESS' or 'FAILED'
            error_message: Error description if status is FAILED
            secure_delete: Whether secure deletion was performed
            
        Returns:
            log_id of the created entry
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        timestamp = datetime.utcnow().isoformat() + 'Z'
        username = getpass.getuser()
        
        cursor.execute('''
            INSERT INTO AuditLog 
            (timestamp, username, operation_type, filename, file_path, 
             file_size, status, error_message, secure_delete)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, username, operation, filename, filepath, 
              file_size, status, error_message, int(secure_delete)))
        
        log_id = cursor.lastrowid
        
        conn.commit()
        conn.close()
        
        return log_id
        
    def get_logs(self, limit: int = 100, offset: int = 0,
                operation: Optional[str] = None,
                status: Optional[str] = None,
                start_date: Optional[str] = None,
                end_date: Optional[str] = None,
                search_term: Optional[str] = None) -> List[Dict]:
        """
        Retrieve audit logs with optional filters
        
        Args:
            limit: Maximum number of records to return
            offset: Number of records to skip
            operation: Filter by operation type
            status: Filter by status
            start_date: Filter by start date (ISO format)
            end_date: Filter by end date (ISO format)
            search_term: Search in filename
            
        Returns:
            List of log entries as dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = 'SELECT * FROM AuditLog WHERE 1=1'
        params = []
        
        if operation:
            query += ' AND operation_type = ?'
            params.append(operation)
            
        if status:
            query += ' AND status = ?'
            params.append(status)
            
        if start_date:
            query += ' AND timestamp >= ?'
            params.append(start_date)
            
        if end_date:
            query += ' AND timestamp <= ?'
            params.append(end_date)
            
        if search_term:
            query += ' AND filename LIKE ?'
            params.append(f'%{search_term}%')
            
        query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        logs = []
        for row in rows:
            logs.append({
                'log_id': row['log_id'],
                'timestamp': row['timestamp'],
                'username': row['username'],
                'operation_type': row['operation_type'],
                'filename': row['filename'],
                'file_path': row['file_path'],
                'file_size': row['file_size'],
                'status': row['status'],
                'error_message': row['error_message'],
                'secure_delete': bool(row['secure_delete'])
            })
            
        conn.close()
        return logs
        
    def get_statistics(self) -> Dict:
        """
        Get audit log statistics
        
        Returns:
            Dictionary with statistics
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Total operations
        cursor.execute('SELECT COUNT(*) FROM AuditLog')
        stats['total_operations'] = cursor.fetchone()[0]
        
        # Successful operations
        cursor.execute("SELECT COUNT(*) FROM AuditLog WHERE status = 'SUCCESS'")
        stats['successful_operations'] = cursor.fetchone()[0]
        
        # Failed operations
        cursor.execute("SELECT COUNT(*) FROM AuditLog WHERE status = 'FAILED'")
        stats['failed_operations'] = cursor.fetchone()[0]
        
        # Encryptions
        cursor.execute("SELECT COUNT(*) FROM AuditLog WHERE operation_type = 'ENCRYPT'")
        stats['total_encryptions'] = cursor.fetchone()[0]
        
        # Decryptions
        cursor.execute("SELECT COUNT(*) FROM AuditLog WHERE operation_type = 'DECRYPT'")
        stats['total_decryptions'] = cursor.fetchone()[0]
        
        # Total data processed
        cursor.execute("SELECT SUM(file_size) FROM AuditLog WHERE status = 'SUCCESS'")
        result = cursor.fetchone()[0]
        stats['total_bytes_processed'] = result if result else 0
        
        conn.close()
        return stats
        
    def export_to_csv(self, output_path: str, **filters):
        """
        Export audit logs to CSV file
        
        Args:
            output_path: Path to output CSV file
            **filters: Optional filters (same as get_logs)
        """
        import csv
        
        logs = self.get_logs(limit=10000, **filters)
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            if not logs:
                return
                
            writer = csv.DictWriter(f, fieldnames=logs[0].keys())
            writer.writeheader()
            writer.writerows(logs)
            
    def clear_old_logs(self, days: int = 365):
        """
        Clear audit logs older than specified days
        
        Args:
            days: Number of days to retain
        """
        from datetime import timedelta
        
        cutoff_date = (datetime.utcnow() - timedelta(days=days)).isoformat() + 'Z'
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM AuditLog WHERE timestamp < ?', (cutoff_date,))
        deleted_count = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        return deleted_count
        
    def verify_integrity(self) -> bool:
        """
        Verify database integrity
        
        Returns:
            True if database is intact
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('PRAGMA integrity_check')
            result = cursor.fetchone()[0]
            
            conn.close()
            
            return result == 'ok'
        except Exception:
            return False


# Test function
def test_audit_logger():
    """Test audit logger functionality"""
    import tempfile
    
    # Create temporary database
    temp_db = os.path.join(tempfile.gettempdir(), 'test_audit.db')
    
    try:
        logger = AuditLogger(temp_db)
        
        # Test logging
        print("Testing audit logging...")
        log_id = logger.log_operation(
            operation='ENCRYPT',
            filename='test.txt',
            filepath='/path/to/test.txt',
            file_size=1024,
            status='SUCCESS',
            secure_delete=True
        )
        print(f"Logged with ID: {log_id}")
        
        # Test retrieval
        print("\nRetrieving logs...")
        logs = logger.get_logs(limit=10)
        for log in logs:
            print(f"  {log['timestamp']} - {log['operation_type']} - {log['filename']} - {log['status']}")
            
        # Test statistics
        print("\nStatistics:")
        stats = logger.get_statistics()
        for key, value in stats.items():
            print(f"  {key}: {value}")
            
        # Test export
        csv_file = os.path.join(tempfile.gettempdir(), 'test_export.csv')
        logger.export_to_csv(csv_file)
        print(f"\nExported to: {csv_file}")
        
        # Test integrity
        print(f"\nDatabase integrity: {logger.verify_integrity()}")
        
        print("\nTest passed!")
        
    finally:
        # Cleanup
        if os.path.exists(temp_db):
            os.remove(temp_db)


if __name__ == "__main__":
    test_audit_logger()