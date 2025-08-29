import sqlite3
import json
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple

class DatabaseManager:
    def __init__(self, db_path: str = 'osint_results.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """데이터베이스 테이블 초기화"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 프로젝트 테이블 생성
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                color TEXT DEFAULT '#4fd1c7',
                status TEXT DEFAULT 'active'
            )
        ''')
        
        # 스캔 결과 테이블에 프로젝트 ID 컬럼 추가
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER,
                domain TEXT,
                subdomain TEXT,
                ip_address TEXT,
                ports TEXT,
                services TEXT,
                vulnerabilities TEXT,
                poc_codes TEXT,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects (id)
            )
        ''')
        
        # 기본 프로젝트 생성
        cursor.execute('SELECT COUNT(*) FROM projects')
        if cursor.fetchone()[0] == 0:
            cursor.execute('''
                INSERT INTO projects (name, description, color) 
                VALUES (?, ?, ?)
            ''', ('기본 프로젝트', 'OSINT 스캔 결과를 저장하는 기본 프로젝트입니다.', '#4fd1c7'))
        
        conn.commit()
        conn.close()
    
    def save_scan_results(self, domain: str, results: Dict[str, Any], project_id: Optional[int] = None):
        """스캔 결과를 데이터베이스에 저장"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 프로젝트 ID가 없으면 기본 프로젝트 사용
        if project_id is None:
            cursor.execute('SELECT id FROM projects WHERE name = ? LIMIT 1', ('기본 프로젝트',))
            result = cursor.fetchone()
            project_id = result[0] if result else 1
        
        for subdomain, data in results.items():
            cursor.execute('''
                INSERT INTO scan_results 
                (project_id, domain, subdomain, ip_address, ports, services, vulnerabilities, poc_codes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                project_id,
                domain,
                subdomain,
                data.get('ip', ''),
                json.dumps(data.get('ports', [])),
                json.dumps(data.get('services', [])),
                json.dumps(data.get('cves', [])),
                json.dumps(data.get('poc_codes', []))
            ))
        
        # 프로젝트 업데이트 날짜 갱신
        cursor.execute('''
            UPDATE projects SET updated_date = CURRENT_TIMESTAMP WHERE id = ?
        ''', (project_id,))
        
        conn.commit()
        conn.close()
    
    # 프로젝트 관리 메서드
    def get_all_projects(self) -> List[Dict[str, Any]]:
        """모든 프로젝트 목록 조회"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT p.*, COUNT(sr.id) as scan_count 
            FROM projects p 
            LEFT JOIN scan_results sr ON p.id = sr.project_id 
            GROUP BY p.id 
            ORDER BY p.updated_date DESC
        ''')
        
        projects = []
        for row in cursor.fetchall():
            projects.append({
                'id': row[0],
                'name': row[1],
                'description': row[2],
                'created_date': row[3],
                'updated_date': row[4],
                'color': row[5],
                'status': row[6],
                'scan_count': row[7]
            })
        
        conn.close()
        return projects
    
    def create_project(self, name: str, description: str = '', color: str = '#4fd1c7') -> int:
        """새 프로젝트 생성"""
        if not name:
            raise ValueError('Project name is required')
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO projects (name, description, color) 
            VALUES (?, ?, ?)
        ''', (name, description, color))
        project_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return project_id
    
    def update_project(self, project_id: int, name: Optional[str] = None, 
                      description: Optional[str] = None, color: Optional[str] = None, 
                      status: Optional[str] = None) -> bool:
        """프로젝트 정보 업데이트"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE projects 
            SET name = COALESCE(?, name), 
                description = COALESCE(?, description), 
                color = COALESCE(?, color),
                status = COALESCE(?, status),
                updated_date = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (name, description, color, status, project_id))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        return success
    
    def delete_project(self, project_id: int) -> Tuple[bool, str]:
        """프로젝트 삭제"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 기본 프로젝트는 삭제할 수 없음
        cursor.execute('SELECT name FROM projects WHERE id = ?', (project_id,))
        result = cursor.fetchone()
        if result and result[0] == '기본 프로젝트':
            conn.close()
            return False, 'Cannot delete default project'
        
        # 프로젝트와 관련된 스캔 결과도 함께 삭제
        cursor.execute('DELETE FROM scan_results WHERE project_id = ?', (project_id,))
        cursor.execute('DELETE FROM projects WHERE id = ?', (project_id,))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        return success, 'Project deleted successfully' if success else 'Project not found'
    
    def get_project_scans(self, project_id: int) -> List[Dict[str, Any]]:
        """특정 프로젝트의 스캔 결과 조회"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM scan_results 
            WHERE project_id = ? 
            ORDER BY scan_date DESC
        ''', (project_id,))
        
        scans = []
        for row in cursor.fetchall():
            scans.append({
                'id': row[0],
                'domain': row[2],
                'subdomain': row[3],
                'ip_address': row[4],
                'ports': json.loads(row[5]) if row[5] else [],
                'services': json.loads(row[6]) if row[6] else [],
                'vulnerabilities': json.loads(row[7]) if row[7] else [],
                'poc_codes': json.loads(row[8]) if row[8] else [],
                'scan_date': row[9]
            })
        
        conn.close()
        return scans
    
    def get_project_by_id(self, project_id: int) -> Optional[Dict[str, Any]]:
        """프로젝트 ID로 프로젝트 정보 조회"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM projects WHERE id = ?', (project_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'id': row[0],
                'name': row[1],
                'description': row[2],
                'created_date': row[3],
                'updated_date': row[4],
                'color': row[5],
                'status': row[6]
            }
        return None
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """스캔 통계 정보 조회"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 전체 스캔 수
        cursor.execute('SELECT COUNT(*) FROM scan_results')
        total_scans = cursor.fetchone()[0]
        
        # 프로젝트별 스캔 수
        cursor.execute('''
            SELECT p.name, COUNT(sr.id) 
            FROM projects p 
            LEFT JOIN scan_results sr ON p.id = sr.project_id 
            GROUP BY p.id, p.name
            ORDER BY COUNT(sr.id) DESC
        ''')
        project_scans = {row[0]: row[1] for row in cursor.fetchall()}
        
        # 최근 스캔 일자
        cursor.execute('SELECT MAX(scan_date) FROM scan_results')
        last_scan = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_scans': total_scans,
            'project_scans': project_scans,
            'last_scan': last_scan
        }