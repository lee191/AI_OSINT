import sqlite3
import json
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from ..database import DatabaseManager


class ProjectManager:
    """프로젝트 관리 클래스"""
    
    def __init__(self):
        self.db = DatabaseManager()
    
    def create_project(self, name: str, description: str = "", color: str = "#4fd1c7") -> int:
        """새 프로젝트 생성"""
        if not name.strip():
            raise ValueError("프로젝트 이름은 필수입니다.")
        
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        # 중복 이름 체크
        cursor.execute('SELECT COUNT(*) FROM projects WHERE name = ?', (name,))
        if cursor.fetchone()[0] > 0:
            conn.close()
            raise ValueError("이미 존재하는 프로젝트 이름입니다.")
        
        # 프로젝트 생성
        cursor.execute('''
            INSERT INTO projects (name, description, color, created_date, updated_date)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ''', (name.strip(), description.strip(), color))
        
        project_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return project_id
    
    def get_project_by_id(self, project_id: int) -> Optional[Dict[str, Any]]:
        """ID로 프로젝트 조회"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT p.*, COUNT(sr.id) as scan_count,
                   MAX(sr.scan_date) as last_scan_date
            FROM projects p 
            LEFT JOIN scan_results sr ON p.id = sr.project_id 
            WHERE p.id = ?
            GROUP BY p.id
        ''', (project_id,))
        
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
                'status': row[6],
                'scan_count': row[7],
                'last_scan_date': row[8]
            }
        return None
    
    def get_all_projects(self) -> List[Dict[str, Any]]:
        """모든 프로젝트 목록 조회"""
        return self.db.get_all_projects()
    
    def update_project(self, project_id: int, name: str = None, description: str = None, 
                      color: str = None, status: str = None) -> bool:
        """프로젝트 정보 업데이트"""
        if not any([name, description, color, status]):
            return False
        
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        # 존재 여부 체크
        cursor.execute('SELECT COUNT(*) FROM projects WHERE id = ?', (project_id,))
        if cursor.fetchone()[0] == 0:
            conn.close()
            return False
        
        # 중복 이름 체크 (자신 제외)
        if name:
            cursor.execute('SELECT COUNT(*) FROM projects WHERE name = ? AND id != ?', (name, project_id))
            if cursor.fetchone()[0] > 0:
                conn.close()
                raise ValueError("이미 존재하는 프로젝트 이름입니다.")
        
        # 업데이트할 필드 구성
        updates = []
        params = []
        
        if name is not None:
            updates.append('name = ?')
            params.append(name.strip())
        if description is not None:
            updates.append('description = ?')
            params.append(description.strip())
        if color is not None:
            updates.append('color = ?')
            params.append(color)
        if status is not None:
            updates.append('status = ?')
            params.append(status)
        
        updates.append('updated_date = CURRENT_TIMESTAMP')
        params.append(project_id)
        
        query = f'UPDATE projects SET {", ".join(updates)} WHERE id = ?'
        cursor.execute(query, params)
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        return success
    
    def delete_project(self, project_id: int) -> Tuple[bool, str]:
        """프로젝트 삭제 (관련 스캔 결과도 함께 삭제)"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        # 기본 프로젝트 삭제 방지
        cursor.execute('SELECT name FROM projects WHERE id = ?', (project_id,))
        result = cursor.fetchone()
        if not result:
            conn.close()
            return False, "프로젝트를 찾을 수 없습니다."
        
        if result[0] == '기본 프로젝트':
            conn.close()
            return False, "기본 프로젝트는 삭제할 수 없습니다."
        
        # 관련 스캔 결과 개수 확인
        cursor.execute('SELECT COUNT(*) FROM scan_results WHERE project_id = ?', (project_id,))
        scan_count = cursor.fetchone()[0]
        
        try:
            # 관련 스캔 결과 먼저 삭제
            cursor.execute('DELETE FROM scan_results WHERE project_id = ?', (project_id,))
            
            # 프로젝트 삭제
            cursor.execute('DELETE FROM projects WHERE id = ?', (project_id,))
            
            conn.commit()
            conn.close()
            
            return True, f"프로젝트와 관련된 {scan_count}개의 스캔 결과가 삭제되었습니다."
        except Exception as e:
            conn.rollback()
            conn.close()
            return False, f"삭제 중 오류가 발생했습니다: {str(e)}"
    
    def get_project_scans(self, project_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        """프로젝트의 스캔 결과 목록 조회"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, domain, subdomain, ip_address, 
                   scan_date, ports, services, vulnerabilities
            FROM scan_results 
            WHERE project_id = ? 
            ORDER BY scan_date DESC 
            LIMIT ?
        ''', (project_id, limit))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'id': row[0],
                'domain': row[1],
                'subdomain': row[2],
                'ip_address': row[3],
                'scan_date': row[4],
                'ports_count': len(json.loads(row[5] or '[]')),
                'services_count': len(json.loads(row[6] or '[]')),
                'vulnerabilities_count': len(json.loads(row[7] or '[]'))
            })
        
        conn.close()
        return results
    
    def get_project_statistics(self, project_id: int) -> Dict[str, Any]:
        """프로젝트 통계 정보"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        # 기본 통계
        cursor.execute('''
            SELECT COUNT(*) as total_scans,
                   COUNT(DISTINCT domain) as unique_domains,
                   COUNT(DISTINCT subdomain) as unique_subdomains,
                   MIN(scan_date) as first_scan,
                   MAX(scan_date) as last_scan
            FROM scan_results 
            WHERE project_id = ?
        ''', (project_id,))
        
        basic_stats = cursor.fetchone()
        
        # 포트 및 서비스 통계
        cursor.execute('''
            SELECT ports, services, vulnerabilities
            FROM scan_results 
            WHERE project_id = ?
        ''', (project_id,))
        
        total_ports = 0
        total_services = 0
        total_vulnerabilities = 0
        
        for row in cursor.fetchall():
            ports = json.loads(row[0] or '[]')
            services = json.loads(row[1] or '[]')
            vulnerabilities = json.loads(row[2] or '[]')
            
            total_ports += len(ports)
            total_services += len(services)
            total_vulnerabilities += len(vulnerabilities)
        
        conn.close()
        
        return {
            'total_scans': basic_stats[0] if basic_stats else 0,
            'unique_domains': basic_stats[1] if basic_stats else 0,
            'unique_subdomains': basic_stats[2] if basic_stats else 0,
            'first_scan': basic_stats[3] if basic_stats else None,
            'last_scan': basic_stats[4] if basic_stats else None,
            'total_ports': total_ports,
            'total_services': total_services,
            'total_vulnerabilities': total_vulnerabilities
        }
    
    def archive_project(self, project_id: int) -> bool:
        """프로젝트 아카이브 (상태를 archived로 변경)"""
        return self.update_project(project_id, status='archived')
    
    def restore_project(self, project_id: int) -> bool:
        """아카이브된 프로젝트 복원"""
        return self.update_project(project_id, status='active')
    
    def get_active_projects(self) -> List[Dict[str, Any]]:
        """활성 프로젝트만 조회"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT p.*, COUNT(sr.id) as scan_count,
                   MAX(sr.scan_date) as last_scan_date
            FROM projects p 
            LEFT JOIN scan_results sr ON p.id = sr.project_id 
            WHERE p.status = 'active'
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
                'scan_count': row[7],
                'last_scan_date': row[8]
            })
        
        conn.close()
        return projects
    
    def search_projects(self, query: str) -> List[Dict[str, Any]]:
        """프로젝트 검색"""
        if not query.strip():
            return self.get_all_projects()
        
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        search_pattern = f"%{query.strip()}%"
        cursor.execute('''
            SELECT p.*, COUNT(sr.id) as scan_count,
                   MAX(sr.scan_date) as last_scan_date
            FROM projects p 
            LEFT JOIN scan_results sr ON p.id = sr.project_id 
            WHERE p.name LIKE ? OR p.description LIKE ?
            GROUP BY p.id
            ORDER BY p.updated_date DESC
        ''', (search_pattern, search_pattern))
        
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
                'scan_count': row[7],
                'last_scan_date': row[8]
            })
        
        conn.close()
        return projects