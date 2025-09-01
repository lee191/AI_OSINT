from flask import jsonify, request
from typing import Dict, Any, List, Optional, Tuple
import threading
import time
from ..database import DatabaseManager
from ..utils import ValidationUtils
from ..project import ProjectManager


class APIRoutes:
    def __init__(self, app, scanner_manager):
        self.app = app
        self.scanner_manager = scanner_manager
        self.db = DatabaseManager()
        self.project_manager = ProjectManager()
        self.validator = ValidationUtils()
        self.register_routes()
    
    def register_routes(self):
        """모든 API 라우트 등록"""
        # 프로젝트 관리 라우트
        self.app.route('/api/projects', methods=['GET'])(self.get_projects)
        self.app.route('/api/projects', methods=['POST'])(self.create_project)
        self.app.route('/api/projects/<int:project_id>', methods=['PUT'])(self.update_project)
        self.app.route('/api/projects/<int:project_id>', methods=['DELETE'])(self.delete_project)
        self.app.route('/api/projects/<int:project_id>/scans', methods=['GET'])(self.get_project_scans)
        self.app.route('/api/projects/<int:project_id>/stats', methods=['GET'])(self.get_project_stats)
        self.app.route('/api/projects/<int:project_id>/recent-scans', methods=['GET'])(self.get_project_recent_scans)
        
        # 대시보드 라우트
        self.app.route('/api/dashboard/stats', methods=['GET'])(self.get_dashboard_stats)
        self.app.route('/api/dashboard/recent-scans', methods=['GET'])(self.get_dashboard_recent_scans)
        
        # 스캔 관리 라우트
        self.app.route('/scan', methods=['POST'])(self.start_scan)
        self.app.route('/scan/<scan_id>/status')(self.scan_status)
        self.app.route('/scan/<scan_id>/results')(self.scan_results)
        
        # 스캔 이력 라우트
        self.app.route('/api/scans', methods=['GET'])(self.get_scans)
        self.app.route('/api/scans/<int:scan_id>', methods=['GET'])(self.get_scan_detail)
        self.app.route('/api/scans/<int:scan_id>/test', methods=['GET'])(self.get_scan_detail_test)
        
    
    # 프로젝트 관리 API
    def get_projects(self):
        """모든 프로젝트 목록 조회"""
        try:
            projects = self.project_manager.get_all_projects()
            return jsonify(projects)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    def create_project(self):
        """새 프로젝트 생성"""
        try:
            data = request.json
            name = data.get('name')
            description = data.get('description', '')
            color = data.get('color', '#4fd1c7')
            
            if not name:
                return jsonify({'error': 'Project name is required'}), 400
            
            project_id = self.project_manager.create_project(name, description, color)
            
            return jsonify({
                'id': project_id, 
                'name': name, 
                'description': description, 
                'color': color
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    def update_project(self, project_id: int):
        """프로젝트 정보 업데이트"""
        try:
            data = request.json
            name = data.get('name')
            description = data.get('description')
            color = data.get('color')
            status = data.get('status')
            
            success = self.project_manager.update_project(project_id, name, description, color, status)
            
            if success:
                return jsonify({'success': True})
            else:
                return jsonify({'error': 'Project not found'}), 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    def delete_project(self, project_id: int):
        """프로젝트 삭제"""
        try:
            success, message = self.project_manager.delete_project(project_id)
            
            if success:
                return jsonify({'success': True, 'message': message})
            else:
                return jsonify({'error': message}), 400 if 'Cannot delete' in message else 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    def get_project_scans(self, project_id: int):
        """특정 프로젝트의 스캔 결과 조회"""
        try:
            scans = self.project_manager.get_project_scans(project_id)
            return jsonify(scans)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    def get_project_stats(self, project_id: int):
        """특정 프로젝트의 대시보드 통계"""
        try:
            import sqlite3
            import json
            
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            
            # 프로젝트별 스캔 수
            cursor.execute('SELECT COUNT(*) FROM scan_results WHERE project_id = ?', (project_id,))
            total_scans = cursor.fetchone()[0]
            
            # 포트 및 서비스 통계 계산
            cursor.execute('SELECT ports, services, vulnerabilities FROM scan_results WHERE project_id = ?', (project_id,))
            total_ports = 0
            total_services = 0
            total_vulnerabilities = 0
            
            for row in cursor.fetchall():
                try:
                    ports = json.loads(row[0] or '[]')
                    services = json.loads(row[1] or '[]')
                    vulnerabilities = json.loads(row[2] or '[]')
                    
                    total_ports += len(ports)
                    total_services += len(services)
                    total_vulnerabilities += len(vulnerabilities)
                except:
                    pass
            
            conn.close()
            
            # 대시보드 포맷에 맞게 변환
            dashboard_stats = {
                'active_scans': 0,  # 현재 진행 중인 스캔 (실시간 데이터이므로 0)
                'completed_scans': total_scans,
                'total_ports': total_ports,
                'critical_services': total_vulnerabilities,
                'running_scans': 0,
                'error_scans': 0,
                'pending_scans': 0
            }
            
            return jsonify(dashboard_stats)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    def get_project_recent_scans(self, project_id: int):
        """특정 프로젝트의 최근 스캔"""
        try:
            scans = self.project_manager.get_project_scans(project_id, limit=10)
            
            # 포트 개수 계산하여 추가
            for scan in scans:
                try:
                    import json
                    ports = json.loads(scan.get('ports', '[]'))
                    scan['ports_count'] = len(ports) if ports else 0
                except:
                    scan['ports_count'] = 0
            
            return jsonify({'scans': scans})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # 대시보드 API
    def get_dashboard_stats(self):
        """전체 대시보드 통계"""
        try:
            import sqlite3
            import json
            
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            
            # 전체 스캔 수
            cursor.execute('SELECT COUNT(*) FROM scan_results')
            total_scans = cursor.fetchone()[0]
            
            # 포트 및 서비스 통계 계산
            cursor.execute('SELECT ports, services, vulnerabilities FROM scan_results')
            total_ports = 0
            total_services = 0
            total_vulnerabilities = 0
            
            for row in cursor.fetchall():
                try:
                    ports = json.loads(row[0] or '[]')
                    services = json.loads(row[1] or '[]')
                    vulnerabilities = json.loads(row[2] or '[]')
                    
                    total_ports += len(ports)
                    total_services += len(services)
                    total_vulnerabilities += len(vulnerabilities)
                except:
                    pass
            
            conn.close()
            
            total_stats = {
                'active_scans': 0,  # 현재 진행 중인 스캔 (실시간 데이터)
                'completed_scans': total_scans,
                'total_ports': total_ports,
                'critical_services': total_vulnerabilities,
                'running_scans': 0,
                'error_scans': 0,
                'pending_scans': 0
            }
            
            return jsonify(total_stats)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    def get_dashboard_recent_scans(self):
        """전체 최근 스캔"""
        try:
            # 모든 프로젝트에서 최근 스캔 가져오기
            import sqlite3
            import json
            
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, domain, subdomain, ip_address, scan_date, ports, services, vulnerabilities
                FROM scan_results 
                ORDER BY scan_date DESC 
                LIMIT 10
            ''')
            
            scans = []
            for row in cursor.fetchall():
                try:
                    ports = json.loads(row[5] or '[]')
                    ports_count = len(ports) if ports else 0
                except:
                    ports_count = 0
                
                scans.append({
                    'id': row[0],
                    'domain': row[1],
                    'subdomain': row[2],
                    'ip_address': row[3],
                    'scan_date': row[4],
                    'ports_count': ports_count,
                    'status': 'completed'
                })
            
            conn.close()
            return jsonify({'scans': scans})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # 스캔 관리 API
    def start_scan(self):
        """스캔 시작"""
        try:
            data = request.json
            targets = data.get('targets')
            project_id = data.get('project_id')
            bulk_mode = data.get('bulk_mode', False)
            settings = data.get('settings', {})
            
            # 하위 호환성을 위해 기존 'domain' 필드도 지원
            if not targets and data.get('domain'):
                targets = [data.get('domain')]
            
            if not targets or (isinstance(targets, list) and len(targets) == 0):
                return jsonify({'error': 'At least one target is required'}), 400
            
            # 단일 타겟인 경우 리스트로 변환
            if isinstance(targets, str):
                targets = [targets]
            
            # 타겟 유효성 검사
            valid_targets, invalid_targets = self.validator.validate_targets(targets)
            
            if len(valid_targets) == 0:
                return jsonify({'error': 'No valid targets found'}), 400
            
            scan_id = f"scan_{int(time.time())}"
            self.scanner_manager.results[scan_id] = {
                'status': 'started', 
                'progress': 0, 
                'results': {},
                'targets': valid_targets,
                'invalid_targets': invalid_targets,
                'bulk_mode': bulk_mode,
                'project_id': project_id,
                'completed_count': 0,
                'total_count': len(valid_targets),
                'settings': settings  # 설정 저장
            }
            
            # 스캔 스레드 시작 (설정 포함)
            if bulk_mode:
                thread = threading.Thread(
                    target=self.scanner_manager.perform_bulk_scan, 
                    args=(scan_id, valid_targets, project_id, settings)
                )
            else:
                thread = threading.Thread(
                    target=self.scanner_manager.perform_single_scan, 
                    args=(scan_id, valid_targets, project_id, settings)
                )
            
            thread.daemon = True
            thread.start()
            
            result = {
                'scan_id': scan_id, 
                'status': 'started',
                'total_targets': len(valid_targets),
                'valid_targets': len(valid_targets)
            }
            
            if invalid_targets:
                result['invalid_targets'] = invalid_targets
                result['invalid_count'] = len(invalid_targets)
            
            return jsonify(result)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    def scan_status(self, scan_id: str):
        """스캔 상태 조회"""
        try:
            if scan_id not in self.scanner_manager.results:
                return jsonify({'error': 'Scan not found'}), 404
            
            return jsonify(self.scanner_manager.results[scan_id])
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    def scan_results(self, scan_id: str):
        """스캔 결과 조회"""
        try:
            if scan_id not in self.scanner_manager.results:
                return jsonify({'error': 'Scan not found'}), 404
            
            return jsonify(self.scanner_manager.results[scan_id]['results'])
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # 스캔 이력 API
    def get_scans(self):
        """스캔 이력 조회 (필터링 및 페이지네이션 지원) - FIXED VERSION"""
        try:
            import sqlite3
            import json
            from datetime import datetime, timedelta
            
            # 쿼리 파라미터 가져오기
            page = int(request.args.get('page', 1))
            limit = int(request.args.get('limit', 20))
            project_id = request.args.get('project_id')
            target = request.args.get('target')
            status = request.args.get('status')
            date_range = request.args.get('date_range')
            
            offset = (page - 1) * limit
            
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            
            # 기본 쿼리
            base_query = '''
                SELECT sr.id, sr.domain, sr.subdomain, sr.ip_address, sr.ports, 
                       sr.services, sr.vulnerabilities, sr.poc_codes, sr.scan_date, sr.project_id,
                       p.name as project_name, p.color as project_color
                FROM scan_results sr
                LEFT JOIN projects p ON sr.project_id = p.id
                WHERE 1=1
            '''
            count_query = '''
                SELECT COUNT(*) 
                FROM scan_results sr
                LEFT JOIN projects p ON sr.project_id = p.id
                WHERE 1=1
            '''
            
            params = []
            conditions = []
            
            # 필터 조건 추가
            if project_id:
                conditions.append('sr.project_id = ?')
                params.append(project_id)
            
            if target:
                conditions.append('(sr.domain LIKE ? OR sr.subdomain LIKE ? OR sr.ip_address LIKE ?)')
                target_pattern = f'%{target}%'
                params.extend([target_pattern, target_pattern, target_pattern])
            
            if status:
                # 현재 스캔 결과는 대부분 완료 상태이므로 completed로 가정
                if status != 'completed':
                    conditions.append('1=0')  # 다른 상태는 없음
            
            if date_range:
                now = datetime.now()
                if date_range == 'today':
                    start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
                elif date_range == 'week':
                    start_date = now - timedelta(days=7)
                elif date_range == 'month':
                    start_date = now - timedelta(days=30)
                
                if date_range in ['today', 'week', 'month']:
                    conditions.append('sr.scan_date >= ?')
                    params.append(start_date.isoformat())
            
            # 조건 적용
            if conditions:
                base_query += ' AND ' + ' AND '.join(conditions)
                count_query += ' AND ' + ' AND '.join(conditions)
            
            # 총 개수 조회
            cursor.execute(count_query, params)
            total_count = cursor.fetchone()[0]
            
            # 정렬 및 페이지네이션 적용
            base_query += ' ORDER BY sr.scan_date DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            
            cursor.execute(base_query, params)
            
            scans = []
            for row in cursor.fetchall():
                try:
                    ports = json.loads(row[4] or '[]')
                    services = json.loads(row[5] or '[]')
                    vulnerabilities = json.loads(row[6] or '[]')
                except:
                    ports = []
                    services = []
                    vulnerabilities = []
                
                # DEBUG: 첫 번째 스캔에 대해 디버그 정보 출력
                if len(scans) == 0:
                    print(f"DEBUG get_scans: row[0]={row[0]}, row[1]={row[1]}, row[2]={row[2]}, row[3]={row[3]}")
                    print(f"DEBUG get_scans: row[4]={str(row[4])[:50]}...")
                    print(f"DEBUG get_scans: row[9]={row[9]}")
                
                scans.append({
                    'id': row[0],
                    'domain': row[1],
                    'subdomain': row[2],
                    'ip_address': row[3],  # 이것이 올바른 IP여야 함
                    'ports': ports,
                    'services': services,
                    'vulnerabilities': vulnerabilities,
                    'scan_date': row[8],
                    'project_id': row[9],  # 이것이 올바른 프로젝트 ID여야 함
                    'status': 'completed',  # 기본 상태
                    'project_name': row[10],
                    'project_color': row[11]
                })
            
            conn.close()
            
            total_pages = (total_count + limit - 1) // limit
            
            return jsonify({
                'scans': scans,
                'total_count': total_count,
                'total_pages': total_pages,
                'current_page': page,
                'page_size': limit
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    def get_scan_detail_old(self, scan_id: int):
        """특정 스캔의 상세 정보 조회 (OLD VERSION)"""
        try:
            import sqlite3
            import json
            
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT sr.id, sr.domain, sr.subdomain, sr.ip_address, sr.ports, 
                       sr.services, sr.vulnerabilities, sr.poc_codes, sr.scan_date, sr.project_id,
                       p.name as project_name, p.color as project_color
                FROM scan_results sr
                LEFT JOIN projects p ON sr.project_id = p.id
                WHERE sr.id = ?
            ''', (scan_id,))
            
            row = cursor.fetchone()
            
            if not row:
                conn.close()
                return jsonify({'error': 'Scan not found'}), 404
            
            try:
                ports = json.loads(row[4] or '[]')
                services = json.loads(row[5] or '[]')
                vulnerabilities = json.loads(row[6] or '[]')
            except:
                ports = []
                services = []
                vulnerabilities = []
            
            scan = {
                'id': row[0],
                'domain': row[1],
                'subdomain': row[2], 
                'ip_address': row[3],
                'ports': ports,
                'services': services,
                'vulnerabilities': vulnerabilities,
                'scan_date': row[8],
                'project_id': row[9],
                'status': 'completed',
                'project_name': row[10],
                'project_color': row[11]
            }
            
            conn.close()
            return jsonify(scan)
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    def get_scan_detail(self, scan_id: int):
        """특정 스캔의 상세 정보 조회 (FIXED VERSION)"""
        print(f"DEBUG: get_scan_detail called with scan_id={scan_id}")
        import sqlite3
        import json
        
        try:
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            
            # Direct query with explicit field selection
            cursor.execute(
                'SELECT id, domain, subdomain, ip_address, ports, services, vulnerabilities, '
                'poc_codes, scan_date, project_id FROM scan_results WHERE id = ?', 
                (scan_id,)
            )
            
            scan_row = cursor.fetchone()
            if not scan_row:
                conn.close()
                return jsonify({'error': 'Scan not found'}), 404
            
            # Get project info separately
            cursor.execute('SELECT name, color FROM projects WHERE id = ?', (scan_row[9],))
            project_row = cursor.fetchone()
            
            # Parse JSON fields safely
            try:
                ports_data = json.loads(scan_row[4] or '[]')
                services_data = json.loads(scan_row[5] or '[]') 
                vulnerabilities_data = json.loads(scan_row[6] or '[]')
            except (json.JSONDecodeError, TypeError):
                ports_data = []
                services_data = []
                vulnerabilities_data = []
            
            # Build response with correct field mapping
            response = {
                'id': scan_row[0],
                'domain': scan_row[1],
                'subdomain': scan_row[2],
                'ip_address': scan_row[3],  # This should be the actual IP
                'ports': ports_data,  # Return as array, not JSON string
                'services': services_data,
                'vulnerabilities': vulnerabilities_data, 
                'scan_date': scan_row[8],
                'project_id': scan_row[9],
                'status': 'completed',
                'project_name': project_row[0] if project_row else 'Unknown',
                'project_color': project_row[1] if project_row else '#4fd1c7'
            }
            
            conn.close()
            return jsonify(response)
            
        except Exception as e:
            if 'conn' in locals():
                conn.close()
            return jsonify({'error': f'Database error: {str(e)}'}), 500
    
    def get_scan_detail_test(self, scan_id: int):
        """TEST: 테스트용 스캔 상세 정보 조회"""
        try:
            import sqlite3
            import json
            
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT sr.id, sr.project_id, sr.domain, sr.subdomain, sr.ip_address, 
                       sr.ports, sr.services, sr.vulnerabilities, sr.scan_date,
                       p.name as project_name, p.color as project_color
                FROM scan_results sr
                LEFT JOIN projects p ON sr.project_id = p.id
                WHERE sr.id = ?
            ''', (scan_id,))
            
            row = cursor.fetchone()
            
            if not row:
                conn.close()
                return jsonify({'error': 'Scan not found'}), 404
            
            try:
                ports = json.loads(row[5] or '[]')
                services = json.loads(row[6] or '[]')
                vulnerabilities = json.loads(row[7] or '[]')
            except:
                ports = []
                services = []
                vulnerabilities = []
            
            # Return raw debug data
            scan = {
                'TEST_MESSAGE': 'This is the fixed version',
                'raw_row_4_ip': row[4],
                'raw_row_5_ports_start': str(row[5])[:50] if row[5] else None,
                'id': row[0],
                'project_id': row[1],
                'domain': row[2],
                'subdomain': row[3],
                'ip_address': row[4],  # This should be correct now
                'ports': ports,
                'services': services,
                'vulnerabilities': vulnerabilities,
                'scan_date': row[8],
                'status': 'completed',
                'project_name': row[9],
                'project_color': row[10]
            }
            
            conn.close()
            return jsonify(scan)
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500

class ScanManager:
    """스캔 작업을 관리하는 클래스"""
    
    def __init__(self):
        self.results = {}
    
    def perform_single_scan(self, scan_id: str, targets: List[str], project_id: Optional[int] = None, settings: Dict = None):
        """단일 타겟 스캔"""
        from ..database import DatabaseManager
        from ..utils import ValidationUtils
        
        db = DatabaseManager()
        validator = ValidationUtils()
        
        target = targets[0]
        target_type = 'ip' if validator.is_valid_ip(target) else 'domain'
        
        try:
            settings = settings or {}
            
            self.results[scan_id]['status'] = 'running'
            self.results[scan_id]['progress'] = 10
            
            # Dynamic import to avoid circular dependency
            from ..scanner import HostScanner
            scanner = HostScanner()
            
            # 설정을 스캐너에 전달
            self.results[scan_id]['progress'] = 30
            host_results = scanner.scan_target(target, settings)
            self.results[scan_id]['results'][target] = host_results
            
            self.results[scan_id]['progress'] = 90
            
            db.save_scan_results(target, self.results[scan_id]['results'], project_id)
            self.results[scan_id]['status'] = 'completed'
            self.results[scan_id]['progress'] = 100
            self.results[scan_id]['completed_count'] = 1
            
        except Exception as e:
            self.results[scan_id]['status'] = 'error'
            self.results[scan_id]['error'] = str(e)
    
    def perform_bulk_scan(self, scan_id: str, targets: List[str], project_id: Optional[int] = None, settings: Dict = None):
        """대량 타겟 스캔"""
        from ..database import DatabaseManager
        
        db = DatabaseManager()
        
        try:
            settings = settings or {}
            
            self.results[scan_id]['status'] = 'running'
            self.results[scan_id]['progress'] = 5
            self.results[scan_id]['target_status'] = {}
            
            total_targets = len(targets)
            completed_count = 0
            
            # Dynamic import to avoid circular dependency
            from ..scanner import HostScanner
            scanner = HostScanner()
            
            # 각 타겟별 상태 초기화
            for target in targets:
                self.results[scan_id]['target_status'][target] = {
                    'status': 'pending',
                    'progress': 0,
                    'error': None
                }
            
            # 각 타겟을 순차적으로 스캔
            for i, target in enumerate(targets):
                try:
                    # 타겟 스캔 시작
                    self.results[scan_id]['target_status'][target]['status'] = 'running'
                    self.results[scan_id]['target_status'][target]['progress'] = 10
                    
                    # 입력된 타겟만 직접 스캔
                    self.results[scan_id]['target_status'][target]['progress'] = 30
                    
                    # FastNmap 스캔 수행
                    host_results = scanner.scan_target(target)
                    
                    # 타겟 결과 저장 (단일 결과로 저장)
                    self.results[scan_id]['results'][target] = host_results
                    self.results[scan_id]['target_status'][target]['progress'] = 90
                    db.save_scan_results(target, {target: host_results}, project_id)
                    
                    # 타겟 완료 처리
                    self.results[scan_id]['target_status'][target]['status'] = 'completed'
                    self.results[scan_id]['target_status'][target]['progress'] = 100
                    completed_count += 1
                    
                except Exception as target_error:
                    # 개별 타겟 오류 처리
                    self.results[scan_id]['target_status'][target]['status'] = 'error'
                    self.results[scan_id]['target_status'][target]['error'] = str(target_error)
                    completed_count += 1
                
                # 전체 진행률 업데이트
                self.results[scan_id]['completed_count'] = completed_count
                self.results[scan_id]['progress'] = 5 + (completed_count * 90 / total_targets)
            
            # 전체 스캔 완료
            self.results[scan_id]['status'] = 'completed'
            self.results[scan_id]['progress'] = 100
            
        except Exception as e:
            self.results[scan_id]['status'] = 'error'
            self.results[scan_id]['error'] = str(e)
    
    def _build_scan_command(self, settings: Dict, target: str) -> str:
        """설정을 기반으로 nmap 명령어 생성 (디버그용)"""
        command = ["nmap"]
        
        # 포트 범위 설정
        port_range = settings.get('portRange', 'common')
        if port_range == 'top100':
            command.append('--top-ports 100')
        elif port_range == 'top1000':
            command.append('--top-ports 1000')
        elif port_range == 'all':
            command.append('-p-')
        elif port_range == 'common':
            command.append('-F')
            
        # 스캔 속도
        speed = settings.get('speed', 'T4')
        command.append(f'-{speed}')
        
        # 서비스 탐지
        service_detection = settings.get('serviceDetection', 'version')
        if service_detection == 'version':
            command.append('-sV')
        elif service_detection == 'aggressive':
            command.append('-sV --version-intensity 9')
        elif service_detection == 'basic':
            command.append('-sS')
            
        # 스크립트 스캔
        script_scan = settings.get('scriptScan', 'default')
        if script_scan == 'default':
            command.append('-sC')
        elif script_scan == 'vuln':
            command.append('--script vuln')
        elif script_scan == 'all':
            command.append('--script all')
            
        # OS 탐지
        os_detection = settings.get('osDetection', 'none')
        if os_detection == 'basic':
            command.append('-O')
        elif os_detection == 'aggressive':
            command.append('-O --osscan-guess')
            
        # 성능 설정
        min_rate = settings.get('minRate', '1000')
        command.append(f'--min-rate {min_rate}')
        
        max_rtt = settings.get('maxRtt', '200')
        command.append(f'--max-rtt-timeout {max_rtt}ms')
        
        host_timeout = settings.get('hostTimeout', '30')
        command.append(f'--host-timeout {host_timeout}m')
        
        # 대상 추가
        command.append(target)
        
        return ' '.join(command)
    
