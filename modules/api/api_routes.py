from flask import jsonify, request
from typing import Dict, Any, List, Optional, Tuple
import threading
import time
from ..database import DatabaseManager
from ..utils import ValidationUtils


class APIRoutes:
    def __init__(self, app, scanner_manager):
        self.app = app
        self.scanner_manager = scanner_manager
        self.db = DatabaseManager()
        self.validator = ValidationUtils()
        self.register_routes()
    
    def register_routes(self):
        """모든 API 라우트 등록"""
        # 프로젝트 관리 라우트
        self.app.route('/projects', methods=['GET'])(self.get_projects)
        self.app.route('/projects', methods=['POST'])(self.create_project)
        self.app.route('/projects/<int:project_id>', methods=['PUT'])(self.update_project)
        self.app.route('/projects/<int:project_id>', methods=['DELETE'])(self.delete_project)
        self.app.route('/projects/<int:project_id>/scans', methods=['GET'])(self.get_project_scans)
        
        # 스캔 관리 라우트
        self.app.route('/scan', methods=['POST'])(self.start_scan)
        self.app.route('/scan/<scan_id>/status')(self.scan_status)
        self.app.route('/scan/<scan_id>/results')(self.scan_results)
        
    
    # 프로젝트 관리 API
    def get_projects(self):
        """모든 프로젝트 목록 조회"""
        try:
            projects = self.db.get_all_projects()
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
            
            project_id = self.db.create_project(name, description, color)
            
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
            
            success = self.db.update_project(project_id, name, description, color, status)
            
            if success:
                return jsonify({'success': True})
            else:
                return jsonify({'error': 'Project not found'}), 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    def delete_project(self, project_id: int):
        """프로젝트 삭제"""
        try:
            success, message = self.db.delete_project(project_id)
            
            if success:
                return jsonify({'success': True, 'message': message})
            else:
                return jsonify({'error': message}), 400 if 'Cannot delete' in message else 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    def get_project_scans(self, project_id: int):
        """특정 프로젝트의 스캔 결과 조회"""
        try:
            scans = self.db.get_project_scans(project_id)
            return jsonify(scans)
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
            }
            
            # 스캔 스레드 시작
            if bulk_mode:
                thread = threading.Thread(
                    target=self.scanner_manager.perform_bulk_scan, 
                    args=(scan_id, valid_targets, project_id)
                )
            else:
                thread = threading.Thread(
                    target=self.scanner_manager.perform_single_scan, 
                    args=(scan_id, valid_targets, project_id)
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

class ScanManager:
    """스캔 작업을 관리하는 클래스"""
    
    def __init__(self):
        self.results = {}
        self.db = DatabaseManager()
        self.validator = ValidationUtils()
    
    def perform_single_scan(self, scan_id: str, targets: List[str], project_id: Optional[int] = None):
        """단일 타겟 스캔"""
        target = targets[0]
        target_type = 'ip' if self.validator.is_valid_ip(target) else 'domain'
        
        try:
            self.results[scan_id]['status'] = 'running'
            self.results[scan_id]['progress'] = 10
            
            # Dynamic import to avoid circular dependency
            from ..scanner import HostScanner
            scanner = HostScanner()
            
            # 입력된 타겟만 직접 스캔 (서브도메인 탐색 제거)
            self.results[scan_id]['progress'] = 30
            host_results = scanner.scan_target(target)
            self.results[scan_id]['results'][target] = host_results
            self.results[scan_id]['progress'] = 90
            
            self.db.save_scan_results(target, self.results[scan_id]['results'], project_id)
            self.results[scan_id]['status'] = 'completed'
            self.results[scan_id]['progress'] = 100
            self.results[scan_id]['completed_count'] = 1
            
        except Exception as e:
            self.results[scan_id]['status'] = 'error'
            self.results[scan_id]['error'] = str(e)
    
    def perform_bulk_scan(self, scan_id: str, targets: List[str], project_id: Optional[int] = None):
        """대량 타겟 스캔"""
        try:
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
                    self.db.save_scan_results(target, {target: host_results}, project_id)
                    
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
    
