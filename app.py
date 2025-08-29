from flask import Flask, render_template
from modules.database import DatabaseManager
from modules.api import APIRoutes, ScanManager
from modules.ai import add_ai_routes
import os


def create_app():
    """Flask 애플리케이션 팩토리"""
    app = Flask(__name__)
    
    # 데이터베이스 매니저 초기화
    db_manager = DatabaseManager()
    
    # 스캔 매니저 초기화
    scan_manager = ScanManager()
    
    # API 라우트 등록
    api_routes = APIRoutes(app, scan_manager)
    
    # AI 분석 라우트 추가
    add_ai_routes(app, scan_manager)
    
    # 메인 페이지 라우트
    @app.route('/')
    def index():
        return render_template('index.html')
    
    return app


def main():
    """메인 실행 함수"""
    app = create_app()
    
    # 개발 환경에서만 디버그 모드 활성화
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    
    # 서버 실행
    app.run(
        debug=debug_mode,
        host='0.0.0.0',
        port=5002
    )


if __name__ == '__main__':
    main()