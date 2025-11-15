"""
电子会计档案管理系统主应用
基于DA/T 94-2022标准
"""
from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_mail import Mail
import os
import logging
from datetime import timedelta

# 导入各个模块
from config import Config
from models import db
from models.audit import AuditLog
from routes import api_bp
from api.enhanced_archive_api import enhanced_archive_bp
from api.enhanced_audit_api import enhanced_audit_bp

def create_app(config_class=Config):
    """应用工厂函数"""
    # 配置Flask的templates和static目录
    app = Flask(__name__, 
                template_folder='templates',
                static_folder='static')
    app.config.from_object(config_class)
    
    # 初始化扩展
    db.init_app(app)
    JWTManager(app)
    CORS(app, resources={
        r"/api/*": {
            "origins": "*",
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"]
        }
    })
    Mail(app)
    
    # 注册蓝图
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(enhanced_archive_bp, url_prefix='/api/enhanced')
    app.register_blueprint(enhanced_audit_bp, url_prefix='/api/enhanced')
     
    # 错误处理
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': '资源未找到'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return jsonify({'error': '服务器内部错误'}), 500
    
    # 健康检查端点
    @app.route('/health')
    def health_check():
        return jsonify({
            'status': 'healthy',
            'version': '1.0.0',
            'database': 'connected' if db else 'disconnected'
        })
    
    # 前端页面路由
    @app.route('/')
    def index():
        """主页 - 返回前端应用"""
        return render_template('index.html')
    
    @app.route('/login')
    def login_page():
        """登录页面"""
        return render_template('index.html')
    
    @app.route('/enhanced')
    def enhanced_archive_page():
        """增强版档案管理页面"""
        return render_template('enhanced_archive.html')
    
    @app.route('/static/<path:filename>')
    def static_files(filename):
        """静态文件服务"""
        return send_from_directory(app.static_folder, filename)
    
    # 初始化数据库
    with app.app_context():
        db.create_all()
        
        # 创建默认管理员用户
        from models.user import User
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                email='admin@archive.com',
                full_name='系统管理员',
                role='admin',
                department='信息技术部'
            )
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            db.session.commit()
    
    return app

if __name__ == '__main__':
    app = create_app()
    port = int(os.environ.get('PORT', 5001))
    app.run(debug=True, host='0.0.0.0', port=port)