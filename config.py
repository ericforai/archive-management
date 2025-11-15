"""
电子会计档案管理系统配置 - Railway部署优化版
"""
import os
from datetime import timedelta
from pathlib import Path

class Config:
    """基础配置 - 针对Railway优化"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here-change-in-production'
    
    # 数据库配置 - 使用SQLite（Railway免费版兼容性更好）
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///instance/electronic_archive.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # JWT配置
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-string-change-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    
    # 文件上传配置
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    UPLOAD_FOLDER = Path('uploads')
    ALLOWED_EXTENSIONS = {
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'jpg', 
        'jpeg', 'png', 'gif', 'tiff', 'bmp', 'ofd'
    }
    
    # 存储路径
    STORAGE_FOLDER = Path('storage')
    ARCHIVE_STORAGE = Path('storage/archives')
    BACKUP_STORAGE = Path('storage/backup')
    
    # Redis配置 - 可选，Railway可能不提供
    REDIS_URL = os.environ.get('REDIS_URL') or None
    
    # Elasticsearch配置 - 可选，跳过搜索功能
    ELASTICSEARCH_URL = os.environ.get('ELASTICSEARCH_URL') or None
    
    # 邮件配置
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    
    # 安全配置
    BCRYPT_LOG_ROUNDS = 12
    SESSION_COOKIE_SECURE = False  # Railway HTTPS
    
    # 审计配置
    AUDIT_LOG_RETENTION_DAYS = 2555  # 7年
    
    # OCR配置 - 可选功能
    OCR_LANGUAGES = ['chi_sim', 'eng']
    OCR_TIMEOUT = 300
    
    # 哈希算法配置
    HASH_ALGORITHM = 'sha256'
    
    # 备份配置
    BACKUP_SCHEDULE = {
        'daily': {'time': '02:00', 'retention': 30},
        'weekly': {'day': 'sunday', 'time': '03:00', 'retention': 12},
        'monthly': {'day': 1, 'time': '04:00', 'retention': 24}
    }
    
    # 日志配置
    LOG_LEVEL = os.environ.get('LOG_LEVEL') or 'INFO'
    LOG_FILE = 'logs/archive_system.log'
    
    @staticmethod
    def init_app(app):
        """初始化应用"""
        # 确保必要目录存在
        Config.UPLOAD_FOLDER.mkdir(exist_ok=True)
        Config.STORAGE_FOLDER.mkdir(exist_ok=True)
        Config.ARCHIVE_STORAGE.mkdir(exist_ok=True)
        Config.BACKUP_STORAGE.mkdir(exist_ok=True)
        
        # 创建instance目录用于SQLite
        instance_dir = Path('instance')
        instance_dir.mkdir(exist_ok=True)
        
        # 创建日志目录
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)

class DevelopmentConfig(Config):
    """开发环境配置"""
    DEBUG = True

class ProductionConfig(Config):
    """生产环境配置 - Railway"""
    DEBUG = False
    SESSION_COOKIE_SECURE = True

class TestingConfig(Config):
    """测试环境配置"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': ProductionConfig  # Railway使用production配置
}