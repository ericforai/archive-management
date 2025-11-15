"""
路由管理 - 统一注册所有API蓝图
基于DA/T 94-2022标准的电子会计档案管理系统
"""
from flask import Blueprint
from api.archive_library_api import archive_library_api
from api.search_api import search_bp
from api.integrity_api import integrity_api
from api.management_api import management_bp
from api.audit_api import audit_bp
from api.metadata_api import metadata_bp
from api.security_api import security_bp
from api.classification_api import classification_bp
from api.collection_api import collection_bp

# 创建主API蓝图
api_bp = Blueprint('api', __name__)

# 注册各个功能模块的蓝图 - 分配正确的URL前缀
api_bp.register_blueprint(archive_library_api, url_prefix='/api/v1')
api_bp.register_blueprint(search_bp, url_prefix='/api/v1')
api_bp.register_blueprint(integrity_api, url_prefix='/api/v1')
api_bp.register_blueprint(management_bp, url_prefix='/api/v1')
api_bp.register_blueprint(audit_bp, url_prefix='/api/v1')
api_bp.register_blueprint(metadata_bp, url_prefix='/api/v1')
api_bp.register_blueprint(security_bp, url_prefix='/api/v1/security')
api_bp.register_blueprint(classification_bp, url_prefix='/api/v1/classification')
api_bp.register_blueprint(collection_bp, url_prefix='/api/v1/collection')

# API文档和健康检查端点
@api_bp.route('/health', methods=['GET'])
def health_check():
    """API健康检查"""
    return {
        'status': 'healthy',
        'timestamp': '2024-01-01T00:00:00Z',
        'version': '1.0.0',
        'modules': {
            'archive_library': 'active',
            'search': 'active',
            'integrity': 'active',
            'management': 'active',
            'audit': 'active',
            'metadata': 'active',
            'security': 'active',
            'classification': 'active',
            'collection': 'active'
        }
    }

@api_bp.route('/info', methods=['GET'])
def api_info():
    """API信息"""
    return {
        'name': '电子会计档案管理系统API',
        'version': '1.0.0',
        'description': '基于DA/T 94-2022标准的电子会计档案管理系统RESTful API',
        'specification': 'DA/T 94-2022',
        'endpoints': {
            'archive_library': '/api/v1/libraries, /api/v1/archives',
            'search': '/api/v1/search',
            'integrity': '/api/v1/integrity',
            'management': '/api/v1/management',
            'audit': '/api/v1/audit',
            'metadata': '/api/v1/metadata',
            'security': '/api/v1/security',
            'classification': '/api/v1/classification',
            'collection': '/api/v1/collections'
        },
        'features': [
            '电子档案全生命周期管理',
            '智能检索和分类',
            '完整性验证',
            '权限控制和审计',
            '元数据管理',
            '安全保护'
        ]
    }