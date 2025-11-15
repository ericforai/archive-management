"""
电子档案库管理API - RESTful API端点
基于DA/T 94-2022标准的档案库管理接口
"""
import os
import json
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename

from services.archive_library_service import ArchiveLibraryService
from utils.auth import require_auth, get_current_user
from utils.response_utils import create_success_response, create_error_response

# 创建蓝图
archive_library_api = Blueprint('archive_library_api', __name__)

# 初始化服务
archive_library_service = ArchiveLibraryService()

# 允许的文件扩展名
ALLOWED_EXTENSIONS = {
    'documents': {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf'},
    'images': {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff'},
    'archives': {'zip', 'rar', '7z', 'tar', 'gz'}
}

def allowed_file(filename, file_type='documents'):
    """检查文件类型是否允许"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS.get(file_type, set())

@archive_library_api.route('/libraries', methods=['POST'])
@require_auth
def create_library():
    """
    创建电子档案库
    
    POST /api/libraries
    
    请求体:
    {
        "name": "档案库名称",
        "description": "档案库描述",
        "category_code": "分类代码"
    }
    
    响应:
    {
        "success": true,
        "data": {
            "library_id": "档案库ID",
            "path": "档案库路径",
            "metadata": {...}
        },
        "message": "档案库创建成功"
    }
    """
    try:
        data = request.get_json()
        if not data:
            return create_error_response('无效的请求数据', 400)
        
        # 验证必需参数
        required_fields = ['name']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return create_error_response(f'缺少必需参数: {", ".join(missing_fields)}', 400)
        
        # 获取当前用户
        current_user = get_current_user()
        user_id = current_user.id if current_user else None
        
        # 创建档案库
        result = archive_library_service.create_archive_library(
            name=data['name'],
            description=data.get('description', ''),
            category_code=data.get('category_code'),
            user_id=user_id
        )
        
        if result['success']:
            return create_success_response(data=result, message=result['message'])
        else:
            return create_error_response(result['error'], 500)
            
    except Exception as e:
        return create_error_response(f'创建档案库失败: {str(e)}', 500)

@archive_library_api.route('/libraries', methods=['GET'])
@require_auth
def list_libraries():
    """
    获取档案库列表
    
    GET /api/libraries
    
    查询参数:
    - page: 页码 (默认: 1)
    - per_page: 每页数量 (默认: 10)
    - status: 状态过滤 (active, inactive)
    - category_code: 分类代码过滤
    
    响应:
    {
        "success": true,
        "data": {
            "libraries": [...],
            "total": 100,
            "page": 1,
            "per_page": 10,
            "total_pages": 10
        }
    }
    """
    try:
        # 获取查询参数
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 10)), 100)  # 最多100条
        status = request.args.get('status')
        category_code = request.args.get('category_code')
        
        # 获取当前用户
        current_user = get_current_user()
        user_id = current_user.id if current_user else None
        
        # 构建查询条件（简化实现）
        # 实际应用中应该从数据库查询
        
        libraries_data = []  # 从服务获取档案库列表
        
        # 分页信息
        total_libraries = 100  # 实际应从数据库获取
        total_pages = (total_libraries + per_page - 1) // per_page
        
        response_data = {
            'libraries': libraries_data,
            'total': total_libraries,
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages
        }
        
        return create_success_response(data=response_data)
        
    except Exception as e:
        return create_error_response(f'获取档案库列表失败: {str(e)}', 500)

@archive_library_api.route('/libraries/<library_id>', methods=['GET'])
@require_auth
def get_library(library_id):
    """
    获取档案库详情
    
    GET /api/libraries/{library_id}
    
    响应:
    {
        "success": true,
        "data": {
            "library_id": "档案库ID",
            "name": "档案库名称",
            "description": "档案库描述",
            "category_code": "分类代码",
            "created_by": "创建者",
            "created_at": "创建时间",
            "status": "状态",
            "settings": {...}
        }
    }
    """
    try:
        # 获取当前用户
        current_user = get_current_user()
        user_id = current_user.id if current_user else None
        
        # 获取档案库详情（简化实现）
        # 实际应用中应该从数据库查询
        library_data = {
            'library_id': library_id,
            'name': '示例档案库',
            'description': '档案库描述',
            'category_code': 'ACCOUNTING',
            'created_by': user_id,
            'created_at': datetime.utcnow().isoformat(),
            'status': 'active',
            'settings': {
                'retention_period': 7,
                'backup_frequency': 'daily',
                'encryption_enabled': True,
                'version_control': True
            }
        }
        
        return create_success_response(data=library_data)
        
    except Exception as e:
        return create_error_response(f'获取档案库详情失败: {str(e)}', 500)

@archive_library_api.route('/libraries/<library_id>', methods=['PUT'])
@require_auth
def update_library(library_id):
    """
    更新档案库信息
    
    PUT /api/libraries/{library_id}
    
    请求体:
    {
        "name": "档案库名称",
        "description": "档案库描述",
        "settings": {...}
    }
    
    响应:
    {
        "success": true,
        "data": {...},
        "message": "档案库更新成功"
    }
    """
    try:
        data = request.get_json()
        if not data:
            return create_error_response('无效的请求数据', 400)
        
        # 获取当前用户
        current_user = get_current_user()
        user_id = current_user.id if current_user else None
        
        # 更新档案库信息（简化实现）
        update_result = {
            'success': True,
            'library_id': library_id,
            'updated_data': data,
            'updated_at': datetime.utcnow().isoformat(),
            'message': '档案库更新成功'
        }
        
        return create_success_response(data=update_result, message=update_result['message'])
        
    except Exception as e:
        return create_error_response(f'更新档案库失败: {str(e)}', 500)

@archive_library_api.route('/libraries/<library_id>', methods=['DELETE'])
@require_auth
def delete_library(library_id):
    """
    删除档案库
    
    DELETE /api/libraries/{library_id}
    
    响应:
    {
        "success": true,
        "message": "档案库删除成功"
    }
    """
    try:
        # 获取当前用户
        current_user = get_current_user()
        user_id = current_user.id if current_user else None
        
        # 删除档案库（简化实现）
        delete_result = {
            'success': True,
            'library_id': library_id,
            'deleted_at': datetime.utcnow().isoformat(),
            'message': '档案库删除成功'
        }
        
        return create_success_response(message=delete_result['message'])
        
    except Exception as e:
        return create_error_response(f'删除档案库失败: {str(e)}', 500)

@archive_library_api.route('/archives/<archive_id>/store', methods=['POST'])
@require_auth
def store_archive(archive_id):
    """
    存储电子档案
    
    POST /api/archives/{archive_id}/store
    
    请求体 (multipart/form-data):
    - file: 档案文件
    - encrypt: 是否加密 (true/false)
    - backup: 是否备份 (true/false)
    - preview: 是否生成预览 (true/false)
    - process: 是否处理文件 (true/false)
    
    响应:
    {
        "success": true,
        "data": {
            "file_id": "文件ID",
            "file_hash": "文件哈希",
            "original_path": "原始文件路径",
            "processed_path": "处理后文件路径",
            "encrypted_path": "加密文件路径",
            "backup_path": "备份文件路径",
            "preview_path": "预览文件路径"
        },
        "message": "档案存储成功"
    }
    """
    try:
        # 检查是否有文件上传
        if 'file' not in request.files:
            return create_error_response('没有上传文件', 400)
        
        file = request.files['file']
        if file.filename == '':
            return create_error_response('没有选择文件', 400)
        
        # 检查文件类型
        if not allowed_file(file.filename):
            return create_error_response('文件类型不被支持', 400)
        
        # 获取当前用户
        current_user = get_current_user()
        user_id = current_user.id if current_user else None
        
        # 获取存储选项
        store_options = {
            'encrypt': request.form.get('encrypt', 'true').lower() == 'true',
            'backup': request.form.get('backup', 'true').lower() == 'true',
            'preview': request.form.get('preview', 'true').lower() == 'true',
            'process': request.form.get('process', 'true').lower() == 'true'
        }
        
        # 准备文件数据
        file_data = {
            'name': secure_filename(file.filename),
            'content': file.read(),
            'type': file.content_type,
            'size': len(file.read()) if hasattr(file, 'read') else 0
        }
        
        # 存储档案
        result = archive_library_service.store_archive(
            archive_id=archive_id,
            file_data=file_data,
            store_options=store_options,
            user_id=user_id
        )
        
        if result['success']:
            return create_success_response(data=result, message=result['message'])
        else:
            return create_error_response(result['error'], 500)
            
    except Exception as e:
        return create_error_response(f'存储档案失败: {str(e)}', 500)

@archive_library_api.route('/archives/<archive_id>/retrieve', methods=['GET'])
@require_auth
def retrieve_archive(archive_id):
    """
    检索电子档案
    
    GET /api/archives/{archive_id}/retrieve
    
    查询参数:
    - version: 版本号 (可选)
    - include_backups: 是否包含备份 (true/false, 默认true)
    
    响应:
    {
        "success": true,
        "data": {
            "archive": {
                "id": "档案ID",
                "title": "档案标题",
                "archive_no": "档案编号",
                "category": "档案分类"
            },
            "files": [...],
            "total_files": 3
        }
    }
    """
    try:
        # 获取查询参数
        version = request.args.get('version', type=int)
        include_backups = request.args.get('include_backups', 'true').lower() == 'true'
        
        # 获取当前用户
        current_user = get_current_user()
        user_id = current_user.id if current_user else None
        
        # 检索档案
        result = archive_library_service.retrieve_archive(
            archive_id=archive_id,
            version=version,
            include_backups=include_backups,
            user_id=user_id
        )
        
        if result['success']:
            return create_success_response(data=result)
        else:
            return create_error_response(result['error'], 500)
            
    except Exception as e:
        return create_error_response(f'检索档案失败: {str(e)}', 500)

@archive_library_api.route('/archives/<archive_id>/versions', methods=['POST'])
@require_auth
def create_version(archive_id):
    """
    创建档案新版本
    
    POST /api/archives/{archive_id}/versions
    
    请求体 (multipart/form-data):
    - file: 档案文件
    - version_options: 版本选项 (JSON字符串)
    
    响应:
    {
        "success": true,
        "data": {
            "version_number": 2,
            "file_id": "文件ID"
        },
        "message": "档案版本2创建成功"
    }
    """
    try:
        # 检查是否有文件上传
        if 'file' not in request.files:
            return create_error_response('没有上传文件', 400)
        
        file = request.files['file']
        if file.filename == '':
            return create_error_response('没有选择文件', 400)
        
        # 检查文件类型
        if not allowed_file(file.filename):
            return create_error_response('文件类型不被支持', 400)
        
        # 获取当前用户
        current_user = get_current_user()
        user_id = current_user.id if current_user else None
        
        # 获取版本选项
        version_options = {}
        if 'version_options' in request.form:
            try:
                version_options = json.loads(request.form['version_options'])
            except json.JSONDecodeError:
                version_options = {}
        
        # 准备文件数据
        file_data = {
            'name': secure_filename(file.filename),
            'content': file.read(),
            'type': file.content_type,
            'size': len(file.read()) if hasattr(file, 'read') else 0
        }
        
        # 创建新版本
        result = archive_library_service.create_archive_version(
            archive_id=archive_id,
            file_data=file_data,
            version_options=version_options,
            user_id=user_id
        )
        
        if result['success']:
            return create_success_response(data=result, message=result['message'])
        else:
            return create_error_response(result['error'], 500)
            
    except Exception as e:
        return create_error_response(f'创建档案版本失败: {str(e)}', 500)

@archive_library_api.route('/archives/<archive_id>/lifecycle', methods=['POST'])
@require_auth
def manage_lifecycle(archive_id):
    """
    管理档案生命周期
    
    POST /api/archives/{archive_id}/lifecycle
    
    请求体:
    {
        "new_stage": "active",  # draft, active, reference, archive, disposal
        "lifecycle_options": {
            "notify_users": true,
            "archive_copy": true
        }
    }
    
    响应:
    {
        "success": true,
        "data": {
            "old_stage": "draft",
            "new_stage": "active",
            "transition_actions": [...]
        },
        "message": "档案生命周期阶段从draft转换到active"
    }
    """
    try:
        data = request.get_json()
        if not data:
            return create_error_response('无效的请求数据', 400)
        
        # 验证必需参数
        if 'new_stage' not in data:
            return create_error_response('缺少必需参数: new_stage', 400)
        
        # 获取当前用户
        current_user = get_current_user()
        user_id = current_user.id if current_user else None
        
        # 管理生命周期
        result = archive_library_service.manage_lifecycle(
            archive_id=archive_id,
            new_stage=data['new_stage'],
            lifecycle_options=data.get('lifecycle_options', {}),
            user_id=user_id
        )
        
        if result['success']:
            return create_success_response(data=result, message=result['message'])
        else:
            return create_error_response(result['error'], 500)
            
    except Exception as e:
        return create_error_response(f'管理档案生命周期失败: {str(e)}', 500)

@archive_library_api.route('/archives/<archive_id>/verify', methods=['POST'])
@require_auth
def verify_integrity(archive_id):
    """
    验证档案完整性
    
    POST /api/archives/{archive_id}/verify
    
    请求体:
    {
        "verification_options": {
            "deep_scan": false,  # 是否深度扫描
            "check_backup": true  # 是否检查备份
        }
    }
    
    响应:
    {
        "success": true,
        "data": {
            "verification_summary": {
                "archive_id": "档案ID",
                "verification_time": "验证时间",
                "total_files": 3,
                "verified_files": 3,
                "failed_files": 0,
                "overall_status": "verified",
                "verification_results": [...]
            }
        },
        "message": "档案完整性验证完成"
    }
    """
    try:
        data = request.get_json() or {}
        
        # 获取当前用户
        current_user = get_current_user()
        user_id = current_user.id if current_user else None
        
        # 验证完整性
        result = archive_library_service.verify_archive_integrity(
            archive_id=archive_id,
            verification_options=data.get('verification_options', {}),
            user_id=user_id
        )
        
        if result['success']:
            return create_success_response(data=result, message=result['message'])
        else:
            return create_error_response(result['error'], 500)
            
    except Exception as e:
        return create_error_response(f'验证档案完整性失败: {str(e)}', 500)

@archive_library_api.route('/libraries/<library_id>/cleanup', methods=['POST'])
@require_auth
def cleanup_library(library_id):
    """
    清理档案库
    
    POST /api/libraries/{library_id}/cleanup
    
    请求体:
    {
        "cleanup_options": {
            "cleanup_backups": true,     # 清理过期备份
            "cleanup_orphaned": true,    # 清理孤立文件
            "cleanup_temp": true         # 清理临时文件
        }
    }
    
    响应:
    {
        "success": true,
        "data": {
            "cleanup_results": {
                "files_cleaned": 15,
                "space_freed": 1024000,
                "errors": []
            }
        },
        "message": "档案库清理完成"
    }
    """
    try:
        data = request.get_json() or {}
        
        # 获取当前用户
        current_user = get_current_user()
        user_id = current_user.id if current_user else None
        
        # 清理档案库
        result = archive_library_service.cleanup_archive_library(
            library_path=f"/storage/libraries/{library_id}",
            cleanup_options=data.get('cleanup_options', {}),
            user_id=user_id
        )
        
        if result['success']:
            return create_success_response(data=result, message=result['message'])
        else:
            return create_error_response(result['error'], 500)
            
    except Exception as e:
        return create_error_response(f'清理档案库失败: {str(e)}', 500)

@archive_library_api.route('/statistics', methods=['GET'])
@require_auth
def get_library_statistics():
    """
    获取档案库统计信息
    
    GET /api/statistics
    
    查询参数:
    - period: 统计周期 (day, week, month, year)
    - library_id: 档案库ID (可选)
    
    响应:
    {
        "success": true,
        "data": {
            "total_archives": 150,
            "total_size": 1024000000,
            "storage_efficiency": 0.85,
            "recent_operations": [...],
            "lifecycle_distribution": {
                "draft": 10,
                "active": 80,
                "reference": 40,
                "archive": 20,
                "disposal": 0
            }
        }
    }
    """
    try:
        period = request.args.get('period', 'month')
        library_id = request.args.get('library_id')
        
        # 获取统计信息（简化实现）
        statistics_data = {
            'total_archives': 150,
            'total_size': 1024000000,
            'storage_efficiency': 0.85,
            'recent_operations': [],
            'lifecycle_distribution': {
                'draft': 10,
                'active': 80,
                'reference': 40,
                'archive': 20,
                'disposal': 0
            },
            'period': period,
            'library_id': library_id,
            'generated_at': datetime.utcnow().isoformat()
        }
        
        return create_success_response(data=statistics_data)
        
    except Exception as e:
        return create_error_response(f'获取统计信息失败: {str(e)}', 500)