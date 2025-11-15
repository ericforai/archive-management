"""
档案管理API端点
基于DA/T 94-2022标准的档案管理RESTful API
"""
import os
from datetime import datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from marshmallow import Schema, fields, validate, ValidationError

from services.management_service import ArchiveManagementService
from models.user import User
from utils.audit_logger import AuditLogger

# 创建蓝图
management_bp = Blueprint('management', __name__)

# 初始化服务
management_service = ArchiveManagementService()
audit_logger = AuditLogger()

class SearchQuerySchema(Schema):
    """搜索查询参数验证模式"""
    keyword = fields.Str(load_default=None)
    category_id = fields.Int(load_default=None, validate=validate.Range(min=1))
    status = fields.Str(load_default=None, validate=validate.OneOf([
        'draft', 'active', 'archived', 'disposed'
    ]))
    start_date = fields.Date(load_default=None)
    end_date = fields.Date(load_default=None)
    created_by = fields.Int(load_default=None, validate=validate.Range(min=1))
    file_type = fields.Str(load_default=None)
    confidentiality_level = fields.Int(load_default=None, validate=validate.Range(min=1, max=5))
    min_size = fields.Int(load_default=None, validate=validate.Range(min=0))
    max_size = fields.Int(load_default=None, validate=validate.Range(min=0))
    sort_field = fields.Str(load_default='created_at', validate=validate.OneOf([
        'title', 'created_at', 'updated_at', 'total_size', 'status'
    ]))
    sort_order = fields.Str(load_default='desc', validate=validate.OneOf(['asc', 'desc']))
    page = fields.Int(load_default=1, validate=validate.Range(min=1))
    per_page = fields.Int(load_default=20, validate=validate.Range(min=1, max=100))

class UpdateArchiveSchema(Schema):
    """更新档案参数验证模式"""
    title = fields.Str(load_default=None, validate=validate.Length(min=1, max=200))
    description = fields.Str(load_default=None, validate=validate.Length(max=1000))
    category_id = fields.Int(load_default=None, validate=validate.Range(min=1))
    confidentiality_level = fields.Int(load_default=None, validate=validate.Range(min=1, max=5))
    retention_period = fields.Int(load_default=None, validate=validate.Range(min=1, max=100))
    metadata = fields.Dict(load_default=None)

class ArchiveArchiveSchema(Schema):
    """归档档案参数验证模式"""
    reason = fields.Str(load_default='', validate=validate.Length(max=500))

class DisposeArchiveSchema(Schema):
    """处置档案参数验证模式"""
    disposal_method = fields.Str(required=True, validate=validate.OneOf([
        'delete', 'destroy', 'transfer', 'store'
    ]))
    reason = fields.Str(required=True, validate=validate.Length(min=1, max=500))

@management_bp.route('/search', methods=['GET'])
@jwt_required()
def search_archives():
    """
    搜索档案
    """
    try:
        # 获取当前用户
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'success': False,
                'error': '用户不存在',
                'error_code': 'USER_NOT_FOUND'
            }), 404
        
        # 解析和验证查询参数
        schema = SearchQuerySchema()
        try:
            query_params = schema.load(request.args.to_dict())
        except ValidationError as e:
            return jsonify({
                'success': False,
                'error': '参数验证失败',
                'error_code': 'VALIDATION_ERROR',
                'details': e.messages
            }), 400
        
        # 执行搜索
        result = management_service.search_archives(
            query_params=query_params,
            user_id=user_id,
            page=query_params['page'],
            per_page=query_params['per_page']
        )
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'搜索失败: {str(e)}',
            'error_code': 'SEARCH_ERROR'
        }), 500

@management_bp.route('/archive/<int:archive_id>', methods=['GET'])
@jwt_required()
def get_archive_detail(archive_id):
    """
    获取档案详细信息
    """
    try:
        user_id = get_jwt_identity()
        
        result = management_service.get_archive_detail(archive_id, user_id)
        
        if result['success']:
            return jsonify(result), 200
        else:
            error_code = result.get('error_code', 'GET_ARCHIVE_ERROR')
            status_code = 400
            if error_code == 'ARCHIVE_NOT_FOUND':
                status_code = 404
            elif error_code == 'PERMISSION_DENIED':
                status_code = 403
            
            return jsonify(result), status_code
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'获取档案详情失败: {str(e)}',
            'error_code': 'GET_ARCHIVE_ERROR'
        }), 500

@management_bp.route('/archive/<int:archive_id>', methods=['PUT'])
@jwt_required()
def update_archive(archive_id):
    """
    更新档案信息
    """
    try:
        user_id = get_jwt_identity()
        
        # 解析和验证请求数据
        schema = UpdateArchiveSchema()
        try:
            update_data = schema.load(request.get_json() or {})
        except ValidationError as e:
            return jsonify({
                'success': False,
                'error': '参数验证失败',
                'error_code': 'VALIDATION_ERROR',
                'details': e.messages
            }), 400
        
        # 检查是否有数据需要更新
        if not update_data:
            return jsonify({
                'success': False,
                'error': '没有提供需要更新的数据',
                'error_code': 'NO_DATA_TO_UPDATE'
            }), 400
        
        # 执行更新
        result = management_service.update_archive(archive_id, update_data, user_id)
        
        if result['success']:
            return jsonify(result), 200
        else:
            error_code = result.get('error_code', 'UPDATE_ERROR')
            status_code = 400
            if error_code == 'ARCHIVE_NOT_FOUND':
                status_code = 404
            elif error_code == 'PERMISSION_DENIED':
                status_code = 403
            
            return jsonify(result), status_code
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'更新档案失败: {str(e)}',
            'error_code': 'UPDATE_ERROR'
        }), 500

@management_bp.route('/archive/<int:archive_id>/archive', methods=['POST'])
@jwt_required()
def archive_archive(archive_id):
    """
    归档档案
    """
    try:
        user_id = get_jwt_identity()
        
        # 解析和验证请求数据
        schema = ArchiveArchiveSchema()
        try:
            data = schema.load(request.get_json() or {})
        except ValidationError as e:
            return jsonify({
                'success': False,
                'error': '参数验证失败',
                'error_code': 'VALIDATION_ERROR',
                'details': e.messages
            }), 400
        
        reason = data.get('reason', '')
        
        # 执行归档
        result = management_service.archive_archive(archive_id, user_id, reason)
        
        if result['success']:
            return jsonify(result), 200
        else:
            error_code = result.get('error_code', 'ARCHIVE_ERROR')
            status_code = 400
            if error_code == 'ARCHIVE_NOT_FOUND':
                status_code = 404
            elif error_code == 'PERMISSION_DENIED':
                status_code = 403
            
            return jsonify(result), status_code
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'归档档案失败: {str(e)}',
            'error_code': 'ARCHIVE_ERROR'
        }), 500

@management_bp.route('/archive/<int:archive_id>/dispose', methods=['POST'])
@jwt_required()
def dispose_archive(archive_id):
    """
    处置档案
    """
    try:
        user_id = get_jwt_identity()
        
        # 解析和验证请求数据
        schema = DisposeArchiveSchema()
        try:
            data = schema.load(request.get_json())
        except ValidationError as e:
            return jsonify({
                'success': False,
                'error': '参数验证失败',
                'error_code': 'VALIDATION_ERROR',
                'details': e.messages
            }), 400
        
        disposal_method = data['disposal_method']
        reason = data['reason']
        
        # 执行处置
        result = management_service.dispose_archive(archive_id, user_id, disposal_method, reason)
        
        if result['success']:
            return jsonify(result), 200
        else:
            error_code = result.get('error_code', 'DISPOSE_ERROR')
            status_code = 400
            if error_code == 'ARCHIVE_NOT_FOUND':
                status_code = 404
            elif error_code == 'PERMISSION_DENIED':
                status_code = 403
            
            return jsonify(result), status_code
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'处置档案失败: {str(e)}',
            'error_code': 'DISPOSE_ERROR'
        }), 500

@management_bp.route('/statistics', methods=['GET'])
@jwt_required()
def get_statistics():
    """
    获取档案统计信息
    """
    try:
        user_id = get_jwt_identity()
        
        # 获取日期范围参数
        date_range = request.args.get('date_range', '30d')
        valid_ranges = ['7d', '30d', '90d', '1y']
        if date_range not in valid_ranges:
            date_range = '30d'
        
        # 获取统计信息
        result = management_service.get_statistics(user_id, date_range)
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'获取统计信息失败: {str(e)}',
            'error_code': 'STATISTICS_ERROR'
        }), 500

@management_bp.route('/categories', methods=['GET'])
@jwt_required()
def get_categories():
    """
    获取档案分类列表
    """
    try:
        from models.archive import ArchiveCategory
        
        categories = ArchiveCategory.query.filter_by(is_active=True).order_by(
            ArchiveCategory.sort_order, ArchiveCategory.name
        ).all()
        
        categories_data = []
        for category in categories:
            categories_data.append({
                'id': category.id,
                'code': category.code,
                'name': category.name,
                'description': category.description,
                'parent_id': category.parent_id,
                'retention_period': category.retention_period,
                'confidentiality_level': category.confidentiality_level,
                'sort_order': category.sort_order
            })
        
        return jsonify({
            'success': True,
            'data': categories_data
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'获取分类失败: {str(e)}',
            'error_code': 'CATEGORIES_ERROR'
        }), 500

@management_bp.route('/status-options', methods=['GET'])
@jwt_required()
def get_status_options():
    """
    获取档案状态选项
    """
    try:
        from models.archive import ArchiveStatus
        
        status_options = []
        for status in ArchiveStatus:
            status_options.append({
                'value': status.value,
                'label': _get_status_label(status.value)
            })
        
        return jsonify({
            'success': True,
            'data': status_options
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'获取状态选项失败: {str(e)}',
            'error_code': 'STATUS_OPTIONS_ERROR'
        }), 500

@management_bp.route('/confidentiality-levels', methods=['GET'])
@jwt_required()
def get_confidentiality_levels():
    """
    获取保密等级选项
    """
    try:
        levels = [
            {'value': 1, 'label': '公开', 'description': '可以公开的档案信息'},
            {'value': 2, 'label': '内部', 'description': '内部使用的档案信息'},
            {'value': 3, 'label': '秘密', 'description': '需要保密的档案信息'},
            {'value': 4, 'label': '机密', 'description': '高度机密的档案信息'},
            {'value': 5, 'label': '绝密', 'description': '最高级别的保密档案'}
        ]
        
        return jsonify({
            'success': True,
            'data': levels
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'获取保密等级失败: {str(e)}',
            'error_code': 'CONFIDENTIALITY_LEVELS_ERROR'
        }), 500

@management_bp.route('/disposal-methods', methods=['GET'])
@jwt_required()
def get_disposal_methods():
    """
    获取处置方式选项
    """
    try:
        methods = [
            {
                'value': 'delete',
                'label': '删除',
                'description': '从系统中永久删除档案'
            },
            {
                'value': 'destroy',
                'label': '销毁',
                'description': '物理销毁档案载体'
            },
            {
                'value': 'transfer',
                'label': '转移',
                'description': '转移到其他机构'
            },
            {
                'value': 'store',
                'label': '继续保存',
                'description': '继续保存档案'
            }
        ]
        
        return jsonify({
            'success': True,
            'data': methods
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'获取处置方式失败: {str(e)}',
            'error_code': 'DISPOSAL_METHODS_ERROR'
        }), 500

@management_bp.route('/batch-operations', methods=['POST'])
@jwt_required()
def batch_operations():
    """
    批量操作档案
    """
    try:
        user_id = get_jwt_identity()
        
        data = request.get_json()
        if not data or 'operation' not in data or 'archive_ids' not in data:
            return jsonify({
                'success': False,
                'error': '缺少必要参数',
                'error_code': 'MISSING_PARAMETERS'
            }), 400
        
        operation = data['operation']
        archive_ids = data['archive_ids']
        
        if not isinstance(archive_ids, list) or not archive_ids:
            return jsonify({
                'success': False,
                'error': '档案ID列表无效',
                'error_code': 'INVALID_ARCHIVE_IDS'
            }), 400
        
        # 支持的批量操作
        if operation == 'archive':
            results = []
            successful_count = 0
            
            for archive_id in archive_ids:
                try:
                    result = management_service.archive_archive(
                        archive_id, user_id, data.get('reason', '批量归档')
                    )
                    if result['success']:
                        successful_count += 1
                    results.append({
                        'archive_id': archive_id,
                        'success': result['success'],
                        'error': result.get('error', '')
                    })
                except Exception as e:
                    results.append({
                        'archive_id': archive_id,
                        'success': False,
                        'error': str(e)
                    })
            
            return jsonify({
                'success': successful_count > 0,
                'message': f'成功归档 {successful_count}/{len(archive_ids)} 个档案',
                'total_count': len(archive_ids),
                'success_count': successful_count,
                'results': results
            })
        
        else:
            return jsonify({
                'success': False,
                'error': f'不支持的批量操作: {operation}',
                'error_code': 'UNSUPPORTED_OPERATION'
            }), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'批量操作失败: {str(e)}',
            'error_code': 'BATCH_OPERATION_ERROR'
        }), 500

def _get_status_label(status_value: str) -> str:
    """
    获取状态标签
    """
    status_labels = {
        'draft': '草稿',
        'active': '活跃',
        'archived': '已归档',
        'disposed': '已处置'
    }
    return status_labels.get(status_value, status_value)