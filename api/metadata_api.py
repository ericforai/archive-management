"""
元数据管理API - 档案元数据标准化、验证、转换
基于DA/T 94-2022标准的电子会计档案元数据管理RESTful API端点
"""
import logging
from datetime import datetime
from typing import List, Dict, Optional, Any
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity

from services.metadata_service import MetadataService
from services.security_service import SecurityService
from utils.response_utils import success_response, error_response

logger = logging.getLogger(__name__)

# 创建蓝图
metadata_bp = Blueprint('metadata', __name__)

# 初始化服务
metadata_service = MetadataService()
security_service = SecurityService()

def get_current_user_id():
    """获取当前用户ID"""
    try:
        return get_jwt_identity()
    except:
        return None

# 获取标准元数据模板
@metadata_bp.route('/templates', methods=['GET'])
@jwt_required()
def get_metadata_templates(current_user):
    """
    获取标准元数据模板列表
    
    URL参数:
    - category_code: 档案分类代码
    - template_type: 模板类型 (basic, extended, custom)
    """
    try:
        # 获取查询参数
        category_code = request.args.get('category_code')
        template_type = request.args.get('template_type', 'basic')
        
        # 获取元数据模板
        result = metadata_service.get_metadata_templates(
            category_code=category_code,
            template_type=template_type
        )
        
        if result['success']:
            return success_response('获取元数据模板成功', {
                'templates': result['data'],
                'category_code': category_code,
                'template_type': template_type
            })
        else:
            return error_response(
                result.get('error', '获取元数据模板失败'),
                result.get('error_code', 'GET_METADATA_TEMPLATES_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"获取元数据模板API错误: {str(e)}")
        return error_response('获取元数据模板服务异常', 'METADATA_TEMPLATES_SERVICE_ERROR', 500)

# 验证元数据
@metadata_bp.route('/validate', methods=['POST'])
@jwt_required()
def validate_metadata(current_user):
    """
    验证元数据
    
    请求体:
    {
        "metadata": {
            "title": "档案标题",
            "category_code": "voucher",
            "document_number": "V2023001",
            "created_date": "2023-01-15",
            "created_by": "用户",
            ...
        },
        "category_code": "voucher",
        "strict_validation": true
    }
    """
    try:
        # 验证用户权限
        current_user_id = get_current_user_id()
        permission_check = security_service.check_permission(
            current_user_id, 
            'metadata', 
            'validate'
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        # 获取请求参数
        data = request.get_json()
        metadata = data.get('metadata', {})
        category_code = data.get('category_code')
        strict_validation = data.get('strict_validation', True)
        
        if not metadata:
            return error_response('缺少元数据内容', 'MISSING_METADATA', 400)
        
        if not category_code:
            return error_response('缺少档案分类代码', 'MISSING_CATEGORY_CODE', 400)
        
        # 验证元数据
        result = metadata_service.validate_metadata(
            metadata=metadata,
            category_code=category_code,
            strict_validation=strict_validation
        )
        
        if result['success']:
            return success_response('元数据验证成功', {
                'is_valid': result['data']['is_valid'],
                'validation_errors': result['data'].get('validation_errors', []),
                'validation_warnings': result['data'].get('validation_warnings', []),
                'suggested_fixes': result['data'].get('suggested_fixes', [])
            })
        else:
            return error_response(
                result.get('error', '元数据验证失败'),
                result.get('error_code', 'METADATA_VALIDATION_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"验证元数据API错误: {str(e)}")
        return error_response('验证元数据服务异常', 'METADATA_VALIDATION_SERVICE_ERROR', 500)

# 标准化元数据
@metadata_bp.route('/standardize', methods=['POST'])
@jwt_required()
def standardize_metadata(current_user):
    """
    标准化元数据
    
    请求体:
    {
        "metadata": {
            "title": "档案标题",
            "category_code": "voucher",
            "document_number": "V2023001",
            "created_date": "2023-01-15T10:30:00", // ISO格式时间
            ...
        },
        "target_format": "DA/T_94_2022",
        "include_missing_fields": true
    }
    """
    try:
        # 验证用户权限
        current_user_id = get_current_user_id()
        permission_check = security_service.check_permission(
            current_user_id, 
            'metadata', 
            'standardize'
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        # 获取请求参数
        data = request.get_json()
        metadata = data.get('metadata', {})
        target_format = data.get('target_format', 'DA/T_94_2022')
        include_missing_fields = data.get('include_missing_fields', True)
        
        if not metadata:
            return error_response('缺少元数据内容', 'MISSING_METADATA', 400)
        
        # 标准化元数据
        result = metadata_service.standardize_metadata(
            metadata=metadata,
            target_format=target_format,
            include_missing_fields=include_missing_fields
        )
        
        if result['success']:
            return success_response('元数据标准化成功', {
                'standardized_metadata': result['data']['standardized_metadata'],
                'format': target_format,
                'added_fields': result['data'].get('added_fields', []),
                'transformed_fields': result['data'].get('transformed_fields', [])
            })
        else:
            return error_response(
                result.get('error', '元数据标准化失败'),
                result.get('error_code', 'METADATA_STANDARDIZATION_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"标准化元数据API错误: {str(e)}")
        return error_response('标准化元数据服务异常', 'METADATA_STANDARDIZATION_SERVICE_ERROR', 500)

# 转换元数据格式
@metadata_bp.route('/convert', methods=['POST'])
@jwt_required()
def convert_metadata_format(current_user):
    """
    转换元数据格式
    
    请求体:
    {
        "metadata": {
            "title": "档案标题",
            "category_code": "voucher",
            "document_number": "V2023001",
            ...
        },
        "source_format": "custom",
        "target_format": "DA/T_94_2022",
        "field_mapping": {
            "title": "档案名称",
            "document_number": "凭证号"
        }
    }
    """
    try:
        # 验证用户权限
        current_user_id = get_current_user_id()
        permission_check = security_service.check_permission(
            current_user_id, 
            'metadata', 
            'convert'
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        # 获取请求参数
        data = request.get_json()
        metadata = data.get('metadata', {})
        source_format = data.get('source_format', 'custom')
        target_format = data.get('target_format', 'DA/T_94_2022')
        field_mapping = data.get('field_mapping', {})
        
        if not metadata:
            return error_response('缺少元数据内容', 'MISSING_METADATA', 400)
        
        # 转换元数据格式
        result = metadata_service.convert_metadata_format(
            metadata=metadata,
            source_format=source_format,
            target_format=target_format,
            field_mapping=field_mapping
        )
        
        if result['success']:
            return success_response('元数据格式转换成功', {
                'converted_metadata': result['data']['converted_metadata'],
                'source_format': source_format,
                'target_format': target_format,
                'field_mapping': field_mapping,
                'conversion_notes': result['data'].get('conversion_notes', [])
            })
        else:
            return error_response(
                result.get('error', '元数据格式转换失败'),
                result.get('error_code', 'METADATA_CONVERSION_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"转换元数据格式API错误: {str(e)}")
        return error_response('转换元数据格式服务异常', 'METADATA_CONVERSION_SERVICE_ERROR', 500)

# 生成元数据报告
@metadata_bp.route('/report', methods=['POST'])
@jwt_required()
def generate_metadata_report(current_user):
    """
    生成元数据质量报告
    
    请求体:
    {
        "archive_ids": [1, 2, 3], // 可选，指定档案ID列表
        "report_type": "quality", // quality, completeness, standard_compliance
        "include_recommendations": true,
        "date_range": {
            "start": "2023-01-01",
            "end": "2023-12-31"
        }
    }
    """
    try:
        # 验证用户权限
        current_user_id = get_current_user_id()
        permission_check = security_service.check_permission(
            current_user_id, 
            'metadata', 
            'report'
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        # 获取请求参数
        data = request.get_json()
        archive_ids = data.get('archive_ids', [])
        report_type = data.get('report_type', 'quality')
        include_recommendations = data.get('include_recommendations', True)
        date_range = data.get('date_range')
        
        # 生成元数据报告
        result = metadata_service.generate_metadata_report(
            archive_ids=archive_ids,
            report_type=report_type,
            include_recommendations=include_recommendations,
            date_range=date_range
        )
        
        if result['success']:
            return success_response('生成元数据报告成功', {
                'report': result['data'],
                'report_type': report_type,
                'generated_at': datetime.utcnow().isoformat(),
                'archive_count': len(archive_ids) if archive_ids else 'all'
            })
        else:
            return error_response(
                result.get('error', '生成元数据报告失败'),
                result.get('error_code', 'METADATA_REPORT_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"生成元数据报告API错误: {str(e)}")
        return error_response('生成元数据报告服务异常', 'METADATA_REPORT_SERVICE_ERROR', 500)

# 获取元数据字段定义
@metadata_bp.route('/fields', methods=['GET'])
@jwt_required()
def get_metadata_fields(current_user):
    """
    获取元数据字段定义
    
    URL参数:
    - category_code: 档案分类代码
    - format: 格式版本 (DA/T_94_2022, custom)
    """
    try:
        # 获取查询参数
        category_code = request.args.get('category_code')
        format_version = request.args.get('format', 'DA/T_94_2022')
        
        # 获取元数据字段定义
        result = metadata_service.get_metadata_fields(
            category_code=category_code,
            format_version=format_version
        )
        
        if result['success']:
            return success_response('获取元数据字段定义成功', {
                'fields': result['data'],
                'category_code': category_code,
                'format': format_version
            })
        else:
            return error_response(
                result.get('error', '获取元数据字段定义失败'),
                result.get('error_code', 'GET_METADATA_FIELDS_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"获取元数据字段定义API错误: {str(e)}")
        return error_response('获取元数据字段定义服务异常', 'METADATA_FIELDS_SERVICE_ERROR', 500)

# 批量更新元数据
@metadata_bp.route('/batch-update', methods=['POST'])
@jwt_required()
def batch_update_metadata(current_user):
    """
    批量更新元数据
    
    请求体:
    {
        "updates": [
            {
                "archive_id": 1,
                "metadata_updates": {
                    "title": "更新后的标题",
                    "description": "更新后的描述"
                }
            },
            {
                "archive_id": 2,
                "metadata_updates": {
                    "title": "更新后的标题2",
                    "document_number": "NEW2023001"
                }
            }
        ],
        "validate_before_update": true
    }
    """
    try:
        # 验证用户权限
        current_user_id = get_current_user_id()
        permission_check = security_service.check_permission(
            current_user_id, 
            'metadata', 
            'batch_update'
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        # 获取请求参数
        data = request.get_json()
        updates = data.get('updates', [])
        validate_before_update = data.get('validate_before_update', True)
        
        if not updates:
            return error_response('缺少更新内容', 'MISSING_UPDATES', 400)
        
        if len(updates) > 100:  # 限制批量操作数量
            return error_response('批量更新数量超限', 'BATCH_UPDATE_LIMIT_EXCEEDED', 400)
        
        # 批量更新元数据
        result = metadata_service.batch_update_metadata(
            updates=updates,
            validate_before_update=validate_before_update,
            user_id=current_user_id
        )
        
        if result['success']:
            return success_response('批量更新元数据成功', {
                'updated_count': result['data']['updated_count'],
                'failed_count': result['data']['failed_count'],
                'validation_errors': result['data'].get('validation_errors', []),
                'update_details': result['data'].get('update_details', [])
            })
        else:
            return error_response(
                result.get('error', '批量更新元数据失败'),
                result.get('error_code', 'BATCH_UPDATE_METADATA_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"批量更新元数据API错误: {str(e)}")
        return error_response('批量更新元数据服务异常', 'BATCH_UPDATE_METADATA_SERVICE_ERROR', 500)

# 错误处理
@metadata_bp.errorhandler(400)
def bad_request(error):
    return error_response('请求参数错误', 'BAD_REQUEST', 400)

@metadata_bp.errorhandler(403)
def forbidden(error):
    return error_response('访问被禁止', 'FORBIDDEN', 403)

@metadata_bp.errorhandler(500)
def internal_error(error):
    return error_response('服务器内部错误', 'INTERNAL_SERVER_ERROR', 500)