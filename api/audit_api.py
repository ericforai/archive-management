"""
审计日志API - 用户操作记录、系统审计、安全日志
基于DA/T 94-2022标准的电子会计档案管理系统审计日志RESTful API端点
"""
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity

from services.audit_service import AuditService
from services.security_service import SecurityService
from utils.response_utils import success_response, error_response
from utils.audit_logger import AuditLogger

logger = logging.getLogger(__name__)

# 创建蓝图
audit_bp = Blueprint('audit', __name__)

# 初始化服务
audit_service = AuditService()
security_service = SecurityService()
audit_logger = AuditLogger()

def get_current_user_id():
    """获取当前用户ID"""
    try:
        return get_jwt_identity()
    except:
        return None

# 获取审计日志列表
@audit_bp.route('/logs', methods=['GET'])
@jwt_required()
def get_audit_logs(current_user):
    """
    获取审计日志列表
    
    URL参数:
    - page: 页码 (默认: 1)
    - per_page: 每页数量 (默认: 20, 最大: 100)
    - start_date: 开始日期 (YYYY-MM-DD)
    - end_date: 结束日期 (YYYY-MM-DD)
    - user_id: 用户ID
    - operation_type: 操作类型
    - resource_type: 资源类型
    - resource_id: 资源ID
    - level: 日志级别 (INFO, WARNING, ERROR)
    """
    try:
        # 验证用户权限
        current_user_id = get_current_user_id()
        permission_check = security_service.check_permission(
            current_user_id, 
            'audit_log', 
            'read'
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        # 获取查询参数
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        user_id = request.args.get('user_id', type=int)
        operation_type = request.args.get('operation_type')
        resource_type = request.args.get('resource_type')
        resource_id = request.args.get('resource_id', type=int)
        level = request.args.get('level')
        
        # 构建过滤条件
        filters = {}
        if start_date:
            filters['start_date'] = start_date
        if end_date:
            filters['end_date'] = end_date
        if user_id:
            filters['user_id'] = user_id
        if operation_type:
            filters['operation_type'] = operation_type
        if resource_type:
            filters['resource_type'] = resource_type
        if resource_id:
            filters['resource_id'] = resource_id
        if level:
            filters['level'] = level
        
        # 获取审计日志
        result = audit_service.get_audit_logs(
            page=page,
            per_page=per_page,
            filters=filters
        )
        
        if result['success']:
            return success_response('获取审计日志成功', {
                'logs': result['data'],
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total_count': result['total_count'],
                    'total_pages': result['total_pages']
                },
                'filters': filters
            })
        else:
            return error_response(
                result.get('error', '获取审计日志失败'),
                result.get('error_code', 'GET_AUDIT_LOGS_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"获取审计日志API错误: {str(e)}")
        return error_response('获取审计日志服务异常', 'AUDIT_LOGS_SERVICE_ERROR', 500)

# 获取审计统计信息
@audit_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_audit_stats(current_user):
    """
    获取审计统计信息
    
    URL参数:
    - date_range: 日期范围 (7d, 30d, 90d, 1y)
    - group_by: 分组方式 (day, week, month)
    """
    try:
        # 验证用户权限
        current_user_id = get_current_user_id()
        permission_check = security_service.check_permission(
            current_user_id, 
            'audit_log', 
            'read'
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        # 获取查询参数
        date_range = request.args.get('date_range', '30d')
        group_by = request.args.get('group_by', 'day')
        
        # 获取审计统计
        result = audit_service.get_audit_statistics(
            date_range=date_range,
            group_by=group_by
        )
        
        if result['success']:
            return success_response('获取审计统计成功', {
                'statistics': result['data'],
                'date_range': date_range,
                'group_by': group_by,
                'generated_at': datetime.utcnow().isoformat()
            })
        else:
            return error_response(
                result.get('error', '获取审计统计失败'),
                result.get('error_code', 'GET_AUDIT_STATS_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"获取审计统计API错误: {str(e)}")
        return error_response('获取审计统计服务异常', 'AUDIT_STATS_SERVICE_ERROR', 500)

# 获取用户操作日志
@audit_bp.route('/user/<int:user_id>/logs', methods=['GET'])
@jwt_required()
def get_user_audit_logs(current_user, user_id):
    """
    获取指定用户的操作日志
    
    URL参数:
    - page: 页码 (默认: 1)
    - per_page: 每页数量 (默认: 20)
    - days: 最近天数 (默认: 30)
    """
    try:
        # 验证用户权限
        current_user_id = get_current_user_id()
        
        # 允许用户查看自己的日志，或管理员查看他人日志
        if current_user_id != user_id:
            permission_check = security_service.check_permission(
                current_user_id, 
                'audit_log', 
                'read'
            )
            if not permission_check['allowed']:
                return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        # 获取查询参数
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        days = int(request.args.get('days', 30))
        
        # 计算日期范围
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # 获取用户审计日志
        result = audit_service.get_user_audit_logs(
            user_id=user_id,
            start_date=start_date.strftime('%Y-%m-%d'),
            end_date=end_date.strftime('%Y-%m-%d'),
            page=page,
            per_page=per_page
        )
        
        if result['success']:
            return success_response('获取用户操作日志成功', {
                'user_id': user_id,
                'logs': result['data'],
                'date_range': {
                    'start': start_date.strftime('%Y-%m-%d'),
                    'end': end_date.strftime('%Y-%m-%d')
                },
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total_count': result['total_count'],
                    'total_pages': result['total_pages']
                }
            })
        else:
            return error_response(
                result.get('error', '获取用户操作日志失败'),
                result.get('error_code', 'GET_USER_AUDIT_LOGS_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"获取用户操作日志API错误: {str(e)}")
        return error_response('获取用户操作日志服务异常', 'USER_AUDIT_LOGS_SERVICE_ERROR', 500)

# 获取系统安全事件
@audit_bp.route('/security/events', methods=['GET'])
@jwt_required()
def get_security_events(current_user):
    """
    获取系统安全事件
    
    URL参数:
    - page: 页码 (默认: 1)
    - per_page: 每页数量 (默认: 20)
    - event_type: 事件类型 (login_failure, permission_denied, suspicious_activity等)
    - severity: 严重级别 (low, medium, high, critical)
    - days: 最近天数 (默认: 7)
    """
    try:
        # 验证用户权限（需要管理员权限）
        current_user_id = get_current_user_id()
        permission_check = security_service.check_permission(
            current_user_id, 
            'audit_log', 
            'read'
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        # 获取查询参数
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        event_type = request.args.get('event_type')
        severity = request.args.get('severity')
        days = int(request.args.get('days', 7))
        
        # 构建过滤条件
        filters = {'level': 'WARNING'}  # 安全事件通常是警告级别以上
        if event_type:
            filters['operation_type'] = event_type
        if severity:
            filters['severity'] = severity
        
        # 计算日期范围
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        filters['start_date'] = start_date.strftime('%Y-%m-%d')
        filters['end_date'] = end_date.strftime('%Y-%m-%d')
        
        # 获取安全事件
        result = audit_service.get_audit_logs(
            page=page,
            per_page=per_page,
            filters=filters
        )
        
        if result['success']:
            return success_response('获取系统安全事件成功', {
                'events': result['data'],
                'date_range': {
                    'start': start_date.strftime('%Y-%m-%d'),
                    'end': end_date.strftime('%Y-%m-%d')
                },
                'filters': filters,
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total_count': result['total_count'],
                    'total_pages': result['total_pages']
                }
            })
        else:
            return error_response(
                result.get('error', '获取系统安全事件失败'),
                result.get('error_code', 'GET_SECURITY_EVENTS_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"获取系统安全事件API错误: {str(e)}")
        return error_response('获取系统安全事件服务异常', 'SECURITY_EVENTS_SERVICE_ERROR', 500)

# 导出审计日志
@audit_bp.route('/export', methods=['POST'])
@jwt_required()
def export_audit_logs(current_user):
    """
    导出审计日志
    
    请求体:
    {
        "start_date": "2023-01-01",
        "end_date": "2023-12-31",
        "format": "csv", // csv, excel, json
        "filters": {
            "user_id": 1,
            "operation_type": "create_archive"
        }
    }
    """
    try:
        # 验证用户权限（需要管理员权限）
        current_user_id = get_current_user_id()
        permission_check = security_service.check_permission(
            current_user_id, 
            'audit_log', 
            'export'
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        # 获取请求参数
        data = request.get_json()
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        export_format = data.get('format', 'csv')
        filters = data.get('filters', {})
        
        if not start_date or not end_date:
            return error_response('缺少开始日期或结束日期', 'MISSING_DATE_RANGE', 400)
        
        # 导出审计日志
        result = audit_service.export_audit_logs(
            start_date=start_date,
            end_date=end_date,
            format=export_format,
            filters=filters
        )
        
        if result['success']:
            # 记录导出操作
            audit_logger.log_user_action(
                user_id=current_user_id,
                action='export_audit_logs',
                details={
                    'start_date': start_date,
                    'end_date': end_date,
                    'format': export_format,
                    'filters': filters,
                    'record_count': result.get('record_count', 0)
                }
            )
            
            return success_response('导出审计日志成功', {
                'download_url': result.get('download_url'),
                'file_name': result.get('file_name'),
                'file_size': result.get('file_size'),
                'record_count': result.get('record_count', 0),
                'export_format': export_format
            })
        else:
            return error_response(
                result.get('error', '导出审计日志失败'),
                result.get('error_code', 'EXPORT_AUDIT_LOGS_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"导出审计日志API错误: {str(e)}")
        return error_response('导出审计日志服务异常', 'EXPORT_AUDIT_LOGS_SERVICE_ERROR', 500)

# 错误处理
@audit_bp.errorhandler(400)
def bad_request(error):
    return error_response('请求参数错误', 'BAD_REQUEST', 400)

@audit_bp.errorhandler(403)
def forbidden(error):
    return error_response('访问被禁止', 'FORBIDDEN', 403)

@audit_bp.errorhandler(500)
def internal_error(error):
    return error_response('服务器内部错误', 'INTERNAL_SERVER_ERROR', 500)