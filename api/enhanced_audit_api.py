"""
增强版审计管理API - 审计日志查询和统计分析
"""
from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, date, timedelta
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db
from models.user import User
from models.audit import AuditLog, IntegrityRecord
from utils.audit_logger import AuditLogger
audit_logger = AuditLogger()
from utils.response_utils import create_success_response, create_error_response
from sqlalchemy import or_, and_, desc, asc, func, text
import json

enhanced_audit_bp = Blueprint('enhanced_audit', __name__)

@enhanced_audit_bp.route('/audit', methods=['GET'])
@jwt_required()
def get_audit_logs():
    """获取审计日志列表"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        # 权限检查（只有管理员和审计员可以查看审计日志）
        if current_user.role not in ['admin', 'auditor']:
            return create_error_response('无权限查看审计日志', 403)
        
        # 获取查询参数
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        search = request.args.get('search', '').strip()
        user_id = request.args.get('user_id', '').strip()
        operation_type = request.args.get('operation_type', '').strip()
        resource_type = request.args.get('resource_type', '').strip()
        result = request.args.get('result', '').strip()
        risk_level = request.args.get('risk_level', '').strip()
        date_from = request.args.get('date_from', '').strip()
        date_to = request.args.get('date_to', '').strip()
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc')
        
        # 构建查询
        query = AuditLog.query.join(User, AuditLog.user_id == User.id)
        
        # 搜索条件
        if search:
            search_condition = or_(
                AuditLog.operation_details.ilike(f'%{search}%'),
                User.full_name.ilike(f'%{search}%'),
                User.username.ilike(f'%{search}%'),
                AuditLog.resource_id.ilike(f'%{search}%')
            )
            query = query.filter(search_condition)
        
        # 用户筛选
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        
        # 操作类型筛选
        if operation_type:
            query = query.filter(AuditLog.operation_type == operation_type)
        
        # 资源类型筛选
        if resource_type:
            query = query.filter(AuditLog.resource_type == resource_type)
        
        # 结果筛选
        if result:
            query = query.filter(AuditLog.result == result)
        
        # 风险等级筛选
        if risk_level:
            query = query.filter(AuditLog.risk_level == int(risk_level))
        
        # 日期范围筛选
        if date_from:
            try:
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(AuditLog.created_at >= date_from_obj)
            except ValueError:
                pass
        
        if date_to:
            try:
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
                query = query.filter(AuditLog.created_at < date_to_obj)
            except ValueError:
                pass
        
        # 排序
        if sort_by == 'created_at':
            sort_field = AuditLog.created_at
        elif sort_by == 'user':
            sort_field = User.full_name
        elif sort_by == 'operation_type':
            sort_field = AuditLog.operation_type
        elif sort_by == 'risk_level':
            sort_field = AuditLog.risk_level
        else:
            sort_field = AuditLog.created_at
        
        if sort_order == 'asc':
            query = query.order_by(asc(sort_field))
        else:
            query = query.order_by(desc(sort_field))
        
        # 分页
        pagination = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        # 构建响应数据
        audit_logs = []
        for log in pagination.items:
            log_data = log.to_dict()
            log_data['user_name'] = log.user.full_name if log.user else None
            log_data['user_role'] = log.user.role if log.user else None
            audit_logs.append(log_data)
        
        return create_success_response({
            'audit_logs': audit_logs,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"获取审计日志失败: {str(e)}")
        return create_error_response(f'获取审计日志失败: {str(e)}', 500)

@enhanced_audit_bp.route('/audit/statistics', methods=['GET'])
@jwt_required()
def get_audit_statistics():
    """获取审计统计数据"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        # 权限检查
        if current_user.role not in ['admin', 'auditor']:
            return create_error_response('无权限查看审计统计', 403)
        
        # 时间范围
        days = int(request.args.get('days', 30))
        date_from = datetime.now() - timedelta(days=days)
        
        # 基础统计
        base_query = AuditLog.query.filter(AuditLog.created_at >= date_from)
        
        # 总操作数
        total_operations = base_query.count()
        
        # 按操作类型统计
        operation_stats = {}
        for op_type in ['create', 'view', 'download', 'print', 'modify', 'delete', 'login', 'logout']:
            count = base_query.filter(AuditLog.operation_type == op_type).count()
            operation_stats[op_type] = count
        
        # 按用户统计
        user_stats = db.session.query(
            User.full_name,
            func.count(AuditLog.id).label('operation_count')
        ).join(
            AuditLog, AuditLog.user_id == User.id
        ).filter(
            AuditLog.created_at >= date_from
        ).group_by(
            User.full_name
        ).order_by(
            text('operation_count DESC')
        ).limit(10).all()
        
        # 按风险等级统计
        risk_stats = {}
        for level in [1, 2, 3, 4]:
            count = base_query.filter(AuditLog.risk_level == level).count()
            risk_stats[f'level_{level}'] = count
        
        # 成功率统计
        success_count = base_query.filter(AuditLog.result == 'success').count()
        failure_count = base_query.filter(AuditLog.result == 'failure').count()
        success_rate = (success_count / total_operations * 100) if total_operations > 0 else 0
        
        # 每日操作趋势（最近7天）
        daily_trends = []
        for i in range(7):
            day = datetime.now() - timedelta(days=i)
            day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day_start + timedelta(days=1)
            
            day_count = AuditLog.query.filter(
                AuditLog.created_at >= day_start,
                AuditLog.created_at < day_end
            ).count()
            
            daily_trends.append({
                'date': day_start.date().isoformat(),
                'count': day_count
            })
        
        daily_trends.reverse()
        
        # 高风险操作统计
        high_risk_operations = base_query.filter(
            AuditLog.risk_level >= 3
        ).all()
        
        high_risk_details = []
        for operation in high_risk_operations[-10:]:  # 最近10个高风险操作
            high_risk_details.append({
                'id': operation.id,
                'operation_type': operation.operation_type,
                'resource_type': operation.resource_type,
                'user_name': operation.user.full_name if operation.user else None,
                'result': operation.result,
                'created_at': operation.created_at.isoformat()
            })
        
        return create_success_response({
            'overview': {
                'total_operations': total_operations,
                'success_count': success_count,
                'failure_count': failure_count,
                'success_rate': round(success_rate, 1),
                'high_risk_count': sum(risk_stats.values())
            },
            'operation_distribution': operation_stats,
            'user_activity': [{'user_name': name, 'count': count} for name, count in user_stats],
            'risk_distribution': risk_stats,
            'daily_trends': daily_trends,
            'high_risk_operations': high_risk_details
        })
        
    except Exception as e:
        current_app.logger.error(f"获取审计统计失败: {str(e)}")
        return create_error_response(f'获取审计统计失败: {str(e)}', 500)

@enhanced_audit_bp.route('/audit/integrity', methods=['GET'])
@jwt_required()
def get_integrity_records():
    """获取完整性记录列表"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        # 权限检查
        if current_user.role not in ['admin', 'auditor']:
            return create_error_response('无权限查看完整性记录', 403)
        
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        archive_id = request.args.get('archive_id')
        operation_type = request.args.get('operation_type')
        verification_status = request.args.get('verification_status')
        
        # 构建查询
        query = IntegrityRecord.query
        
        if archive_id:
            query = query.filter(IntegrityRecord.archive_id == archive_id)
        if operation_type:
            query = query.filter(IntegrityRecord.operation_type == operation_type)
        if verification_status:
            query = query.filter(IntegrityRecord.verification_status == verification_status)
        
        # 分页
        pagination = query.order_by(IntegrityRecord.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return create_success_response({
            'integrity_records': [record.to_dict() for record in pagination.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"获取完整性记录失败: {str(e)}")
        return create_error_response(f'获取完整性记录失败: {str(e)}', 500)

@enhanced_audit_bp.route('/audit/export', methods=['GET'])
@jwt_required()
def export_audit_logs():
    """导出审计日志"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        # 权限检查
        if current_user.role not in ['admin', 'auditor']:
            return create_error_response('无权限导出审计日志', 403)
        
        # 获取查询参数（与get_audit_logs相同）
        date_from = request.args.get('date_from', '').strip()
        date_to = request.args.get('date_to', '').strip()
        operation_type = request.args.get('operation_type', '').strip()
        
        # 构建查询
        query = AuditLog.query.join(User, AuditLog.user_id == User.id)
        
        if date_from:
            try:
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(AuditLog.created_at >= date_from_obj)
            except ValueError:
                pass
        
        if date_to:
            try:
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
                query = query.filter(AuditLog.created_at < date_to_obj)
            except ValueError:
                pass
        
        if operation_type:
            query = query.filter(AuditLog.operation_type == operation_type)
        
        # 获取数据
        audit_logs = query.order_by(AuditLog.created_at.desc()).limit(10000).all()
        
        # 构建导出数据
        export_data = []
        for log in audit_logs:
            export_data.append({
                '时间': log.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                '用户': log.user.full_name if log.user else '未知',
                '操作类型': log.operation_type,
                '资源类型': log.resource_type,
                '资源ID': log.resource_id,
                '操作结果': log.result,
                '风险等级': log.risk_level,
                'IP地址': log.ip_address or '',
                '详细信息': json.dumps(log.operation_details, ensure_ascii=False) if log.operation_details else ''
            })
        
        # 记录导出操作
        audit_logger.log_operation(
            user_id=str(current_user.id),
            operation_type='export_audit_logs',
            target_type='system',
            target_id='audit_export',
            description=f'导出审计日志',
            details={
                'export_count': len(export_data),
                'date_range': f"{date_from} - {date_to}",
                'operation_type': operation_type or '全部'
            }
        )
        
        return create_success_response({
            'message': f'成功导出 {len(export_data)} 条审计记录',
            'export_data': export_data,
            'export_time': datetime.now().isoformat()
        })
        
    except Exception as e:
        current_app.logger.error(f"导出审计日志失败: {str(e)}")
        return create_error_response(f'导出审计日志失败: {str(e)}', 500)