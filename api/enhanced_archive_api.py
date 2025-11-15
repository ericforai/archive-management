"""
增强版档案管理API - 完整的档案CRUD操作
支持高级搜索、筛选、分页等功能
"""
from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, date, timedelta
from werkzeug.security import check_password_hash
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db
from models.archive import ElectronicArchive, ArchiveCategory, ArchiveFile
from models.user import User
from models.audit import AuditLog, LifecycleRecord
from models.workflow import WorkflowRecord
from utils.audit_logger import AuditLogger
audit_logger = AuditLogger()
from utils.response_utils import create_success_response, create_error_response
from sqlalchemy import or_, and_, desc, asc
from sqlalchemy.orm import joinedload
import json
import uuid

enhanced_archive_bp = Blueprint('enhanced_archive', __name__)

# 修复所有路由路径 - 移除重复前缀
# GET /archives
@enhanced_archive_bp.route('/archives', methods=['GET'])
@jwt_required()
def list_archives():
    """获取档案列表 - 支持高级搜索和筛选"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        # 获取查询参数
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        search = request.args.get('search', '').strip()
        category_id = request.args.get('category_id', '').strip()
        status = request.args.get('status', '').strip()
        security_level = request.args.get('security_level', '').strip()
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc')
        date_from = request.args.get('date_from', '').strip()
        date_to = request.args.get('date_to', '').strip()
        
        # 构建查询
        query = ElectronicArchive.query.options(
            joinedload(ElectronicArchive.category),
            joinedload(ElectronicArchive.creator),
            joinedload(ElectronicArchive.files)
        )
        
        # 权限过滤
        if current_user.role != 'admin':
            query = query.filter(ElectronicArchive.created_by == current_user.id)
        
        # 搜索条件
        if search:
            search_condition = or_(
                ElectronicArchive.title.ilike(f'%{search}%'),
                ElectronicArchive.archive_no.ilike(f'%{search}%'),
                ElectronicArchive.description.ilike(f'%{search}%'),
                ElectronicArchive.keywords.ilike(f'%{search}%')
            )
            query = query.filter(search_condition)
        
        # 分类筛选
        if category_id:
            query = query.filter(ElectronicArchive.category_id == category_id)
        
        # 状态筛选
        if status:
            query = query.filter(ElectronicArchive.status == status)
        
        # 保密等级筛选
        if security_level:
            query = query.filter(ElectronicArchive.confidentiality_level == int(security_level))
        
        # 日期范围筛选
        if date_from:
            try:
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
                query = query.filter(ElectronicArchive.created_date >= date_from_obj)
            except ValueError:
                pass
        
        if date_to:
            try:
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
                query = query.filter(ElectronicArchive.created_date <= date_to_obj)
            except ValueError:
                pass
        
        # 排序
        if sort_by == 'title':
            sort_field = ElectronicArchive.title
        elif sort_by == 'created_date':
            sort_field = ElectronicArchive.created_date
        elif sort_by == 'category':
            sort_field = ArchiveCategory.name
        elif sort_by == 'size':
            sort_field = ElectronicArchive.total_size
        else:
            sort_field = ElectronicArchive.created_at
        
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
        archives = []
        for archive in pagination.items:
            archive_data = archive.to_dict(include_files=False, include_metadata=False)
            
            # 计算真实的统计信息
            file_count = len(archive.files) if archive.files else 0
            total_file_size = sum(file.file_size for file in archive.files) if archive.files else 0
            
            archive_data['statistics'] = {
                'file_count': file_count,
                'total_size_mb': round(total_file_size / (1024 * 1024), 2),
                'total_size_text': f"{round(total_file_size / (1024 * 1024), 2)} MB"
            }
            
            # 简化分类信息
            if archive.category:
                archive_data['category_name'] = archive.category.name
            else:
                archive_data['category_name'] = '未分类'
                
            # 简化创建者信息
            if archive.creator:
                archive_data['creator_name'] = archive.creator.full_name
            else:
                archive_data['creator_name'] = '未知用户'
            
            # 添加当前借阅状态（基于状态判断）
            if archive.status == 'active':
                archive_data['borrow_status'] = 'available'
                archive_data['borrow_status_text'] = '可借阅'
            elif archive.status == 'archived':
                archive_data['borrow_status'] = 'archived'
                archive_data['borrow_status_text'] = '已归档'
            else:
                archive_data['borrow_status'] = 'draft'
                archive_data['borrow_status_text'] = '草稿'
            
            archives.append(archive_data)
        
        # 记录操作日志
        audit_logger.log_operation(
            user_id=str(current_user.id),
            operation_type='list_archives',
            target_type='archive',
            target_id=None,
            description=f'获取档案列表',
            details={
                'search': search,
                'filters': {'category_id': category_id, 'status': status, 'security_level': security_level},
                'total_count': pagination.total
            }
        )
        
        return create_success_response({
            'archives': archives,
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
        current_app.logger.error(f"获取档案列表失败: {str(e)}")
        return create_error_response(f'获取档案列表失败: {str(e)}', 500)

@enhanced_archive_bp.route('/archives', methods=['POST'])
@jwt_required()
def create_archive():
    """创建新档案"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        data = request.get_json()
        
        # 验证必填字段
        required_fields = ['title', 'category_id', 'retention_period']
        for field in required_fields:
            if not data.get(field):
                return create_error_response(f'缺少必填字段: {field}', 400)
        
        # 验证分类是否存在
        category = ArchiveCategory.query.filter_by(id=data['category_id'], is_active=True).first()
        if not category:
            return create_error_response('指定的分类不存在', 400)
        
        # 生成档案号
        archive_no = f"DA{datetime.now().strftime('%Y%m%d')}{str(uuid.uuid4())[:8].upper()}"
        
        # 创建档案
        archive = ElectronicArchive(
            archive_no=archive_no,
            title=data['title'],
            category_id=data['category_id'],
            organization_id=current_user.organization_id or 'default',
            created_by=current_user.id,
            retention_period=data['retention_period'],
            status='draft',
            created_date=datetime.strptime(data.get('created_date', datetime.now().strftime('%Y-%m-%d')), '%Y-%m-%d').date(),
            description=data.get('description', ''),
            keywords=data.get('keywords', ''),
            confidentiality_level=int(data.get('confidentiality_level', 1)),
            ai_tags=data.get('ai_tags', '')
        )
        
        db.session.add(archive)
        db.session.flush()  # 获取ID
        
        # 记录操作日志
        audit_logger.log_operation(
            user_id=str(current_user.id),
            operation_type='create_archive',
            target_type='archive',
            target_id=str(archive.id),
            description=f'创建档案 {archive_no}',
            details={
                'archive_no': archive_no,
                'title': data['title'],
                'category': category.name
            }
        )
        
        db.session.commit()
        
        return create_success_response({
            'message': '档案创建成功',
            'archive': archive.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"创建档案失败: {str(e)}")
        return create_error_response(f'创建档案失败: {str(e)}', 500)

@enhanced_archive_bp.route('/archives/<archive_id>', methods=['GET'])
@jwt_required()
def get_archive(archive_id):
    """获取档案详情"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        # 查询档案
        query = ElectronicArchive.query.options(
            joinedload(ElectronicArchive.category),
            joinedload(ElectronicArchive.creator),
            joinedload(ElectronicArchive.files)
        )
        
        # 权限过滤
        if current_user.role != 'admin':
            query = query.filter(ElectronicArchive.created_by == current_user.id)
        
        archive = query.filter(ElectronicArchive.id == archive_id).first()
        
        if not archive:
            return create_error_response('档案不存在', 404)
        
        # 记录操作日志
        audit_logger.log_operation(
            user_id=str(current_user.id),
            operation_type='view_archive',
            target_type='archive',
            target_id=str(archive_id),
            description=f'查看档案 {archive.archive_no}',
            details={'archive_no': archive.archive_no}
        )
        
        return create_success_response({
            'archive': archive.to_dict(include_files=True, include_metadata=True)
        })
        
    except Exception as e:
        current_app.logger.error(f"获取档案详情失败: {str(e)}")
        return create_error_response(f'获取档案详情失败: {str(e)}', 500)

@enhanced_archive_bp.route('/archives/<archive_id>', methods=['PUT'])
@jwt_required()
def update_archive(archive_id):
    """更新档案信息"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        data = request.get_json()
        
        # 查询档案
        query = ElectronicArchive.query
        if current_user.role != 'admin':
            query = query.filter(ElectronicArchive.created_by == current_user.id)
        
        archive = query.filter(ElectronicArchive.id == archive_id).first()
        
        if not archive:
            return create_error_response('档案不存在', 404)
        
        # 更新字段
        if 'title' in data:
            archive.title = data['title']
        if 'description' in data:
            archive.description = data['description']
        if 'keywords' in data:
            archive.keywords = data['keywords']
        if 'confidentiality_level' in data:
            archive.confidentiality_level = int(data['confidentiality_level'])
        if 'retention_period' in data:
            archive.retention_period = data['retention_period']
        if 'status' in data:
            archive.status = data['status']
        
        archive.updated_at = datetime.utcnow()
        
        # 记录操作日志
        audit_logger.log_operation(
            user_id=str(current_user.id),
            operation_type='update_archive',
            target_type='archive',
            target_id=str(archive_id),
            description=f'更新档案 {archive.archive_no}',
            details={
                'archive_no': archive.archive_no,
                'updated_fields': list(data.keys())
            }
        )
        
        db.session.commit()
        
        return create_success_response({
            'message': '档案更新成功',
            'archive': archive.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"更新档案失败: {str(e)}")
        return create_error_response(f'更新档案失败: {str(e)}', 500)

@enhanced_archive_bp.route('/archives/<archive_id>', methods=['DELETE'])
@jwt_required()
def delete_archive(archive_id):
    """删除档案"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        # 查询档案
        query = ElectronicArchive.query
        if current_user.role != 'admin':
            query = query.filter(ElectronicArchive.created_by == current_user.id)
        
        archive = query.filter(ElectronicArchive.id == archive_id).first()
        
        if not archive:
            return create_error_response('档案不存在', 404)
        
        # 检查是否有关联文件
        if archive.files:
            return create_error_response('该档案包含文件，无法删除', 400)
        
        archive_no = archive.archive_no
        
        db.session.delete(archive)
        
        # 记录操作日志
        audit_logger.log_operation(
            user_id=str(current_user.id),
            operation_type='delete_archive',
            target_type='archive',
            target_id=str(archive_id),
            description=f'删除档案 {archive_no}',
            details={'archive_no': archive_no}
        )
        
        db.session.commit()
        
        return create_success_response({
            'message': '档案删除成功'
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"删除档案失败: {str(e)}")
        return create_error_response(f'删除档案失败: {str(e)}', 500)

@enhanced_archive_bp.route('/categories', methods=['GET'])
@jwt_required()
def get_categories():
    """获取分类树"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        categories = ArchiveCategory.query.filter_by(is_active=True).order_by(ArchiveCategory.code).all()
        
        def build_tree(categories, parent_id=None):
            tree = []
            for category in categories:
                if category.parent_id == parent_id:
                    children = build_tree(categories, category.id)
                    category_dict = category.to_dict()
                    if children:
                        category_dict['children'] = children
                    tree.append(category_dict)
            return tree
        
        category_tree = build_tree(categories)
        
        return create_success_response({
            'categories': category_tree
        })
        
    except Exception as e:
        current_app.logger.error(f"获取分类失败: {str(e)}")
        return create_error_response(f'获取分类失败: {str(e)}', 500)

@enhanced_archive_bp.route('/statistics', methods=['GET'])
@jwt_required()
def get_statistics():
    """获取档案统计信息"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        # 基础查询
        query = ElectronicArchive.query
        if current_user.role != 'admin':
            query = query.filter(ElectronicArchive.created_by == current_user.id)
        
        # 总档案数
        total_archives = query.count()
        
        # 按状态统计
        status_stats = {}
        for status in ['draft', 'active', 'archived', 'disposed', 'transferred']:
            count = query.filter(ElectronicArchive.status == status).count()
            status_stats[status] = count
        
        # 按保密等级统计
        security_stats = {}
        for level in range(1, 6):
            count = query.filter(ElectronicArchive.confidentiality_level == level).count()
            security_stats[f'level_{level}'] = count
        
        # 按分类统计
        category_stats = db.session.query(
            ArchiveCategory.name,
            db.func.count(ElectronicArchive.id).label('count')
        ).outerjoin(
            ElectronicArchive, ArchiveCategory.id == ElectronicArchive.category_id
        ).group_by(
            ArchiveCategory.id, ArchiveCategory.name
        ).all()
        
        category_distribution = {cat.name: cat.count for cat in category_stats}
        
        # 文件统计
        total_files = db.session.query(db.func.count(ArchiveFile.id)).join(
            ElectronicArchive, ArchiveFile.archive_id == ElectronicArchive.id
        ).filter(
            ElectronicArchive.id.in_(query.with_entities(ElectronicArchive.id))
        ).scalar() or 0
        
        # 总存储空间 - 真实计算
        total_size = query.with_entities(
            db.func.sum(ElectronicArchive.total_size)
        ).scalar() or 0
        
        # 时间趋势分析（最近30天）
        thirty_days_ago = datetime.now() - timedelta(days=30)
        recent_query = query.filter(ElectronicArchive.created_at >= thirty_days_ago)
        
        # 每日创建趋势
        daily_trends = []
        for i in range(30):
            day_start = thirty_days_ago + timedelta(days=i)
            day_end = day_start + timedelta(days=1)
            day_count = recent_query.filter(
                ElectronicArchive.created_at >= day_start,
                ElectronicArchive.created_at < day_end
            ).count()
            daily_trends.append({
                'date': day_start.strftime('%Y-%m-%d'),
                'count': day_count
            })
        
        # 最近活动（基于真实数据）
        recent_activities = []
        
        # 获取最近的创建活动
        recent_creates = query.order_by(
            desc(ElectronicArchive.created_at)
        ).limit(3).all()
        
        for archive in recent_creates:
            if archive.creator:
                recent_activities.append({
                    'type': 'create',
                    'message': f'新增档案：{archive.title}',
                    'user': archive.creator.full_name,
                    'timestamp': archive.created_at.isoformat(),
                    'archive_id': str(archive.id)
                })
        
        # 获取最近的审计日志作为活动参考
        recent_audits = AuditLog.query.order_by(
            desc(AuditLog.created_at)
        ).limit(5).all()
        
        for audit in recent_audits:
            if audit.user:
                recent_activities.append({
                    'type': audit.operation_type,
                    'message': f'{audit.operation_type}: {audit.description}',
                    'user': audit.user.full_name,
                    'timestamp': audit.created_at.isoformat(),
                    'archive_id': audit.resource_id
                })
        
        # 按时间排序并限制数量
        recent_activities.sort(key=lambda x: x['timestamp'], reverse=True)
        recent_activities = recent_activities[:10]
        
        # 存储使用统计
        storage_stats = {
            'total_mb': round(total_size / (1024 * 1024), 2),
            'total_gb': round(total_size / (1024 * 1024 / 1024), 2),
            'avg_per_archive_mb': round(total_size / (1024 * 1024) / total_archives, 2) if total_archives > 0 else 0,
            'avg_per_file_mb': round(total_size / (1024 * 1024) / total_files, 2) if total_files > 0 else 0
        }
        
        # 计算活跃率
        active_archives = status_stats.get('draft', 0) + status_stats.get('active', 0)
        active_rate = (active_archives / total_archives * 100) if total_archives > 0 else 0
        
        return create_success_response({
            'overview': {
                'total_archives': total_archives,
                'active_archives': active_archives,
                'archived_archives': status_stats.get('archived', 0),
                'total_files': total_files,
                'active_rate': round(active_rate, 1),
                'storage_stats': storage_stats
            },
            'status_distribution': status_stats,
            'security_distribution': security_stats,
            'category_distribution': category_distribution,
            'daily_trends': daily_trends,
            'recent_activities': recent_activities
        })
        
    except Exception as e:
        current_app.logger.error(f"获取统计信息失败: {str(e)}")
        return create_error_response(f'获取统计信息失败: {str(e)}', 500)

@enhanced_archive_bp.route('/borrow/<archive_id>', methods=['POST'])
@jwt_required()
def borrow_archive(archive_id):
    """借阅档案"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        data = request.get_json() or {}
        days = int(data.get('days', 7))  # 默认借阅7天
        
        # 查询档案
        query = ElectronicArchive.query
        if current_user.role != 'admin':
            query = query.filter(ElectronicArchive.created_by == current_user.id)
        
        archive = query.filter(ElectronicArchive.id == archive_id).first()
        
        if not archive:
            return create_error_response('档案不存在', 404)
        
        # 检查借阅条件
        if archive.confidentiality_level > 3:
            return create_error_response('档案保密等级较高，无法借阅', 403)
        
        # 记录操作日志
        audit_logger.log_operation(
            user_id=str(current_user.id),
            operation_type='borrow_archive',
            target_type='archive',
            target_id=str(archive_id),
            description=f'借阅档案 {archive.archive_no}',
            details={
                'archive_no': archive.archive_no,
                'borrow_days': days
            }
        )
        
        # 这里应该实际创建借阅记录，简化处理
        return create_success_response({
            'message': f'档案借阅成功，借阅期限{days}天',
            'borrow_info': {
                'archive_id': archive_id,
                'archive_no': archive.archive_no,
                'borrow_date': datetime.now().date().isoformat(),
                'return_date': (datetime.now().date()).isoformat(),
                'borrower': current_user.full_name
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"借阅档案失败: {str(e)}")
        return create_error_response(f'借阅档案失败: {str(e)}', 500)

@enhanced_archive_bp.route('/return/<archive_id>', methods=['POST'])
@jwt_required()
def return_archive(archive_id):
    """归还档案"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        # 查询档案
        query = ElectronicArchive.query
        if current_user.role != 'admin':
            query = query.filter(ElectronicArchive.created_by == current_user.id)
        
        archive = query.filter(ElectronicArchive.id == archive_id).first()
        
        if not archive:
            return create_error_response('档案不存在', 404)
        
        # 记录操作日志
        audit_logger.log_operation(
            user_id=str(current_user.id),
            operation_type='return_archive',
            target_type='archive',
            target_id=str(archive_id),
            description=f'归还档案 {archive.archive_no}',
            details={'archive_no': archive.archive_no}
        )
        
        return create_success_response({
            'message': '档案归还成功'
        })
        
    except Exception as e:
        current_app.logger.error(f"归还档案失败: {str(e)}")
        return create_error_response(f'归还档案失败: {str(e)}', 500)

@enhanced_archive_bp.route('/lifecycle', methods=['GET'])
@jwt_required()
def get_lifecycle_records():
    """获取生命周期记录列表"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        archive_id = request.args.get('archive_id')
        event_type = request.args.get('event_type')
        
        # 构建查询
        query = LifecycleRecord.query
        
        # 权限过滤
        if current_user.role != 'admin':
            query = query.join(ElectronicArchive).filter(
                ElectronicArchive.created_by == current_user.id
            )
        
        # 筛选条件
        if archive_id:
            query = query.filter(LifecycleRecord.archive_id == archive_id)
        if event_type:
            query = query.filter(LifecycleRecord.event_type == event_type)
        
        # 分页
        pagination = query.order_by(LifecycleRecord.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return create_success_response({
            'items': [record.to_dict() for record in pagination.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"获取生命周期记录失败: {str(e)}")
        return create_error_response(f'获取生命周期记录失败: {str(e)}', 500)

@enhanced_archive_bp.route('/lifecycle', methods=['POST'])
@jwt_required()
def create_lifecycle_record():
    """创建生命周期记录"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        data = request.get_json()
        
        # 验证必填字段
        required_fields = ['archive_id', 'event_type', 'description']
        for field in required_fields:
            if not data.get(field):
                return create_error_response(f'缺少必填字段: {field}', 400)
        
        # 检查档案是否存在
        archive = ElectronicArchive.query.filter_by(id=data['archive_id']).first()
        if not archive:
            return create_error_response('档案不存在', 404)
        
        # 权限检查
        if current_user.role != 'admin' and archive.created_by != current_user.id:
            return create_error_response('无权限操作该档案', 403)
        
        # 创建生命周期记录
        lifecycle_record = LifecycleRecord(
            archive_id=data['archive_id'],
            event_type=data['event_type'],
            event_date=datetime.strptime(data.get('event_date', datetime.now().date().isoformat()), '%Y-%m-%d'),
            description=data['description'],
            operator_id=current_user.id,
            event_metadata=data.get('metadata'),
            approval_required=data.get('approval_required', False),
            is_automated=data.get('is_automated', False),
            automation_rule=data.get('automation_rule')
        )
        
        db.session.add(lifecycle_record)
        db.session.commit()
        
        # 记录操作日志
        audit_logger.log_operation(
            user_id=str(current_user.id),
            operation_type='create_lifecycle_record',
            target_type='lifecycle_record',
            target_id=str(lifecycle_record.id),
            description=f'创建生命周期记录: {data["event_type"]}',
            details={
                'archive_id': data['archive_id'],
                'event_type': data['event_type']
            }
        )
        
        return create_success_response({
            'message': '生命周期记录创建成功',
            'record': lifecycle_record.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"创建生命周期记录失败: {str(e)}")
        return create_error_response(f'创建生命周期记录失败: {str(e)}', 500)

@enhanced_archive_bp.route('/lifecycle/<record_id>', methods=['PUT'])
@jwt_required()
def update_lifecycle_record(record_id):
    """更新生命周期记录"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        lifecycle_record = LifecycleRecord.query.get(record_id)
        if not lifecycle_record:
            return create_error_response('生命周期记录不存在', 404)
        
        # 权限检查
        if current_user.role != 'admin' and lifecycle_record.operator_id != current_user.id:
            return create_error_response('无权限修改该记录', 403)
        
        data = request.get_json()
        
        # 更新字段
        if 'description' in data:
            lifecycle_record.description = data['description']
        if 'event_metadata' in data:
            lifecycle_record.event_metadata = data['event_metadata']
        if 'approval_status' in data:
            lifecycle_record.approval_status = data['approval_status']
            lifecycle_record.approved_by = current_user.id
            lifecycle_record.approved_at = datetime.utcnow()
        if 'approval_comments' in data:
            lifecycle_record.approval_comments = data['approval_comments']
        
        lifecycle_record.created_at = datetime.utcnow()  # 更新时间
        
        db.session.commit()
        
        # 记录操作日志
        audit_logger.log_operation(
            user_id=str(current_user.id),
            operation_type='update_lifecycle_record',
            target_type='lifecycle_record',
            target_id=str(record_id),
            description=f'更新生命周期记录',
            details={'record_id': record_id}
        )
        
        return create_success_response({
            'message': '生命周期记录更新成功',
            'record': lifecycle_record.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"更新生命周期记录失败: {str(e)}")
        return create_error_response(f'更新生命周期记录失败: {str(e)}', 500)

@enhanced_archive_bp.route('/lifecycle/<record_id>', methods=['DELETE'])
@jwt_required()
def delete_lifecycle_record(record_id):
    """删除生命周期记录"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        lifecycle_record = LifecycleRecord.query.get(record_id)
        if not lifecycle_record:
            return create_error_response('生命周期记录不存在', 404)
        
        # 权限检查（只有管理员和创建者可以删除）
        if current_user.role != 'admin' and lifecycle_record.operator_id != current_user.id:
            return create_error_response('无权限删除该记录', 403)
        
        # 检查是否有审批记录（已审批的记录不能删除）
        if lifecycle_record.approval_status == 'approved':
            return create_error_response('已审批的记录不能删除', 403)
        
        db.session.delete(lifecycle_record)
        db.session.commit()
        
        # 记录操作日志
        audit_logger.log_operation(
            user_id=str(current_user.id),
            operation_type='delete_lifecycle_record',
            target_type='lifecycle_record',
            target_id=str(record_id),
            description=f'删除生命周期记录',
            details={'record_id': record_id}
        )
        
        return create_success_response({
            'message': '生命周期记录删除成功'
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"删除生命周期记录失败: {str(e)}")
        return create_error_response(f'删除生命周期记录失败: {str(e)}', 500)

@enhanced_archive_bp.route('/lifecycle/statistics', methods=['GET'])
@jwt_required()
def get_lifecycle_statistics():
    """获取生命周期统计信息"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        # 构建查询
        query = LifecycleRecord.query.join(ElectronicArchive)
        
        # 权限过滤
        if current_user.role != 'admin':
            query = query.filter(ElectronicArchive.created_by == current_user.id)
        
        # 按事件类型统计
        event_type_stats = {}
        for event_type in ['created', 'archived', 'transferred', 'disposed', 'migrated', 'restored']:
            count = query.filter(LifecycleRecord.event_type == event_type).count()
            event_type_stats[event_type] = count
        
        # 按月份统计（最近12个月）
        monthly_stats = []
        for i in range(12):
            month_start = datetime.now().replace(day=1) - timedelta(days=30*i)
            month_end = month_start + timedelta(days=32)
            month_end = month_end.replace(day=1)
            
            count = query.filter(
                LifecycleRecord.created_at >= month_start,
                LifecycleRecord.created_at < month_end
            ).count()
            
            monthly_stats.append({
                'month': month_start.strftime('%Y-%m'),
                'count': count
            })
        
        # 自动化事件统计
        automated_stats = query.filter(LifecycleRecord.is_automated == True).count()
        manual_stats = query.filter(LifecycleRecord.is_automated == False).count()
        
        # 待审批事件
        pending_approval = query.filter(
            LifecycleRecord.approval_required == True,
            LifecycleRecord.approval_status == 'pending'
        ).count()
        
        return create_success_response({
            'event_type_distribution': event_type_stats,
            'monthly_trend': monthly_stats,
            'automation_stats': {
                'automated': automated_stats,
                'manual': manual_stats,
                'automation_rate': round(automated_stats / (automated_stats + manual_stats) * 100, 1) if (automated_stats + manual_stats) > 0 else 0
            },
            'approval_stats': {
                'pending_approval': pending_approval
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"获取生命周期统计失败: {str(e)}")
        return create_error_response(f'获取生命周期统计失败: {str(e)}', 500)

@enhanced_archive_bp.route('/lifecycle/auto-trigger', methods=['POST'])
@jwt_required()
def trigger_lifecycle_event():
    """自动触发生命周期事件"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        data = request.get_json()
        archive_id = data.get('archive_id')
        event_type = data.get('event_type')
        
        if not archive_id or not event_type:
            return create_error_response('缺少必要参数', 400)
        
        # 查询档案
        archive = ElectronicArchive.query.filter_by(id=archive_id).first()
        if not archive:
            return create_error_response('档案不存在', 404)
        
        # 权限检查
        if current_user.role != 'admin' and archive.created_by != current_user.id:
            return create_error_response('无权限操作该档案', 403)
        
        # 定义事件描述和元数据
        event_descriptions = {
            'created': '档案创建',
            'archived': '档案归档',
            'transferred': '档案转移',
            'disposed': '档案销毁',
            'migrated': '档案迁移',
            'restored': '档案恢复'
        }
        
        # 创建生命周期记录
        lifecycle_record = LifecycleRecord(
            archive_id=archive_id,
            event_type=event_type,
            event_date=datetime.now().date(),
            description=event_descriptions.get(event_type, f'档案{event_type}'),
            operator_id=current_user.id,
            is_automated=True,
            automation_rule=f'manual_trigger_{event_type}',
            approval_required=event_type in ['disposed', 'transferred']  # 销毁和转移需要审批
        )
        
        db.session.add(lifecycle_record)
        db.session.commit()
        
        # 记录操作日志
        audit_logger.log_operation(
            user_id=str(current_user.id),
            operation_type='trigger_lifecycle_event',
            target_type='lifecycle_record',
            target_id=str(lifecycle_record.id),
            description=f'触发生命周期事件: {event_type}',
            details={
                'archive_id': archive_id,
                'event_type': event_type,
                'is_automated': True
            }
        )
        
        return create_success_response({
            'message': f'生命周期事件 {event_type} 触发成功',
            'record': lifecycle_record.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"触发生命周期事件失败: {str(e)}")
        return create_error_response(f'触发生命周期事件失败: {str(e)}', 500)

@enhanced_archive_bp.route('/workflow', methods=['POST'])
@jwt_required()
def create_workflow():
    """创建工作流"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        data = request.get_json()
        
        # 验证必填字段
        required_fields = ['title', 'type', 'target_resource_id']
        for field in required_fields:
            if not data.get(field):
                return create_error_response(f'缺少必填字段: {field}', 400)
        
        # 创建工作流记录
        workflow = WorkflowRecord(
            title=data['title'],
            workflow_type=data['type'],
            target_resource_type=data.get('target_resource_type', 'archive'),
            target_resource_id=data['target_resource_id'],
            description=data.get('description', ''),
            initiator_id=current_user.id,
            status='pending',
            priority=data.get('priority', 'normal'),
            due_date=datetime.strptime(data['due_date'], '%Y-%m-%d').date() if data.get('due_date') else None,
            workflow_config=data.get('workflow_config', {})
        )
        
        db.session.add(workflow)
        db.session.commit()
        
        # 记录操作日志
        audit_logger.log_operation(
            user_id=str(current_user.id),
            operation_type='create_workflow',
            target_type='workflow',
            target_id=str(workflow.id),
            description=f'创建工作流: {data["title"]}',
            details={
                'workflow_type': data['type'],
                'target_resource_id': data['target_resource_id']
            }
        )
        
        return create_success_response({
            'message': '工作流创建成功',
            'workflow': workflow.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"创建工作流失败: {str(e)}")
        return create_error_response(f'创建工作流失败: {str(e)}', 500)

@enhanced_archive_bp.route('/workflow/<workflow_id>/approve', methods=['POST'])
@jwt_required()
def approve_workflow(workflow_id):
    """审批工作流"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        data = request.get_json()
        comments = data.get('comments', '')
        
        workflow = WorkflowRecord.query.filter_by(id=workflow_id).first()
        if not workflow:
            return create_error_response('工作流不存在', 404)
        
        # 更新工作流状态
        workflow.status = 'approved'
        workflow.approved_by = current_user.id
        workflow.approved_at = datetime.utcnow()
        workflow.approval_comments = comments
        
        db.session.commit()
        
        # 记录操作日志
        audit_logger.log_operation(
            user_id=str(current_user.id),
            operation_type='approve_workflow',
            target_type='workflow',
            target_id=str(workflow_id),
            description=f'审批通过工作流: {workflow.title}',
            details={
                'workflow_title': workflow.title,
                'comments': comments
            }
        )
        
        return create_success_response({
            'message': '工作流审批通过',
            'workflow': workflow.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"审批工作流失败: {str(e)}")
        return create_error_response(f'审批工作流失败: {str(e)}', 500)

@enhanced_archive_bp.route('/workflow/<workflow_id>/reject', methods=['POST'])
@jwt_required()
def reject_workflow(workflow_id):
    """拒绝工作流"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        data = request.get_json()
        reason = data.get('reason', '未说明原因')
        
        workflow = WorkflowRecord.query.filter_by(id=workflow_id).first()
        if not workflow:
            return create_error_response('工作流不存在', 404)
        
        # 更新工作流状态
        workflow.status = 'rejected'
        workflow.approved_by = current_user.id
        workflow.approved_at = datetime.utcnow()
        workflow.approval_comments = reason
        
        db.session.commit()
        
        # 记录操作日志
        audit_logger.log_operation(
            user_id=str(current_user.id),
            operation_type='reject_workflow',
            target_type='workflow',
            target_id=str(workflow_id),
            description=f'拒绝工作流: {workflow.title}',
            details={
                'workflow_title': workflow.title,
                'reason': reason
            }
        )
        
        return create_success_response({
            'message': '工作流已拒绝',
            'workflow': workflow.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"拒绝工作流失败: {str(e)}")
        return create_error_response(f'拒绝工作流失败: {str(e)}', 500)

@enhanced_archive_bp.route('/workflow', methods=['GET'])
@jwt_required()
def list_workflows():
    """获取工作流列表"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        # 获取查询参数
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        status = request.args.get('status', '').strip()
        workflow_type = request.args.get('type', '').strip()
        priority = request.args.get('priority', '').strip()
        search = request.args.get('search', '').strip()
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc')
        
        # 构建查询
        query = WorkflowRecord.query.options(
            joinedload(WorkflowRecord.initiator),
            joinedload(WorkflowRecord.approver)
        )
        
        # 权限过滤
        if current_user.role != 'admin':
            query = query.filter(
                or_(
                    WorkflowRecord.initiator_id == current_user.id,
                    WorkflowRecord.approved_by == current_user.id
                )
            )
        
        # 搜索条件
        if search:
            search_condition = or_(
                WorkflowRecord.title.ilike(f'%{search}%'),
                WorkflowRecord.description.ilike(f'%{search}%')
            )
            query = query.filter(search_condition)
        
        # 状态筛选
        if status:
            query = query.filter(WorkflowRecord.status == status)
        
        # 工作流类型筛选
        if workflow_type:
            query = query.filter(WorkflowRecord.workflow_type == workflow_type)
        
        # 优先级筛选
        if priority:
            query = query.filter(WorkflowRecord.priority == priority)
        
        # 排序
        if sort_by == 'title':
            sort_field = WorkflowRecord.title
        elif sort_by == 'due_date':
            sort_field = WorkflowRecord.due_date
        elif sort_by == 'priority':
            # 优先级排序
            priority_order = case(
                (WorkflowRecord.priority == 'high', 1),
                (WorkflowRecord.priority == 'normal', 2),
                (WorkflowRecord.priority == 'low', 3),
                else_=4
            )
            if sort_order == 'asc':
                query = query.order_by(asc(priority_order))
            else:
                query = query.order_by(desc(priority_order))
        else:
            sort_field = WorkflowRecord.created_at
        
        if sort_by != 'priority':
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
        workflows = []
        for workflow in pagination.items:
            workflow_data = workflow.to_dict()
            
            # 添加发起人信息
            if workflow.initiator:
                workflow_data['initiator_name'] = workflow.initiator.full_name
            else:
                workflow_data['initiator_name'] = '未知用户'
                
            # 添加审批人信息
            if workflow.approver:
                workflow_data['approver_name'] = workflow.approver.full_name
            else:
                workflow_data['approver_name'] = None
            
            # 计算状态显示文本
            status_map = {
                'pending': '待审批',
                'approved': '已通过',
                'rejected': '已拒绝',
                'cancelled': '已取消'
            }
            workflow_data['status_text'] = status_map.get(workflow.status, workflow.status)
            
            # 优先级显示文本
            priority_map = {
                'high': '高',
                'normal': '中',
                'low': '低'
            }
            workflow_data['priority_text'] = priority_map.get(workflow.priority, workflow.priority)
            
            workflows.append(workflow_data)
        
        # 记录操作日志
        audit_logger.log_operation(
            user_id=str(current_user.id),
            operation_type='list_workflows',
            target_type='workflow',
            target_id=None,
            description=f'获取工作流列表',
            details={
                'filters': {
                    'status': status,
                    'type': workflow_type,
                    'priority': priority
                },
                'total_count': pagination.total
            }
        )
        
        return create_success_response({
            'workflows': workflows,
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
        current_app.logger.error(f"获取工作流列表失败: {str(e)}")
        return create_error_response(f'获取工作流列表失败: {str(e)}', 500)

@enhanced_archive_bp.route('/lifecycle-records', methods=['GET'])
@jwt_required()
def list_lifecycle_records():
    """获取生命周期记录列表"""
    try:
        current_user = User.query.filter_by(id=get_jwt_identity()).first()
        if not current_user:
            return create_error_response('用户不存在', 401)
        
        # 获取查询参数
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        event_type = request.args.get('event_type', '').strip()
        status = request.args.get('status', '').strip()
        search = request.args.get('search', '').strip()
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc')
        
        # 构建查询
        query = LifecycleRecord.query.options(
            joinedload(LifecycleRecord.archive),
            joinedload(LifecycleRecord.archived_by_user)
        )
        
        # 权限过滤
        if current_user.role != 'admin':
            query = query.filter(
                LifecycleRecord.archive_id.in_(
                    db.session.query(Archive.id).filter(
                        or_(
                            Archive.created_by == current_user.id,
                            Archive.assigned_to == current_user.id
                        )
                    )
                )
            )
        
        # 搜索条件
        if search:
            search_condition = or_(
                LifecycleRecord.description.ilike(f'%{search}%'),
                Archive.title.ilike(f'%{search}%')
            )
            query = query.filter(search_condition)
        
        # 事件类型筛选
        if event_type:
            query = query.filter(LifecycleRecord.event_type == event_type)
        
        # 状态筛选
        if status:
            query = query.filter(LifecycleRecord.status == status)
        
        # 排序
        if sort_by == 'event_type':
            sort_field = LifecycleRecord.event_type
        elif sort_by == 'event_date':
            sort_field = LifecycleRecord.event_date
        elif sort_by == 'status':
            sort_field = LifecycleRecord.status
        else:
            sort_field = LifecycleRecord.created_at
        
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
        lifecycle_records = []
        for record in pagination.items:
            record_data = record.to_dict()
            
            # 添加档案信息
            if record.archive:
                record_data['archive_title'] = record.archive.title
                record_data['archive_number'] = record.archive.archive_number
            else:
                record_data['archive_title'] = '未知档案'
                record_data['archive_number'] = 'N/A'
                
            # 添加操作人信息
            if record.archived_by_user:
                record_data['archived_by_name'] = record.archived_by_user.full_name
            else:
                record_data['archived_by_name'] = '系统'
            
            # 计算事件类型显示文本
            event_type_map = {
                'archive_created': '档案创建',
                'archive_updated': '档案更新',
                'archive_approved': '档案审核通过',
                'archive_rejected': '档案审核拒绝',
                'archive_borrowed': '档案借出',
                'archive_returned': '档案归还',
                'archive_expired': '档案到期',
                'archive_archived': '档案归档',
                'archive_destroyed': '档案销毁',
                'archive_transferred': '档案转移',
                'security_review': '安全审查',
                'compliance_check': '合规检查',
                'backup_created': '备份创建',
                'backup_restored': '备份恢复'
            }
            record_data['event_type_text'] = event_type_map.get(record.event_type, record.event_type)
            
            # 状态显示文本
            status_map = {
                'completed': '已完成',
                'in_progress': '进行中',
                'failed': '失败',
                'cancelled': '已取消'
            }
            record_data['status_text'] = status_map.get(record.status, record.status)
            
            lifecycle_records.append(record_data)
        
        # 记录操作日志
        audit_logger.log_operation(
            user_id=str(current_user.id),
            operation_type='list_lifecycle_records',
            target_type='lifecycle_record',
            target_id=None,
            description=f'获取生命周期记录列表',
            details={
                'filters': {
                    'event_type': event_type,
                    'status': status
                },
                'total_count': pagination.total
            }
        )
        
        return create_success_response({
            'lifecycle_records': lifecycle_records,
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
        current_app.logger.error(f"获取生命周期记录列表失败: {str(e)}")
        return create_error_response(f'获取生命周期记录列表失败: {str(e)}', 500)