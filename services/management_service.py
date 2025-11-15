"""
档案管理服务
基于DA/T 94-2022标准的档案生命周期管理服务
"""
import os
import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from flask import current_app
from sqlalchemy import and_, or_, desc, asc, func
from werkzeug.utils import secure_filename

from models.archive import ElectronicArchive, ArchiveFile, ArchiveCategory
from models.user import User
from models.audit import AuditLog
from services.audit_service import AuditService
from services.integrity_service import IntegrityService
from utils.file_handler import FileHandler
from utils.archive_validator import ArchiveValidator

class ArchiveManagementService:
    """
    档案管理服务类
    
    负责档案的全生命周期管理，包括：
    - 档案查询和检索
    - 档案信息更新
    - 档案归档和处置
    - 档案生命周期状态管理
    - 档案权限控制
    - 档案统计分析
    """
    
    def __init__(self):
        self.file_handler = FileHandler()
        self.validator = ArchiveValidator()
        self.audit_service = AuditService()
        self.integrity_service = IntegrityService()
        
    def search_archives(self, 
                       query_params: Dict[str, Any], 
                       user_id: int,
                       page: int = 1,
                       per_page: int = 20) -> Dict[str, Any]:
        """
        档案搜索查询
        
        Args:
            query_params: 查询参数
            user_id: 用户ID
            page: 页码
            per_page: 每页数量
            
        Returns:
            查询结果和分页信息
        """
        try:
            # 构建查询条件
            query = ElectronicArchive.query
            
            # 关键词搜索
            if query_params.get('keyword'):
                keyword = f"%{query_params['keyword']}%"
                query = query.filter(
                    or_(
                        ElectronicArchive.title.ilike(keyword),
                        ElectronicArchive.description.ilike(keyword),
                        ElectronicArchive.archive_no.ilike(keyword)
                    )
                )
            
            # 按分类筛选
            if query_params.get('category_id'):
                query = query.filter(ElectronicArchive.category_id == query_params['category_id'])
            
            # 按状态筛选
            if query_params.get('status'):
                query = query.filter(ElectronicArchive.status == query_params['status'])
            
            # 按日期范围筛选
            if query_params.get('start_date'):
                start_date = datetime.strptime(query_params['start_date'], '%Y-%m-%d')
                query = query.filter(ElectronicArchive.created_at >= start_date)
            
            if query_params.get('end_date'):
                end_date = datetime.strptime(query_params['end_date'], '%Y-%m-%d') + timedelta(days=1)
                query = query.filter(ElectronicArchive.created_at < end_date)
            
            # 按创建人筛选
            if query_params.get('created_by'):
                query = query.filter(ElectronicArchive.created_by == query_params['created_by'])
            
            # 按文件类型筛选
            if query_params.get('file_type'):
                query = query.join(ArchiveFile).filter(
                    ArchiveFile.file_type.ilike(f"%{query_params['file_type']}%")
                )
            
            # 按保密等级筛选
            if query_params.get('confidentiality_level'):
                query = query.filter(ElectronicArchive.confidentiality_level == query_params['confidentiality_level'])
            
            # 按大小范围筛选
            if query_params.get('min_size'):
                query = query.filter(ElectronicArchive.total_size >= query_params['min_size'])
            
            if query_params.get('max_size'):
                query = query.filter(ElectronicArchive.total_size <= query_params['max_size'])
            
            # 权限过滤
            query = self._apply_permission_filter(query, user_id)
            
            # 排序
            sort_field = query_params.get('sort_field', 'created_at')
            sort_order = query_params.get('sort_order', 'desc')
            
            if sort_field in ['title', 'created_at', 'updated_at', 'total_size', 'status']:
                if sort_order == 'asc':
                    query = query.order_by(asc(getattr(ElectronicArchive, sort_field)))
                else:
                    query = query.order_by(desc(getattr(ElectronicArchive, sort_field)))
            
            # 执行分页查询
            pagination = query.paginate(
                page=page,
                per_page=per_page,
                error_out=False
            )
            
            # 格式化结果
            archives = []
            for archive in pagination.items:
                archive_dict = self._format_archive_summary(archive)
                archives.append(archive_dict)
            
            return {
                'success': True,
                'data': {
                    'archives': archives,
                    'pagination': {
                        'page': page,
                        'per_page': per_page,
                        'total': pagination.total,
                        'pages': pagination.pages,
                        'has_prev': pagination.has_prev,
                        'has_next': pagination.has_next
                    }
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'档案搜索失败: {str(e)}',
                'error_code': 'ARCHIVE_SEARCH_ERROR'
            }
    
    def get_archive_detail(self, archive_id: int, user_id: int) -> Dict[str, Any]:
        """
        获取档案详细信息
        
        Args:
            archive_id: 档案ID
            user_id: 用户ID
            
        Returns:
            档案详细信息
        """
        try:
            # 获取档案信息
            archive = ElectronicArchive.query.get(archive_id)
            if not archive:
                return {
                    'success': False,
                    'error': '档案不存在',
                    'error_code': 'ARCHIVE_NOT_FOUND'
                }
            
            # 权限检查
            if not self._check_archive_permission(archive, user_id, 'read'):
                return {
                    'success': False,
                    'error': '没有访问权限',
                    'error_code': 'PERMISSION_DENIED'
                }
            
            # 获取详细信息
            archive_detail = self._format_archive_detail(archive)
            
            # 记录访问日志
            self.audit_service.log_operation(
                user_id=user_id,
                operation_type='VIEW_ARCHIVE',
                target_type='archive',
                target_id=str(archive_id),
                description=f'查看档案: {archive.title}',
                ip_address='127.0.0.1'  # 实际应从请求中获取
            )
            
            return {
                'success': True,
                'data': archive_detail
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'获取档案详情失败: {str(e)}',
                'error_code': 'ARCHIVE_DETAIL_ERROR'
            }
    
    def update_archive(self, archive_id: int, update_data: Dict[str, Any], user_id: int) -> Dict[str, Any]:
        """
        更新档案信息
        
        Args:
            archive_id: 档案ID
            update_data: 更新数据
            user_id: 用户ID
            
        Returns:
            更新结果
        """
        try:
            # 获取档案信息
            archive = ElectronicArchive.query.get(archive_id)
            if not archive:
                return {
                    'success': False,
                    'error': '档案不存在',
                    'error_code': 'ARCHIVE_NOT_FOUND'
                }
            
            # 权限检查
            if not self._check_archive_permission(archive, user_id, 'write'):
                return {
                    'success': False,
                    'error': '没有修改权限',
                    'error_code': 'PERMISSION_DENIED'
                }
            
            # 保存原始信息（用于审计）
            original_data = {
                'title': archive.title,
                'description': archive.description,
                'category_id': archive.category_id,
                'confidentiality_level': archive.confidentiality_level,
                'retention_period': archive.retention_period
            }
            
            # 更新字段
            if 'title' in update_data:
                archive.title = update_data['title']
            
            if 'description' in update_data:
                archive.description = update_data['description']
            
            if 'category_id' in update_data:
                # 检查分类是否存在
                category = ArchiveCategory.query.get(update_data['category_id'])
                if not category:
                    return {
                        'success': False,
                        'error': '分类不存在',
                        'error_code': 'CATEGORY_NOT_FOUND'
                    }
                archive.category_id = update_data['category_id']
            
            if 'confidentiality_level' in update_data:
                archive.confidentiality_level = update_data['confidentiality_level']
            
            if 'retention_period' in update_data:
                archive.retention_period = update_data['retention_period']
            
            # 设置元数据
            if 'metadata' in update_data:
                import json
                archive.metadata_json = json.dumps(update_data['metadata'], ensure_ascii=False)
            
            # 更新修改时间和修改人
            archive.updated_at = datetime.now()
            archive.updated_by = user_id
            
            # 提交更改
            from models import db
            db.session.commit()
            
            # 记录审计日志
            changes = []
            for field in original_data:
                if field in update_data and original_data[field] != update_data[field]:
                    changes.append(f'{field}: {original_data[field]} -> {update_data[field]}')
            
            if changes:
                self.audit_service.log_operation(
                    user_id=user_id,
                    operation_type='UPDATE_ARCHIVE',
                    target_type='archive',
                    target_id=str(archive_id),
                    description=f'更新档案: {archive.title}',
                    details={'changes': changes},
                    ip_address='127.0.0.1'
                )
            
            return {
                'success': True,
                'message': '档案信息更新成功',
                'data': {
                    'archive_id': archive_id,
                    'updated_fields': list(update_data.keys())
                }
            }
            
        except Exception as e:
            from models import db
            db.session.rollback()
            return {
                'success': False,
                'error': f'档案更新失败: {str(e)}',
                'error_code': 'ARCHIVE_UPDATE_ERROR'
            }
    
    def archive_archive(self, archive_id: int, user_id: int, reason: str = '') -> Dict[str, Any]:
        """
        归档档案
        
        Args:
            archive_id: 档案ID
            user_id: 用户ID
            reason: 归档原因
            
        Returns:
            归档结果
        """
        try:
            # 获取档案信息
            archive = ElectronicArchive.query.get(archive_id)
            if not archive:
                return {
                    'success': False,
                    'error': '档案不存在',
                    'error_code': 'ARCHIVE_NOT_FOUND'
                }
            
            # 权限检查
            if not self._check_archive_permission(archive, user_id, 'archive'):
                return {
                    'success': False,
                    'error': '没有归档权限',
                    'error_code': 'PERMISSION_DENIED'
                }
            
            # 检查是否可以归档
            if archive.status == ArchiveStatus.ARCHIVED:
                return {
                    'success': False,
                    'error': '档案已经归档',
                    'error_code': 'ALREADY_ARCHIVED'
                }
            
            # 执行归档
            archive.status = ArchiveStatus.ARCHIVED
            archive.archived_at = datetime.now()
            archive.archived_by = user_id
            archive.archive_reason = reason
            
            # 设置保管期限到期时间
            if archive.retention_period:
                archive.disposal_due_date = datetime.now() + timedelta(days=archive.retention_period * 365)
            
            # 提交更改
            from models import db
            db.session.commit()
            
            # 执行完整性检查
            integrity_result = self.integrity_service.verify_archive_integrity(archive_id)
            
            # 记录审计日志
            self.audit_service.log_operation(
                user_id=user_id,
                operation_type='ARCHIVE_ARCHIVE',
                target_type='archive',
                target_id=str(archive_id),
                description=f'归档档案: {archive.title}',
                details={
                    'archive_reason': reason,
                    'integrity_check': integrity_result.get('success', False)
                },
                ip_address='127.0.0.1'
            )
            
            return {
                'success': True,
                'message': '档案归档成功',
                'data': {
                    'archive_id': archive_id,
                    'archived_at': archive.archived_at.isoformat(),
                    'integrity_verified': integrity_result.get('success', False)
                }
            }
            
        except Exception as e:
            from models import db
            db.session.rollback()
            return {
                'success': False,
                'error': f'档案归档失败: {str(e)}',
                'error_code': 'ARCHIVE_OPERATION_ERROR'
            }
    
    def dispose_archive(self, archive_id: int, user_id: int, disposal_method: str, reason: str) -> Dict[str, Any]:
        """
        处置档案
        
        Args:
            archive_id: 档案ID
            user_id: 用户ID
            disposal_method: 处置方式
            reason: 处置原因
            
        Returns:
            处置结果
        """
        try:
            # 获取档案信息
            archive = ElectronicArchive.query.get(archive_id)
            if not archive:
                return {
                    'success': False,
                    'error': '档案不存在',
                    'error_code': 'ARCHIVE_NOT_FOUND'
                }
            
            # 权限检查
            if not self._check_archive_permission(archive, user_id, 'dispose'):
                return {
                    'success': False,
                    'error': '没有处置权限',
                    'error_code': 'PERMISSION_DENIED'
                }
            
            # 检查是否已归档
            if archive.status != ArchiveStatus.ARCHIVED:
                return {
                    'success': False,
                    'error': '只能处置已归档的档案',
                    'error_code': 'NOT_ARCHIVED'
                }
            
            # 检查保管期限
            if archive.disposal_due_date and datetime.now() < archive.disposal_due_date:
                return {
                    'success': False,
                    'error': '档案尚未到达保管期限',
                    'error_code': 'RETENTION_PERIOD_NOT_EXPIRED'
                }
            
            # 执行处置
            archive.status = ArchiveStatus.DISPOSED
            archive.disposed_at = datetime.now()
            archive.disposed_by = user_id
            archive.disposal_method = disposal_method
            archive.disposal_reason = reason
            
            # 删除物理文件（根据处置方式）
            if disposal_method in ['delete', 'destroy']:
                self._delete_archive_files(archive_id)
            
            # 提交更改
            from models import db
            db.session.commit()
            
            # 记录审计日志
            self.audit_service.log_operation(
                user_id=user_id,
                operation_type='DISPOSE_ARCHIVE',
                target_type='archive',
                target_id=str(archive_id),
                description=f'处置档案: {archive.title}',
                details={
                    'disposal_method': disposal_method,
                    'disposal_reason': reason
                },
                ip_address='127.0.0.1'
            )
            
            return {
                'success': True,
                'message': '档案处置成功',
                'data': {
                    'archive_id': archive_id,
                    'disposed_at': archive.disposed_at.isoformat(),
                    'disposal_method': disposal_method
                }
            }
            
        except Exception as e:
            from models import db
            db.session.rollback()
            return {
                'success': False,
                'error': f'档案处置失败: {str(e)}',
                'error_code': 'ARCHIVE_DISPOSAL_ERROR'
            }
    
    def get_statistics(self, user_id: int, date_range: str = '30d') -> Dict[str, Any]:
        """
        获取档案统计信息
        
        Args:
            user_id: 用户ID
            date_range: 日期范围
            
        Returns:
            统计信息
        """
        try:
            # 计算日期范围
            end_date = datetime.now()
            if date_range == '7d':
                start_date = end_date - timedelta(days=7)
            elif date_range == '30d':
                start_date = end_date - timedelta(days=30)
            elif date_range == '90d':
                start_date = end_date - timedelta(days=90)
            elif date_range == '1y':
                start_date = end_date - timedelta(days=365)
            else:
                start_date = end_date - timedelta(days=30)
            
            # 基础统计
            query = ElectronicArchive.query.filter(
                ElectronicArchive.created_at >= start_date
            )
            
            # 应用权限过滤
            query = self._apply_permission_filter(query, user_id)
            
            # 总数统计
            total_count = query.count()
            
            # 按状态统计
            status_stats = {}
            for status in ArchiveStatus:
                status_count = query.filter(ElectronicArchive.status == status).count()
                status_stats[status.value] = status_count
            
            # 按分类统计
            category_stats = {}
            category_query = query.join(ArchiveCategory).with_entities(
                ArchiveCategory.name,
                func.count(ElectronicArchive.id).label('count')
            ).group_by(ArchiveCategory.name)
            
            for row in category_query.all():
                category_stats[row.name] = row.count
            
            # 按月统计
            monthly_stats = {}
            monthly_query = query.with_entities(
                func.strftime('%Y-%m', ElectronicArchive.created_at).label('month'),
                func.count(ElectronicArchive.id).label('count')
            ).group_by('month').order_by('month')
            
            for row in monthly_query.all():
                monthly_stats[row.month] = row.count
            
            # 存储统计
            total_size = query.with_entities(
                func.sum(ElectronicArchive.total_size)
            ).scalar() or 0
            
            # 即将到期的档案
            upcoming_expiry = query.filter(
                and_(
                    ElectronicArchive.status == ArchiveStatus.ARCHIVED,
                    ElectronicArchive.disposal_due_date <= end_date + timedelta(days=30),
                    ElectronicArchive.disposal_due_date > end_date
                )
            ).count()
            
            return {
                'success': True,
                'data': {
                    'date_range': date_range,
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat(),
                    'total_count': total_count,
                    'total_size_mb': round(total_size / 1024 / 1024, 2),
                    'status_distribution': status_stats,
                    'category_distribution': category_stats,
                    'monthly_trend': monthly_stats,
                    'upcoming_expiry_count': upcoming_expiry
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'获取统计信息失败: {str(e)}',
                'error_code': 'STATISTICS_ERROR'
            }
    
    def _apply_permission_filter(self, query, user_id: int):
        """
        应用权限过滤
        
        Args:
            query: SQLAlchemy查询对象
            user_id: 用户ID
            
        Returns:
            过滤后的查询对象
        """
        # 获取用户信息
        user = User.query.get(user_id)
        if not user:
            return query.filter(ElectronicArchive.id == -1)  # 返回空结果
        
        # 管理员可以查看所有档案
        if user.role == 'admin':
            return query
        
        # 普通用户只能查看自己创建的档案
        if user.role == 'user':
            return query.filter(ElectronicArchive.created_by == user_id)
        
        # 其他角色基于具体需求扩展
        return query.filter(ElectronicArchive.created_by == user_id)
    
    def _check_archive_permission(self, archive: ElectronicArchive, user_id: int, action: str) -> bool:
        """
        检查档案权限
        
        Args:
            archive: 档案对象
            user_id: 用户ID
            action: 操作类型
            
        Returns:
            是否有权限
        """
        # 获取用户信息
        user = User.query.get(user_id)
        if not user:
            return False
        
        # 管理员拥有所有权限
        if user.role == 'admin':
            return True
        
        # 档案创建者拥有所有权限
        if archive.created_by == user_id:
            return True
        
        # 根据操作类型进行进一步检查
        if action == 'read':
            # 读取权限可以根据需要扩展
            return True
        
        return False
    
    def _delete_archive_files(self, archive_id: int):
        """
        删除档案物理文件
        
        Args:
            archive_id: 档案ID
        """
        try:
            # 获取档案文件列表
            archive_files = ArchiveFile.query.filter_by(archive_id=archive_id).all()
            
            for file_obj in archive_files:
                if os.path.exists(file_obj.file_path):
                    try:
                        os.remove(file_obj.file_path)
                    except Exception:
                        pass  # 忽略删除失败
                        
        except Exception:
            pass  # 忽略删除过程中的异常
    
    def _format_archive_summary(self, archive: ElectronicArchive) -> Dict[str, Any]:
        """
        格式化档案摘要信息
        
        Args:
            archive: 档案对象
            
        Returns:
            格式化的档案信息
        """
        return {
            'id': archive.id,
            'archive_no': archive.archive_no,
            'title': archive.title,
            'description': archive.description,
            'status': archive.status.value,
            'category_name': archive.category.name if archive.category else '',
            'file_count': archive.file_count,
            'total_size': archive.total_size,
            'created_at': archive.created_at.isoformat(),
            'created_by_name': archive.creator.username if archive.creator else '',
            'confidentiality_level': archive.confidentiality_level,
            'retention_period': archive.retention_period
        }
    
    def _format_archive_detail(self, archive: ElectronicArchive) -> Dict[str, Any]:
        """
        格式化档案详细信息
        
        Args:
            archive: 档案对象
            
        Returns:
            格式化的档案详细信息
        """
        # 解析元数据
        metadata = {}
        if archive.metadata_json:
            try:
                import json
                metadata = json.loads(archive.metadata_json)
            except:
                metadata = {}
        
        # 获取文件列表
        files = []
        for file_obj in archive.files:
            files.append({
                'id': file_obj.id,
                'file_name': file_obj.file_name,
                'file_type': file_obj.file_type,
                'file_size': file_obj.file_size,
                'file_path': file_obj.file_path,
                'hash_md5': file_obj.hash_md5,
                'hash_sha256': file_obj.hash_sha256,
                'created_at': file_obj.created_at.isoformat()
            })
        
        return {
            'id': archive.id,
            'archive_no': archive.archive_no,
            'title': archive.title,
            'description': archive.description,
            'status': archive.status.value,
            'category_id': archive.category_id,
            'category_name': archive.category.name if archive.category else '',
            'file_count': archive.file_count,
            'total_size': archive.total_size,
            'confidentiality_level': archive.confidentiality_level,
            'retention_period': archive.retention_period,
            'created_at': archive.created_at.isoformat(),
            'updated_at': archive.updated_at.isoformat() if archive.updated_at else None,
            'archived_at': archive.archived_at.isoformat() if archive.archived_at else None,
            'disposal_due_date': archive.disposal_due_date.isoformat() if archive.disposal_due_date else None,
            'disposed_at': archive.disposed_at.isoformat() if archive.disposed_at else None,
            'metadata': metadata,
            'files': files,
            'created_by_name': archive.creator.username if archive.creator else '',
            'updated_by_name': archive.updater.username if archive.updater else '',
            'archived_by_name': archive.archiver.username if archive.archiver else '',
            'disposed_by_name': archive.disposer.username if archive.disposer else ''
        }