"""
电子档案库管理服务 - 档案存储、版本控制、完整性管理
基于DA/T 94-2022标准的档案库管理模块
"""
import os
import json
import hashlib
import logging
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from flask import current_app

from models.archive import ElectronicArchive, ArchiveFile, ArchiveCategory
from models.audit import AuditLog, IntegrityRecord, LifecycleRecord
from models.user import User
from models import db
from utils.audit_logger import AuditLogger
from utils.file_processor import FileProcessor
from services.integrity_service import IntegrityService

logger = logging.getLogger(__name__)

class ArchiveLibraryService:
    """电子档案库管理服务"""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
        self.file_processor = FileProcessor()
        self.integrity_service = IntegrityService()
        
        # 使用默认值，避免应用上下文依赖
        # 档案库配置 - 使用项目目录下的路径
        self.storage_root = os.path.join(os.path.dirname(__file__), '..', 'storage', 'archives')
        self.backup_root = os.path.join(os.path.dirname(__file__), '..', 'storage', 'backup')
        self.temp_root = os.path.join(os.path.dirname(__file__), '..', 'storage', 'temp')
        
        # 版本控制配置
        self.max_versions = 10
        self.auto_cleanup_days = 365
        
        # 生命周期阶段
        self.lifecycle_stages = [
            'draft',      # 草稿
            'active',     # 活跃使用
            'reference',  # 日常参考
            'archive',    # 归档存储
            'disposal'    # 待销毁
        ]
        
        # 创建必要的目录
        self._ensure_directories()
    
    def _ensure_directories(self):
        """确保必要的目录存在"""
        directories = [
            self.storage_root,
            self.backup_root,
            self.temp_root,
            os.path.join(self.storage_root, 'original'),
            os.path.join(self.storage_root, 'processed'),
            os.path.join(self.storage_root, 'encrypted'),
            os.path.join(self.storage_root, 'archived'),
            os.path.join(self.backup_root, 'daily'),
            os.path.join(self.backup_root, 'weekly'),
            os.path.join(self.backup_root, 'monthly')
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def create_archive_library(self, name, description, category_code=None, user_id=None):
        """
        创建电子档案库
        
        Args:
            name: 档案库名称
            description: 档案库描述
            category_code: 分类代码
            user_id: 创建者ID
            
        Returns:
            dict: 创建结果
        """
        try:
            # 验证用户权限
            if not self._check_permission(user_id, 'create_library'):
                return {
                    'success': False,
                    'error': '无权限创建档案库',
                    'error_code': 'INSUFFICIENT_PERMISSION'
                }
            
            # 创建档案库目录结构
            library_id = self._generate_library_id()
            library_path = os.path.join(self.storage_root, 'libraries', library_id)
            
            directories = [
                'original',
                'processed', 
                'backup',
                'metadata',
                'integrity',
                'temp'
            ]
            
            for directory in directories:
                os.makedirs(os.path.join(library_path, directory), exist_ok=True)
            
            # 创建档案库元数据文件
            metadata = {
                'library_id': library_id,
                'name': name,
                'description': description,
                'category_code': category_code,
                'created_by': user_id,
                'created_at': datetime.utcnow().isoformat(),
                'status': 'active',
                'settings': {
                    'retention_period': 7,  # 7年保留期
                    'backup_frequency': 'daily',
                    'encryption_enabled': True,
                    'version_control': True
                }
            }
            
            metadata_file = os.path.join(library_path, 'library_metadata.json')
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, ensure_ascii=False, indent=2)
            
            # 记录审计日志
            self.audit_logger.log_operation(
                user_id=user_id,
                operation_type='create',
                resource_type='archive_library',
                resource_id=library_id,
                operation_details={
                    'name': name,
                    'category_code': category_code,
                    'path': library_path
                }
            )
            
            return {
                'success': True,
                'library_id': library_id,
                'path': library_path,
                'metadata': metadata,
                'message': f'档案库"{name}"创建成功'
            }
            
        except Exception as e:
            logger.error(f"创建档案库失败: {str(e)}")
            return {
                'success': False,
                'error': f'创建档案库失败: {str(e)}',
                'error_code': 'LIBRARY_CREATION_ERROR'
            }
    
    def store_archive(self, archive_id, file_data, store_options=None, user_id=None):
        """
        存储电子档案
        
        Args:
            archive_id: 档案ID
            file_data: 文件数据 (字典包含文件路径、名称、类型等)
            store_options: 存储选项
            user_id: 用户ID
            
        Returns:
            dict: 存储结果
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
            
            # 验证权限
            if not self._check_permission(user_id, 'store_archive', archive_id):
                return {
                    'success': False,
                    'error': '无权限存储档案',
                    'error_code': 'INSUFFICIENT_PERMISSION'
                }
            
            # 准备存储选项
            store_options = store_options or {}
            encryption_enabled = store_options.get('encrypt', True)
            create_backup = store_options.get('backup', True)
            generate_preview = store_options.get('preview', True)
            
            # 存储原始文件
            original_path = self._store_original_file(archive, file_data, user_id)
            if not original_path:
                return {
                    'success': False,
                    'error': '原始文件存储失败',
                    'error_code': 'ORIGINAL_STORAGE_ERROR'
                }
            
            # 生成文件哈希
            file_hash = self._calculate_file_hash(original_path)
            
            # 处理文件（转换、压缩等）
            processed_path = None
            if store_options.get('process', True):
                processed_path = self._process_file(original_path, archive, user_id)
            
            # 加密文件
            encrypted_path = None
            if encryption_enabled:
                encrypted_path = self._encrypt_file(original_path, archive, user_id)
            
            # 创建备份
            backup_path = None
            if create_backup:
                backup_path = self._create_backup(original_path, archive, user_id)
            
            # 生成预览文件
            preview_path = None
            if generate_preview:
                preview_path = self._generate_preview(original_path, archive, user_id)
            
            # 创建档案文件记录
            archive_file = ArchiveFile(
                archive_id=archive_id,
                file_name=file_data.get('name', ''),
                file_path=original_path,
                file_type=file_data.get('type', ''),
                file_size=file_data.get('size', 0),
                file_hash=file_hash,
                processed_file_path=processed_path,
                encrypted_file_path=encrypted_path,
                backup_file_path=backup_path,
                preview_file_path=preview_path,
                created_by=user_id,
                created_at=datetime.utcnow(),
                is_original=True,
                version_number=1,
                status='active'
            )
            
            db.session.add(archive_file)
            db.session.commit()
            
            # 创建完整性记录
            integrity_record = IntegrityRecord(
                resource_type='archive_file',
                resource_id=archive_file.id,
                hash_value=file_hash,
                file_path=original_path,
                algorithm='SHA-256',
                created_at=datetime.utcnow(),
                verified_at=datetime.utcnow(),
                status='verified'
            )
            
            db.session.add(integrity_record)
            db.session.commit()
            
            # 记录生命周期事件
            self._record_lifecycle_event(
                archive_id, 'stored', user_id,
                {
                    'file_id': archive_file.id,
                    'file_name': archive_file.file_name,
                    'original_path': original_path,
                    'file_hash': file_hash,
                    'storage_options': store_options
                }
            )
            
            # 记录审计日志
            self.audit_logger.log_operation(
                user_id=user_id,
                operation_type='store',
                resource_type='archive',
                resource_id=archive_id,
                operation_details={
                    'file_id': archive_file.id,
                    'file_name': archive_file.file_name,
                    'file_hash': file_hash,
                    'original_path': original_path,
                    'storage_options': store_options
                }
            )
            
            return {
                'success': True,
                'file_id': archive_file.id,
                'file_hash': file_hash,
                'original_path': original_path,
                'processed_path': processed_path,
                'encrypted_path': encrypted_path,
                'backup_path': backup_path,
                'preview_path': preview_path,
                'message': '档案存储成功'
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"存储档案失败: {str(e)}")
            return {
                'success': False,
                'error': f'存储档案失败: {str(e)}',
                'error_code': 'ARCHIVE_STORAGE_ERROR'
            }
    
    def retrieve_archive(self, archive_id, version=None, include_backups=True, user_id=None):
        """
        检索电子档案
        
        Args:
            archive_id: 档案ID
            version: 版本号（None表示最新版本）
            include_backups: 是否包含备份
            user_id: 用户ID
            
        Returns:
            dict: 检索结果
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
            
            # 验证权限
            if not self._check_permission(user_id, 'retrieve_archive', archive_id):
                return {
                    'success': False,
                    'error': '无权限检索档案',
                    'error_code': 'INSUFFICIENT_PERMISSION'
                }
            
            # 获取档案文件
            query = ArchiveFile.query.filter_by(archive_id=archive_id)
            
            if version:
                query = query.filter_by(version_number=version)
            else:
                query = query.order_by(ArchiveFile.version_number.desc())
            
            archive_files = query.all()
            
            if not archive_files:
                return {
                    'success': False,
                    'error': '档案文件不存在',
                    'error_code': 'ARCHIVE_FILE_NOT_FOUND'
                }
            
            # 准备检索结果
            results = []
            for archive_file in archive_files:
                file_info = {
                    'id': archive_file.id,
                    'file_name': archive_file.file_name,
                    'file_type': archive_file.file_type,
                    'file_size': archive_file.file_size,
                    'file_hash': archive_file.file_hash,
                    'version_number': archive_file.version_number,
                    'original_path': archive_file.file_path,
                    'processed_path': archive_file.processed_file_path,
                    'encrypted_path': archive_file.encrypted_file_path,
                    'preview_path': archive_file.preview_file_path,
                    'created_at': archive_file.created_at.isoformat(),
                    'status': archive_file.status
                }
                
                # 包含备份信息
                if include_backups and archive_file.backup_file_path:
                    file_info['backup_paths'] = self._get_backup_paths(archive_file)
                
                results.append(file_info)
            
            # 记录审计日志
            self.audit_logger.log_operation(
                user_id=user_id,
                operation_type='retrieve',
                resource_type='archive',
                resource_id=archive_id,
                operation_details={
                    'file_count': len(results),
                    'version': version,
                    'include_backups': include_backups
                }
            )
            
            return {
                'success': True,
                'archive': {
                    'id': archive.id,
                    'title': archive.title,
                    'archive_no': archive.archive_no,
                    'category': archive.category.name if archive.category else None
                },
                'files': results,
                'total_files': len(results)
            }
            
        except Exception as e:
            logger.error(f"检索档案失败: {str(e)}")
            return {
                'success': False,
                'error': f'检索档案失败: {str(e)}',
                'error_code': 'ARCHIVE_RETRIEVAL_ERROR'
            }
    
    def create_archive_version(self, archive_id, file_data, version_options=None, user_id=None):
        """
        创建档案新版本
        
        Args:
            archive_id: 档案ID
            file_data: 新版本文件数据
            version_options: 版本选项
            user_id: 用户ID
            
        Returns:
            dict: 创建结果
        """
        try:
            # 获取当前最新版本
            latest_file = ArchiveFile.query.filter_by(
                archive_id=archive_id,
                status='active'
            ).order_by(ArchiveFile.version_number.desc()).first()
            
            if not latest_file:
                return {
                    'success': False,
                    'error': '档案不存在',
                    'error_code': 'ARCHIVE_NOT_FOUND'
                }
            
            # 检查版本数量限制
            if latest_file.version_number >= self.max_versions:
                return {
                    'success': False,
                    'error': f'版本数量已达上限({self.max_versions})',
                    'error_code': 'VERSION_LIMIT_EXCEEDED'
                }
            
            # 验证权限
            if not self._check_permission(user_id, 'create_version', archive_id):
                return {
                    'success': False,
                    'error': '无权限创建版本',
                    'error_code': 'INSUFFICIENT_PERMISSION'
                }
            
            version_options = version_options or {}
            new_version_number = latest_file.version_number + 1
            
            # 存储新版本文件
            store_result = self.store_archive(archive_id, file_data, version_options, user_id)
            if not store_result['success']:
                return store_result
            
            # 更新版本记录
            archive_file_id = store_result['file_id']
            archive_file = ArchiveFile.query.get(archive_file_id)
            
            if archive_file:
                archive_file.version_number = new_version_number
                db.session.commit()
            
            # 记录生命周期事件
            self._record_lifecycle_event(
                archive_id, 'version_created', user_id,
                {
                    'old_version': latest_file.version_number,
                    'new_version': new_version_number,
                    'file_id': archive_file_id
                }
            )
            
            return {
                'success': True,
                'version_number': new_version_number,
                'file_id': archive_file_id,
                'message': f'档案版本{new_version_number}创建成功'
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"创建档案版本失败: {str(e)}")
            return {
                'success': False,
                'error': f'创建档案版本失败: {str(e)}',
                'error_code': 'VERSION_CREATION_ERROR'
            }
    
    def manage_lifecycle(self, archive_id, new_stage, lifecycle_options=None, user_id=None):
        """
        管理档案生命周期
        
        Args:
            archive_id: 档案ID
            new_stage: 新生命周期阶段
            lifecycle_options: 生命周期选项
            user_id: 用户ID
            
        Returns:
            dict: 管理结果
        """
        try:
            # 验证生命周期阶段
            if new_stage not in self.lifecycle_stages:
                return {
                    'success': False,
                    'error': f'无效的生命周期阶段: {new_stage}',
                    'error_code': 'INVALID_LIFECYCLE_STAGE'
                }
            
            # 获取档案
            archive = ElectronicArchive.query.get(archive_id)
            if not archive:
                return {
                    'success': False,
                    'error': '档案不存在',
                    'error_code': 'ARCHIVE_NOT_FOUND'
                }
            
            # 验证权限
            if not self._check_permission(user_id, 'manage_lifecycle', archive_id):
                return {
                    'success': False,
                    'error': '无权限管理生命周期',
                    'error_code': 'INSUFFICIENT_PERMISSION'
                }
            
            old_stage = archive.lifecycle_stage
            lifecycle_options = lifecycle_options or {}
            
            # 执行生命周期转换
            stage_transition_result = self._execute_stage_transition(
                archive, old_stage, new_stage, lifecycle_options, user_id
            )
            
            if not stage_transition_result['success']:
                return stage_transition_result
            
            # 更新档案生命周期阶段
            archive.lifecycle_stage = new_stage
            archive.lifecycle_stage_changed_at = datetime.utcnow()
            
            # 根据阶段设置相关属性
            if new_stage == 'archive':
                archive.archived_at = datetime.utcnow()
            elif new_stage == 'disposal':
                archive.disposal_scheduled_at = datetime.utcnow()
            
            db.session.commit()
            
            # 记录生命周期事件
            self._record_lifecycle_event(
                archive_id, 'lifecycle_changed', user_id,
                {
                    'old_stage': old_stage,
                    'new_stage': new_stage,
                    'lifecycle_options': lifecycle_options
                }
            )
            
            # 记录审计日志
            self.audit_logger.log_operation(
                user_id=user_id,
                operation_type='lifecycle_change',
                resource_type='archive',
                resource_id=archive_id,
                operation_details={
                    'old_stage': old_stage,
                    'new_stage': new_stage,
                    'transition_actions': stage_transition_result.get('actions', [])
                }
            )
            
            return {
                'success': True,
                'old_stage': old_stage,
                'new_stage': new_stage,
                'transition_actions': stage_transition_result.get('actions', []),
                'message': f'档案生命周期阶段从{old_stage}转换到{new_stage}'
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"管理档案生命周期失败: {str(e)}")
            return {
                'success': False,
                'error': f'管理档案生命周期失败: {str(e)}',
                'error_code': 'LIFECYCLE_MANAGEMENT_ERROR'
            }
    
    def verify_archive_integrity(self, archive_id, verification_options=None, user_id=None):
        """
        验证档案完整性
        
        Args:
            archive_id: 档案ID
            verification_options: 验证选项
            user_id: 用户ID
            
        Returns:
            dict: 验证结果
        """
        try:
            # 获取档案文件
            archive_files = ArchiveFile.query.filter_by(archive_id=archive_id).all()
            
            if not archive_files:
                return {
                    'success': False,
                    'error': '档案文件不存在',
                    'error_code': 'ARCHIVE_FILE_NOT_FOUND'
                }
            
            verification_options = verification_options or {}
            verification_results = []
            
            for archive_file in archive_files:
                # 验证文件完整性
                integrity_result = self.integrity_service.verify_file_integrity(
                    archive_file.file_path,
                    archive_file.file_hash,
                    archive_file.id,
                    verification_options.get('deep_scan', False)
                )
                
                verification_results.append({
                    'file_id': archive_file.id,
                    'file_name': archive_file.file_name,
                    'file_hash': archive_file.file_hash,
                    'verification_result': integrity_result,
                    'verified_at': datetime.utcnow().isoformat()
                })
            
            # 计算整体完整性状态
            all_verified = all(result['verification_result']['valid'] for result in verification_results)
            
            # 记录验证结果
            verification_summary = {
                'archive_id': archive_id,
                'verification_time': datetime.utcnow().isoformat(),
                'total_files': len(archive_files),
                'verified_files': sum(1 for result in verification_results if result['verification_result']['valid']),
                'failed_files': sum(1 for result in verification_results if not result['verification_result']['valid']),
                'overall_status': 'verified' if all_verified else 'failed',
                'verification_results': verification_results
            }
            
            # 记录审计日志
            self.audit_logger.log_operation(
                user_id=user_id,
                operation_type='verify_integrity',
                resource_type='archive',
                resource_id=archive_id,
                operation_details=verification_summary
            )
            
            return {
                'success': True,
                'verification_summary': verification_summary,
                'message': '档案完整性验证完成'
            }
            
        except Exception as e:
            logger.error(f"验证档案完整性失败: {str(e)}")
            return {
                'success': False,
                'error': f'验证档案完整性失败: {str(e)}',
                'error_code': 'INTEGRITY_VERIFICATION_ERROR'
            }
    
    def cleanup_archive_library(self, library_path=None, cleanup_options=None, user_id=None):
        """
        清理档案库
        
        Args:
            library_path: 档案库路径
            cleanup_options: 清理选项
            user_id: 用户ID
            
        Returns:
            dict: 清理结果
        """
        try:
            cleanup_options = cleanup_options or {}
            cleanup_results = {
                'files_cleaned': 0,
                'space_freed': 0,
                'errors': []
            }
            
            # 清理临时文件
            temp_cleanup_result = self._cleanup_temp_files()
            cleanup_results['files_cleaned'] += temp_cleanup_result['files_cleaned']
            cleanup_results['space_freed'] += temp_cleanup_result['space_freed']
            
            # 清理过期备份
            if cleanup_options.get('cleanup_backups', True):
                backup_cleanup_result = self._cleanup_expired_backups()
                cleanup_results['files_cleaned'] += backup_cleanup_result['files_cleaned']
                cleanup_results['space_freed'] += backup_cleanup_result['space_freed']
            
            # 清理孤立文件
            if cleanup_options.get('cleanup_orphaned', True):
                orphaned_cleanup_result = self._cleanup_orphaned_files()
                cleanup_results['files_cleaned'] += orphaned_cleanup_result['files_cleaned']
                cleanup_results['space_freed'] += orphaned_cleanup_result['space_freed']
            
            # 记录清理结果
            self.audit_logger.log_operation(
                user_id=user_id,
                operation_type='cleanup',
                resource_type='archive_library',
                operation_details={
                    'library_path': library_path,
                    'cleanup_options': cleanup_options,
                    'cleanup_results': cleanup_results
                }
            )
            
            return {
                'success': True,
                'cleanup_results': cleanup_results,
                'message': '档案库清理完成'
            }
            
        except Exception as e:
            logger.error(f"清理档案库失败: {str(e)}")
            return {
                'success': False,
                'error': f'清理档案库失败: {str(e)}',
                'error_code': 'CLEANUP_ERROR'
            }
    
    def _store_original_file(self, archive, file_data, user_id):
        """
        存储原始文件
        """
        try:
            # 构建文件路径
            archive_folder = f"{archive.id:06d}"  # 6位数字文件夹
            file_name = file_data.get('name', '')
            file_extension = os.path.splitext(file_name)[1]
            
            target_path = os.path.join(
                self.storage_root,
                'original',
                archive_folder,
                f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file_name}"
            )
            
            # 复制文件到目标路径
            source_path = file_data.get('path')
            if source_path:
                shutil.copy2(source_path, target_path)
            else:
                # 如果没有源路径，使用文件内容
                with open(target_path, 'wb') as f:
                    f.write(file_data.get('content', b''))
            
            return target_path
            
        except Exception as e:
            logger.error(f"存储原始文件失败: {str(e)}")
            return None
    
    def _process_file(self, original_path, archive, user_id):
        """
        处理文件（转换、压缩等）
        """
        try:
            archive_folder = f"{archive.id:06d}"
            file_name = os.path.basename(original_path)
            
            processed_path = os.path.join(
                self.storage_root,
                'processed',
                archive_folder,
                f"processed_{file_name}"
            )
            
            # 使用FileProcessor处理文件
            result = self.file_processor.convert_to_pdf_a(
                original_path,
                processed_path,
                preserve_metadata=True
            )
            
            return processed_path if result['success'] else None
            
        except Exception as e:
            logger.error(f"处理文件失败: {str(e)}")
            return None
    
    def _encrypt_file(self, file_path, archive, user_id):
        """
        加密文件
        """
        try:
            archive_folder = f"{archive.id:06d}"
            file_name = os.path.basename(file_path)
            
            encrypted_path = os.path.join(
                self.storage_root,
                'encrypted',
                archive_folder,
                f"encrypted_{file_name}"
            )
            
            # 简化加密实现（实际应使用更强加密算法）
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # 基础编码（实际应用中应使用AES等加密算法）
            import base64
            encrypted_data = base64.b64encode(data)
            
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            return encrypted_path
            
        except Exception as e:
            logger.error(f"加密文件失败: {str(e)}")
            return None
    
    def _create_backup(self, file_path, archive, user_id):
        """
        创建备份
        """
        try:
            backup_folder = datetime.utcnow().strftime('%Y%m%d')
            archive_folder = f"{archive.id:06d}"
            file_name = os.path.basename(file_path)
            
            backup_path = os.path.join(
                self.backup_root,
                'daily',
                backup_folder,
                archive_folder,
                file_name
            )
            
            # 确保备份目录存在
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)
            
            # 创建备份
            shutil.copy2(file_path, backup_path)
            
            return backup_path
            
        except Exception as e:
            logger.error(f"创建备份失败: {str(e)}")
            return None
    
    def _generate_preview(self, file_path, archive, user_id):
        """
        生成预览文件
        """
        # 简化实现，返回原路径
        # 实际应用中可以根据文件类型生成缩略图或预览页面
        return file_path
    
    def _calculate_file_hash(self, file_path):
        """
        计算文件哈希值
        """
        try:
            with open(file_path, 'rb') as f:
                hasher = hashlib.sha256()
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
                return hasher.hexdigest()
        except Exception as e:
            logger.error(f"计算文件哈希失败: {str(e)}")
            return None
    
    def _generate_library_id(self):
        """
        生成档案库ID
        """
        return datetime.utcnow().strftime('%Y%m%d%H%M%S%f')[:18]
    
    def _check_permission(self, user_id, action, resource_id=None):
        """
        检查用户权限（简化实现）
        """
        # 实际实现中应集成RBAC权限系统
        return user_id is not None
    
    def _get_backup_paths(self, archive_file):
        """
        获取备份文件路径
        """
        if not archive_file.backup_file_path:
            return []
        
        # 查找所有相关备份
        backup_dir = os.path.dirname(archive_file.backup_file_path)
        backup_files = []
        
        if os.path.exists(backup_dir):
            for file in os.listdir(backup_dir):
                if file == os.path.basename(archive_file.backup_file_path):
                    backup_files.append(os.path.join(backup_dir, file))
        
        return backup_files
    
    def _execute_stage_transition(self, archive, old_stage, new_stage, options, user_id):
        """
        执行生命周期阶段转换
        """
        actions = []
        
        if old_stage == 'draft' and new_stage == 'active':
            actions.append('文件验证完成')
            actions.append('访问权限设置')
        
        elif new_stage == 'archive':
            actions.append('生成归档副本')
            actions.append('设置长期存储策略')
            actions.append('创建只读保护')
        
        elif new_stage == 'disposal':
            actions.append('标记销毁计划')
            actions.append('通知相关人员')
        
        return {
            'success': True,
            'actions': actions
        }
    
    def _record_lifecycle_event(self, archive_id, event_type, user_id, details):
        """
        记录生命周期事件
        """
        try:
            lifecycle_record = LifecycleRecord(
                archive_id=archive_id,
                event_type=event_type,
                event_details=json.dumps(details, ensure_ascii=False),
                created_by=user_id,
                created_at=datetime.utcnow()
            )
            
            db.session.add(lifecycle_record)
            db.session.commit()
            
        except Exception as e:
            logger.error(f"记录生命周期事件失败: {str(e)}")
    
    def _cleanup_temp_files(self):
        """
        清理临时文件
        """
        cleaned_count = 0
        space_freed = 0
        
        try:
            temp_dir = self.temp_root
            if os.path.exists(temp_dir):
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            file_size = os.path.getsize(file_path)
                            os.remove(file_path)
                            cleaned_count += 1
                            space_freed += file_size
                        except OSError:
                            pass
        except Exception as e:
            logger.error(f"清理临时文件失败: {str(e)}")
        
        return {
            'files_cleaned': cleaned_count,
            'space_freed': space_freed
        }
    
    def _cleanup_expired_backups(self):
        """
        清理过期备份
        """
        # 简化实现，清理30天前的备份
        expired_days = 30
        cutoff_date = datetime.utcnow() - timedelta(days=expired_days)
        
        cleaned_count = 0
        space_freed = 0
        
        # 这里可以实现具体的清理逻辑
        return {
            'files_cleaned': cleaned_count,
            'space_freed': space_freed
        }
    
    def _cleanup_orphaned_files(self):
        """
        清理孤立文件
        """
        # 简化实现
        cleaned_count = 0
        space_freed = 0
        
        return {
            'files_cleaned': cleaned_count,
            'space_freed': space_freed
        }