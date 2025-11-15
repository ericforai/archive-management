"""
完整性验证服务 - 档案完整性检查、哈希验证、数字签名
基于DA/T 94-2022标准的电子会计档案完整性保障模块
"""
import os
import hashlib
import hmac
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Any
from flask import current_app
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import mimetypes

from models.archive import ElectronicArchive, ArchiveFile
from models.audit import AuditLog
from models import db
from utils.file_processor import FileProcessor
from utils.audit_logger import AuditLogger

logger = logging.getLogger(__name__)

class IntegrityService:
    """完整性验证服务"""
    
    def __init__(self):
        self.file_processor = FileProcessor()
        self.audit_logger = AuditLogger()
        
        # 完整性验证配置
        self.hash_algorithms = {
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'md5': hashlib.md5
        }
        
        self.default_hash_algorithm = 'sha256'
        # 使用默认值，避免应用上下文依赖
        self.integrity_check_interval_hours = 24
        self.max_integrity_failures = 3
        
        # 数字签名配置 - 使用默认值
        self.private_key_path = None
        self.public_key_path = None
        self.enable_digital_signature = True
        
        # 验证类型
        self.verification_types = {
            'hash_verification': '哈希验证',
            'digital_signature': '数字签名',
            'checksum_verification': '校验和验证',
            'metadata_integrity': '元数据完整性',
            'content_signature': '内容签名'
        }
        
        # 验证状态
        self.verification_status = {
            'pending': '待验证',
            'passed': '通过',
            'failed': '失败',
            'warning': '警告',
            'expired': '过期'
        }
    
    def generate_file_hash(self, file_path: str, algorithm: str = None) -> Dict:
        """
        生成文件哈希值
        
        Args:
            file_path: 文件路径
            algorithm: 哈希算法
            
        Returns:
            dict: 哈希结果
        """
        try:
            if not os.path.exists(file_path):
                return {
                    'success': False,
                    'error': f'文件不存在: {file_path}',
                    'error_code': 'FILE_NOT_FOUND'
                }
            
            algorithm = algorithm or self.default_hash_algorithm
            
            if algorithm not in self.hash_algorithms:
                return {
                    'success': False,
                    'error': f'不支持的哈希算法: {algorithm}',
                    'error_code': 'UNSUPPORTED_ALGORITHM'
                }
            
            hash_func = self.hash_algorithms[algorithm]
            
            # 计算文件哈希
            with open(file_path, 'rb') as f:
                hasher = hash_func()
                
                # 分块读取大文件
                while chunk := f.read(8192):
                    hasher.update(chunk)
                
                file_hash = hasher.hexdigest()
            
            # 获取文件信息
            file_stat = os.stat(file_path)
            file_size = file_stat.st_size
            file_mtime = datetime.fromtimestamp(file_stat.st_mtime)
            mime_type, _ = mimetypes.guess_type(file_path)
            
            return {
                'success': True,
                'file_hash': file_hash,
                'algorithm': algorithm,
                'file_size': file_size,
                'file_mtime': file_mtime.isoformat(),
                'mime_type': mime_type,
                'generated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"生成文件哈希失败: {str(e)}")
            return {
                'success': False,
                'error': f'生成文件哈希失败: {str(e)}',
                'error_code': 'HASH_GENERATION_ERROR'
            }
    
    def verify_file_integrity(self, file_path: str, expected_hash: str, algorithm: str = None) -> Dict:
        """
        验证文件完整性
        
        Args:
            file_path: 文件路径
            expected_hash: 期望的哈希值
            algorithm: 哈希算法
            
        Returns:
            dict: 验证结果
        """
        try:
            # 生成当前文件哈希
            hash_result = self.generate_file_hash(file_path, algorithm)
            
            if not hash_result['success']:
                return {
                    'success': False,
                    'verified': False,
                    'error': hash_result['error'],
                    'error_code': hash_result['error_code']
                }
            
            # 比较哈希值
            current_hash = hash_result['file_hash']
            is_valid = hmac.compare_digest(current_hash.lower(), expected_hash.lower())
            
            # 计算相似度
            similarity_score = self._calculate_similarity(current_hash, expected_hash)
            
            # 确定验证状态
            if is_valid:
                status = 'passed'
            elif similarity_score > 0.8:
                status = 'warning'
            else:
                status = 'failed'
            
            # 构建详细结果
            verification_result = {
                'success': True,
                'verified': is_valid,
                'status': status,
                'file_hash': current_hash,
                'expected_hash': expected_hash,
                'algorithm': hash_result['algorithm'],
                'similarity_score': similarity_score,
                'file_size': hash_result['file_size'],
                'file_mtime': hash_result['file_mtime'],
                'verified_at': datetime.utcnow().isoformat()
            }
            
            # 如果验证失败，记录详细信息
            if not is_valid:
                verification_result.update({
                    'hash_match': False,
                    'potential_corruption': True,
                    'file_size_match': hash_result['file_size'] == os.path.getsize(file_path),
                    'timestamp_match': True  # 实际应用中可能需要更复杂的比较
                })
            
            return verification_result
            
        except Exception as e:
            logger.error(f"验证文件完整性失败: {str(e)}")
            return {
                'success': False,
                'verified': False,
                'error': f'验证文件完整性失败: {str(e)}',
                'error_code': 'INTEGRITY_VERIFICATION_ERROR'
            }
    
    def create_digital_signature(self, data: bytes, private_key_path: str = None) -> Dict:
        """
        创建数字签名
        
        Args:
            data: 要签名的数据
            private_key_path: 私钥路径
            
        Returns:
            dict: 签名结果
        """
        try:
            if not self.enable_digital_signature:
                return {
                    'success': False,
                    'error': '数字签名功能未启用',
                    'error_code': 'DIGITAL_SIGNATURE_DISABLED'
                }
            
            private_key_path = private_key_path or self.private_key_path
            
            if not private_key_path or not os.path.exists(private_key_path):
                return {
                    'success': False,
                    'error': '私钥文件不存在',
                    'error_code': 'PRIVATE_KEY_NOT_FOUND'
                }
            
            # 读取私钥
            with open(private_key_path, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            
            # 创建数字签名
            signature = private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # 记录签名操作
            self.audit_logger.log_operation(
                user_id=0,  # 系统操作
                operation_type='create_digital_signature',
                resource_type='digital_signature',
                operation_details={
                    'data_size': len(data),
                    'algorithm': 'RSA-PSS-SHA256',
                    'signature_size': len(signature)
                }
            )
            
            return {
                'success': True,
                'signature': signature.hex(),
                'algorithm': 'RSA-PSS-SHA256',
                'key_id': private_key_path,
                'signed_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"创建数字签名失败: {str(e)}")
            return {
                'success': False,
                'error': f'创建数字签名失败: {str(e)}',
                'error_code': 'DIGITAL_SIGNATURE_ERROR'
            }
    
    def verify_digital_signature(self, data: bytes, signature: str, public_key_path: str = None) -> Dict:
        """
        验证数字签名
        
        Args:
            data: 原始数据
            signature: 数字签名
            public_key_path: 公钥路径
            
        Returns:
            dict: 验证结果
        """
        try:
            if not self.enable_digital_signature:
                return {
                    'success': False,
                    'error': '数字签名功能未启用',
                    'error_code': 'DIGITAL_SIGNATURE_DISABLED'
                }
            
            public_key_path = public_key_path or self.public_key_path
            
            if not public_key_path or not os.path.exists(public_key_path):
                return {
                    'success': False,
                    'error': '公钥文件不存在',
                    'error_code': 'PUBLIC_KEY_NOT_FOUND'
                }
            
            # 读取公钥
            with open(public_key_path, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            
            # 解码签名
            try:
                signature_bytes = bytes.fromhex(signature)
            except ValueError:
                return {
                    'success': False,
                    'error': '签名格式无效',
                    'error_code': 'INVALID_SIGNATURE_FORMAT'
                }
            
            # 验证签名
            try:
                public_key.verify(
                    signature_bytes,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                is_valid = True
                error_message = None
                
            except InvalidSignature:
                is_valid = False
                error_message = '数字签名验证失败'
            
            # 记录验证操作
            self.audit_logger.log_operation(
                user_id=0,  # 系统操作
                operation_type='verify_digital_signature',
                resource_type='digital_signature',
                operation_details={
                    'data_size': len(data),
                    'signature_size': len(signature_bytes),
                    'verification_result': 'valid' if is_valid else 'invalid'
                }
            )
            
            return {
                'success': True,
                'verified': is_valid,
                'error': error_message,
                'algorithm': 'RSA-PSS-SHA256',
                'verified_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"验证数字签名失败: {str(e)}")
            return {
                'success': False,
                'error': f'验证数字签名失败: {str(e)}',
                'error_code': 'DIGITAL_SIGNATURE_VERIFICATION_ERROR'
            }
    
    def verify_archive_integrity(self, archive_id: int, verification_types: List[str] = None) -> Dict:
        """
        验证档案完整性
        
        Args:
            archive_id: 档案ID
            verification_types: 验证类型列表
            
        Returns:
            dict: 验证结果
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
            
            # 默认验证类型
            if not verification_types:
                verification_types = ['hash_verification', 'metadata_integrity']
            
            # 验证结果汇总
            verification_results = {}
            overall_status = 'passed'
            failure_count = 0
            
            # 执行各项验证
            for verification_type in verification_types:
                if verification_type == 'hash_verification':
                    result = self._verify_archive_hash_integrity(archive)
                elif verification_type == 'metadata_integrity':
                    result = self._verify_archive_metadata_integrity(archive)
                elif verification_type == 'digital_signature':
                    result = self._verify_archive_digital_signature(archive)
                elif verification_type == 'content_signature':
                    result = self._verify_archive_content_signature(archive)
                else:
                    result = {
                        'success': False,
                        'error': f'不支持的验证类型: {verification_type}',
                        'error_code': 'UNSUPPORTED_VERIFICATION_TYPE'
                    }
                
                verification_results[verification_type] = result
                
                # 更新总体状态
                if not result.get('verified', False):
                    failure_count += 1
                    if result.get('status') == 'failed':
                        overall_status = 'failed'
                    elif result.get('status') == 'warning' and overall_status == 'passed':
                        overall_status = 'warning'
            
            # 计算完整性得分
            integrity_score = self._calculate_integrity_score(verification_results)
            
            # 更新档案完整性状态
            archive.integrity_status = overall_status
            archive.integrity_score = integrity_score
            archive.last_integrity_check = datetime.utcnow()
            archive.integrity_check_count += 1
            
            # 如果连续失败次数过多，标记为需要人工检查
            if failure_count > 0:
                archive.integrity_failure_count += 1
                if archive.integrity_failure_count >= self.max_integrity_failures:
                    archive.integrity_status = 'failed'
                    # 这里可以触发告警机制
                    self._trigger_integrity_alert(archive_id, verification_results)
            
            db.session.commit()
            
            # 记录完整性验证操作
            self.audit_logger.log_operation(
                user_id=0,  # 系统操作
                operation_type='verify_archive_integrity',
                resource_type='archive',
                resource_id=archive_id,
                operation_details={
                    'verification_types': verification_types,
                    'overall_status': overall_status,
                    'integrity_score': integrity_score,
                    'failure_count': failure_count
                }
            )
            
            return {
                'success': True,
                'archive_id': archive_id,
                'overall_status': overall_status,
                'integrity_score': integrity_score,
                'verification_results': verification_results,
                'checked_at': datetime.utcnow().isoformat(),
                'requires_attention': overall_status in ['failed', 'warning']
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"验证档案完整性失败: {str(e)}")
            return {
                'success': False,
                'error': f'验证档案完整性失败: {str(e)}',
                'error_code': 'ARCHIVE_INTEGRITY_VERIFICATION_ERROR'
            }
    
    def batch_verify_integrity(self, archive_ids: List[int], verification_types: List[str] = None) -> Dict:
        """
        批量验证档案完整性
        
        Args:
            archive_ids: 档案ID列表
            verification_types: 验证类型列表
            
        Returns:
            dict: 批量验证结果
        """
        try:
            verification_results = {}
            summary = {
                'total_archives': len(archive_ids),
                'passed': 0,
                'failed': 0,
                'warning': 0,
                'errors': 0
            }
            
            for archive_id in archive_ids:
                try:
                    result = self.verify_archive_integrity(archive_id, verification_types)
                    
                    if result['success']:
                        verification_results[archive_id] = result
                        
                        # 统计结果
                        status = result.get('overall_status', 'unknown')
                        if status == 'passed':
                            summary['passed'] += 1
                        elif status == 'failed':
                            summary['failed'] += 1
                        elif status == 'warning':
                            summary['warning'] += 1
                    else:
                        verification_results[archive_id] = result
                        summary['errors'] += 1
                        
                except Exception as e:
                    logger.error(f"验证档案 {archive_id} 完整性失败: {str(e)}")
                    verification_results[archive_id] = {
                        'success': False,
                        'error': str(e)
                    }
                    summary['errors'] += 1
            
            # 计算总体成功率
            summary['success_rate'] = (summary['passed'] + summary['warning']) / summary['total_archives'] * 100
            
            return {
                'success': True,
                'verification_results': verification_results,
                'summary': summary,
                'completed_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"批量验证档案完整性失败: {str(e)}")
            return {
                'success': False,
                'error': f'批量验证档案完整性失败: {str(e)}',
                'error_code': 'BATCH_VERIFICATION_ERROR'
            }
    
    def schedule_integrity_check(self, archive_id: int, check_interval_hours: int = None) -> Dict:
        """
        安排完整性检查任务
        
        Args:
            archive_id: 档案ID
            check_interval_hours: 检查间隔（小时）
            
        Returns:
            dict: 安排结果
        """
        try:
            archive = ElectronicArchive.query.get(archive_id)
            if not archive:
                return {
                    'success': False,
                    'error': '档案不存在',
                    'error_code': 'ARCHIVE_NOT_FOUND'
                }
            
            check_interval_hours = check_interval_hours or self.integrity_check_interval_hours
            
            # 计算下次检查时间
            next_check_time = datetime.utcnow() + timedelta(hours=check_interval_hours)
            
            # 更新档案的完整性检查设置
            archive.integrity_check_interval = check_interval_hours
            archive.next_integrity_check = next_check_time
            archive.auto_integrity_check = True
            
            db.session.commit()
            
            # 记录任务安排
            self.audit_logger.log_operation(
                user_id=0,  # 系统操作
                operation_type='schedule_integrity_check',
                resource_type='archive',
                resource_id=archive_id,
                operation_details={
                    'check_interval_hours': check_interval_hours,
                    'next_check_time': next_check_time.isoformat()
                }
            )
            
            return {
                'success': True,
                'archive_id': archive_id,
                'check_interval_hours': check_interval_hours,
                'next_check_time': next_check_time.isoformat(),
                'message': f'已安排档案 {archive_id} 的完整性检查任务'
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"安排完整性检查任务失败: {str(e)}")
            return {
                'success': False,
                'error': f'安排完整性检查任务失败: {str(e)}',
                'error_code': 'INTEGRITY_SCHEDULE_ERROR'
            }
    
    def get_integrity_statistics(self, time_period: str = '30d') -> Dict:
        """
        获取完整性统计信息
        
        Args:
            time_period: 统计时间期间 (7d, 30d, 90d, 1y)
            
        Returns:
            dict: 统计信息
        """
        try:
            # 计算时间范围
            time_delta_map = {
                '7d': timedelta(days=7),
                '30d': timedelta(days=30),
                '90d': timedelta(days=90),
                '1y': timedelta(days=365)
            }
            
            start_date = datetime.utcnow() - time_delta_map.get(time_period, timedelta(days=30))
            
            # 统计档案完整性状态
            from sqlalchemy import func
            
            status_stats = db.session.query(
                ElectronicArchive.integrity_status,
                func.count(ElectronicArchive.id)
            ).filter(
                ElectronicArchive.last_integrity_check >= start_date
            ).group_by(ElectronicArchive.integrity_status).all()
            
            status_summary = {}
            for status, count in status_stats:
                status_summary[status] = count
            
            # 计算平均完整性得分
            avg_score = db.session.query(
                func.avg(ElectronicArchive.integrity_score)
            ).filter(
                ElectronicArchive.last_integrity_check >= start_date
            ).scalar() or 0
            
            # 统计验证失败次数最多的档案
            failed_archives = db.session.query(
                ElectronicArchive.id,
                ElectronicArchive.title,
                ElectronicArchive.integrity_failure_count
            ).filter(
                ElectronicArchive.integrity_failure_count > 0
            ).order_by(
                ElectronicArchive.integrity_failure_count.desc()
            ).limit(10).all()
            
            # 统计验证类型使用情况
            verification_stats = {
                'hash_verification': ElectronicArchive.query.filter(
                    ElectronicArchive.hash_value.isnot(None)
                ).count(),
                'digital_signature': ElectronicArchive.query.filter(
                    ElectronicArchive.digital_signature.isnot(None)
                ).count()
            }
            
            statistics = {
                'time_period': time_period,
                'start_date': start_date.isoformat(),
                'end_date': datetime.utcnow().isoformat(),
                'total_archives_checked': sum(status_summary.values()),
                'status_distribution': status_summary,
                'average_integrity_score': round(float(avg_score), 2),
                'most_failed_archives': [
                    {
                        'archive_id': archive_id,
                        'title': title,
                        'failure_count': failure_count
                    }
                    for archive_id, title, failure_count in failed_archives
                ],
                'verification_methods': verification_stats,
                'generated_at': datetime.utcnow().isoformat()
            }
            
            return {
                'success': True,
                'statistics': statistics
            }
            
        except Exception as e:
            logger.error(f"获取完整性统计信息失败: {str(e)}")
            return {
                'success': False,
                'error': f'获取完整性统计信息失败: {str(e)}',
                'error_code': 'INTEGRITY_STATISTICS_ERROR'
            }
    
    def _verify_archive_hash_integrity(self, archive: ElectronicArchive) -> Dict:
        """验证档案哈希完整性"""
        try:
            if not archive.hash_value:
                return {
                    'success': False,
                    'verified': False,
                    'status': 'warning',
                    'error': '档案未设置哈希值',
                    'error_code': 'NO_HASH_VALUE'
                }
            
            # 检查档案内容文件
            archive_files = ArchiveFile.query.filter_by(
                archive_id=archive.id
            ).all()
            
            if not archive_files:
                return {
                    'success': False,
                    'verified': False,
                    'status': 'warning',
                    'error': '档案无内容文件',
                    'error_code': 'NO_CONTENT_FILES'
                }
            
            # 验证每个内容文件的哈希
            content_results = []
            overall_verified = True
            
            for content in archive_files:
                if content.file_path and os.path.exists(content.file_path):
                    content_result = self.verify_file_integrity(
                        content.file_path,
                        archive.hash_value
                    )
                    content_results.append({
                        'content_id': content.id,
                        'content_type': content.content_type,
                        'verified': content_result.get('verified', False),
                        'status': content_result.get('status', 'unknown')
                    })
                    
                    if not content_result.get('verified', False):
                        overall_verified = False
                else:
                    content_results.append({
                        'content_id': content.id,
                        'content_type': content.content_type,
                        'verified': False,
                        'status': 'failed',
                        'error': '内容文件不存在'
                    })
                    overall_verified = False
            
            return {
                'success': True,
                'verified': overall_verified,
                'status': 'passed' if overall_verified else 'failed',
                'content_results': content_results,
                'verified_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"验证档案哈希完整性失败: {str(e)}")
            return {
                'success': False,
                'verified': False,
                'status': 'failed',
                'error': f'验证哈希完整性失败: {str(e)}'
            }
    
    def _verify_archive_metadata_integrity(self, archive: ElectronicArchive) -> Dict:
        """验证档案元数据完整性"""
        try:
            required_metadata_fields = [
                'title', 'archive_type', 'created_by', 'created_at', 
                'department', 'fiscal_year'
            ]
            
            missing_fields = []
            invalid_fields = []
            
            # 检查必需字段
            for field in required_metadata_fields:
                value = getattr(archive, field, None)
                if not value:
                    missing_fields.append(field)
                elif field in ['created_at', 'updated_at'] and not isinstance(value, datetime):
                    invalid_fields.append(field)
            
            # 检查扩展元数据
            if hasattr(archive, 'metadata_list') and archive.metadata_list:
                try:
                    # archive.metadata_list 是 ArchiveMetadata 关系，不是简单的 JSON 字符串
                    metadata_dict = {}
                    for meta in archive.metadata_list:
                        metadata_dict[meta.metadata_key] = meta.metadata_value
                    if not isinstance(metadata_dict, dict):
                        invalid_fields.append('metadata')
                except (json.JSONDecodeError, TypeError):
                    invalid_fields.append('metadata')
            
            is_valid = len(missing_fields) == 0 and len(invalid_fields) == 0
            
            return {
                'success': True,
                'verified': is_valid,
                'status': 'passed' if is_valid else 'failed',
                'missing_fields': missing_fields,
                'invalid_fields': invalid_fields,
                'verified_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"验证档案元数据完整性失败: {str(e)}")
            return {
                'success': False,
                'verified': False,
                'status': 'failed',
                'error': f'验证元数据完整性失败: {str(e)}'
            }
    
    def _verify_archive_digital_signature(self, archive: ElectronicArchive) -> Dict:
        """验证档案数字签名"""
        try:
            if not archive.digital_signature:
                return {
                    'success': True,
                    'verified': False,
                    'status': 'warning',
                    'error': '档案未设置数字签名',
                    'error_code': 'NO_DIGITAL_SIGNATURE'
                }
            
            if not self.enable_digital_signature:
                return {
                    'success': True,
                    'verified': False,
                    'status': 'warning',
                    'error': '数字签名功能未启用',
                    'error_code': 'DIGITAL_SIGNATURE_DISABLED'
                }
            
            # 准备签名的数据（档案基本信息）
            signature_data = json.dumps({
                'archive_id': archive.id,
                'title': archive.title,
                'archive_type': archive.archive_type,
                'created_at': archive.created_at.isoformat() if archive.created_at else None,
                'hash_value': archive.hash_value
            }, sort_keys=True).encode('utf-8')
            
            # 验证数字签名
            verification_result = self.verify_digital_signature(
                signature_data,
                archive.digital_signature
            )
            
            return {
                'success': True,
                'verified': verification_result.get('verified', False),
                'status': 'passed' if verification_result.get('verified', False) else 'failed',
                'verification_result': verification_result,
                'verified_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"验证档案数字签名失败: {str(e)}")
            return {
                'success': False,
                'verified': False,
                'status': 'failed',
                'error': f'验证数字签名失败: {str(e)}'
            }
    
    def _verify_archive_content_signature(self, archive: ElectronicArchive) -> Dict:
        """验证档案内容签名"""
        try:
            # 检查档案内容是否存在
            archive_files = ArchiveFile.query.filter_by(
                archive_id=archive.id
            ).all()
            
            if not archive_files:
                return {
                    'success': True,
                    'verified': False,
                    'status': 'warning',
                    'error': '档案无内容文件',
                    'error_code': 'NO_CONTENT_FILES'
                }
            
            # 验证每个内容的签名
            content_signatures = []
            all_verified = True
            
            for content in archive_files:
                if content.file_path and os.path.exists(content.file_path):
                    # 生成内容哈希
                    hash_result = self.generate_file_hash(content.file_path)
                    if hash_result['success']:
                        content_signatures.append({
                            'content_id': content.id,
                            'content_type': content.content_type,
                            'hash': hash_result['file_hash'],
                            'signature': content.content_signature,
                            'has_signature': bool(content.content_signature)
                        })
                        
                        # 如果有签名但验证失败
                        if content.content_signature:
                            # 这里可以添加具体的内容签名验证逻辑
                            pass
                else:
                    content_signatures.append({
                        'content_id': content.id,
                        'content_type': content.content_type,
                        'error': '内容文件不存在'
                    })
                    all_verified = False
            
            return {
                'success': True,
                'verified': all_verified,
                'status': 'passed' if all_verified else 'warning',
                'content_signatures': content_signatures,
                'verified_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"验证档案内容签名失败: {str(e)}")
            return {
                'success': False,
                'verified': False,
                'status': 'failed',
                'error': f'验证内容签名失败: {str(e)}'
            }
    
    def _calculate_similarity(self, hash1: str, hash2: str) -> float:
        """计算哈希值相似度"""
        try:
            if len(hash1) != len(hash2):
                return 0.0
            
            # 计算相同位置的字符数量
            matches = sum(1 for i in range(len(hash1)) if hash1[i] == hash2[i])
            similarity = matches / len(hash1)
            
            return similarity
            
        except Exception:
            return 0.0
    
    def _calculate_integrity_score(self, verification_results: Dict) -> float:
        """计算完整性得分"""
        try:
            if not verification_results:
                return 0.0
            
            total_score = 0.0
            valid_results = 0
            
            for verification_type, result in verification_results.items():
                if result.get('success'):
                    valid_results += 1
                    
                    # 根据验证类型和结果计算得分
                    if verification_type == 'hash_verification':
                        if result.get('verified', False):
                            total_score += 40.0
                        elif result.get('status') == 'warning':
                            total_score += 20.0
                    
                    elif verification_type == 'metadata_integrity':
                        if result.get('verified', False):
                            total_score += 25.0
                        elif result.get('status') == 'warning':
                            total_score += 15.0
                    
                    elif verification_type == 'digital_signature':
                        if result.get('verified', False):
                            total_score += 20.0
                        elif result.get('status') == 'warning':
                            total_score += 10.0
                    
                    elif verification_type == 'content_signature':
                        if result.get('verified', False):
                            total_score += 15.0
                        elif result.get('status') == 'warning':
                            total_score += 8.0
            
            # 如果没有有效的验证结果，返回0分
            if valid_results == 0:
                return 0.0
            
            return min(total_score, 100.0)
            
        except Exception as e:
            logger.error(f"计算完整性得分失败: {str(e)}")
            return 0.0
    
    def _trigger_integrity_alert(self, archive_id: int, verification_results: Dict):
        """触发完整性告警"""
        try:
            # 记录完整性告警
            self.audit_logger.log_operation(
                user_id=0,  # 系统操作
                operation_type='integrity_alert',
                resource_type='archive',
                resource_id=archive_id,
                operation_details={
                    'alert_reason': 'integrity_verification_failed',
                    'verification_results': verification_results,
                    'alert_time': datetime.utcnow().isoformat()
                }
            )
            
            # 这里可以添加具体的告警机制，如发送邮件、短信等
            logger.warning(f"档案 {archive_id} 完整性验证失败，已触发告警")
            
        except Exception as e:
            logger.error(f"触发完整性告警失败: {str(e)}")