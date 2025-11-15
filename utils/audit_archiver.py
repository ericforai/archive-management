"""
审计归档器 - 审计日志归档、压缩、清理
基于DA/T 94-2022标准的审计归档模块
"""
import os
import json
import gzip
import shutil
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class AuditArchiver:
    """审计日志归档器"""
    
    def __init__(self):
        self.archive_dir = Path("audit_archives")
        self.archive_dir.mkdir(exist_ok=True)
        
        # 归档配置
        self.default_retention_days = 2555  # 7年
        self.compression_enabled = True
        self.batch_size = 10000
        
        # 归档文件命名规则
        self.archive_filename_pattern = "audit_logs_{start_date}_{end_date}.json.gz"
        self.metadata_filename_pattern = "audit_metadata_{start_date}_{end_date}.json"
    
    def archive_audit_logs(self, 
                          start_date: datetime, 
                          end_date: datetime, 
                          retention_days: int = None) -> Dict:
        """
        归档审计日志
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            retention_days: 保留天数
            
        Returns:
            dict: 归档结果
        """
        try:
            from models.audit import AuditLog
            from models import db
            
            retention_days = retention_days or self.default_retention_days
            archive_cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
            
            # 验证日期范围
            if end_date > archive_cutoff_date:
                return {
                    'success': False,
                    'error': f'结束日期不能晚于归档截止日期 {archive_cutoff_date.date()}',
                    'error_code': 'INVALID_DATE_RANGE'
                }
            
            # 获取要归档的日志
            logs_to_archive = AuditLog.query.filter(
                AuditLog.created_at >= start_date,
                AuditLog.created_at <= end_date,
                AuditLog.archived == False
            ).all()
            
            if not logs_to_archive:
                return {
                    'success': False,
                    'error': '没有找到需要归档的日志',
                    'error_code': 'NO_LOGS_TO_ARCHIVE'
                }
            
            # 生成归档文件名
            archive_filename = self._generate_archive_filename(start_date, end_date)
            archive_path = self.archive_dir / archive_filename
            
            metadata = {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'total_logs': len(logs_to_archive),
                'archived_at': datetime.utcnow().isoformat(),
                'archive_version': '1.0',
                'compression': self.compression_enabled,
                'log_statistics': self._calculate_log_statistics(logs_to_archive)
            }
            
            # 创建归档文件
            self._create_archive_file(logs_to_archive, archive_path, metadata)
            
            # 更新日志状态为已归档
            for log in logs_to_archive:
                log.archived = True
                log.archived_at = datetime.utcnow()
                log.archive_path = str(archive_path)
            
            db.session.commit()
            
            return {
                'success': True,
                'archive_path': str(archive_path),
                'archived_logs_count': len(logs_to_archive),
                'archive_size': self._get_file_size(archive_path),
                'metadata': metadata
            }
            
        except Exception as e:
            logger.error(f"审计日志归档失败: {str(e)}")
            return {
                'success': False,
                'error': f'审计日志归档失败: {str(e)}',
                'error_code': 'ARCHIVE_ERROR'
            }
    
    def restore_audit_logs(self, archive_path: str, target_date_range: Dict = None) -> Dict:
        """
        恢复审计日志
        
        Args:
            archive_path: 归档文件路径
            target_date_range: 目标日期范围
            
        Returns:
            dict: 恢复结果
        """
        try:
            archive_file = Path(archive_path)
            
            if not archive_file.exists():
                return {
                    'success': False,
                    'error': f'归档文件不存在: {archive_path}',
                    'error_code': 'ARCHIVE_NOT_FOUND'
                }
            
            # 读取归档文件
            logs_data, metadata = self._read_archive_file(archive_file)
            
            # 过滤指定日期范围的日志
            if target_date_range:
                start_date = datetime.fromisoformat(target_date_range['start_date'])
                end_date = datetime.fromisoformat(target_date_range['end_date'])
                
                filtered_logs = []
                for log_data in logs_data:
                    log_date = datetime.fromisoformat(log_data['created_at'])
                    if start_date <= log_date <= end_date:
                        filtered_logs.append(log_data)
                logs_data = filtered_logs
            
            # 恢复到数据库
            restored_count = self._restore_logs_to_database(logs_data)
            
            return {
                'success': True,
                'restored_count': restored_count,
                'archive_metadata': metadata,
                'original_archive_path': archive_path
            }
            
        except Exception as e:
            logger.error(f"审计日志恢复失败: {str(e)}")
            return {
                'success': False,
                'error': f'审计日志恢复失败: {str(e)}',
                'error_code': 'RESTORE_ERROR'
            }
    
    def cleanup_expired_archives(self, retention_days: int = None) -> Dict:
        """
        清理过期归档
        
        Args:
            retention_days: 保留天数
            
        Returns:
            dict: 清理结果
        """
        try:
            retention_days = retention_days or self.default_retention_days
            cleanup_date = datetime.utcnow() - timedelta(days=retention_days * 2)  # 归档文件保留时间更长
            
            archived_files = list(self.archive_dir.glob("audit_logs_*.json.gz"))
            
            cleaned_files = []
            total_size_freed = 0
            
            for archive_file in archived_files:
                # 从文件名解析日期
                try:
                    file_date_str = archive_file.stem.split('_')[-2:]
                    file_start_date = datetime.strptime(file_date_str[0], '%Y-%m-%d')
                    
                    # 如果文件日期超过保留期，删除
                    if file_start_date < cleanup_date:
                        file_size = self._get_file_size(archive_file)
                        archive_file.unlink()
                        cleaned_files.append(str(archive_file))
                        total_size_freed += file_size
                        
                except (ValueError, IndexError):
                    # 跳过无法解析的文件名
                    continue
            
            return {
                'success': True,
                'cleaned_files_count': len(cleaned_files),
                'cleaned_files': cleaned_files,
                'total_size_freed': total_size_freed,
                'cleanup_date': cleanup_date.isoformat()
            }
            
        except Exception as e:
            logger.error(f"清理过期归档失败: {str(e)}")
            return {
                'success': False,
                'error': f'清理过期归档失败: {str(e)}',
                'error_code': 'CLEANUP_ERROR'
            }
    
    def get_archive_statistics(self) -> Dict:
        """
        获取归档统计信息
        
        Returns:
            dict: 归档统计
        """
        try:
            archive_files = list(self.archive_dir.glob("audit_logs_*.json.gz"))
            
            total_files = len(archive_files)
            total_size = sum(self._get_file_size(f) for f in archive_files)
            
            # 按年份统计
            yearly_stats = {}
            for archive_file in archive_files:
                try:
                    year = archive_file.stem.split('_')[-2][:4]
                    if year not in yearly_stats:
                        yearly_stats[year] = {'count': 0, 'size': 0}
                    yearly_stats[year]['count'] += 1
                    yearly_stats[year]['size'] += self._get_file_size(archive_file)
                except (ValueError, IndexError):
                    continue
            
            return {
                'total_archives': total_files,
                'total_size_bytes': total_size,
                'total_size_mb': round(total_size / (1024 * 1024), 2),
                'yearly_breakdown': yearly_stats,
                'archive_directory': str(self.archive_dir),
                'last_updated': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"获取归档统计失败: {str(e)}")
            return {
                'error': str(e),
                'last_updated': datetime.utcnow().isoformat()
            }
    
    def verify_archive_integrity(self, archive_path: str) -> Dict:
        """
        验证归档文件完整性
        
        Args:
            archive_path: 归档文件路径
            
        Returns:
            dict: 验证结果
        """
        try:
            archive_file = Path(archive_path)
            
            if not archive_file.exists():
                return {
                    'success': False,
                    'error': '归档文件不存在',
                    'error_code': 'ARCHIVE_NOT_FOUND'
                }
            
            # 检查文件大小
            file_size = self._get_file_size(archive_file)
            if file_size == 0:
                return {
                    'success': False,
                    'error': '归档文件为空',
                    'error_code': 'EMPTY_ARCHIVE'
                }
            
            # 尝试读取和解压缩文件
            try:
                logs_data, metadata = self._read_archive_file(archive_file)
                log_count = len(logs_data) if logs_data else 0
                
                # 验证元数据
                required_metadata_fields = ['start_date', 'end_date', 'total_logs', 'archived_at']
                metadata_valid = all(field in metadata for field in required_metadata_fields)
                
                return {
                    'success': True,
                    'archive_path': str(archive_path),
                    'file_size': file_size,
                    'log_count': log_count,
                    'metadata_valid': metadata_valid,
                    'compression_used': metadata.get('compression', False),
                    'archive_date': metadata.get('archived_at'),
                    'verification_timestamp': datetime.utcnow().isoformat()
                }
                
            except Exception as e:
                return {
                    'success': False,
                    'error': f'归档文件损坏或格式错误: {str(e)}',
                    'error_code': 'CORRUPTED_ARCHIVE'
                }
                
        except Exception as e:
            logger.error(f"验证归档完整性失败: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'error_code': 'VERIFICATION_ERROR'
            }
    
    def _generate_archive_filename(self, start_date: datetime, end_date: datetime) -> str:
        """生成归档文件名"""
        start_str = start_date.strftime('%Y-%m-%d')
        end_str = end_date.strftime('%Y-%m-%d')
        extension = '.json.gz' if self.compression_enabled else '.json'
        
        return f"audit_logs_{start_str}_{end_str}{extension}"
    
    def _create_archive_file(self, logs: List, archive_path: Path, metadata: Dict):
        """创建归档文件"""
        # 准备日志数据
        logs_data = []
        for log in logs:
            log_dict = {
                'id': log.id,
                'user_id': log.user_id,
                'operation_type': log.operation_type,
                'resource_type': log.resource_type,
                'resource_id': log.resource_id,
                'operation_details': log.operation_details,
                'risk_level': log.risk_level,
                'result': log.result,
                'created_at': log.created_at.isoformat()
            }
            logs_data.append(log_dict)
        
        # 创建压缩文件
        if self.compression_enabled:
            with gzip.open(archive_path, 'wt', encoding='utf-8') as f:
                json.dump({
                    'metadata': metadata,
                    'logs': logs_data
                }, f, ensure_ascii=False, indent=2)
        else:
            with open(archive_path, 'w', encoding='utf-8') as f:
                json.dump({
                    'metadata': metadata,
                    'logs': logs_data
                }, f, ensure_ascii=False, indent=2)
    
    def _read_archive_file(self, archive_path: Path) -> tuple:
        """读取归档文件"""
        if archive_path.suffix == '.gz':
            with gzip.open(archive_path, 'rt', encoding='utf-8') as f:
                data = json.load(f)
        else:
            with open(archive_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        
        return data['logs'], data['metadata']
    
    def _calculate_log_statistics(self, logs: List) -> Dict:
        """计算日志统计信息"""
        if not logs:
            return {}
        
        stats = {
            'operation_types': {},
            'risk_levels': {},
            'results': {},
            'date_range': {
                'earliest': min(log.created_at for log in logs).isoformat(),
                'latest': max(log.created_at for log in logs).isoformat()
            }
        }
        
        for log in logs:
            # 操作类型统计
            op_type = log.operation_type
            stats['operation_types'][op_type] = stats['operation_types'].get(op_type, 0) + 1
            
            # 风险级别统计
            risk_level = log.risk_level
            stats['risk_levels'][risk_level] = stats['risk_levels'].get(risk_level, 0) + 1
            
            # 结果统计
            result = log.result
            stats['results'][result] = stats['results'].get(result, 0) + 1
        
        return stats
    
    def _get_file_size(self, file_path: Path) -> int:
        """获取文件大小"""
        try:
            return file_path.stat().st_size
        except OSError:
            return 0
    
    def _restore_logs_to_database(self, logs_data: List) -> int:
        """恢复日志到数据库"""
        from models.audit import AuditLog
        from models import db
        
        restored_count = 0
        batch_size = 1000
        
        for i in range(0, len(logs_data), batch_size):
            batch = logs_data[i:i + batch_size]
            
            for log_data in batch:
                try:
                    # 检查日志是否已存在
                    existing_log = AuditLog.query.get(log_data['id'])
                    if existing_log:
                        continue
                    
                    # 创建新日志记录
                    new_log = AuditLog(
                        id=log_data['id'],
                        user_id=log_data['user_id'],
                        operation_type=log_data['operation_type'],
                        resource_type=log_data['resource_type'],
                        resource_id=log_data['resource_id'],
                        operation_details=log_data['operation_details'],
                        risk_level=log_data['risk_level'],
                        result=log_data['result'],
                        created_at=datetime.fromisoformat(log_data['created_at'])
                    )
                    
                    db.session.add(new_log)
                    restored_count += 1
                    
                except Exception as e:
                    logger.warning(f"恢复单条日志失败: {str(e)}")
                    continue
            
            db.session.commit()
        
        return restored_count