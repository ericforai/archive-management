"""
文件处理器 - 文件上传、存储、转换工具
基于DA/T 94-2022标准的文件处理模块
"""
import os
import hashlib
import mimetypes
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage

logger = logging.getLogger(__name__)

class FileHandler:
    """文件处理器"""
    
    def __init__(self):
        self.base_upload_dir = Path("storage/uploads")
        self.base_archive_dir = Path("storage/archives")
        self.base_temp_dir = Path("storage/temp")
        
        # 创建目录
        for directory in [self.base_upload_dir, self.base_archive_dir, self.base_temp_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # 支持的文件类型
        self.supported_types = {
            'document': ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf'],
            'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif'],
            'archive': ['.zip', '.rar', '.7z', '.tar', '.gz']
        }
        
        # 文件大小限制 (MB)
        self.max_file_size = {
            'document': 100,
            'image': 50,
            'archive': 500
        }
    
    def save_uploaded_file(self, 
                          file: FileStorage, 
                          file_type: str = 'document',
                          user_id: int = None) -> Dict:
        """
        保存上传文件
        
        Args:
            file: 上传的文件
            file_type: 文件类型
            user_id: 用户ID
            
        Returns:
            dict: 保存结果
        """
        try:
            # 验证文件
            validation_result = self._validate_file(file, file_type)
            if not validation_result['valid']:
                return validation_result
            
            # 生成安全的文件名
            filename = secure_filename(file.filename)
            if not filename:
                return {
                    'success': False,
                    'error': '无效的文件名',
                    'error_code': 'INVALID_FILENAME'
                }
            
            # 生成唯一文件名
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            file_ext = Path(filename).suffix
            unique_filename = f"{timestamp}_{user_id or 'anonymous'}{file_ext}"
            
            # 创建用户目录
            user_dir = self.base_upload_dir / str(user_id) if user_id else self.base_upload_dir / 'anonymous'
            user_dir.mkdir(exist_ok=True)
            
            # 保存文件
            file_path = user_dir / unique_filename
            file.save(str(file_path))
            
            # 计算文件哈希值
            file_hash = self._calculate_file_hash(file_path)
            
            # 获取文件信息
            file_info = self._get_file_info(file_path)
            
            result = {
                'success': True,
                'file_path': str(file_path),
                'filename': filename,
                'stored_filename': unique_filename,
                'file_type': file_type,
                'file_size': file_info['size'],
                'mime_type': file_info['mime_type'],
                'file_hash': file_hash,
                'upload_time': datetime.utcnow().isoformat()
            }
            
            logger.info(f"文件上传成功: {filename} -> {unique_filename}")
            return result
            
        except Exception as e:
            logger.error(f"文件上传失败: {str(e)}")
            return {
                'success': False,
                'error': f'文件上传失败: {str(e)}',
                'error_code': 'UPLOAD_ERROR'
            }
    
    def move_to_archive(self, 
                       source_path: str, 
                       archive_id: str,
                       file_name: str) -> Dict:
        """
        将文件移动到档案目录
        
        Args:
            source_path: 源文件路径
            archive_id: 档案ID
            file_name: 文件名
            
        Returns:
            dict: 移动结果
        """
        try:
            source = Path(source_path)
            if not source.exists():
                return {
                    'success': False,
                    'error': '源文件不存在',
                    'error_code': 'SOURCE_NOT_FOUND'
                }
            
            # 创建档案目录
            archive_dir = self.base_archive_dir / str(archive_id)
            archive_dir.mkdir(parents=True, exist_ok=True)
            
            # 目标路径
            target_path = archive_dir / secure_filename(file_name)
            
            # 移动文件
            source.rename(target_path)
            
            return {
                'success': True,
                'file_path': str(target_path),
                'archive_id': archive_id
            }
            
        except Exception as e:
            logger.error(f"文件移动失败: {str(e)}")
            return {
                'success': False,
                'error': f'文件移动失败: {str(e)}',
                'error_code': 'MOVE_ERROR'
            }
    
    def delete_file(self, file_path: str) -> Dict:
        """
        删除文件
        
        Args:
            file_path: 文件路径
            
        Returns:
            dict: 删除结果
        """
        try:
            path = Path(file_path)
            if path.exists():
                path.unlink()
                return {
                    'success': True,
                    'deleted_path': file_path
                }
            else:
                return {
                    'success': False,
                    'error': '文件不存在',
                    'error_code': 'FILE_NOT_FOUND'
                }
                
        except Exception as e:
            logger.error(f"文件删除失败: {str(e)}")
            return {
                'success': False,
                'error': f'文件删除失败: {str(e)}',
                'error_code': 'DELETE_ERROR'
            }
    
    def get_file_content(self, file_path: str) -> Optional[bytes]:
        """
        获取文件内容
        
        Args:
            file_path: 文件路径
            
        Returns:
            bytes: 文件内容
        """
        try:
            path = Path(file_path)
            if path.exists():
                return path.read_bytes()
            return None
        except Exception as e:
            logger.error(f"读取文件失败: {str(e)}")
            return None
    
    def get_file_info(self, file_path: str) -> Dict:
        """
        获取文件信息
        
        Args:
            file_path: 文件路径
            
        Returns:
            dict: 文件信息
        """
        try:
            path = Path(file_path)
            if not path.exists():
                return {}
            
            stat = path.stat()
            mime_type, _ = mimetypes.guess_type(str(path))
            
            return {
                'name': path.name,
                'size': stat.st_size,
                'mime_type': mime_type or 'application/octet-stream',
                'modified_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'extension': path.suffix.lower()
            }
            
        except Exception as e:
            logger.error(f"获取文件信息失败: {str(e)}")
            return {}
    
    def create_backup(self, file_path: str, backup_type: str = 'daily') -> Dict:
        """
        创建文件备份
        
        Args:
            file_path: 文件路径
            backup_type: 备份类型 (daily/weekly/monthly)
            
        Returns:
            dict: 备份结果
        """
        try:
            source_path = Path(file_path)
            if not source_path.exists():
                return {
                    'success': False,
                    'error': '源文件不存在',
                    'error_code': 'SOURCE_NOT_FOUND'
                }
            
            # 创建备份目录
            backup_base = Path("storage/backup") / backup_type
            backup_base.mkdir(parents=True, exist_ok=True)
            
            # 生成备份文件名
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            backup_name = f"{timestamp}_{source_path.name}"
            backup_path = backup_base / backup_name
            
            # 复制文件
            import shutil
            shutil.copy2(source_path, backup_path)
            
            return {
                'success': True,
                'backup_path': str(backup_path),
                'backup_type': backup_type,
                'backup_time': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"创建备份失败: {str(e)}")
            return {
                'success': False,
                'error': f'创建备份失败: {str(e)}',
                'error_code': 'BACKUP_ERROR'
            }
    
    def _validate_file(self, file: FileStorage, file_type: str) -> Dict:
        """验证文件"""
        # 检查文件名
        if not file.filename:
            return {
                'valid': False,
                'error': '文件名不能为空',
                'error_code': 'EMPTY_FILENAME'
            }
        
        # 检查文件扩展名
        file_ext = Path(file.filename).suffix.lower()
        if file_type not in self.supported_types:
            return {
                'valid': False,
                'error': f'不支持的文件类型: {file_type}',
                'error_code': 'UNSUPPORTED_TYPE'
            }
        
        if file_ext not in self.supported_types[file_type]:
            return {
                'valid': False,
                'error': f'不支持的文件格式: {file_ext}',
                'error_code': 'UNSUPPORTED_FORMAT'
            }
        
        # 检查文件大小
        file.seek(0, 2)  # 移动到文件末尾
        file_size = file.tell()  # 获取当前偏移量（文件大小）
        file.seek(0)  # 重置到文件开头
        
        max_size = self.max_file_size[file_type] * 1024 * 1024  # 转换为字节
        if file_size > max_size:
            return {
                'valid': False,
                'error': f'文件大小超过限制 ({self.max_file_size[file_type]}MB)',
                'error_code': 'FILE_TOO_LARGE'
            }
        
        return {'valid': True}
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """计算文件哈希值"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def _get_file_info(self, file_path: Path) -> Dict:
        """获取文件详细信息"""
        stat = file_path.stat()
        mime_type, _ = mimetypes.guess_type(str(file_path))
        
        return {
            'size': stat.st_size,
            'mime_type': mime_type or 'application/octet-stream',
            'modified_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'extension': file_path.suffix.lower()
        }