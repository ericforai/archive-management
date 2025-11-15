"""
完整性检查器 - 文件和档案完整性验证工具
基于DA/T 94-2022标准的完整性检查模块
"""
import os
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class IntegrityCheckResult:
    """完整性检查结果"""
    is_valid: bool
    file_hash: Optional[str] = None
    expected_hash: Optional[str] = None
    error_message: Optional[str] = None
    details: Dict = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}

class IntegrityChecker:
    """完整性检查器"""
    
    def __init__(self):
        self.algorithm = 'sha256'
        self.chunk_size = 8192  # 8KB chunks
    
    def calculate_file_hash(self, file_path: str) -> str:
        """
        计算文件哈希值
        
        Args:
            file_path: 文件路径
            
        Returns:
            文件哈希值
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"文件不存在: {file_path}")
        
        hash_func = hashlib.new(self.algorithm)
        
        with open(path, 'rb') as f:
            while chunk := f.read(self.chunk_size):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    def verify_file_integrity(self, file_path: str, expected_hash: str) -> IntegrityCheckResult:
        """
        验证文件完整性
        
        Args:
            file_path: 文件路径
            expected_hash: 预期哈希值
            
        Returns:
            完整性检查结果
        """
        try:
            path = Path(file_path)
            if not path.exists():
                return IntegrityCheckResult(
                    is_valid=False,
                    expected_hash=expected_hash,
                    error_message=f"文件不存在: {file_path}"
                )
            
            actual_hash = self.calculate_file_hash(file_path)
            
            return IntegrityCheckResult(
                is_valid=actual_hash.lower() == expected_hash.lower(),
                file_hash=actual_hash,
                expected_hash=expected_hash
            )
            
        except Exception as e:
            return IntegrityCheckResult(
                is_valid=False,
                expected_hash=expected_hash,
                error_message=f"完整性验证失败: {str(e)}"
            )
    
    def verify_archive_integrity(self, archive_id: int, files_data: List[Dict]) -> Dict[str, Any]:
        """
        验证档案完整性
        
        Args:
            archive_id: 档案ID
            files_data: 文件数据列表 [{'path': str, 'hash': str}]
            
        Returns:
            完整性验证结果
        """
        results = []
        valid_count = 0
        total_count = len(files_data)
        
        for file_data in files_data:
            file_path = file_data.get('path')
            expected_hash = file_data.get('hash')
            
            if not file_path or not expected_hash:
                results.append({
                    'file_path': file_path,
                    'valid': False,
                    'error': '缺少文件路径或哈希值'
                })
                continue
            
            check_result = self.verify_file_integrity(file_path, expected_hash)
            
            results.append({
                'file_path': file_path,
                'valid': check_result.is_valid,
                'actual_hash': check_result.file_hash,
                'expected_hash': check_result.expected_hash,
                'error': check_result.error_message
            })
            
            if check_result.is_valid:
                valid_count += 1
        
        return {
            'archive_id': archive_id,
            'total_files': total_count,
            'valid_files': valid_count,
            'invalid_files': total_count - valid_count,
            'integrity_rate': round(valid_count / total_count * 100, 2) if total_count > 0 else 0,
            'results': results,
            'checked_at': datetime.utcnow().isoformat()
        }
    
    def calculate_directory_hash(self, directory_path: str) -> Dict[str, str]:
        """
        计算目录中所有文件的哈希值
        
        Args:
            directory_path: 目录路径
            
        Returns:
            文件路径到哈希值的映射
        """
        directory = Path(directory_path)
        if not directory.exists() or not directory.is_dir():
            raise ValueError(f"目录不存在或不是有效目录: {directory_path}")
        
        file_hashes = {}
        
        for file_path in directory.rglob('*'):
            if file_path.is_file():
                try:
                    file_hash = self.calculate_file_hash(str(file_path))
                    # 使用相对路径
                    rel_path = file_path.relative_to(directory)
                    file_hashes[str(rel_path)] = file_hash
                except Exception as e:
                    logger.warning(f"计算文件哈希失败 {file_path}: {str(e)}")
        
        return file_hashes
    
    def create_checksum_file(self, directory_path: str, output_file: str) -> str:
        """
        创建校验和文件
        
        Args:
            directory_path: 目录路径
            output_file: 输出文件路径
            
        Returns:
            校验和文件路径
        """
        file_hashes = self.calculate_directory_hash(directory_path)
        
        checksum_path = Path(output_file)
        checksum_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(checksum_path, 'w') as f:
            f.write(f"# Checksum file generated on {datetime.utcnow().isoformat()}\n")
            f.write(f"# Algorithm: {self.algorithm}\n")
            f.write(f"# Directory: {directory_path}\n\n")
            
            for file_path, file_hash in sorted(file_hashes.items()):
                f.write(f"{file_hash}  {file_path}\n")
        
        return str(checksum_path)
    
    def verify_checksum_file(self, checksum_file: str, directory_path: str) -> Dict[str, Any]:
        """
        验证校验和文件
        
        Args:
            checksum_file: 校验和文件路径
            directory_path: 目录路径
            
        Returns:
            验证结果
        """
        checksum_path = Path(checksum_file)
        if not checksum_path.exists():
            return {
                'valid': False,
                'error': '校验和文件不存在'
            }
        
        # 解析校验和文件
        expected_hashes = {}
        try:
            with open(checksum_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        hash_value, file_path = parts
                        expected_hashes[file_path] = hash_value
        except Exception as e:
            return {
                'valid': False,
                'error': f'解析校验和文件失败: {str(e)}'
            }
        
        # 计算实际哈希值
        actual_hashes = self.calculate_directory_hash(directory_path)
        
        # 比较结果
        results = []
        all_valid = True
        
        for file_path, expected_hash in expected_hashes.items():
            actual_hash = actual_hashes.get(file_path)
            
            if actual_hash is None:
                results.append({
                    'file_path': file_path,
                    'valid': False,
                    'error': '文件不存在'
                })
                all_valid = False
            elif actual_hash.lower() != expected_hash.lower():
                results.append({
                    'file_path': file_path,
                    'valid': False,
                    'expected_hash': expected_hash,
                    'actual_hash': actual_hash,
                    'error': '哈希值不匹配'
                })
                all_valid = False
            else:
                results.append({
                    'file_path': file_path,
                    'valid': True
                })
        
        # 检查是否有额外的文件
        for file_path in actual_hashes:
            if file_path not in expected_hashes:
                results.append({
                    'file_path': file_path,
                    'valid': False,
                    'error': '校验和文件中缺少此文件'
                })
                all_valid = False
        
        return {
            'valid': all_valid,
            'total_files': len(expected_hashes),
            'verified_files': sum(1 for r in results if r['valid']),
            'results': results,
            'checked_at': datetime.utcnow().isoformat()
        }
    
    def batch_verify_files(self, file_list: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        批量验证文件完整性
        
        Args:
            file_list: 文件列表 [{'path': str, 'hash': str}]
            
        Returns:
            批量验证结果
        """
        results = []
        valid_count = 0
        
        for file_data in file_list:
            file_path = file_data.get('path')
            expected_hash = file_data.get('hash')
            
            if not file_path or not expected_hash:
                results.append({
                    'file_path': file_path or 'unknown',
                    'valid': False,
                    'error': '缺少文件路径或哈希值'
                })
                continue
            
            check_result = self.verify_file_integrity(file_path, expected_hash)
            
            results.append({
                'file_path': file_path,
                'valid': check_result.is_valid,
                'actual_hash': check_result.file_hash,
                'expected_hash': check_result.expected_hash,
                'error': check_result.error_message
            })
            
            if check_result.is_valid:
                valid_count += 1
        
        total_count = len(file_list)
        
        return {
            'total_files': total_count,
            'valid_files': valid_count,
            'invalid_files': total_count - valid_count,
            'success_rate': round(valid_count / total_count * 100, 2) if total_count > 0 else 0,
            'results': results,
            'checked_at': datetime.utcnow().isoformat()
        }
    
    def get_supported_algorithms(self) -> List[str]:
        """获取支持的哈希算法"""
        return ['md5', 'sha1', 'sha256', 'sha512']
    
    def set_algorithm(self, algorithm: str):
        """
        设置哈希算法
        
        Args:
            algorithm: 哈希算法名称
        """
        if algorithm not in self.get_supported_algorithms():
            raise ValueError(f"不支持的哈希算法: {algorithm}")
        
        # 验证算法是否可用
        try:
            hashlib.new(algorithm)
        except ValueError:
            raise ValueError(f"哈希算法不可用: {algorithm}")
        
        self.algorithm = algorithm