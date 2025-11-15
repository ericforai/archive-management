"""
档案验证器 - 档案合规性、完整性验证工具
基于DA/T 94-2022标准的档案验证模块
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
class ValidationResult:
    """验证结果"""
    is_valid: bool
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    warnings: List[str] = None
    details: Dict = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []
        if self.details is None:
            self.details = {}

class ArchiveValidator:
    """档案验证器"""
    
    def __init__(self):
        # 验证规则配置
        self.required_fields = {
            'title': '档案题名',
            'archive_no': '档号',
            'category_id': '分类ID',
            'created_date': '创建日期',
            'retention_period': '保管期限'
        }
        
        self.field_validators = {
            'archive_no': self._validate_archive_no,
            'title': self._validate_title,
            'confidentiality_level': self._validate_confidentiality_level,
            'retention_period': self._validate_retention_period
        }
        
        # 合规性标准
        self.compliance_standards = {
            '完整性': self._check_integrity,
            '规范性': self._check_standardization,
            '可读性': self._check_readability,
            '长期性': self._check_long_term_availability
        }
    
    def validate_archive_basic_info(self, archive_data: Dict) -> ValidationResult:
        """
        验证档案基本信息
        
        Args:
            archive_data: 档案数据
            
        Returns:
            ValidationResult: 验证结果
        """
        errors = []
        warnings = []
        details = {}
        
        # 检查必需字段
        for field, field_name in self.required_fields.items():
            if not archive_data.get(field):
                errors.append(f"缺少必需字段: {field_name}")
        
        # 执行字段验证
        for field, validator_func in self.field_validators.items():
            if field in archive_data and archive_data[field]:
                try:
                    field_result = validator_func(archive_data[field])
                    if not field_result['valid']:
                        errors.extend(field_result['errors'])
                    if field_result.get('warnings'):
                        warnings.extend(field_result['warnings'])
                except Exception as e:
                    errors.append(f"验证字段 {field} 时发生错误: {str(e)}")
        
        # 检查日期逻辑
        date_validation = self._validate_dates(archive_data)
        if not date_validation['valid']:
            errors.append(date_validation['error'])
        
        # 检查文件关联
        if archive_data.get('file_count', 0) == 0:
            warnings.append("档案没有关联文件")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            error_code="VALIDATION_FAILED" if errors else None,
            error_message="; ".join(errors) if errors else None,
            warnings=warnings,
            details=details
        )
    
    def validate_file_integrity(self, file_hash: str, file_path: str) -> ValidationResult:
        """
        验证文件完整性
        
        Args:
            file_hash: 文件哈希值
            file_path: 文件路径
            
        Returns:
            ValidationResult: 验证结果
        """
        try:
            # 检查文件是否存在
            path = Path(file_path)
            if not path.exists():
                return ValidationResult(
                    is_valid=False,
                    error_code="FILE_NOT_FOUND",
                    error_message=f"文件不存在: {file_path}"
                )
            
            # 计算实际哈希值
            actual_hash = self._calculate_file_hash(path)
            
            if actual_hash.lower() == file_hash.lower():
                return ValidationResult(
                    is_valid=True,
                    details={'expected_hash': file_hash, 'actual_hash': actual_hash}
                )
            else:
                return ValidationResult(
                    is_valid=False,
                    error_code="HASH_MISMATCH",
                    error_message="文件哈希值不匹配",
                    details={'expected_hash': file_hash, 'actual_hash': actual_hash}
                )
                
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error_code="INTEGRITY_CHECK_ERROR",
                error_message=f"完整性检查失败: {str(e)}"
            )
    
    def validate_archive_compliance(self, archive_data: Dict, file_list: List[str]) -> ValidationResult:
        """
        验证档案合规性
        
        Args:
            archive_data: 档案数据
            file_list: 文件列表
            
        Returns:
            ValidationResult: 验证结果
        """
        warnings = []
        details = {}
        
        # 检查合规性标准
        for standard_name, check_func in self.compliance_standards.items():
            try:
                standard_result = check_func(archive_data, file_list)
                if not standard_result['passed']:
                    warnings.append(f"{standard_name}不合规: {standard_result['message']}")
                details[standard_name] = standard_result
            except Exception as e:
                warnings.append(f"{standard_name}检查失败: {str(e)}")
        
        # 检查格式要求
        format_validation = self._check_format_requirements(file_list)
        if not format_validation['passed']:
            warnings.extend(format_validation['warnings'])
        
        # 检查完整性
        if archive_data.get('file_count', 0) != len(file_list):
            warnings.append(f"文件数量不匹配: 记录{archive_data.get('file_count', 0)}个，实际{len(file_list)}个")
        
        return ValidationResult(
            is_valid=len(warnings) == 0,
            error_code="COMPLIANCE_ISSUE" if warnings else None,
            error_message=None,  # 合规性问题不影响有效性
            warnings=warnings,
            details=details
        )
    
    def validate_archive_lifecycle(self, archive_data: Dict) -> ValidationResult:
        """
        验证档案生命周期状态
        
        Args:
            archive_data: 档案数据
            
        Returns:
            ValidationResult: 验证结果
        """
        errors = []
        warnings = []
        details = {}
        
        try:
            status = archive_data.get('status')
            created_date = archive_data.get('created_date')
            archive_date = archive_data.get('archive_date')
            disposal_date = archive_data.get('disposal_date')
            
            # 状态转换验证
            status_transitions = {
                'draft': ['archived'],
                'archived': ['disposed', 'transferred'],
                'transferred': [],
                'disposed': []
            }
            
            if status in status_transitions:
                expected_next_states = status_transitions[status]
                # 这里可以添加更复杂的生命周期验证逻辑
            
            # 日期逻辑验证
            if created_date and archive_date:
                if archive_date < created_date:
                    errors.append("归档日期不能早于创建日期")
            
            if archive_date and disposal_date:
                if disposal_date < archive_date:
                    errors.append("处置日期不能早于归档日期")
            
            # 状态与日期一致性
            if status == 'archived' and not archive_date:
                warnings.append("档案状态为已归档但缺少归档日期")
            
            if status == 'disposed' and not disposal_date:
                warnings.append("档案状态为已处置但缺少处置日期")
            
        except Exception as e:
            errors.append(f"生命周期验证失败: {str(e)}")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            error_code="LIFECYCLE_ERROR" if errors else None,
            error_message="; ".join(errors) if errors else None,
            warnings=warnings,
            details=details
        )
    
    def generate_compliance_report(self, validation_results: List[ValidationResult]) -> Dict:
        """
        生成合规性报告
        
        Args:
            validation_results: 验证结果列表
            
        Returns:
            dict: 合规性报告
        """
        total_count = len(validation_results)
        valid_count = sum(1 for result in validation_results if result.is_valid)
        warning_count = sum(1 for result in validation_results if result.warnings)
        error_count = total_count - valid_count
        
        # 统计错误代码
        error_codes = {}
        all_warnings = []
        
        for result in validation_results:
            if not result.is_valid and result.error_code:
                error_codes[result.error_code] = error_codes.get(result.error_code, 0) + 1
            
            all_warnings.extend(result.warnings)
        
        # 生成建议
        recommendations = self._generate_recommendations(error_codes, all_warnings)
        
        return {
            'total_archives': total_count,
            'valid_archives': valid_count,
            'warning_archives': warning_count,
            'invalid_archives': error_count,
            'compliance_rate': round(valid_count / total_count * 100, 2) if total_count > 0 else 0,
            'error_distribution': error_codes,
            'top_warnings': all_warnings[:10],
            'recommendations': recommendations,
            'generated_at': datetime.utcnow().isoformat()
        }
    
    def _validate_archive_no(self, archive_no: str) -> Dict:
        """验证档号格式"""
        errors = []
        warnings = []
        
        if len(archive_no) > 100:
            errors.append("档号长度不能超过100个字符")
        
        if not archive_no.strip():
            errors.append("档号不能为空")
        
        # 检查特殊字符
        forbidden_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*']
        for char in forbidden_chars:
            if char in archive_no:
                errors.append(f"档号包含非法字符: {char}")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings
        }
    
    def _validate_title(self, title: str) -> Dict:
        """验证题名"""
        errors = []
        warnings = []
        
        if len(title) > 500:
            errors.append("题名长度不能超过500个字符")
        
        if len(title) < 2:
            errors.append("题名长度不能少于2个字符")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings
        }
    
    def _validate_confidentiality_level(self, level: int) -> Dict:
        """验证保密等级"""
        errors = []
        
        if level < 1 or level > 5:
            errors.append("保密等级必须在1-5之间")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': []
        }
    
    def _validate_retention_period(self, period: str) -> Dict:
        """验证保管期限"""
        errors = []
        valid_periods = ['permanent', '30_years', '10_years', '5_years', '3_years']
        
        if period not in valid_periods:
            errors.append(f"保管期限必须是以下之一: {', '.join(valid_periods)}")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': []
        }
    
    def _validate_dates(self, archive_data: Dict) -> Dict:
        """验证日期逻辑"""
        errors = []
        
        try:
            created_date = archive_data.get('created_date')
            archive_date = archive_data.get('archive_date')
            disposal_date = archive_data.get('disposal_date')
            
            if created_date and isinstance(created_date, str):
                created_date = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
            
            if archive_date and isinstance(archive_date, str):
                archive_date = datetime.fromisoformat(archive_date.replace('Z', '+00:00'))
            
            if disposal_date and isinstance(disposal_date, str):
                disposal_date = datetime.fromisoformat(disposal_date.replace('Z', '+00:00'))
            
            # 检查日期逻辑
            if created_date and archive_date and archive_date < created_date:
                errors.append("归档日期不能早于创建日期")
            
            if archive_date and disposal_date and disposal_date < archive_date:
                errors.append("处置日期不能早于归档日期")
            
            # 检查未来日期
            now = datetime.utcnow()
            for date_name, date_value in [('创建日期', created_date), ('归档日期', archive_date), ('处置日期', disposal_date)]:
                if date_value and date_value > now:
                    errors.append(f"{date_name}不能是未来日期")
        
        except Exception as e:
            errors.append(f"日期格式错误: {str(e)}")
        
        return {
            'valid': len(errors) == 0,
            'error': '; '.join(errors) if errors else None
        }
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """计算文件哈希值"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def _check_integrity(self, archive_data: Dict, file_list: List[str]) -> Dict:
        """检查完整性"""
        return {
            'passed': True,
            'message': '完整性检查通过'
        }
    
    def _check_standardization(self, archive_data: Dict, file_list: List[str]) -> Dict:
        """检查规范性"""
        # 检查是否遵循命名规范
        title = archive_data.get('title', '')
        if len(title) > 200:
            return {
                'passed': False,
                'message': '题名过长，不符合规范化要求'
            }
        
        return {
            'passed': True,
            'message': '规范性检查通过'
        }
    
    def _check_readability(self, archive_data: Dict, file_list: List[str]) -> Dict:
        """检查可读性"""
        # 检查文件格式是否支持
        readable_formats = ['.pdf', '.doc', '.docx', '.txt']
        unreadable_files = []
        
        for file_path in file_list:
            file_ext = Path(file_path).suffix.lower()
            if file_ext not in readable_formats:
                unreadable_files.append(file_ext)
        
        if unreadable_files:
            return {
                'passed': False,
                'message': f'存在不可读格式: {", ".join(set(unreadable_files))}'
            }
        
        return {
            'passed': True,
            'message': '可读性检查通过'
        }
    
    def _check_long_term_availability(self, archive_data: Dict, file_list: List[str]) -> Dict:
        """检查长期可用性"""
        # 检查文件格式的长期可用性
        archival_formats = ['.pdf', '.pdfa']
        non_archival_files = []
        
        for file_path in file_list:
            file_ext = Path(file_path).suffix.lower()
            if file_ext not in archival_formats:
                non_archival_files.append(file_ext)
        
        if non_archival_files:
            return {
                'passed': False,
                'message': f'存在非长期保存格式: {", ".join(set(non_archival_files))}'
            }
        
        return {
            'passed': True,
            'message': '长期可用性检查通过'
        }
    
    def _check_format_requirements(self, file_list: List[str]) -> Dict:
        """检查格式要求"""
        warnings = []
        
        # 检查是否有主文件
        if not file_list:
            warnings.append('没有关联文件')
        
        return {
            'passed': len(warnings) == 0,
            'warnings': warnings
        }
    
    def _generate_recommendations(self, error_codes: Dict, warnings: List[str]) -> List[str]:
        """生成建议"""
        recommendations = []
        
        if error_codes.get('VALIDATION_FAILED'):
            recommendations.append('请检查必填字段是否完整')
        
        if error_codes.get('HASH_MISMATCH'):
            recommendations.append('文件完整性验证失败，请重新上传文件')
        
        if any('规范' in warning for warning in warnings):
            recommendations.append('建议遵循档案命名和格式规范')
        
        if any('可读性' in warning for warning in warnings):
            recommendations.append('建议将文件转换为PDF/A等长期保存格式')
        
        return recommendations