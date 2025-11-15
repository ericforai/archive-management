"""
元数据管理中心服务 - 元数据管理、标准化、扩展
基于DA/T 94-2022标准的元数据管理模块
"""
import json
import re
import logging
from datetime import datetime
from flask import current_app
from sqlalchemy import func, or_, and_

from models.archive import ElectronicArchive, ArchiveMetadata, ArchiveCategory
from models.audit import AuditLog
from models import db
from utils.audit_logger import AuditLogger

logger = logging.getLogger(__name__)

class MetadataService:
    """元数据管理中心服务"""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
        
        # 标准元数据定义（基于DA/T 94-2022）
        self.standard_metadata = {
            'title': {
                'type': 'text',
                'required': True,
                'description': '档案标题',
                'validation': lambda x: len(x.strip()) > 0
            },
            'description': {
                'type': 'text',
                'required': False,
                'description': '档案描述',
                'validation': lambda x: len(x.strip()) <= 1000
            },
            'keywords': {
                'type': 'text',
                'required': False,
                'description': '关键词',
                'validation': lambda x: len(x.strip()) <= 500
            },
            'created_date': {
                'type': 'date',
                'required': True,
                'description': '创建日期',
                'validation': lambda x: self._validate_date(x)
            },
            'author': {
                'type': 'text',
                'required': False,
                'description': '作者',
                'validation': lambda x: len(x.strip()) <= 100
            },
            'organization': {
                'type': 'text',
                'required': False,
                'description': '机构名称',
                'validation': lambda x: len(x.strip()) <= 200
            },
            'department': {
                'type': 'text',
                'required': False,
                'description': '部门名称',
                'validation': lambda x: len(x.strip()) <= 100
            },
            'document_type': {
                'type': 'text',
                'required': True,
                'description': '文档类型',
                'validation': lambda x: x in ['记账凭证', '账簿', '财务报表', '合同', '发票', '其他']
            },
            'document_number': {
                'type': 'text',
                'required': False,
                'description': '文档编号',
                'validation': lambda x: len(x.strip()) <= 50
            },
            'amount': {
                'type': 'number',
                'required': False,
                'description': '金额',
                'validation': lambda x: float(x) >= 0
            },
            'currency': {
                'type': 'text',
                'required': False,
                'description': '币种',
                'validation': lambda x: x in ['CNY', 'USD', 'EUR', 'GBP', 'JPY']
            },
            'accounting_period': {
                'type': 'text',
                'required': False,
                'description': '会计期间',
                'validation': lambda x: self._validate_accounting_period(x)
            },
            'account_code': {
                'type': 'text',
                'required': False,
                'description': '会计科目代码',
                'validation': lambda x: self._validate_account_code(x)
            },
            'account_name': {
                'type': 'text',
                'required': False,
                'description': '会计科目名称',
                'validation': lambda x: len(x.strip()) <= 100
            },
            'contract_party_a': {
                'type': 'text',
                'required': False,
                'description': '合同甲方',
                'validation': lambda x: len(x.strip()) <= 200
            },
            'contract_party_b': {
                'type': 'text',
                'required': False,
                'description': '合同乙方',
                'validation': lambda x: len(x.strip()) <= 200
            },
            'contract_amount': {
                'type': 'number',
                'required': False,
                'description': '合同金额',
                'validation': lambda x: float(x) >= 0
            },
            'invoice_number': {
                'type': 'text',
                'required': False,
                'description': '发票号码',
                'validation': lambda x: self._validate_invoice_number(x)
            },
            'invoice_date': {
                'type': 'date',
                'required': False,
                'description': '发票日期',
                'validation': lambda x: self._validate_date(x)
            },
            'tax_amount': {
                'type': 'number',
                'required': False,
                'description': '税额',
                'validation': lambda x: float(x) >= 0
            },
            'vat_rate': {
                'type': 'number',
                'required': False,
                'description': '增值税率',
                'validation': lambda x: x in ['0', '3', '6', '9', '13']
            }
        }
    
    def validate_metadata(self, metadata_dict, category_code=None):
        """
        验证元数据
        
        Args:
            metadata_dict: 元数据字典
            category_code: 分类代码（可选，用于分类特定的验证）
            
        Returns:
            dict: 验证结果
        """
        errors = []
        warnings = []
        
        # 检查必需字段
        for field_name, field_config in self.standard_metadata.items():
            if field_config['required'] and field_name not in metadata_dict:
                errors.append(f'缺少必需字段: {field_name}')
            
            # 验证字段值
            if field_name in metadata_dict:
                value = metadata_dict[field_name]
                if not self._validate_field_value(field_name, value, field_config):
                    errors.append(f'字段 {field_name} 的值无效')
        
        # 分类特定的验证
        if category_code:
            category_errors = self._validate_category_specific_metadata(metadata_dict, category_code)
            errors.extend(category_errors)
        
        # 检查自定义元数据
        for key, value in metadata_dict.items():
            if key not in self.standard_metadata:
                if not self._validate_custom_metadata(key, value):
                    warnings.append(f'自定义元数据 {key} 可能不符合标准')
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings
        }
    
    def create_metadata(self, archive_id, metadata_dict, user_id):
        """
        创建元数据
        
        Args:
            archive_id: 档案ID
            metadata_dict: 元数据字典
            user_id: 用户ID
            
        Returns:
            dict: 创建结果
        """
        try:
            # 验证元数据
            archive = ElectronicArchive.query.get(archive_id)
            if not archive:
                return {
                    'success': False,
                    'error': '档案不存在',
                    'error_code': 'ARCHIVE_NOT_FOUND'
                }
            
            category_code = archive.category.code if archive.category else None
            validation_result = self.validate_metadata(metadata_dict, category_code)
            
            if not validation_result['valid']:
                return {
                    'success': False,
                    'error': '元数据验证失败',
                    'error_code': 'VALIDATION_FAILED',
                    'details': validation_result['errors']
                }
            
            created_metadata = []
            
            for key, value in metadata_dict.items():
                metadata_type = self._determine_metadata_type(value)
                
                # 标准化处理
                normalized_value = self._normalize_metadata_value(key, value, metadata_type)
                
                metadata = ArchiveMetadata(
                    archive_id=archive_id,
                    metadata_key=key,
                    metadata_value=normalized_value,
                    metadata_type=metadata_type,
                    is_indexed=self._should_index_field(key),
                    created_by=user_id,
                    created_at=datetime.utcnow()
                )
                
                db.session.add(metadata)
                created_metadata.append(metadata)
            
            db.session.commit()
            
            # 记录审计日志
            self.audit_logger.log_operation(
                user_id=user_id,
                operation_type='create',
                resource_type='metadata',
                resource_id=archive_id,
                operation_details={
                    'metadata_count': len(created_metadata),
                    'metadata_keys': list(metadata_dict.keys())
                }
            )
            
            return {
                'success': True,
                'message': '元数据创建成功',
                'metadata_count': len(created_metadata),
                'metadata_keys': list(metadata_dict.keys())
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"创建元数据失败: {str(e)}")
            return {
                'success': False,
                'error': f'创建元数据失败: {str(e)}',
                'error_code': 'METADATA_CREATION_ERROR'
            }
    
    def update_metadata(self, archive_id, metadata_dict, user_id):
        """
        更新元数据
        
        Args:
            archive_id: 档案ID
            metadata_dict: 更新的元数据字典
            user_id: 用户ID
            
        Returns:
            dict: 更新结果
        """
        try:
            # 获取现有元数据
            existing_metadata = ArchiveMetadata.query.filter_by(archive_id=archive_id).all()
            existing_keys = {meta.metadata_key: meta for meta in existing_metadata}
            
            updated_keys = []
            created_keys = []
            
            for key, value in metadata_dict.items():
                if key in existing_keys:
                    # 更新现有元数据
                    metadata = existing_keys[key]
                    old_value = metadata.metadata_value
                    
                    # 标准化处理
                    metadata_type = self._determine_metadata_type(value)
                    normalized_value = self._normalize_metadata_value(key, value, metadata_type)
                    
                    metadata.metadata_value = normalized_value
                    metadata.metadata_type = metadata_type
                    metadata.updated_by = user_id
                    metadata.updated_at = datetime.utcnow()
                    
                    updated_keys.append({
                        'key': key,
                        'old_value': old_value,
                        'new_value': normalized_value
                    })
                else:
                    # 创建新元数据
                    metadata_type = self._determine_metadata_type(value)
                    normalized_value = self._normalize_metadata_value(key, value, metadata_type)
                    
                    new_metadata = ArchiveMetadata(
                        archive_id=archive_id,
                        metadata_key=key,
                        metadata_value=normalized_value,
                        metadata_type=metadata_type,
                        is_indexed=self._should_index_field(key),
                        created_by=user_id,
                        created_at=datetime.utcnow()
                    )
                    
                    db.session.add(new_metadata)
                    created_keys.append(key)
            
            db.session.commit()
            
            # 记录审计日志
            self.audit_logger.log_operation(
                user_id=user_id,
                operation_type='update',
                resource_type='metadata',
                resource_id=archive_id,
                operation_details={
                    'updated_keys': updated_keys,
                    'created_keys': created_keys
                }
            )
            
            return {
                'success': True,
                'message': '元数据更新成功',
                'updated_keys': [k['key'] for k in updated_keys],
                'created_keys': created_keys
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"更新元数据失败: {str(e)}")
            return {
                'success': False,
                'error': f'更新元数据失败: {str(e)}',
                'error_code': 'METADATA_UPDATE_ERROR'
            }
    
    def get_metadata(self, archive_id, include_standard=True, include_custom=True):
        """
        获取档案元数据
        
        Args:
            archive_id: 档案ID
            include_standard: 是否包含标准元数据
            include_custom: 是否包含自定义元数据
            
        Returns:
            dict: 元数据
        """
        try:
            metadata_list = ArchiveMetadata.query.filter_by(archive_id=archive_id).all()
            
            standard_metadata = {}
            custom_metadata = {}
            
            for metadata in metadata_list:
                key = metadata.metadata_key
                value = metadata.metadata_value
                
                if key in self.standard_metadata:
                    standard_metadata[key] = {
                        'value': value,
                        'type': metadata.metadata_type,
                        'is_indexed': metadata.is_indexed,
                        'created_at': metadata.created_at.isoformat() if metadata.created_at else None,
                        'updated_at': metadata.updated_at.isoformat() if metadata.updated_at else None
                    }
                else:
                    custom_metadata[key] = {
                        'value': value,
                        'type': metadata.metadata_type,
                        'is_indexed': metadata.is_indexed,
                        'created_at': metadata.created_at.isoformat() if metadata.created_at else None,
                        'updated_at': metadata.updated_at.isoformat() if metadata.updated_at else None
                    }
            
            result = {}
            if include_standard:
                result['standard'] = standard_metadata
            if include_custom:
                result['custom'] = custom_metadata
            
            return {
                'success': True,
                'data': result,
                'total_count': len(metadata_list)
            }
            
        except Exception as e:
            logger.error(f"获取元数据失败: {str(e)}")
            return {
                'success': False,
                'error': f'获取元数据失败: {str(e)}',
                'error_code': 'METADATA_FETCH_ERROR'
            }
    
    def search_by_metadata(self, search_criteria, page=1, per_page=20):
        """
        基于元数据搜索档案
        
        Args:
            search_criteria: 搜索条件字典
            page: 页码
            per_page: 每页数量
            
        Returns:
            dict: 搜索结果
        """
        try:
            # 构建查询
            query = db.session.query(ElectronicArchive).join(ArchiveMetadata)
            
            # 应用搜索条件
            for key, value in search_criteria.items():
                if key == 'date_range':
                    # 日期范围搜索
                    query = query.filter(
                        ArchiveMetadata.metadata_key == 'created_date',
                        ArchiveMetadata.metadata_value >= value['start_date'],
                        ArchiveMetadata.metadata_value <= value['end_date']
                    )
                elif key == 'amount_range':
                    # 金额范围搜索
                    query = query.filter(
                        ArchiveMetadata.metadata_key == 'amount',
                        ArchiveMetadata.metadata_value >= value['min_amount'],
                        ArchiveMetadata.metadata_value <= value['max_amount']
                    )
                else:
                    # 精确匹配或模糊搜索
                    if isinstance(value, str) and value.startswith('*') and value.endswith('*'):
                        # 模糊搜索
                        search_value = value[1:-1]
                        query = query.filter(
                            ArchiveMetadata.metadata_key == key,
                            ArchiveMetadata.metadata_value.ilike(f'%{search_value}%')
                        )
                    else:
                        # 精确匹配
                        query = query.filter(
                            ArchiveMetadata.metadata_key == key,
                            ArchiveMetadata.metadata_value == str(value)
                        )
            
            # 去重并分页
            query = query.distinct()
            total_count = query.count()
            
            archives = query.offset((page - 1) * per_page).limit(per_page).all()
            
            # 格式化结果
            results = []
            for archive in archives:
                results.append({
                    'id': archive.id,
                    'archive_no': archive.archive_no,
                    'title': archive.title,
                    'category': archive.category.name if archive.category else None,
                    'created_date': archive.created_date.isoformat() if archive.created_date else None,
                    'created_at': archive.created_at.isoformat() if archive.created_at else None
                })
            
            return {
                'success': True,
                'data': results,
                'total_count': total_count,
                'page': page,
                'per_page': per_page,
                'total_pages': (total_count + per_page - 1) // per_page
            }
            
        except Exception as e:
            logger.error(f"元数据搜索失败: {str(e)}")
            return {
                'success': False,
                'error': f'搜索失败: {str(e)}',
                'error_code': 'METADATA_SEARCH_ERROR'
            }
    
    def _validate_field_value(self, field_name, value, field_config):
        """
        验证字段值
        """
        try:
            if field_config.get('validation'):
                return field_config['validation'](value)
            return True
        except Exception:
            return False
    
    def _validate_category_specific_metadata(self, metadata_dict, category_code):
        """
        验证分类特定的元数据要求
        """
        errors = []
        
        category_specific_requirements = {
            'invoice': ['invoice_number', 'invoice_date', 'tax_amount'],
            'contract': ['contract_party_a', 'contract_party_b', 'contract_amount'],
            'report': ['accounting_period', 'author'],
            'voucher': ['account_code', 'account_name', 'amount']
        }
        
        if category_code in category_specific_requirements:
            required_fields = category_specific_requirements[category_code]
            for field in required_fields:
                if field not in metadata_dict:
                    errors.append(f'{category_code}分类需要字段: {field}')
        
        return errors
    
    def _validate_custom_metadata(self, key, value):
        """
        验证自定义元数据
        """
        # 检查键名格式
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', key):
            return False
        
        # 检查值长度
        if isinstance(value, str) and len(value) > 1000:
            return False
        
        return True
    
    def _determine_metadata_type(self, value):
        """
        确定元数据类型
        """
        if isinstance(value, bool):
            return 'boolean'
        elif isinstance(value, (int, float)):
            return 'number'
        elif isinstance(value, datetime):
            return 'date'
        else:
            return 'text'
    
    def _normalize_metadata_value(self, key, value, metadata_type):
        """
        标准化元数据值
        """
        if metadata_type == 'date' and isinstance(value, str):
            # 日期标准化
            try:
                if len(value) == 10:  # YYYY-MM-DD
                    return value
                elif len(value) == 19:  # YYYY-MM-DD HH:MM:SS
                    return value[:10]
                else:
                    return value
            except Exception:
                return value
        elif metadata_type == 'number':
            # 数字标准化
            try:
                return str(float(value))
            except (ValueError, TypeError):
                return str(value)
        else:
            return str(value).strip()
    
    def _should_index_field(self, field_name):
        """
        判断字段是否应该建立索引
        """
        indexed_fields = [
            'title', 'created_date', 'author', 'organization', 'document_type',
            'document_number', 'amount', 'accounting_period', 'invoice_number'
        ]
        return field_name in indexed_fields
    
    def _validate_date(self, date_str):
        """
        验证日期格式
        """
        try:
            datetime.strptime(date_str, '%Y-%m-%d')
            return True
        except ValueError:
            return False
    
    def _validate_accounting_period(self, period_str):
        """
        验证会计期间格式
        """
        # 支持格式: YYYY-MM, YYYY-Q1, YYYY
        patterns = [
            r'^\d{4}-\d{2}$',      # YYYY-MM
            r'^\d{4}-Q[1-4]$',     # YYYY-Q1
            r'^\d{4}$'              # YYYY
        ]
        
        for pattern in patterns:
            if re.match(pattern, period_str):
                return True
        return False
    
    def _validate_account_code(self, code_str):
        """
        验证会计科目代码格式
        """
        # 支持格式: 数字和点，如 1001, 1001.01
        return re.match(r'^\d+(\.\d+)*$', code_str) is not None
    
    def _validate_invoice_number(self, invoice_str):
        """
        验证发票号码格式
        """
        # 支持格式: 数字和字母，长度6-20
        return re.match(r'^[A-Z0-9]{6,20}$', invoice_str) is not None