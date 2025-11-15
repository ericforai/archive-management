"""
电子档案模型 - 实现电子档案采集中心、归类引擎等模块
基于DA/T 94-2022标准的电子档案管理
"""
from datetime import datetime, date
from flask_sqlalchemy import SQLAlchemy
from models import db

class ArchiveCategory(db.Model):
    """档案分类模型 - 支持凭证/合同/发票自动归类"""
    __tablename__ = 'archive_categories'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(datetime.utcnow().timestamp()))
    code = db.Column(db.String(50), unique=True, nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    parent_id = db.Column(db.String(36), db.ForeignKey('archive_categories.id'))
    level = db.Column(db.Integer, default=1)
    retention_period = db.Column(db.Enum('permanent', '30_years', '10_years', '5_years', '3_years', 
                                       name='retention_period'), nullable=False)
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    ai_classification_rules = db.Column(db.Text)  # AI分类规则JSON
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 自引用关系
    parent = db.relationship('ArchiveCategory', remote_side=[id], backref='children')
    
    def __repr__(self):
        return f'<ArchiveCategory {self.code} {self.name}>'
    
    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'code': self.code,
            'name': self.name,
            'parent_id': self.parent_id,
            'level': self.level,
            'retention_period': self.retention_period,
            'description': self.description,
            'is_active': self.is_active,
            'ai_classification_rules': self.ai_classification_rules,
            'created_at': self.created_at.isoformat()
        }

class ElectronicArchive(db.Model):
    """电子档案主表 - 核心档案管理"""
    __tablename__ = 'electronic_archives'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(datetime.utcnow().timestamp()))
    archive_no = db.Column(db.String(100), unique=True, nullable=False, index=True)  # 档号
    title = db.Column(db.String(500), nullable=False, index=True)  # 题名
    category_id = db.Column(db.String(36), db.ForeignKey('archive_categories.id'), nullable=False)
    organization_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=False)
    created_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    file_count = db.Column(db.Integer, default=0)
    total_size = db.Column(db.BigInteger, default=0)  # 字节
    retention_period = db.Column(db.Enum('permanent', '30_years', '10_years', '5_years', '3_years', 
                                       name='retention_period'), nullable=False)
    status = db.Column(db.Enum('draft', 'archived', 'disposed', 'transferred', name='archive_status'), 
                      default='draft')
    created_date = db.Column(db.Date, nullable=False)
    archive_date = db.Column(db.Date)  # 归档日期
    disposal_date = db.Column(db.Date)  # 处置日期
    description = db.Column(db.Text)
    keywords = db.Column(db.Text)  # 关键词，用逗号分隔
    confidentiality_level = db.Column(db.Integer, default=1)  # 密级 1-公开 2-内部 3-秘密 4-机密 5-绝密
    
    # OCR和AI处理结果
    ai_extracted_text = db.Column(db.Text)  # AI提取的文本
    ai_tags = db.Column(db.Text)  # AI标签，逗号分隔
    ocr_confidence = db.Column(db.Float)  # OCR置信度
    
    # 版本控制
    version = db.Column(db.Integer, default=1)
    parent_archive_id = db.Column(db.String(36), db.ForeignKey('electronic_archives.id'))
    is_latest_version = db.Column(db.Boolean, default=True)
    
    # 完整性校验
    integrity_hash = db.Column(db.String(64))  # SHA256哈希值
    digital_signature = db.Column(db.Text)  # 数字签名
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 关系
    category = db.relationship('ArchiveCategory')
    organization = db.relationship('Organization')
    creator = db.relationship('User', foreign_keys=[created_by])
    files = db.relationship('ArchiveFile', backref='archive', cascade='all, delete-orphan')
    metadata_list = db.relationship('ArchiveMetadata', backref='archive', cascade='all, delete-orphan')
    lifecycle_records = db.relationship('LifecycleRecord', overlaps="archive")
    integrity_records = db.relationship('IntegrityRecord', back_populates='archive', overlaps="archive")
    
    # 自引用关系（版本控制）
    parent_archive = db.relationship('ElectronicArchive', remote_side=[id], backref='versions')
    
    def __repr__(self):
        return f'<ElectronicArchive {self.archive_no} {self.title}>'
    
    def get_retention_end_date(self):
        """获取保管期限结束日期"""
        if self.retention_period == 'permanent':
            return None
        elif self.retention_period == '30_years':
            return date(self.created_date.year + 30, self.created_date.month, self.created_date.day)
        elif self.retention_period == '10_years':
            return date(self.created_date.year + 10, self.created_date.month, self.created_date.day)
        elif self.retention_period == '5_years':
            return date(self.created_date.year + 5, self.created_date.month, self.created_date.day)
        elif self.retention_period == '3_years':
            return date(self.created_date.year + 3, self.created_date.month, self.created_date.day)
        return None
    
    def is_expired(self):
        """检查是否已过期"""
        end_date = self.get_retention_end_date()
        if not end_date:
            return False  # 永久保管
        return date.today() > end_date
    
    def needs_disposal_review(self):
        """检查是否需要处置审核"""
        return self.status == 'archived' and self.is_expired()
    
    def to_dict(self, include_files=False, include_metadata=False):
        """转换为字典"""
        data = {
            'id': self.id,
            'archive_no': self.archive_no,
            'title': self.title,
            'category_id': self.category_id,
            'category_name': self.category.name if self.category else None,
            'organization_id': self.organization_id,
            'organization_name': self.organization.name if self.organization else None,
            'created_by': self.created_by,
            'creator_name': self.creator.full_name if self.creator else None,
            'file_count': self.file_count,
            'total_size': self.total_size,
            'retention_period': self.retention_period,
            'status': self.status,
            'created_date': self.created_date.isoformat(),
            'archive_date': self.archive_date.isoformat() if self.archive_date else None,
            'disposal_date': self.disposal_date.isoformat() if self.disposal_date else None,
            'description': self.description,
            'keywords': self.keywords.split(',') if self.keywords else [],
            'confidentiality_level': self.confidentiality_level,
            'ai_extracted_text': self.ai_extracted_text,
            'ai_tags': self.ai_tags.split(',') if self.ai_tags else [],
            'ocr_confidence': self.ocr_confidence,
            'version': self.version,
            'parent_archive_id': self.parent_archive_id,
            'is_latest_version': self.is_latest_version,
            'integrity_hash': self.integrity_hash,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'retention_end_date': self.get_retention_end_date().isoformat() if self.get_retention_end_date() else None,
            'is_expired': self.is_expired(),
            'needs_disposal_review': self.needs_disposal_review()
        }
        
        if include_files:
            data['files'] = [f.to_dict() for f in self.files]
        
        if include_metadata:
            data['metadata'] = {m.metadata_key: m.metadata_value for m in self.metadata_list}
        
        return data

class ArchiveFile(db.Model):
    """档案文件模型 - 支持OCR/自动解析"""
    __tablename__ = 'archive_files'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(datetime.utcnow().timestamp()))
    archive_id = db.Column(db.String(36), db.ForeignKey('electronic_archives.id'), nullable=False)
    file_name = db.Column(db.String(500), nullable=False)
    original_name = db.Column(db.String(500), nullable=False)
    file_path = db.Column(db.String(1000), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)  # pdf, doc, xls, jpg等
    file_size = db.Column(db.BigInteger, nullable=False)
    file_hash = db.Column(db.String(64), nullable=False, index=True)  # SHA256哈希值
    mime_type = db.Column(db.String(100))
    sort_order = db.Column(db.Integer, default=0)
    is_main = db.Column(db.Boolean, default=False)  # 是否为主文件
    
    # OCR处理结果
    ocr_text = db.Column(db.Text)
    ocr_confidence = db.Column(db.Float)
    ocr_processed_at = db.Column(db.DateTime)
    
    # AI分析结果
    ai_content_type = db.Column(db.String(50))  # content_type: 发票, 合同, 凭证等
    ai_confidence = db.Column(db.Float)
    ai_extracted_fields = db.Column(db.Text)  # JSON格式存储AI提取的字段
    ai_processed_at = db.Column(db.DateTime)
    
    # 格式转换
    converted_format = db.Column(db.String(50))  # 转换后的格式，如PDF/A
    original_format = db.Column(db.String(50))  # 原始格式
    conversion_hash = db.Column(db.String(64))  # 转换后文件的哈希值
    
    # 元数据
    file_metadata = db.Column(db.Text)  # JSON格式
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ArchiveFile {self.file_name}>'
    
    def is_convertible_format(self):
        """判断是否为可转换格式"""
        convertible_formats = {'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf'}
        return self.file_type.lower() in convertible_formats
    
    def needs_ocr(self):
        """判断是否需要OCR处理"""
        ocr_needed_formats = {'pdf', 'jpg', 'jpeg', 'png', 'tiff', 'bmp', 'gif'}
        return self.file_type.lower() in ocr_needed_formats
    
    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'archive_id': self.archive_id,
            'file_name': self.file_name,
            'original_name': self.original_name,
            'file_path': self.file_path,
            'file_type': self.file_type,
            'file_size': self.file_size,
            'file_hash': self.file_hash,
            'mime_type': self.mime_type,
            'sort_order': self.sort_order,
            'is_main': self.is_main,
            'ocr_text': self.ocr_text,
            'ocr_confidence': self.ocr_confidence,
            'ocr_processed_at': self.ocr_processed_at.isoformat() if self.ocr_processed_at else None,
            'ai_content_type': self.ai_content_type,
            'ai_confidence': self.ai_confidence,
            'ai_extracted_fields': self.ai_extracted_fields,
            'ai_processed_at': self.ai_processed_at.isoformat() if self.ai_processed_at else None,
            'converted_format': self.converted_format,
            'original_format': self.original_format,
            'conversion_hash': self.conversion_hash,
            'file_metadata': self.file_metadata,
            'created_at': self.created_at.isoformat(),
            'is_convertible_format': self.is_convertible_format(),
            'needs_ocr': self.needs_ocr()
        }

class ArchiveMetadata(db.Model):
    """档案元数据模型 - 元数据管理中心"""
    __tablename__ = 'archive_metadata'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(datetime.utcnow().timestamp()))
    archive_id = db.Column(db.String(36), db.ForeignKey('electronic_archives.id'), nullable=False)
    metadata_key = db.Column(db.String(100), nullable=False)
    metadata_value = db.Column(db.Text)
    metadata_type = db.Column(db.String(50), default='text')  # text, number, date, boolean, json
    is_indexed = db.Column(db.Boolean, default=False)  # 是否建立索引
    is_required = db.Column(db.Boolean, default=False)  # 是否必需
    validation_rules = db.Column(db.Text)  # 验证规则JSON
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<ArchiveMetadata {self.archive_id}:{self.metadata_key}>'
    
    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'archive_id': self.archive_id,
            'metadata_key': self.metadata_key,
            'metadata_value': self.metadata_value,
            'metadata_type': self.metadata_type,
            'is_indexed': self.is_indexed,
            'is_required': self.is_required,
            'validation_rules': self.validation_rules,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }