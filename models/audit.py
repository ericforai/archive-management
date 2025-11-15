"""
审计和完整性模型 - 实现审计追溯系统、不可篡改存证系统
基于DA/T 94-2022标准的审计和四性检测要求
"""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from models import db

class AuditLog(db.Model):
    """审计日志模型 - 审计追溯系统"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(datetime.utcnow().timestamp()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    operation_type = db.Column(db.Enum('create', 'view', 'download', 'print', 'modify', 'delete', 
                                     'transfer', 'dispose', 'login', 'logout', name='operation_type'), 
                              nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)  # archive, file, metadata, user等
    resource_id = db.Column(db.String(36), nullable=False)
    operation_details = db.Column(db.JSON)  # JSON格式
    ip_address = db.Column(db.String(45))  # 支持IPv6
    user_agent = db.Column(db.Text)
    session_id = db.Column(db.String(100))
    result = db.Column(db.String(20), default='success')  # success, failure, warning
    error_message = db.Column(db.Text)
    risk_level = db.Column(db.Integer, default=1)  # 风险等级 1-低 2-中 3-高 4-严重
    is_suspicious = db.Column(db.Boolean, default=False)  # 是否可疑操作
    alert_triggered = db.Column(db.Boolean, default=False)  # 是否触发告警
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 关系
    user = db.relationship('User', backref='audit_logs')
    
    def __repr__(self):
        return f'<AuditLog {self.user_id} {self.operation_type} {self.resource_type}:{self.resource_id}>'
    
    def is_high_risk(self):
        """判断是否为高风险操作"""
        high_risk_operations = ['delete', 'dispose', 'transfer', 'modify']
        return self.operation_type in high_risk_operations or self.risk_level >= 3
    
    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'user_name': self.user.full_name if self.user else None,
            'operation_type': self.operation_type,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'operation_details': self.operation_details,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'session_id': self.session_id,
            'result': self.result,
            'error_message': self.error_message,
            'risk_level': self.risk_level,
            'is_suspicious': self.is_suspicious,
            'alert_triggered': self.alert_triggered,
            'created_at': self.created_at.isoformat(),
            'is_high_risk': self.is_high_risk()
        }

class IntegrityRecord(db.Model):
    """完整性记录模型 - 不可篡改存证系统"""
    __tablename__ = 'integrity_records'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(datetime.utcnow().timestamp()))
    archive_id = db.Column(db.String(36), db.ForeignKey('electronic_archives.id'))
    file_id = db.Column(db.String(36), db.ForeignKey('archive_files.id'))
    operation_type = db.Column(db.String(50), nullable=False)  # created, modified, archived, transferred, migrated
    hash_algorithm = db.Column(db.String(20), default='sha256')
    hash_value = db.Column(db.String(64), nullable=False)
    digital_signature = db.Column(db.Text)  # 数字签名
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    verification_status = db.Column(db.String(20), default='verified')  # verified, failed, pending
    verification_details = db.Column(db.Text)  # 验证详细信息JSON
    verification_frequency = db.Column(db.Integer, default=1)  # 验证次数
    last_verified_at = db.Column(db.DateTime)
    next_verification_due = db.Column(db.DateTime)  # 下次验证时间
    chain_previous = db.Column(db.String(64))  # 链上前一个哈希值
    chain_height = db.Column(db.Integer, default=1)  # 链上高度
    
    # 四性检测结果
    authenticity_check = db.Column(db.Boolean, default=True)  # 真实性
    integrity_check = db.Column(db.Boolean, default=True)  # 完整性
    availability_check = db.Column(db.Boolean, default=True)  # 可用性
    security_check = db.Column(db.Boolean, default=True)  # 安全性
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 关系
    archive = db.relationship('ElectronicArchive')
    file = db.relationship('ArchiveFile')
    
    def __repr__(self):
        return f'<IntegrityRecord {self.operation_type} {self.hash_value[:16]}>'
    
    def verify_integrity(self):
        """验证完整性"""
        try:
            # 这里实现实际的验证逻辑
            import hashlib
            
            # 计算当前哈希值（简化示例）
            current_hash = hashlib.sha256(f"{self.archive_id}{self.file_id}{self.operation_type}".encode()).hexdigest()
            
            # 验证哈希值
            if current_hash == self.hash_value:
                self.verification_status = 'verified'
            else:
                self.verification_status = 'failed'
            
            self.verification_frequency += 1
            self.last_verified_at = datetime.utcnow()
            
            return self.verification_status == 'verified'
            
        except Exception as e:
            self.verification_status = 'failed'
            self.verification_details = f"验证失败: {str(e)}"
            return False
    
    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'archive_id': self.archive_id,
            'file_id': self.file_id,
            'operation_type': self.operation_type,
            'hash_algorithm': self.hash_algorithm,
            'hash_value': self.hash_value,
            'digital_signature': self.digital_signature,
            'timestamp': self.timestamp.isoformat(),
            'verification_status': self.verification_status,
            'verification_details': self.verification_details,
            'verification_frequency': self.verification_frequency,
            'last_verified_at': self.last_verified_at.isoformat() if self.last_verified_at else None,
            'next_verification_due': self.next_verification_due.isoformat() if self.next_verification_due else None,
            'chain_previous': self.chain_previous,
            'chain_height': self.chain_height,
            'authenticity_check': self.authenticity_check,
            'integrity_check': self.integrity_check,
            'availability_check': self.availability_check,
            'security_check': self.security_check,
            'created_at': self.created_at.isoformat()
        }

class LifecycleRecord(db.Model):
    """生命周期记录模型 - 生命周期管理系统"""
    __tablename__ = 'lifecycle_records'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(datetime.utcnow().timestamp()))
    archive_id = db.Column(db.String(36), db.ForeignKey('electronic_archives.id'), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)  # created, archived, transferred, disposed, migrated
    event_date = db.Column(db.Date, nullable=False)
    description = db.Column(db.Text)
    operator_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    event_metadata = db.Column(db.Text)  # JSON格式，事件相关的元数据
    
    # 审批相关
    approval_required = db.Column(db.Boolean, default=False)
    approval_status = db.Column(db.String(20))  # pending, approved, rejected
    approved_by = db.Column(db.String(36), db.ForeignKey('users.id'))
    approved_at = db.Column(db.DateTime)
    approval_comments = db.Column(db.Text)
    
    # 自动化相关
    is_automated = db.Column(db.Boolean, default=False)
    automation_rule = db.Column(db.String(100))  # 触发规则名称
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 关系
    archive = db.relationship('ElectronicArchive')
    operator = db.relationship('User', foreign_keys=[operator_id], backref='lifecycle_operations')
    approver = db.relationship('User', foreign_keys=[approved_by])
    
    def __repr__(self):
        return f'<LifecycleRecord {self.archive_id} {self.event_type}>'
    
    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'archive_id': self.archive_id,
            'event_type': self.event_type,
            'event_date': self.event_date.isoformat(),
            'description': self.description,
            'operator_id': self.operator_id,
            'operator_name': self.operator.full_name if self.operator else None,
            'metadata': self.event_metadata,
            'approval_required': self.approval_required,
            'approval_status': self.approval_status,
            'approved_by': self.approved_by,
            'approved_at': self.approved_at.isoformat() if self.approved_at else None,
            'approval_comments': self.approval_comments,
            'is_automated': self.is_automated,
            'automation_rule': self.automation_rule,
            'created_at': self.created_at.isoformat()
        }

class StorageMedia(db.Model):
    """存储介质模型 - 存储管理"""
    __tablename__ = 'storage_media'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(datetime.utcnow().timestamp()))
    name = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # disk, tape, cloud, network等
    location = db.Column(db.String(200))
    capacity = db.Column(db.BigInteger, nullable=False)  # 总容量（字节）
    used_space = db.Column(db.BigInteger, default=0)  # 已使用空间
    available_space = db.Column(db.BigInteger, default=0)  # 可用空间
    status = db.Column(db.String(20), default='active')  # active, inactive, damaged, deprecated
    health_status = db.Column(db.String(20), default='good')  # good, warning, error, critical
    last_check_date = db.Column(db.Date)
    next_check_date = db.Column(db.Date)
    check_frequency_days = db.Column(db.Integer, default=30)  # 检查频率（天）
    description = db.Column(db.Text)
    
    # 监控阈值
    warning_threshold = db.Column(db.Float, default=0.8)  # 告警阈值（80%）
    critical_threshold = db.Column(db.Float, default=0.9)  # 严重告警阈值（90%）
    
    # 备份配置
    is_backup_target = db.Column(db.Boolean, default=False)  # 是否为备份目标
    backup_frequency = db.Column(db.String(20), default='daily')  # daily, weekly, monthly
    backup_retention_days = db.Column(db.Integer, default=30)
    
    # 性能指标
    read_speed_mbps = db.Column(db.Float)  # 读取速度MB/s
    write_speed_mbps = db.Column(db.Float)  # 写入速度MB/s
    response_time_ms = db.Column(db.Float)  # 响应时间毫秒
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<StorageMedia {self.name} ({self.type})>'
    
    def get_usage_percentage(self):
        """获取使用率百分比"""
        if self.capacity == 0:
            return 0
        return (self.used_space / self.capacity) * 100
    
    def needs_attention(self):
        """判断是否需要关注"""
        usage_percentage = self.get_usage_percentage()
        return usage_percentage >= (self.warning_threshold * 100)
    
    def is_critical(self):
        """判断是否严重"""
        usage_percentage = self.get_usage_percentage()
        return usage_percentage >= (self.critical_threshold * 100)
    
    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'name': self.name,
            'type': self.type,
            'location': self.location,
            'capacity': self.capacity,
            'used_space': self.used_space,
            'available_space': self.available_space,
            'status': self.status,
            'health_status': self.health_status,
            'last_check_date': self.last_check_date.isoformat() if self.last_check_date else None,
            'next_check_date': self.next_check_date.isoformat() if self.next_check_date else None,
            'check_frequency_days': self.check_frequency_days,
            'description': self.description,
            'warning_threshold': self.warning_threshold,
            'critical_threshold': self.critical_threshold,
            'is_backup_target': self.is_backup_target,
            'backup_frequency': self.backup_frequency,
            'backup_retention_days': self.backup_retention_days,
            'read_speed_mbps': self.read_speed_mbps,
            'write_speed_mbps': self.write_speed_mbps,
            'response_time_ms': self.response_time_ms,
            'usage_percentage': self.get_usage_percentage(),
            'needs_attention': self.needs_attention(),
            'is_critical': self.is_critical(),
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }