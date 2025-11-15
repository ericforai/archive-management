"""
用户模型 - 实现权限与访问控制（RBAC）模块
基于DA/T 94-2022标准的用户管理和权限控制
"""
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from models import db

class User(db.Model):
    """用户模型 - 支持三员分立安全管理"""
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(datetime.utcnow().timestamp()))
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.Enum('admin', 'archivist', 'accountant', 'auditor', 'user', name='user_role'), 
                     nullable=False, default='user')
    department = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)  # 登录失败次数
    lockout_until = db.Column(db.DateTime)  # 账户锁定时间
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 用户扩展信息
    phone = db.Column(db.String(20))
    employee_id = db.Column(db.String(50), unique=True)
    position = db.Column(db.String(100))
    manager_id = db.Column(db.String(36), db.ForeignKey('users.id'))
    ip_whitelist = db.Column(db.Text)  # IP白名单，用逗号分隔
    mac_address = db.Column(db.String(17))  # MAC地址绑定
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)  # 密码更改时间
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def set_password(self, password):
        """设置密码哈希"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        """验证密码"""
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        """是否为管理员"""
        return self.role == 'admin'
    
    def is_auditor(self):
        """是否为审计员"""
        return self.role == 'auditor'
    
    def is_archivist(self):
        """是否为档案员"""
        return self.role == 'archivist'
    
    def can_access(self, resource_type, resource_id=None):
        """检查用户是否有权限访问指定资源"""
        # 管理员和审计员可以访问所有资源
        if self.role in ['admin', 'auditor']:
            return True
            
        # 检查具体权限
        permission = Permission.query.filter_by(
            user_id=self.id,
            resource_type=resource_type,
            resource_id=resource_id
        ).first()
        
        return permission is not None and permission.is_active
    
    def has_permission(self, operation, resource_type, resource_id=None):
        """检查用户是否有指定操作权限"""
        # 管理员和审计员拥有所有权限
        if self.role in ['admin', 'auditor']:
            return True
        
        # 检查具体权限
        permission = Permission.query.filter_by(
            user_id=self.id,
            resource_type=resource_type,
            resource_id=resource_id,
            operation=operation
        ).first()
        
        if not permission:
            return False
        
        # 检查权限是否过期
        if permission.expires_at and permission.expires_at < datetime.utcnow():
            return False
        
        return permission.is_active
    
    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'role': self.role,
            'department': self.department,
            'is_active': self.is_active,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat(),
            'phone': self.phone,
            'employee_id': self.employee_id,
            'position': self.position
        }

class Organization(db.Model):
    """组织机构模型"""
    __tablename__ = 'organizations'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(datetime.utcnow().timestamp()))
    name = db.Column(db.String(200), nullable=False)
    code = db.Column(db.String(50), unique=True, nullable=False, index=True)
    parent_id = db.Column(db.String(36), db.ForeignKey('organizations.id'))
    level = db.Column(db.Integer, default=1)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 自引用关系
    parent = db.relationship('Organization', remote_side=[id], backref='children')
    
    def __repr__(self):
        return f'<Organization {self.name}>'
    
    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'name': self.name,
            'code': self.code,
            'parent_id': self.parent_id,
            'level': self.level,
            'description': self.description,
            'created_at': self.created_at.isoformat()
        }

class Permission(db.Model):
    """权限模型"""
    __tablename__ = 'permissions'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(datetime.utcnow().timestamp()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)  # archive, category, file等
    resource_id = db.Column(db.String(36))  # 具体的资源ID，NULL表示对所有此类资源
    operation = db.Column(db.String(20), nullable=False)  # read, write, delete, admin
    granted_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # 关系
    user = db.relationship('User', foreign_keys=[user_id], backref='permissions')
    grantor = db.relationship('User', foreign_keys=[granted_by])
    
    def __repr__(self):
        return f'<Permission {self.user_id} {self.resource_type}:{self.operation}>'
    
    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'operation': self.operation,
            'granted_by': self.granted_by,
            'granted_at': self.granted_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_active': self.is_active
        }

class LoginLog(db.Model):
    """登录日志模型"""
    __tablename__ = 'login_logs'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(datetime.utcnow().timestamp()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))
    username = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(45))  # 支持IPv6
    user_agent = db.Column(db.Text)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    logout_time = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='success')  # success, failure, locked
    failure_reason = db.Column(db.String(100))
    
    def __repr__(self):
        return f'<LoginLog {self.username} {self.status}>'