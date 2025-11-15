"""
安全访问控制服务 - 用户认证、授权、权限管理
基于DA/T 94-2022标准的电子会计档案安全控制模块
"""
import os
import json
import hashlib
import secrets
import jwt
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set
from flask import current_app, request
from werkzeug.security import generate_password_hash, check_password_hash

from models.user import User, Permission
from models.audit import AuditLog
from models import db
from utils.audit_logger import AuditLogger
from utils.token_manager import TokenManager
from utils.session_manager import SessionManager

logger = logging.getLogger(__name__)

class SecurityService:
    """安全访问控制服务"""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
        self.token_manager = TokenManager()
        self.session_manager = SessionManager()
        
        # 安全配置 - 使用默认值，避免应用上下文依赖
        self.jwt_secret = secrets.token_hex(32)
        self.jwt_algorithm = 'HS256'
        self.token_expiry_hours = 24
        self.max_login_attempts = 5
        self.lockout_duration_minutes = 30
        
        # 权限级别
        self.permission_levels = {
            'read': 1,
            'write': 2, 
            'delete': 3,
            'admin': 4,
            'super_admin': 5
        }
        
        # 敏感操作列表
        self.sensitive_operations = [
            'delete_archive',
            'bulk_delete',
            'system_config',
            'user_management',
            'security_settings',
            'audit_delete',
            'database_export',
            'system_backup'
        ]
    
    def authenticate_user(self, username: str, password: str, client_info: Dict = None) -> Dict:
        """
        用户认证
        
        Args:
            username: 用户名
            password: 密码
            client_info: 客户端信息
            
        Returns:
            dict: 认证结果
        """
        try:
            # 获取客户端信息
            client_info = client_info or {}
            ip_address = client_info.get('ip_address', request.remote_addr)
            user_agent = client_info.get('user_agent', request.headers.get('User-Agent', ''))
            
            # 查找用户
            user = User.query.filter_by(username=username, is_active=True).first()
            
            if not user:
                self._log_authentication_attempt(username, 'user_not_found', ip_address, user_agent)
                return {
                    'success': False,
                    'error': '用户名或密码错误',
                    'error_code': 'INVALID_CREDENTIALS'
                }
            
            # 检查账户锁定状态
            if self._is_account_locked(user):
                self._log_authentication_attempt(username, 'account_locked', ip_address, user_agent)
                return {
                    'success': False,
                    'error': '账户已被锁定，请稍后再试',
                    'error_code': 'ACCOUNT_LOCKED'
                }
            
            # 验证密码
            if not check_password_hash(user.password_hash, password):
                # 增加登录失败次数
                self._increment_failed_attempts(user)
                self._log_authentication_attempt(username, 'invalid_password', ip_address, user_agent)
                
                return {
                    'success': False,
                    'error': '用户名或密码错误',
                    'error_code': 'INVALID_CREDENTIALS'
                }
            
            # 验证密码是否需要更新
            if self._is_password_expired(user):
                self._log_authentication_attempt(username, 'password_expired', ip_address, user_agent)
                return {
                    'success': False,
                    'error': '密码已过期，请重置密码',
                    'error_code': 'PASSWORD_EXPIRED',
                    'password_reset_required': True
                }
            
            # 认证成功
            self._reset_failed_attempts(user)
            self._update_last_login(user)
            
            # 创建JWT令牌
            token_data = {
                'user_id': user.id,
                'username': user.username,
                'email': user.email,
                'department': user.department,
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + timedelta(hours=self.token_expiry_hours)
            }
            
            # 添加用户角色信息
            user_roles = self._get_user_roles(user.id)
            token_data['roles'] = user_roles
            token_data['role_ids'] = user_roles  # 使用角色名称作为ID
            
            # 添加用户权限信息
            user_permissions = self._get_user_permissions(user.id)
            token_data['permissions'] = user_permissions
            
            access_token = self.token_manager.generate_token(token_data)
            
            # 创建用户会话
            session_data = {
                'user_id': user.id,
                'username': user.username,
                'roles': token_data['roles'],
                'permissions': token_data['permissions'],
                'login_time': datetime.utcnow().isoformat(),
                'ip_address': ip_address,
                'user_agent': user_agent
            }
            
            session_id = self.session_manager.create_session(user.id, session_data)
            
            # 记录成功认证日志
            self._log_authentication_attempt(username, 'success', ip_address, user_agent, user.id)
            
            return {
                'success': True,
                'access_token': access_token,
                'session_id': session_id,
                'token_type': 'Bearer',
                'expires_in': self.token_expiry_hours * 3600,
                'user_info': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'full_name': user.full_name,
                    'department': user.department,
                    'roles': token_data['roles'],
                    'permissions': token_data['permissions']
                }
            }
            
        except Exception as e:
            logger.error(f"用户认证失败: {str(e)}")
            return {
                'success': False,
                'error': f'认证过程发生错误',
                'error_code': 'AUTHENTICATION_ERROR'
            }
    
    def verify_token(self, token: str) -> Dict:
        """
        验证JWT令牌
        
        Args:
            token: JWT令牌
            
        Returns:
            dict: 验证结果
        """
        try:
            # 验证令牌
            payload = self.token_manager.verify_token(token)
            if not payload:
                return {
                    'valid': False,
                    'error': '无效或已过期的令牌',
                    'error_code': 'INVALID_TOKEN'
                }
            
            # 检查会话是否仍然有效
            user_id = payload.get('user_id')
            session_data = self.session_manager.get_session_data(user_id)
            
            if not session_data:
                return {
                    'valid': False,
                    'error': '会话已失效',
                    'error_code': 'SESSION_EXPIRED'
                }
            
            # 检查用户是否仍然活跃
            user = User.query.get(user_id)
            if not user or not user.is_active:
                return {
                    'valid': False,
                    'error': '用户账户已被禁用',
                    'error_code': 'USER_INACTIVE'
                }
            
            return {
                'valid': True,
                'user_id': user_id,
                'payload': payload,
                'user_info': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'full_name': user.full_name,
                    'department': user.department,
                    'roles': payload.get('roles', []),
                    'permissions': payload.get('permissions', [])
                }
            }
            
        except jwt.ExpiredSignatureError:
            return {
                'valid': False,
                'error': '令牌已过期',
                'error_code': 'TOKEN_EXPIRED'
            }
        except jwt.InvalidTokenError:
            return {
                'valid': False,
                'error': '无效令牌',
                'error_code': 'INVALID_TOKEN'
            }
        except Exception as e:
            logger.error(f"令牌验证失败: {str(e)}")
            return {
                'valid': False,
                'error': '令牌验证失败',
                'error_code': 'TOKEN_VERIFICATION_ERROR'
            }
    
    def check_permission(self, user_id: int, resource: str, action: str, resource_context: Dict = None) -> bool:
        """
        检查用户权限
        
        Args:
            user_id: 用户ID
            resource: 资源名称
            action: 操作名称
            resource_context: 资源上下文
            
        Returns:
            bool: 是否有权限
        """
        try:
            # 获取用户权限
            user_permissions = self._get_user_permissions(user_id)
            
            # 检查具体权限
            permission_name = f"{resource}:{action}"
            
            # 1. 检查具体权限
            if permission_name in user_permissions:
                return True
            
            # 2. 检查通配符权限
            wildcard_permissions = [
                f"{resource}:*",
                f"*:{action}",
                f"*:*"
            ]
            
            for perm in user_permissions:
                if perm in wildcard_permissions:
                    return True
            
            # 3. 检查角色继承权限
            if self._check_role_permissions(user_id, resource, action):
                return True
            
            # 4. 记录权限检查
            self._log_permission_check(user_id, resource, action, False)
            
            return False
            
        except Exception as e:
            logger.error(f"权限检查失败: {str(e)}")
            return False
    
    def check_resource_ownership(self, user_id: int, resource_type: str, resource_id: int, ownership_rules: Dict = None) -> bool:
        """
        检查资源所有权
        
        Args:
            user_id: 用户ID
            resource_type: 资源类型
            resource_id: 资源ID
            ownership_rules: 所有权规则
            
        Returns:
            bool: 是否有所有权
        """
        try:
            ownership_rules = ownership_rules or {}
            
            # 默认所有权规则
            default_rules = {
                'archive': 'created_by',  # 档案的创建者拥有所有权
                'audit_log': 'user_id',   # 审计日志的用户拥有访问权
                'user': 'id',             # 用户只能访问自己的信息
                'system_config': None     # 系统配置需要特殊权限
            }
            
            ownership_field = ownership_rules.get(resource_type, default_rules.get(resource_type))
            
            if not ownership_field:
                return False
            
            # 根据不同资源类型进行所有权检查
            if resource_type == 'archive':
                # 检查档案创建者
                from models.archive import ElectronicArchive
                archive = ElectronicArchive.query.get(resource_id)
                if archive and archive.created_by == user_id:
                    return True
                    
            elif resource_type == 'user':
                # 检查是否为本人
                if resource_id == user_id:
                    return True
                    
            # 记录所有权检查
            self._log_ownership_check(user_id, resource_type, resource_id, ownership_field)
            
            return False
            
        except Exception as e:
            logger.error(f"所有权检查失败: {str(e)}")
            return False
    
    def check_sensitive_operation(self, user_id: int, operation: str, operation_context: Dict = None) -> Dict:
        """
        检查敏感操作权限
        
        Args:
            user_id: 用户ID
            operation: 操作名称
            operation_context: 操作上下文
            
        Returns:
            dict: 检查结果
        """
        try:
            # 检查是否为敏感操作
            if operation not in self.sensitive_operations:
                return {
                    'allowed': True,
                    'sensitive': False,
                    'reason': '非敏感操作'
                }
            
            # 获取用户信息
            user = User.query.get(user_id)
            if not user:
                return {
                    'allowed': False,
                    'sensitive': True,
                    'reason': '用户不存在'
                }
            
            # 检查是否有敏感操作权限
            sensitive_permission = f"system:{operation}"
            
            has_permission = self.check_permission(user_id, 'system', operation)
            
            if not has_permission:
                return {
                    'allowed': False,
                    'sensitive': True,
                    'reason': '缺少敏感操作权限'
                }
            
            # 检查是否需要额外的验证
            operation_context = operation_context or {}
            
            if operation_context.get('require_additional_verification', False):
                return {
                    'allowed': True,
                    'sensitive': True,
                    'additional_verification_required': True,
                    'verification_methods': ['password', 'totp', 'sms'],
                    'reason': '需要额外的身份验证'
                }
            
            # 记录敏感操作访问
            self._log_sensitive_operation(user_id, operation, operation_context)
            
            return {
                'allowed': True,
                'sensitive': True,
                'additional_verification_required': False,
                'reason': '敏感操作已授权'
            }
            
        except Exception as e:
            logger.error(f"敏感操作检查失败: {str(e)}")
            return {
                'allowed': False,
                'sensitive': True,
                'reason': f'检查过程出错: {str(e)}'
            }
    
    def create_user(self, user_data: Dict, creator_id: int) -> Dict:
        """
        创建用户账户
        
        Args:
            user_data: 用户数据
            creator_id: 创建者ID
            
        Returns:
            dict: 创建结果
        """
        try:
            # 验证权限
            if not self.check_permission(creator_id, 'user', 'create'):
                return {
                    'success': False,
                    'error': '无权限创建用户',
                    'error_code': 'INSUFFICIENT_PERMISSION'
                }
            
            # 验证用户名和邮箱唯一性
            existing_user = User.query.filter(
                (User.username == user_data['username']) | 
                (User.email == user_data['email'])
            ).first()
            
            if existing_user:
                return {
                    'success': False,
                    'error': '用户名或邮箱已存在',
                    'error_code': 'USER_EXISTS'
                }
            
            # 创建用户
            user = User(
                username=user_data['username'],
                email=user_data['email'],
                full_name=user_data.get('full_name', ''),
                department=user_data.get('department', ''),
                phone=user_data.get('phone', ''),
                role=user_data.get('role', 'user'),  # 使用角色字符串而不是ID
                is_active=user_data.get('is_active', True),
                password_hash=generate_password_hash(user_data['password']),
                created_at=datetime.utcnow(),
                created_by=creator_id,
                password_changed_at=datetime.utcnow()
            )
            
            db.session.add(user)
            db.session.commit()
            
            # 记录审计日志
            self.audit_logger.log_operation(
                user_id=creator_id,
                operation_type='create',
                resource_type='user',
                resource_id=user.id,
                operation_details={
                    'username': user.username,
                    'email': user.email,
                    'roles_assigned': user_data.get('role_ids', [])
                }
            )
            
            return {
                'success': True,
                'user_id': user.id,
                'username': user.username,
                'message': f'用户{user.username}创建成功'
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"创建用户失败: {str(e)}")
            return {
                'success': False,
                'error': f'创建用户失败: {str(e)}',
                'error_code': 'USER_CREATION_ERROR'
            }
    
    def update_user_password(self, user_id: int, current_password: str, new_password: str) -> Dict:
        """
        更新用户密码
        
        Args:
            user_id: 用户ID
            current_password: 当前密码
            new_password: 新密码
            
        Returns:
            dict: 更新结果
        """
        try:
            user = User.query.get(user_id)
            if not user:
                return {
                    'success': False,
                    'error': '用户不存在',
                    'error_code': 'USER_NOT_FOUND'
                }
            
            # 验证当前密码
            if not check_password_hash(user.password_hash, current_password):
                return {
                    'success': False,
                    'error': '当前密码错误',
                    'error_code': 'INVALID_CURRENT_PASSWORD'
                }
            
            # 验证新密码强度
            password_validation = self._validate_password_strength(new_password)
            if not password_validation['valid']:
                return {
                    'success': False,
                    'error': f'密码不符合安全要求: {password_validation["errors"]}',
                    'error_code': 'WEAK_PASSWORD'
                }
            
            # 更新密码
            user.password_hash = generate_password_hash(new_password)
            user.password_changed_at = datetime.utcnow()
            user.password_reset_token = None
            user.password_reset_expires = None
            
            db.session.commit()
            
            # 记录审计日志
            self.audit_logger.log_operation(
                user_id=user_id,
                operation_type='password_change',
                resource_type='user',
                resource_id=user_id,
                operation_details={
                    'changed_at': datetime.utcnow().isoformat(),
                    'require_relogin': True
                }
            )
            
            # 使现有令牌失效
            self.session_manager.invalidate_user_sessions(user_id)
            
            return {
                'success': True,
                'message': '密码更新成功，请重新登录'
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"更新密码失败: {str(e)}")
            return {
                'success': False,
                'error': f'密码更新失败: {str(e)}',
                'error_code': 'PASSWORD_UPDATE_ERROR'
            }
    
    def revoke_user_session(self, session_id: str, user_id: int) -> Dict:
        """
        撤销用户会话
        
        Args:
            session_id: 会话ID
            user_id: 用户ID
            
        Returns:
            dict: 撤销结果
        """
        try:
            # 验证权限
            if not self.check_permission(user_id, 'session', 'revoke') and not self.session_manager.is_owner(session_id, user_id):
                return {
                    'success': False,
                    'error': '无权限撤销此会话',
                    'error_code': 'INSUFFICIENT_PERMISSION'
                }
            
            # 撤销会话
            success = self.session_manager.revoke_session(session_id)
            
            if success:
                # 记录审计日志
                self.audit_logger.log_operation(
                    user_id=user_id,
                    operation_type='revoke_session',
                    resource_type='session',
                    resource_id=session_id,
                    operation_details={
                        'revoked_at': datetime.utcnow().isoformat()
                    }
                )
                
                return {
                    'success': True,
                    'message': '会话已撤销'
                }
            else:
                return {
                    'success': False,
                    'error': '会话撤销失败',
                    'error_code': 'SESSION_REVOCATION_ERROR'
                }
                
        except Exception as e:
            logger.error(f"撤销会话失败: {str(e)}")
            return {
                'success': False,
                'error': f'撤销会话失败: {str(e)}',
                'error_code': 'SESSION_REVOCATION_ERROR'
            }
    
    def get_security_statistics(self) -> Dict:
        """
        获取安全统计信息
        
        Returns:
            dict: 统计信息
        """
        try:
            # 统计活跃用户
            active_users = User.query.filter_by(is_active=True).count()
            
            # 统计今日登录
            today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            login_attempts_today = AuditLog.query.filter(
                AuditLog.operation_type == 'login',
                AuditLog.created_at >= today_start
            ).count()
            
            # 统计失败登录
            failed_logins_today = AuditLog.query.filter(
                AuditLog.operation_type == 'login',
                AuditLog.operation_details['result'].astext == 'failed',
                AuditLog.created_at >= today_start
            ).count()
            
            # 统计活跃会话
            active_sessions = self.session_manager.get_active_session_count()
            
            # 统计被锁定账户
            locked_accounts = User.query.filter(
                User.failed_login_attempts >= self.max_login_attempts
            ).count()
            
            statistics = {
                'active_users': active_users,
                'login_attempts_today': login_attempts_today,
                'failed_logins_today': failed_logins_today,
                'active_sessions': active_sessions,
                'locked_accounts': locked_accounts,
                'security_score': self._calculate_security_score(),
                'generated_at': datetime.utcnow().isoformat()
            }
            
            return {
                'success': True,
                'statistics': statistics
            }
            
        except Exception as e:
            logger.error(f"获取安全统计失败: {str(e)}")
            return {
                'success': False,
                'error': f'获取安全统计失败: {str(e)}',
                'error_code': 'STATISTICS_ERROR'
            }
    
    def _is_account_locked(self, user: User) -> bool:
        """检查账户是否被锁定"""
        return user.failed_login_attempts >= self.max_login_attempts
    
    def _is_password_expired(self, user: User) -> bool:
        """检查密码是否过期"""
        if not user.password_changed_at:
            return True
        
        # 使用固定的密码最大有效期，避免应用上下文依赖
        password_max_age_days = 90
        expiry_date = user.password_changed_at + timedelta(days=password_max_age_days)
        
        return datetime.utcnow() > expiry_date
    
    def _increment_failed_attempts(self, user: User):
        """增加登录失败次数"""
        user.failed_login_attempts += 1
        db.session.commit()
    
    def _reset_failed_attempts(self, user: User):
        """重置登录失败次数"""
        user.failed_login_attempts = 0
        user.last_failed_login = None
        db.session.commit()
    
    def _update_last_login(self, user: User):
        """更新最后登录时间"""
        user.last_login = datetime.utcnow()
        db.session.commit()
    
    def _get_user_roles(self, user_id: int) -> List[str]:
        """获取用户角色"""
        user = User.query.get(user_id)
        if user and user.role:
            return [user.role]  # 返回角色名称列表
        return []
    
    def _get_user_permissions(self, user_id: int) -> List[str]:
        """获取用户权限"""
        user = User.query.get(user_id)
        if not user:
            return []
        
        # 基于角色返回权限
        role_permissions = {
            'admin': ['*:*'],  # 管理员拥有所有权限
            'archivist': [
                'archive:read', 'archive:create', 'archive:update', 'archive:delete',
                'collection:read', 'collection:create', 'collection:update',
                'search:*', 'metadata:read', 'metadata:create', 'metadata:update'
            ],
            'accountant': [
                'archive:read', 'archive:create', 'archive:update',
                'collection:read', 'collection:create',
                'search:*', 'metadata:read', 'metadata:create'
            ],
            'auditor': [
                'archive:read', 'collection:read', 'search:*', 'metadata:read',
                'audit:read'
            ],
            'user': [
                'archive:read', 'collection:read', 'search:basic'
            ]
        }
        
        return role_permissions.get(user.role, [])
    
    def _check_role_permissions(self, user_id: int, resource: str, action: str) -> bool:
        """检查角色权限"""
        # 简化实现，实际可以检查角色继承树
        return False
    
    def _log_authentication_attempt(self, username: str, result: str, ip_address: str, user_agent: str, user_id: int = None):
        """记录认证尝试"""
        try:
            audit_log = AuditLog(
                user_id=user_id,
                operation_type='login',
                resource_type='authentication',
                resource_id='login_attempt',  # 认证尝试的资源ID
                operation_details={
                    'username': username,
                    'result': result,
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                created_at=datetime.utcnow()
            )
            
            db.session.add(audit_log)
            db.session.commit()
            
        except Exception as e:
            logger.error(f"记录认证日志失败: {str(e)}")
    
    def _log_permission_check(self, user_id: int, resource: str, action: str, granted: bool):
        """记录权限检查"""
        # 简化实现，只记录重要权限检查
        if granted or resource in ['archive', 'user', 'system']:
            try:
                self.audit_logger.log_operation(
                    user_id=user_id,
                    operation_type='permission_check',
                    resource_type='security',
                    resource_id=user_id,
                    operation_details={
                        'resource': resource,
                        'action': action,
                        'granted': granted
                    }
                )
            except Exception as e:
                logger.error(f"记录权限检查日志失败: {str(e)}")
    
    def _log_ownership_check(self, user_id: int, resource_type: str, resource_id: int, ownership_field: str):
        """记录所有权检查"""
        # 简化实现
        pass
    
    def _log_sensitive_operation(self, user_id: int, operation: str, operation_context: Dict):
        """记录敏感操作"""
        try:
            self.audit_logger.log_operation(
                user_id=user_id,
                operation_type='sensitive_operation',
                resource_type='system',
                resource_id=user_id,
                operation_details={
                    'operation': operation,
                    'context': operation_context,
                    'timestamp': datetime.utcnow().isoformat()
                }
            )
        except Exception as e:
            logger.error(f"记录敏感操作日志失败: {str(e)}")
    
    def _validate_password_strength(self, password: str) -> Dict:
        """验证密码强度"""
        errors = []
        
        # 检查密码长度
        if len(password) < 8:
            errors.append('密码长度至少8位')
        
        # 检查是否包含大写字母
        if not any(c.isupper() for c in password):
            errors.append('密码必须包含大写字母')
        
        # 检查是否包含小写字母
        if not any(c.islower() for c in password):
            errors.append('密码必须包含小写字母')
        
        # 检查是否包含数字
        if not any(c.isdigit() for c in password):
            errors.append('密码必须包含数字')
        
        # 检查是否包含特殊字符
        special_chars = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        if not any(c in special_chars for c in password):
            errors.append('密码必须包含特殊字符')
        
        return {
            'valid': len(errors) == 0,
            'errors': errors
        }
    
    def _calculate_security_score(self) -> float:
        """计算安全评分"""
        try:
            # 简化的安全评分计算
            factors = {
                'active_users': 0.2,      # 活跃用户数
                'failed_logins': 0.3,     # 失败登录率
                'session_security': 0.2,   # 会话安全
                'account_lockout': 0.2,   # 账户锁定情况
                'password_policy': 0.1    # 密码策略合规性
            }
            
            # 实际计算逻辑
            score = 85.0  # 模拟安全评分
            
            return min(max(score, 0), 100)
            
        except Exception as e:
            logger.error(f"计算安全评分失败: {str(e)}")
            return 0.0