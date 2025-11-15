"""
认证装饰器模块
提供API认证相关的装饰器功能
"""
from functools import wraps
from flask import request, jsonify
from utils.auth import get_current_user

def token_required(f):
    """
    Token认证装饰器
    要求用户具有有效的token才能访问
    
    使用方法:
    @token_required
    def my_function(current_user):
        # 你的逻辑
        pass
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'error': '未授权访问',
                'message': '需要有效的token才能访问此资源',
                'code': 'UNAUTHORIZED'
            }), 401
        
        # 将当前用户作为第一个参数传递给被装饰的函数
        return f(current_user, *args, **kwargs)
    
    return decorated_function

def admin_required(f):
    """
    管理员权限装饰器
    要求用户具有管理员权限
    
    使用方法:
    @admin_required
    def admin_function(current_user):
        # 你的逻辑
        pass
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'error': '未授权访问',
                'message': '需要登录才能访问此资源',
                'code': 'UNAUTHORIZED'
            }), 401
        
        # 检查用户是否为管理员（简化实现）
        if hasattr(current_user, 'role') and current_user.role == 'admin':
            return f(current_user, *args, **kwargs)
        else:
            return jsonify({
                'success': False,
                'error': '权限不足',
                'message': '需要管理员权限才能访问此资源',
                'code': 'INSUFFICIENT_PERMISSION'
            }), 403
    
    return decorated_function

def permission_required(permission_name):
    """
    权限装饰器
    要求用户具有指定权限
    
    Args:
        permission_name: 权限名称
        
    使用方法:
    @permission_required('read_archives')
    def read_function(current_user):
        # 你的逻辑
        pass
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user = get_current_user()
            if not current_user:
                return jsonify({
                    'success': False,
                    'error': '未授权访问',
                    'message': '需要登录才能访问此资源',
                    'code': 'UNAUTHORIZED'
                }), 401
            
            # 简化权限检查，实际应用中需要更复杂的逻辑
            # 这里可以扩展为从数据库或配置文件读取用户权限
            user_permissions = getattr(current_user, 'permissions', ['read', 'write'])
            
            if permission_name in user_permissions:
                return f(current_user, *args, **kwargs)
            else:
                return jsonify({
                    'success': False,
                    'error': '权限不足',
                    'message': f'需要{permission_name}权限才能访问此资源',
                    'code': 'INSUFFICIENT_PERMISSION'
                }), 403
        
        return decorated_function
    return decorator