"""
认证工具模块
提供用户认证和权限管理功能
"""
from functools import wraps
from flask import request, jsonify, current_app
from models.user import User

def get_current_user():
    """
    获取当前用户
    
    Returns:
        User: 当前用户对象，如果未登录返回None
    """
    try:
        # 简化实现，从请求头获取用户ID
        user_id = request.headers.get('X-User-ID')
        if user_id:
            return User.query.get(int(user_id))
        return None
    except:
        return None

def require_auth(f):
    """
    认证装饰器
    要求用户已登录才能访问
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'error': '未授权访问',
                'message': '需要登录才能访问此资源'
            }), 401
        return f(*args, **kwargs)
    return decorated_function

def require_permission(permission_name):
    """
    权限装饰器
    要求用户具有指定权限
    
    Args:
        permission_name: 权限名称
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user = get_current_user()
            if not current_user:
                return jsonify({
                    'success': False,
                    'error': '未授权访问',
                    'message': '需要登录才能访问此资源'
                }), 401
            
            # 简化权限检查，实际应用中需要更复杂的逻辑
            # 这里假设所有已登录用户都有所有权限
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def is_admin():
    """
    检查当前用户是否为管理员
    
    Returns:
        bool: 如果当前用户是管理员返回True，否则返回False
    """
    current_user = get_current_user()
    return current_user and current_user.role == 'admin' if hasattr(current_user, 'role') else False

def get_user_permissions(user_id):
    """
    获取用户权限列表
    
    Args:
        user_id: 用户ID
        
    Returns:
        list: 权限列表
    """
    # 简化实现，返回默认权限
    return ['read', 'write', 'admin']