"""
安全服务API - 身份认证、权限控制、加密解密、安全审计
基于DA/T 94-2022标准的电子会计档案安全服务RESTful API端点
"""
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token, get_jwt

from services.security_service import SecurityService
from services.audit_service import AuditService
from utils.response_utils import success_response, error_response
from utils.audit_logger import AuditLogger

logger = logging.getLogger(__name__)

# 创建蓝图
security_bp = Blueprint('security', __name__)

# 初始化服务
security_service = SecurityService()
audit_service = AuditService()
audit_logger = AuditLogger()

def get_current_user_id():
    """获取当前用户ID"""
    try:
        return get_jwt_identity()
    except:
        return None

# 用户登录
@security_bp.route('/login', methods=['POST'])
def user_login():
    """
    用户登录
    
    请求体:
    {
        "username": "用户名",
        "password": "密码",
        "remember_me": false
    }
    """
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        remember_me = data.get('remember_me', False)
        
        if not username or not password:
            return error_response('缺少用户名或密码', 'MISSING_CREDENTIALS', 400)
        
        # 验证用户凭据
        result = security_service.authenticate_user(
            username=username,
            password=password
        )
        
        if result['success']:
            user_info = result['user_info']
            access_token = result['access_token']
            session_id = result['session_id']
            expires_in = result['expires_in']
            
            # 记录登录操作
            audit_logger.log_user_action(
                user_id=user_info['id'],
                action='user_login',
                details={
                    'username': username,
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent'),
                    'success': True
                }
            )
            
            return success_response('登录成功', {
                'access_token': access_token,
                'token_type': result.get('token_type', 'Bearer'),
                'expires_in': expires_in,
                'session_id': session_id,
                'user': {
                    'id': user_info['id'],
                    'username': user_info['username'],
                    'email': user_info.get('email'),
                    'full_name': user_info.get('full_name'),
                    'department': user_info.get('department'),
                    'roles': user_info.get('roles', []),
                    'permissions': user_info.get('permissions', [])
                }
            })
        else:
            # 记录失败的登录尝试
            audit_logger.log_security_event(
                event_type='login_failure',
                severity='medium',
                details={
                    'username': username,
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent'),
                    'reason': result.get('error', 'Authentication failed')
                }
            )
            
            return error_response(
                result.get('error', '登录失败'),
                result.get('error_code', 'LOGIN_FAILED'),
                401
            )
            
    except Exception as e:
        logger.error(f"用户登录API错误: {str(e)}")
        return error_response('登录服务异常', 'LOGIN_SERVICE_ERROR', 500)

# 用户登出
@security_bp.route('/logout', methods=['POST'])
@jwt_required()
def user_logout(current_user):
    """
    用户登出
    """
    try:
        current_user_id = get_current_user_id()
        
        # 获取JWT令牌信息
        jti = get_jwt()['jti'] if get_jwt() else None
        
        # 将令牌加入黑名单
        if jti:
            result = security_service.revoke_token(jti)
        
        # 记录登出操作
        audit_logger.log_user_action(
            user_id=current_user_id,
            action='user_logout',
            details={
                'ip_address': request.remote_addr,
                'user_agent': request.headers.get('User-Agent')
            }
        )
        
        return success_response('登出成功', {})
        
    except Exception as e:
        logger.error(f"用户登出API错误: {str(e)}")
        return error_response('登出服务异常', 'LOGOUT_SERVICE_ERROR', 500)

# 验证令牌
@security_bp.route('/verify-token', methods=['POST'])
@jwt_required()
def verify_token(current_user):
    """
    验证当前令牌有效性
    """
    try:
        current_user_id = get_current_user_id()
        
        # 获取令牌信息
        jwt_data = get_jwt()
        
        result = security_service.verify_token_validity(
            token_jti=jwt_data['jti'],
            user_id=current_user_id
        )
        
        if result['success']:
            return success_response('令牌有效', {
                'user_id': current_user_id,
                'username': jwt_data.get('username'),
                'role': jwt_data.get('role'),
                'permissions': jwt_data.get('permissions', []),
                'expires_at': datetime.fromtimestamp(jwt_data.get('exp', 0)).isoformat()
            })
        else:
            return error_response(
                result.get('error', '令牌无效'),
                result.get('error_code', 'INVALID_TOKEN'),
                401
            )
            
    except Exception as e:
        logger.error(f"验证令牌API错误: {str(e)}")
        return error_response('验证令牌服务异常', 'TOKEN_VERIFICATION_SERVICE_ERROR', 500)

# 刷新令牌
@security_bp.route('/refresh', methods=['POST'])
@jwt_required()
def refresh_token(current_user):
    """
    刷新访问令牌
    """
    try:
        current_user_id = get_current_user_id()
        
        # 获取用户信息
        user_info = security_service.get_user_by_id(current_user_id)
        if not user_info['success']:
            return error_response('用户不存在', 'USER_NOT_FOUND', 404)
        
        user = user_info['data']
        
        # 创建新的访问令牌
        new_token = create_access_token(
            identity=user['id'],
            additional_claims={
                'username': user['username'],
                'role': user['role'],
                'permissions': user.get('permissions', [])
            },
            expires_delta=timedelta(hours=24)
        )
        
        return success_response('令牌刷新成功', {
            'access_token': new_token,
            'token_type': 'bearer',
            'expires_in': 86400
        })
        
    except Exception as e:
        logger.error(f"刷新令牌API错误: {str(e)}")
        return error_response('刷新令牌服务异常', 'TOKEN_REFRESH_SERVICE_ERROR', 500)

# 检查权限
@security_bp.route('/check-permission', methods=['POST'])
@jwt_required()
def check_permission(current_user):
    """
    检查用户权限
    
    请求体:
    {
        "resource_type": "archive",
        "operation": "read",
        "resource_id": 123 // 可选
    }
    """
    try:
        current_user_id = get_current_user_id()
        data = request.get_json()
        
        resource_type = data.get('resource_type')
        operation = data.get('operation')
        resource_id = data.get('resource_id')
        
        if not resource_type or not operation:
            return error_response('缺少资源类型或操作类型', 'MISSING_PARAMETERS', 400)
        
        # 检查权限
        result = security_service.check_permission(
            user_id=current_user_id,
            resource_type=resource_type,
            operation=operation,
            resource_id=resource_id
        )
        
        return success_response('权限检查完成', {
            'has_permission': result['allowed'],
            'resource_type': resource_type,
            'operation': operation,
            'resource_id': resource_id,
            'user_role': result.get('user_role'),
            'granted_permissions': result.get('granted_permissions', [])
        })
        
    except Exception as e:
        logger.error(f"检查权限API错误: {str(e)}")
        return error_response('检查权限服务异常', 'PERMISSION_CHECK_SERVICE_ERROR', 500)

# 获取用户权限列表
@security_bp.route('/permissions', methods=['GET'])
@jwt_required()
def get_user_permissions(current_user):
    """
    获取当前用户的权限列表
    """
    try:
        current_user_id = get_current_user_id()
        
        result = security_service.get_user_permissions(current_user_id)
        
        if result['success']:
            return success_response('获取用户权限成功', {
                'user_id': current_user_id,
                'permissions': result['data']['permissions'],
                'role': result['data']['role'],
                'effective_permissions': result['data'].get('effective_permissions', [])
            })
        else:
            return error_response(
                result.get('error', '获取用户权限失败'),
                result.get('error_code', 'GET_USER_PERMISSIONS_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"获取用户权限API错误: {str(e)}")
        return error_response('获取用户权限服务异常', 'USER_PERMISSIONS_SERVICE_ERROR', 500)

# 修改密码
@security_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password(current_user):
    """
    修改用户密码
    
    请求体:
    {
        "current_password": "当前密码",
        "new_password": "新密码",
        "confirm_password": "确认新密码"
    }
    """
    try:
        current_user_id = get_current_user_id()
        data = request.get_json()
        
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        
        if not current_password or not new_password or not confirm_password:
            return error_response('缺少密码参数', 'MISSING_PASSWORD_PARAMETERS', 400)
        
        if new_password != confirm_password:
            return error_response('新密码与确认密码不匹配', 'PASSWORD_MISMATCH', 400)
        
        # 修改密码
        result = security_service.change_user_password(
            user_id=current_user_id,
            current_password=current_password,
            new_password=new_password
        )
        
        if result['success']:
            # 记录密码修改操作
            audit_logger.log_user_action(
                user_id=current_user_id,
                action='change_password',
                details={
                    'ip_address': request.remote_addr,
                    'timestamp': datetime.utcnow().isoformat()
                }
            )
            
            return success_response('密码修改成功', {})
        else:
            return error_response(
                result.get('error', '密码修改失败'),
                result.get('error_code', 'CHANGE_PASSWORD_ERROR'),
                400
            )
            
    except Exception as e:
        logger.error(f"修改密码API错误: {str(e)}")
        return error_response('修改密码服务异常', 'CHANGE_PASSWORD_SERVICE_ERROR', 500)

# 文件加密
@security_bp.route('/encrypt-file', methods=['POST'])
@jwt_required()
def encrypt_file(current_user):
    """
    文件加密
    
    请求体:
    {
        "file_path": "/path/to/file",
        "algorithm": "AES256", // 可选，默认AES256
        "key_id": 1 // 可选，使用指定密钥
    }
    """
    try:
        current_user_id = get_current_user_id()
        data = request.get_json()
        
        file_path = data.get('file_path')
        algorithm = data.get('algorithm', 'AES256')
        key_id = data.get('key_id')
        
        if not file_path:
            return error_response('缺少文件路径', 'MISSING_FILE_PATH', 400)
        
        # 检查权限（需要加密权限）
        permission_check = security_service.check_permission(
            current_user_id, 
            'file', 
            'encrypt'
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        # 文件加密
        result = security_service.encrypt_file(
            file_path=file_path,
            algorithm=algorithm,
            key_id=key_id,
            user_id=current_user_id
        )
        
        if result['success']:
            return success_response('文件加密成功', {
                'original_path': file_path,
                'encrypted_path': result['data']['encrypted_path'],
                'algorithm': algorithm,
                'encryption_key_id': result['data'].get('encryption_key_id'),
                'file_size': result['data'].get('file_size'),
                'encrypted_at': datetime.utcnow().isoformat()
            })
        else:
            return error_response(
                result.get('error', '文件加密失败'),
                result.get('error_code', 'FILE_ENCRYPTION_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"文件加密API错误: {str(e)}")
        return error_response('文件加密服务异常', 'FILE_ENCRYPTION_SERVICE_ERROR', 500)

# 文件解密
@security_bp.route('/decrypt-file', methods=['POST'])
@jwt_required()
def decrypt_file(current_user):
    """
    文件解密
    
    请求体:
    {
        "encrypted_file_path": "/path/to/encrypted/file",
        "output_path": "/path/to/output/file",
        "key_id": 1 // 必须，提供加密时使用的密钥ID
    }
    """
    try:
        current_user_id = get_current_user_id()
        data = request.get_json()
        
        encrypted_file_path = data.get('encrypted_file_path')
        output_path = data.get('output_path')
        key_id = data.get('key_id')
        
        if not encrypted_file_path or not output_path or not key_id:
            return error_response('缺少必要参数', 'MISSING_REQUIRED_PARAMETERS', 400)
        
        # 检查权限（需要解密权限）
        permission_check = security_service.check_permission(
            current_user_id, 
            'file', 
            'decrypt'
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        # 文件解密
        result = security_service.decrypt_file(
            encrypted_file_path=encrypted_file_path,
            output_path=output_path,
            key_id=key_id,
            user_id=current_user_id
        )
        
        if result['success']:
            return success_response('文件解密成功', {
                'encrypted_path': encrypted_file_path,
                'decrypted_path': output_path,
                'decryption_key_id': key_id,
                'file_size': result['data'].get('file_size'),
                'decrypted_at': datetime.utcnow().isoformat()
            })
        else:
            return error_response(
                result.get('error', '文件解密失败'),
                result.get('error_code', 'FILE_DECRYPTION_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"文件解密API错误: {str(e)}")
        return error_response('文件解密服务异常', 'FILE_DECRYPTION_SERVICE_ERROR', 500)

# 获取安全配置
@security_bp.route('/config', methods=['GET'])
@jwt_required()
def get_security_config(current_user):
    """
    获取安全配置（只返回非敏感信息）
    """
    try:
        # 检查权限（需要管理员权限）
        permission_check = security_service.check_permission(
            get_current_user_id(), 
            'security_config', 
            'read'
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        result = security_service.get_security_config()
        
        if result['success']:
            return success_response('获取安全配置成功', {
                'config': result['data']
            })
        else:
            return error_response(
                result.get('error', '获取安全配置失败'),
                result.get('error_code', 'GET_SECURITY_CONFIG_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"获取安全配置API错误: {str(e)}")
        return error_response('获取安全配置服务异常', 'SECURITY_CONFIG_SERVICE_ERROR', 500)

# 错误处理
@security_bp.errorhandler(400)
def bad_request(error):
    return error_response('请求参数错误', 'BAD_REQUEST', 400)

@security_bp.errorhandler(401)
def unauthorized(error):
    return error_response('未授权访问', 'UNAUTHORIZED', 401)

@security_bp.errorhandler(403)
def forbidden(error):
    return error_response('访问被禁止', 'FORBIDDEN', 403)

@security_bp.errorhandler(500)
def internal_error(error):
    return error_response('服务器内部错误', 'INTERNAL_SERVER_ERROR', 500)