"""
响应工具模块
提供统一的API响应格式
"""
from datetime import datetime
from flask import jsonify
from typing import Any, Optional

def create_success_response(
    data: Any = None, 
    message: str = "操作成功", 
    status_code: int = 200,
    pagination: Optional[dict] = None
):
    """
    创建成功响应
    
    Args:
        data: 响应数据
        message: 响应消息
        status_code: HTTP状态码
        pagination: 分页信息
        
    Returns:
        tuple: (响应对象, 状态码)
    """
    response = {
        'success': True,
        'message': message,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    if data is not None:
        response['data'] = data
        
    if pagination:
        response['pagination'] = pagination
    
    return jsonify(response), status_code

def create_error_response(
    error: str = "操作失败", 
    status_code: int = 400, 
    error_code: Optional[str] = None,
    details: Optional[Any] = None
):
    """
    创建错误响应
    
    Args:
        error: 错误消息
        status_code: HTTP状态码
        error_code: 错误代码
        details: 错误详情
        
    Returns:
        tuple: (响应对象, 状态码)
    """
    response = {
        'success': False,
        'error': error,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    if error_code:
        response['error_code'] = error_code
        
    if details:
        response['details'] = details
    
    return jsonify(response), status_code

def create_validation_error_response(missing_fields: list, invalid_fields: list = None):
    """
    创建验证错误响应
    
    Args:
        missing_fields: 缺失字段列表
        invalid_fields: 无效字段列表
        
    Returns:
        tuple: (响应对象, 状态码)
    """
    error_details = {
        'missing_fields': missing_fields
    }
    
    if invalid_fields:
        error_details['invalid_fields'] = invalid_fields
    
    return create_error_response(
        error="请求参数验证失败",
        status_code=400,
        error_code="VALIDATION_ERROR",
        details=error_details
    )

def create_not_found_response(resource_name: str = "资源"):
    """
    创建资源未找到响应
    
    Args:
        resource_name: 资源名称
        
    Returns:
        tuple: (响应对象, 状态码)
    """
    return create_error_response(
        error=f"{resource_name}未找到",
        status_code=404,
        error_code="RESOURCE_NOT_FOUND"
    )

def create_unauthorized_response(message: str = "未授权访问"):
    """
    创建未授权响应
    
    Args:
        message: 错误消息
        
    Returns:
        tuple: (响应对象, 状态码)
    """
    return create_error_response(
        error=message,
        status_code=401,
        error_code="UNAUTHORIZED"
    )

def create_forbidden_response(message: str = "访问被禁止"):
    """
    创建禁止访问响应
    
    Args:
        message: 错误消息
        
    Returns:
        tuple: (响应对象, 状态码)
    """
    return create_error_response(
        error=message,
        status_code=403,
        error_code="FORBIDDEN"
    )

def create_internal_server_error_response(error: str = "服务器内部错误"):
    """
    创建服务器内部错误响应
    
    Args:
        error: 错误消息
        
    Returns:
        tuple: (响应对象, 状态码)
    """
    return create_error_response(
        error=error,
        status_code=500,
        error_code="INTERNAL_SERVER_ERROR"
    )

# 提供简化的别名函数以保持向后兼容性
success_response = create_success_response
error_response = create_error_response