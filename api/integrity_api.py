"""
完整性验证API - 档案完整性检查、哈希验证、数字签名
基于DA/T 94-2022标准的电子会计档案完整性验证RESTful API端点
"""
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity

# 导入服务模块
from services.integrity_service import IntegrityService
from services.security_service import SecurityService
from services.audit_service import AuditService

# 创建蓝图
integrity_api = Blueprint('integrity_api', __name__)

# 初始化服务
integrity_service = IntegrityService()
security_service = SecurityService()
audit_service = AuditService()

@integrity_api.route('/verify/<int:archive_id>', methods=['POST'])
@jwt_required()
def verify_archive_integrity(archive_id: int):
    """验证档案完整性"""
    try:
        # 验证用户权限
        current_user_id = get_jwt_identity()
        user_permission = security_service.check_permission(
            current_user_id, 
            'archive', 
            'read',
            resource_id=archive_id
        )
        
        if not user_permission['allowed']:
            return jsonify({
                'success': False,
                'error': '权限不足',
                'error_code': 'INSUFFICIENT_PERMISSIONS'
            }), 403
        
        # 获取请求参数
        data = request.get_json() or {}
        verification_types = data.get('verification_types', ['hash_verification', 'metadata_integrity'])
        
        # 执行完整性验证
        result = integrity_service.verify_archive_integrity(
            archive_id=archive_id,
            verification_types=verification_types
        )
        
        # 记录审计日志
        audit_service.log_operation(
            user_id=current_user_id,
            operation_type='verify_archive_integrity',
            resource_type='archive',
            resource_id=archive_id,
            operation_details={
                'verification_types': verification_types,
                'result': result
            }
        )
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        current_app.logger.error(f"验证档案完整性API错误: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'验证档案完整性失败: {str(e)}',
            'error_code': 'INTEGRITY_VERIFICATION_API_ERROR'
        }), 500

@integrity_api.route('/batch-verify', methods=['POST'])
@jwt_required()
def batch_verify_integrity():
    """批量验证档案完整性"""
    try:
        # 验证用户权限
        current_user_id = get_jwt_identity()
        user_permission = security_service.check_permission(
            current_user_id, 
            'archive', 
            'read'
        )
        
        if not user_permission['allowed']:
            return jsonify({
                'success': False,
                'error': '权限不足',
                'error_code': 'INSUFFICIENT_PERMISSIONS'
            }), 403
        
        # 获取请求参数
        data = request.get_json() or {}
        archive_ids = data.get('archive_ids', [])
        verification_types = data.get('verification_types', ['hash_verification', 'metadata_integrity'])
        
        if not archive_ids:
            return jsonify({
                'success': False,
                'error': '未提供档案ID列表',
                'error_code': 'NO_ARCHIVE_IDS'
            }), 400
        
        # 批量验证
        result = integrity_service.batch_verify_integrity(
            archive_ids=archive_ids,
            verification_types=verification_types
        )
        
        # 记录审计日志
        audit_service.log_operation(
            user_id=current_user_id,
            operation_type='batch_verify_archive_integrity',
            resource_type='archive',
            operation_details={
                'archive_count': len(archive_ids),
                'verification_types': verification_types,
                'result': result
            }
        )
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        current_app.logger.error(f"批量验证档案完整性API错误: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'批量验证档案完整性失败: {str(e)}',
            'error_code': 'BATCH_INTEGRITY_VERIFICATION_API_ERROR'
        }), 500

@integrity_api.route('/hash/verify', methods=['POST'])
@jwt_required()
def verify_file_hash():
    """验证文件哈希值"""
    try:
        # 验证用户权限
        current_user_id = get_jwt_identity()
        user_permission = security_service.check_permission(
            current_user_id, 
            'archive', 
            'read'
        )
        
        if not user_permission['allowed']:
            return jsonify({
                'success': False,
                'error': '权限不足',
                'error_code': 'INSUFFICIENT_PERMISSIONS'
            }), 403
        
        # 获取请求参数
        data = request.get_json() or {}
        file_path = data.get('file_path')
        expected_hash = data.get('expected_hash')
        algorithm = data.get('algorithm', 'sha256')
        
        if not file_path or not expected_hash:
            return jsonify({
                'success': False,
                'error': '缺少必需参数：file_path 或 expected_hash',
                'error_code': 'MISSING_REQUIRED_PARAMETERS'
            }), 400
        
        # 验证文件哈希
        result = integrity_service.verify_file_integrity(
            file_path=file_path,
            expected_hash=expected_hash,
            algorithm=algorithm
        )
        
        # 记录审计日志
        audit_service.log_operation(
            user_id=current_user_id,
            operation_type='verify_file_hash',
            resource_type='file',
            operation_details={
                'file_path': file_path,
                'algorithm': algorithm,
                'result': result
            }
        )
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        current_app.logger.error(f"验证文件哈希API错误: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'验证文件哈希失败: {str(e)}',
            'error_code': 'FILE_HASH_VERIFICATION_API_ERROR'
        }), 500

@integrity_api.route('/hash/generate', methods=['POST'])
@jwt_required()
def generate_file_hash():
    """生成文件哈希值"""
    try:
        # 验证用户权限
        current_user_id = get_jwt_identity()
        user_permission = security_service.check_permission(
            current_user_id, 
            'archive', 
            'read'
        )
        
        if not user_permission['allowed']:
            return jsonify({
                'success': False,
                'error': '权限不足',
                'error_code': 'INSUFFICIENT_PERMISSIONS'
            }), 403
        
        # 获取请求参数
        data = request.get_json() or {}
        file_path = data.get('file_path')
        algorithm = data.get('algorithm', 'sha256')
        
        if not file_path:
            return jsonify({
                'success': False,
                'error': '缺少必需参数：file_path',
                'error_code': 'MISSING_FILE_PATH'
            }), 400
        
        # 生成文件哈希
        result = integrity_service.generate_file_hash(
            file_path=file_path,
            algorithm=algorithm
        )
        
        # 记录审计日志
        audit_service.log_operation(
            user_id=current_user_id,
            operation_type='generate_file_hash',
            resource_type='file',
            operation_details={
                'file_path': file_path,
                'algorithm': algorithm,
                'result': result
            }
        )
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        current_app.logger.error(f"生成文件哈希API错误: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'生成文件哈希失败: {str(e)}',
            'error_code': 'FILE_HASH_GENERATION_API_ERROR'
        }), 500

@integrity_api.route('/signature/sign', methods=['POST'])
@jwt_required()
def create_digital_signature():
    """创建数字签名"""
    try:
        # 验证用户权限
        current_user_id = get_jwt_identity()
        user_permission = security_service.check_permission(
            current_user_id, 
            'archive', 
            'sign'
        )
        
        if not user_permission['allowed']:
            return jsonify({
                'success': False,
                'error': '权限不足',
                'error_code': 'INSUFFICIENT_PERMISSIONS'
            }), 403
        
        # 获取请求参数
        data = request.get_json() or {}
        file_path = data.get('file_path')
        archive_id = data.get('archive_id')
        private_key_path = data.get('private_key_path')
        
        # 验证必需参数
        if not file_path and not archive_id:
            return jsonify({
                'success': False,
                'error': '缺少必需参数：file_path 或 archive_id',
                'error_code': 'MISSING_REQUIRED_PARAMETERS'
            }), 400
        
        # 读取要签名的数据
        if archive_id:
            # 对档案签名 - 使用档案元数据
            from models.archive import ElectronicArchive
            archive = ElectronicArchive.query.get(archive_id)
            if not archive:
                return jsonify({
                    'success': False,
                    'error': '档案不存在',
                    'error_code': 'ARCHIVE_NOT_FOUND'
                }), 404
            
            signature_data = json.dumps({
                'archive_id': archive.id,
                'title': archive.title,
                'archive_type': archive.archive_type,
                'created_at': archive.created_at.isoformat() if archive.created_at else None,
                'created_by': archive.created_by,
                'department': archive.department,
                'fiscal_year': archive.fiscal_year
            }, sort_keys=True).encode('utf-8')
            
        else:
            # 对文件签名
            if not os.path.exists(file_path):
                return jsonify({
                    'success': False,
                    'error': f'文件不存在: {file_path}',
                    'error_code': 'FILE_NOT_FOUND'
                }), 404
            
            with open(file_path, 'rb') as f:
                signature_data = f.read()
        
        # 创建数字签名
        result = integrity_service.create_digital_signature(
            data=signature_data,
            private_key_path=private_key_path
        )
        
        # 如果是对档案签名，更新数据库
        if archive_id and result['success']:
            from models.archive import ElectronicArchive
            archive = ElectronicArchive.query.get(archive_id)
            if archive:
                archive.digital_signature = result['signature']
                archive.signed_at = datetime.utcnow()
                from models import db
                db.session.commit()
        
        # 记录审计日志
        audit_service.log_operation(
            user_id=current_user_id,
            operation_type='create_digital_signature',
            resource_type='archive' if archive_id else 'file',
            resource_id=archive_id,
            operation_details={
                'file_path': file_path,
                'archive_id': archive_id,
                'algorithm': result.get('algorithm'),
                'result': result
            }
        )
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        current_app.logger.error(f"创建数字签名API错误: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'创建数字签名失败: {str(e)}',
            'error_code': 'DIGITAL_SIGNATURE_API_ERROR'
        }), 500

@integrity_api.route('/signature/verify', methods=['POST'])
@jwt_required()
def verify_digital_signature():
    """验证数字签名"""
    try:
        # 验证用户权限
        current_user_id = get_jwt_identity()
        user_permission = security_service.check_permission(
            current_user_id, 
            'archive', 
            'read'
        )
        
        if not user_permission['allowed']:
            return jsonify({
                'success': False,
                'error': '权限不足',
                'error_code': 'INSUFFICIENT_PERMISSIONS'
            }), 403
        
        # 获取请求参数
        data = request.get_json() or {}
        signature = data.get('signature')
        file_path = data.get('file_path')
        archive_id = data.get('archive_id')
        public_key_path = data.get('public_key_path')
        
        if not signature:
            return jsonify({
                'success': False,
                'error': '缺少必需参数：signature',
                'error_code': 'MISSING_SIGNATURE'
            }), 400
        
        # 准备要验证的数据
        if archive_id:
            # 验证档案签名
            from models.archive import ElectronicArchive
            archive = ElectronicArchive.query.get(archive_id)
            if not archive:
                return jsonify({
                    'success': False,
                    'error': '档案不存在',
                    'error_code': 'ARCHIVE_NOT_FOUND'
                }), 404
            
            verification_data = json.dumps({
                'archive_id': archive.id,
                'title': archive.title,
                'archive_type': archive.archive_type,
                'created_at': archive.created_at.isoformat() if archive.created_at else None,
                'hash_value': archive.hash_value
            }, sort_keys=True).encode('utf-8')
            
        elif file_path:
            # 验证文件签名
            if not os.path.exists(file_path):
                return jsonify({
                    'success': False,
                    'error': f'文件不存在: {file_path}',
                    'error_code': 'FILE_NOT_FOUND'
                }), 404
            
            with open(file_path, 'rb') as f:
                verification_data = f.read()
        else:
            return jsonify({
                'success': False,
                'error': '缺少必需参数：archive_id 或 file_path',
                'error_code': 'MISSING_DATA_SOURCE'
            }), 400
        
        # 验证数字签名
        result = integrity_service.verify_digital_signature(
            data=verification_data,
            signature=signature,
            public_key_path=public_key_path
        )
        
        # 记录审计日志
        audit_service.log_operation(
            user_id=current_user_id,
            operation_type='verify_digital_signature',
            resource_type='archive' if archive_id else 'file',
            resource_id=archive_id,
            operation_details={
                'file_path': file_path,
                'archive_id': archive_id,
                'verification_result': result.get('verified'),
                'result': result
            }
        )
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        current_app.logger.error(f"验证数字签名API错误: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'验证数字签名失败: {str(e)}',
            'error_code': 'DIGITAL_SIGNATURE_VERIFICATION_API_ERROR'
        }), 500

@integrity_api.route('/schedule/<int:archive_id>', methods=['POST'])
@jwt_required()
def schedule_integrity_check(archive_id: int):
    """安排完整性检查任务"""
    try:
        # 验证用户权限
        current_user_id = get_jwt_identity()
        user_permission = security_service.check_permission(
            current_user_id, 
            'archive', 
            'update',
            resource_id=archive_id
        )
        
        if not user_permission['allowed']:
            return jsonify({
                'success': False,
                'error': '权限不足',
                'error_code': 'INSUFFICIENT_PERMISSIONS'
            }), 403
        
        # 获取请求参数
        data = request.get_json() or {}
        check_interval_hours = data.get('check_interval_hours')
        
        # 安排完整性检查
        result = integrity_service.schedule_integrity_check(
            archive_id=archive_id,
            check_interval_hours=check_interval_hours
        )
        
        # 记录审计日志
        audit_service.log_operation(
            user_id=current_user_id,
            operation_type='schedule_integrity_check',
            resource_type='archive',
            resource_id=archive_id,
            operation_details={
                'check_interval_hours': check_interval_hours,
                'result': result
            }
        )
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        current_app.logger.error(f"安排完整性检查API错误: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'安排完整性检查失败: {str(e)}',
            'error_code': 'INTEGRITY_SCHEDULE_API_ERROR'
        }), 500

@integrity_api.route('/statistics', methods=['GET'])
@jwt_required()
def get_integrity_statistics():
    """获取完整性统计信息"""
    try:
        # 验证用户权限
        current_user_id = get_jwt_identity()
        user_permission = security_service.check_permission(
            current_user_id, 
            'archive', 
            'read'
        )
        
        if not user_permission['allowed']:
            return jsonify({
                'success': False,
                'error': '权限不足',
                'error_code': 'INSUFFICIENT_PERMISSIONS'
            }), 403
        
        # 获取请求参数
        time_period = request.args.get('time_period', '30d')
        
        # 获取统计信息
        result = integrity_service.get_integrity_statistics(time_period=time_period)
        
        # 记录审计日志
        audit_service.log_operation(
            user_id=current_user_id,
            operation_type='get_integrity_statistics',
            resource_type='integrity',
            operation_details={
                'time_period': time_period,
                'result': result
            }
        )
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        current_app.logger.error(f"获取完整性统计API错误: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'获取完整性统计失败: {str(e)}',
            'error_code': 'INTEGRITY_STATISTICS_API_ERROR'
        }), 500

@integrity_api.route('/config', methods=['GET'])
@jwt_required()
def get_integrity_config():
    """获取完整性验证配置"""
    try:
        # 验证用户权限
        current_user_id = get_jwt_identity()
        user_permission = security_service.check_permission(
            current_user_id, 
            'system', 
            'read'
        )
        
        if not user_permission['allowed']:
            return jsonify({
                'success': False,
                'error': '权限不足',
                'error_code': 'INSUFFICIENT_PERMISSIONS'
            }), 403
        
        # 获取配置信息
        config = {
            'supported_hash_algorithms': list(integrity_service.hash_algorithms.keys()),
            'default_hash_algorithm': integrity_service.default_hash_algorithm,
            'integrity_check_interval_hours': integrity_service.integrity_check_interval_hours,
            'max_integrity_failures': integrity_service.max_integrity_failures,
            'enable_digital_signature': integrity_service.enable_digital_signature,
            'verification_types': integrity_service.verification_types,
            'verification_status': integrity_service.verification_status
        }
        
        return jsonify({
            'success': True,
            'config': config
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"获取完整性配置API错误: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'获取完整性配置失败: {str(e)}',
            'error_code': 'INTEGRITY_CONFIG_API_ERROR'
        }), 500

@integrity_api.route('/status/<int:archive_id>', methods=['GET'])
@jwt_required()
def get_archive_integrity_status(archive_id: int):
    """获取档案完整性状态"""
    try:
        # 验证用户权限
        current_user_id = get_jwt_identity()
        user_permission = security_service.check_permission(
            current_user_id, 
            'archive', 
            'read',
            resource_id=archive_id
        )
        
        if not user_permission['allowed']:
            return jsonify({
                'success': False,
                'error': '权限不足',
                'error_code': 'INSUFFICIENT_PERMISSIONS'
            }), 403
        
        # 获取档案完整性状态
        from models.archive import ElectronicArchive
        
        archive = ElectronicArchive.query.get(archive_id)
        if not archive:
            return jsonify({
                'success': False,
                'error': '档案不存在',
                'error_code': 'ARCHIVE_NOT_FOUND'
            }), 404
        
        # 构建状态信息
        status_info = {
            'archive_id': archive.id,
            'title': archive.title,
            'integrity_status': archive.integrity_status,
            'integrity_score': archive.integrity_score,
            'hash_value': archive.hash_value,
            'digital_signature': bool(archive.digital_signature),
            'last_integrity_check': archive.last_integrity_check.isoformat() if archive.last_integrity_check else None,
            'next_integrity_check': archive.next_integrity_check.isoformat() if archive.next_integrity_check else None,
            'integrity_check_count': archive.integrity_check_count,
            'integrity_failure_count': archive.integrity_failure_count,
            'auto_integrity_check': archive.auto_integrity_check,
            'requires_attention': archive.integrity_status in ['failed', 'warning']
        }
        
        return jsonify({
            'success': True,
            'status': status_info
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"获取档案完整性状态API错误: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'获取档案完整性状态失败: {str(e)}',
            'error_code': 'INTEGRITY_STATUS_API_ERROR'
        }), 500