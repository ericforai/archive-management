"""
电子档案采集中心API端点
基于DA/T 94-2022标准的采集中心RESTful API
"""
import os
import json
import base64
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename

from services.collection_service import ArchiveCollectionService
from models.archive import ElectronicArchive, ArchiveCategory
from models.user import User
from models import db
from utils.audit_logger import AuditLogger

# 创建蓝图
collection_bp = Blueprint('collection', __name__)

# 初始化服务
collection_service = ArchiveCollectionService()
audit_logger = AuditLogger()

@collection_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload_archive():
    """
    上传电子档案
    """
    try:
        # 获取当前用户
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'success': False,
                'error': '用户不存在',
                'error_code': 'USER_NOT_FOUND'
            }), 404
        
        # 获取请求数据
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': '请求数据为空',
                'error_code': 'EMPTY_DATA'
            }), 400
        
        # 处理文件数据（base64编码的二进制数据）
        processed_data = _process_file_data(data)
        
        # 执行档案采集
        result = collection_service.collect_archive_from_system(processed_data, user_id)
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': result['message'],
                'data': {
                    'archive_id': result['archive_id'],
                    'archive_no': result['archive_no'],
                    'files_count': result['files_saved'],
                    'ocr_results': result['ocr_results'],
                    'integrity_verified': result['integrity_records']
                }
            }), 201
        else:
            return jsonify({
                'success': False,
                'error': result['error'],
                'error_code': result['error_code'],
                'warning': result.get('warning')
            }), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'服务器内部错误: {str(e)}',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@collection_bp.route('/categories', methods=['GET'])
@jwt_required()
def get_categories():
    """
    获取档案分类列表
    """
    try:
        categories = ArchiveCategory.query.filter_by(is_active=True).order_by(ArchiveCategory.sort_order).all()
        
        categories_data = []
        for category in categories:
            categories_data.append({
                'id': category.id,
                'code': category.code,
                'name': category.name,
                'description': category.description,
                'parent_id': category.parent_id,
                'retention_period': category.retention_period,
                'confidentiality_level': category.confidentiality_level
            })
        
        return jsonify({
            'success': True,
            'data': categories_data
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'获取分类失败: {str(e)}',
            'error_code': 'CATEGORIES_FETCH_ERROR'
        }), 500

@collection_bp.route('/validate', methods=['POST'])
@jwt_required()
def validate_upload():
    """
    预验证上传数据
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': '请求数据为空',
                'error_code': 'EMPTY_DATA'
            }), 400
        
        # 基本验证
        validation_result = collection_service._validate_incoming_data(data)
        
        # 重复检测
        duplicate_result = collection_service._check_for_duplicates(data)
        
        return jsonify({
            'success': True,
            'validation': validation_result,
            'duplicate_check': duplicate_result,
            'warnings': _generate_upload_warnings(data)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'验证失败: {str(e)}',
            'error_code': 'VALIDATION_ERROR'
        }), 500

@collection_bp.route('/preview', methods=['POST'])
@jwt_required()
def preview_upload():
    """
    预览上传的档案信息
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': '请求数据为空',
                'error_code': 'EMPTY_DATA'
            }), 400
        
        # 处理文件数据
        processed_data = _process_file_data(data)
        
        # 生成预览信息
        preview_info = _generate_archive_preview(processed_data)
        
        return jsonify({
            'success': True,
            'data': preview_info
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'预览失败: {str(e)}',
            'error_code': 'PREVIEW_ERROR'
        }), 500

@collection_bp.route('/batch-upload', methods=['POST'])
@jwt_required()
def batch_upload():
    """
    批量上传档案
    """
    try:
        # 获取当前用户
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'success': False,
                'error': '用户不存在',
                'error_code': 'USER_NOT_FOUND'
            }), 404
        
        data = request.get_json()
        if not data or 'archives' not in data:
            return jsonify({
                'success': False,
                'error': '缺少档案数据',
                'error_code': 'MISSING_ARCHIVES'
            }), 400
        
        archives = data['archives']
        results = []
        successful_uploads = 0
        
        for i, archive_data in enumerate(archives):
            try:
                # 处理文件数据
                processed_data = _process_file_data(archive_data)
                
                # 执行档案采集
                result = collection_service.collect_archive_from_system(processed_data, user_id)
                
                if result['success']:
                    successful_uploads += 1
                    results.append({
                        'index': i,
                        'success': True,
                        'archive_id': result['archive_id'],
                        'archive_no': result['archive_no']
                    })
                else:
                    results.append({
                        'index': i,
                        'success': False,
                        'error': result['error'],
                        'error_code': result['error_code']
                    })
                    
            except Exception as e:
                results.append({
                    'index': i,
                    'success': False,
                    'error': str(e),
                    'error_code': 'BATCH_UPLOAD_ERROR'
                })
        
        return jsonify({
            'success': successful_uploads > 0,
            'message': f'成功上传 {successful_uploads}/{len(archives)} 个档案',
            'total_count': len(archives),
            'success_count': successful_uploads,
            'failure_count': len(archives) - successful_uploads,
            'results': results
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'批量上传失败: {str(e)}',
            'error_code': 'BATCH_ERROR'
        }), 500

@collection_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_collection_stats():
    """
    获取采集统计信息
    """
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        # 获取最近30天的采集统计
        from datetime import timedelta
        from sqlalchemy import func, desc
        
        since_date = datetime.now() - timedelta(days=30)
        
        # 按日期统计
        daily_stats = db.session.query(
            func.date(ElectronicArchive.created_at).label('date'),
            func.count(ElectronicArchive.id).label('count'),
            func.sum(ElectronicArchive.total_size).label('total_size')
        ).filter(
            ElectronicArchive.created_at >= since_date
        ).group_by(
            func.date(ElectronicArchive.created_at)
        ).order_by(desc('date')).all()
        
        # 按分类统计
        category_stats = db.session.query(
            ArchiveCategory.name.label('category_name'),
            func.count(ElectronicArchive.id).label('count')
        ).join(
            ElectronicArchive, ElectronicArchive.category_id == ArchiveCategory.id
        ).group_by(ArchiveCategory.name).all()
        
        # 总计统计
        total_stats = {
            'total_archives': ElectronicArchive.query.count(),
            'total_size': db.session.query(func.sum(ElectronicArchive.total_size)).scalar() or 0,
            'today_archives': ElectronicArchive.query.filter(
                func.date(ElectronicArchive.created_at) == datetime.now().date()
            ).count(),
            'this_month_archives': ElectronicArchive.query.filter(
                ElectronicArchive.created_at >= datetime.now().replace(day=1)
            ).count()
        }
        
        return jsonify({
            'success': True,
            'data': {
                'total_stats': total_stats,
                'daily_stats': [
                    {
                        'date': stat.date.isoformat(),
                        'count': stat.count,
                        'size_mb': round(stat.total_size / 1024 / 1024, 2) if stat.total_size else 0
                    } for stat in daily_stats
                ],
                'category_stats': [
                    {
                        'category_name': stat.category_name,
                        'count': stat.count
                    } for stat in category_stats
                ]
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'获取统计失败: {str(e)}',
            'error_code': 'STATS_ERROR'
        }), 500

def _process_file_data(data):
    """
    处理文件数据（解码base64）
    """
    processed_data = data.copy()
    
    if 'files' in processed_data:
        for file_info in processed_data['files']:
            if 'content_base64' in file_info:
                try:
                    # 解码base64内容
                    content = base64.b64decode(file_info['content_base64'])
                    file_info['content'] = content
                    del file_info['content_base64']
                except Exception as e:
                    raise ValueError(f"文件内容解码失败: {str(e)}")
    
    return processed_data

def _generate_upload_warnings(data):
    """
    生成上传警告信息
    """
    warnings = []
    
    # 检查文件大小
    total_size = 0
    for file_info in data.get('files', []):
        if 'content' in file_info:
            total_size += len(file_info['content'])
    
    if total_size > 100 * 1024 * 1024:  # 100MB
        warnings.append('档案总大小超过100MB，可能影响上传速度')
    
    # 检查文件类型
    supported_types = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.png', '.jpg', '.jpeg', '.tiff']
    for file_info in data.get('files', []):
        file_name = file_info.get('file_name', '')
        file_ext = os.path.splitext(file_name)[1].lower()
        if file_ext not in supported_types:
            warnings.append(f'文件类型 {file_ext} 可能不被完全支持')
    
    return warnings

def _generate_archive_preview(data):
    """
    生成档案预览信息
    """
    preview = {
        'title': data.get('title', ''),
        'category_id': data.get('category_id'),
        'created_date': data.get('created_date'),
        'file_count': len(data.get('files', [])),
        'total_size': 0,
        'estimated_duration': 0,
        'estimated_ocr_confidence': 0
    }
    
    # 计算文件大小
    for file_info in data.get('files', []):
        if 'content' in file_info:
            preview['total_size'] += len(file_info['content'])
    
    # 估算处理时间（简单估算）
    preview['estimated_duration'] = max(30, len(data.get('files', [])) * 60)  # 最少30秒
    
    # 估算OCR置信度
    image_count = 0
    for file_info in data.get('files', []):
        file_type = file_info.get('file_type', '').lower()
        if file_type in ['.png', '.jpg', '.jpeg', '.bmp', '.tiff']:
            image_count += 1
    
    if image_count > 0:
        preview['estimated_ocr_confidence'] = 75  # 简单估算
    
    return preview