"""
档案分类API - 自动分类、人工确认、批量处理
基于DA/T 94-2022标准的电子会计档案分类服务RESTful API端点
"""
import logging
from datetime import datetime
from typing import List, Dict, Optional, Any
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity

from services.classification_service import AutoClassifierService
from services.security_service import SecurityService
from utils.response_utils import success_response, error_response

logger = logging.getLogger(__name__)

# 创建蓝图
classification_bp = Blueprint('classification', __name__)

# 初始化服务
classification_service = AutoClassifierService()
security_service = SecurityService()

def get_current_user_id():
    """获取当前用户ID"""
    try:
        return get_jwt_identity()
    except:
        return None

# 自动分类档案
@classification_bp.route('/auto-classify/<int:archive_id>', methods=['POST'])
@jwt_required()
def auto_classify_archive(current_user, archive_id):
    """
    对指定档案进行自动归类
    
    URL参数:
    - force_retrain: 是否强制重新训练模型 (默认: false)
    """
    try:
        # 验证用户权限
        current_user_id = get_current_user_id()
        permission_check = security_service.check_permission(
            current_user_id, 
            'archive', 
            'update',
            resource_id=archive_id
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        # 获取请求参数
        force_retrain = request.args.get('force_retrain', 'false').lower() == 'true'
        
        # 执行自动归类
        result = classification_service.classify_archive(
            archive_id=archive_id,
            force_retrain=force_retrain
        )
        
        if result['success']:
            response_data = {
                'archive_id': archive_id,
                'classification_result': result
            }
            
            # 如果是自动分类成功，记录操作日志
            if result.get('auto_classified'):
                response_data['message'] = '自动归类成功并已更新档案分类'
            else:
                response_data['message'] = '已生成归类建议，需要人工确认'
            
            return success_response(response_data['message'], response_data)
        else:
            return error_response(
                result.get('error', '自动归类失败'),
                result.get('error_code', 'AUTO_CLASSIFICATION_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"自动分类档案API错误: {str(e)}")
        return error_response('自动分类服务异常', 'AUTO_CLASSIFICATION_SERVICE_ERROR', 500)

# 训练分类模型
@classification_bp.route('/train-model', methods=['POST'])
@jwt_required()
def train_classification_model(current_user):
    """
    训练自动分类模型
    
    请求体:
    {
        "force_retrain": false, // 是否强制重新训练
        "validation_split": 0.2, // 验证集比例
        "test_data_only": false // 是否仅使用测试数据训练
    }
    """
    try:
        # 验证用户权限（需要管理员权限）
        current_user_id = get_current_user_id()
        permission_check = security_service.check_permission(
            current_user_id, 
            'classification', 
            'train'
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        # 获取请求参数
        data = request.get_json() or {}
        force_retrain = data.get('force_retrain', False)
        validation_split = data.get('validation_split', 0.2)
        test_data_only = data.get('test_data_only', False)
        
        # 训练分类模型
        result = classification_service.train_classifier_model(
            force_retrain=force_retrain
        )
        
        if result['success']:
            # 记录训练操作
            audit_info = {
                'user_id': current_user_id,
                'action': 'train_classification_model',
                'details': {
                    'force_retrain': force_retrain,
                    'model_exists': result.get('model_exists', False),
                    'training_samples': result.get('training_samples', 0),
                    'training_time': result.get('training_time'),
                    'validation_accuracy': result.get('validation_accuracy'),
                    'test_accuracy': result.get('test_accuracy')
                }
            }
            
            return success_response('分类模型训练成功', {
                'model_info': result.get('model_info', {}),
                'training_samples': result.get('training_samples', 0),
                'training_time': result.get('training_time'),
                'validation_accuracy': result.get('validation_accuracy'),
                'test_accuracy': result.get('test_accuracy'),
                'classification_report': result.get('classification_report', {}),
                'model_exists': result.get('model_exists', False)
            })
        else:
            return error_response(
                result.get('error', '模型训练失败'),
                result.get('error_code', 'MODEL_TRAINING_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"训练分类模型API错误: {str(e)}")
        return error_response('训练分类模型服务异常', 'MODEL_TRAINING_SERVICE_ERROR', 500)

# 获取分类建议
@classification_bp.route('/suggest/<int:archive_id>', methods=['GET'])
@jwt_required()
def get_classification_suggestion(current_user, archive_id):
    """
    获取档案分类建议
    
    URL参数:
    - include_confidence: 是否包含置信度信息 (默认: true)
    - include_evidence: 是否包含证据信息 (默认: true)
    """
    try:
        # 验证用户权限
        current_user_id = get_current_user_id()
        permission_check = security_service.check_permission(
            current_user_id, 
            'archive', 
            'read',
            resource_id=archive_id
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        # 获取查询参数
        include_confidence = request.args.get('include_confidence', 'true').lower() == 'true'
        include_evidence = request.args.get('include_evidence', 'true').lower() == 'true'
        
        # 获取分类建议
        result = classification_service.get_classification_suggestion(
            archive_id=archive_id,
            include_confidence=include_confidence,
            include_evidence=include_evidence
        )
        
        if result['success']:
            return success_response('获取分类建议成功', {
                'archive_id': archive_id,
                'suggestion': result['data']
            })
        else:
            return error_response(
                result.get('error', '获取分类建议失败'),
                result.get('error_code', 'GET_CLASSIFICATION_SUGGESTION_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"获取分类建议API错误: {str(e)}")
        return error_response('获取分类建议服务异常', 'CLASSIFICATION_SUGGESTION_SERVICE_ERROR', 500)

# 手动分类档案
@classification_bp.route('/manual-classify/<int:archive_id>', methods=['POST'])
@jwt_required()
def manual_classify_archive(current_user, archive_id):
    """
    手动分类档案
    
    请求体:
    {
        "category_id": 1, // 档案分类ID
        "confidence": 0.95, // 分类置信度 (0-1)
        "reason": "人工确认根据文档内容判断", // 分类理由
        "evidence": ["关键词匹配", "内容分析"] // 分类证据
    }
    """
    try:
        # 验证用户权限
        current_user_id = get_current_user_id()
        permission_check = security_service.check_permission(
            current_user_id, 
            'archive', 
            'update',
            resource_id=archive_id
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        # 获取请求参数
        data = request.get_json()
        category_id = data.get('category_id')
        confidence = data.get('confidence', 1.0)
        reason = data.get('reason', '人工分类')
        evidence = data.get('evidence', [])
        
        if not category_id:
            return error_response('缺少分类ID', 'MISSING_CATEGORY_ID', 400)
        
        # 手动分类档案
        result = classification_service.manual_classify_archive(
            archive_id=archive_id,
            category_id=category_id,
            user_id=current_user_id,
            confidence=confidence,
            reason=reason,
            evidence=evidence
        )
        
        if result['success']:
            return success_response('手动分类成功', {
                'archive_id': archive_id,
                'category_id': category_id,
                'classification_method': 'manual',
                'confidence': confidence,
                'reason': reason,
                'evidence': evidence,
                'classified_by': current_user_id,
                'classified_at': datetime.utcnow().isoformat()
            })
        else:
            return error_response(
                result.get('error', '手动分类失败'),
                result.get('error_code', 'MANUAL_CLASSIFICATION_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"手动分类档案API错误: {str(e)}")
        return error_response('手动分类服务异常', 'MANUAL_CLASSIFICATION_SERVICE_ERROR', 500)

# 批量分类档案
@classification_bp.route('/batch-classify', methods=['POST'])
@jwt_required()
def batch_classify_archives(current_user):
    """
    批量分类档案
    
    请求体:
    {
        "archive_ids": [1, 2, 3], // 档案ID列表
        "auto_classify": true, // 是否使用自动分类
        "category_id": 1, // 手动指定的分类ID（当auto_classify=false时必须）
        "force_retrain": false, // 是否强制重新训练模型
        "max_concurrent": 5 // 最大并发数
    }
    """
    try:
        # 验证用户权限
        current_user_id = get_current_user_id()
        permission_check = security_service.check_permission(
            current_user_id, 
            'archive', 
            'update'
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        # 获取请求参数
        data = request.get_json()
        archive_ids = data.get('archive_ids', [])
        auto_classify = data.get('auto_classify', True)
        category_id = data.get('category_id')
        force_retrain = data.get('force_retrain', False)
        max_concurrent = data.get('max_concurrent', 5)
        
        if not archive_ids:
            return error_response('缺少档案ID列表', 'MISSING_ARCHIVE_IDS', 400)
        
        if len(archive_ids) > 100:  # 限制批量操作数量
            return error_response('批量分类数量超限', 'BATCH_CLASSIFICATION_LIMIT_EXCEEDED', 400)
        
        if not auto_classify and not category_id:
            return error_response('手动分类时必须提供分类ID', 'MISSING_CATEGORY_ID', 400)
        
        # 批量分类档案
        result = classification_service.batch_classify_archives(
            archive_ids=archive_ids,
            auto_classify=auto_classify,
            category_id=category_id,
            user_id=current_user_id,
            force_retrain=force_retrain,
            max_concurrent=max_concurrent
        )
        
        if result['success']:
            return success_response('批量分类完成', {
                'total_archives': len(archive_ids),
                'successfully_classified': result['data']['successfully_classified'],
                'failed_count': result['data']['failed_count'],
                'auto_classified_count': result['data'].get('auto_classified_count', 0),
                'manual_classified_count': result['data'].get('manual_classified_count', 0),
                'classification_details': result['data'].get('classification_details', []),
                'processing_time': result['data'].get('processing_time')
            })
        else:
            return error_response(
                result.get('error', '批量分类失败'),
                result.get('error_code', 'BATCH_CLASSIFICATION_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"批量分类档案API错误: {str(e)}")
        return error_response('批量分类服务异常', 'BATCH_CLASSIFICATION_SERVICE_ERROR', 500)

# 获取分类统计信息
@classification_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_classification_stats(current_user):
    """
    获取分类统计信息
    
    URL参数:
    - date_range: 日期范围 (7d, 30d, 90d, 1y)
    - include_trends: 是否包含趋势信息 (默认: true)
    - category_filter: 分类过滤 (逗号分隔的分类ID)
    """
    try:
        # 验证用户权限
        current_user_id = get_current_user_id()
        permission_check = security_service.check_permission(
            current_user_id, 
            'classification', 
            'read'
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        # 获取查询参数
        date_range = request.args.get('date_range', '30d')
        include_trends = request.args.get('include_trends', 'true').lower() == 'true'
        category_filter = request.args.get('category_filter')
        
        # 获取分类统计
        result = classification_service.get_classification_statistics(
            date_range=date_range,
            include_trends=include_trends,
            category_filter=category_filter
        )
        
        if result['success']:
            return success_response('获取分类统计成功', {
                'statistics': result['data'],
                'date_range': date_range,
                'include_trends': include_trends,
                'generated_at': datetime.utcnow().isoformat()
            })
        else:
            return error_response(
                result.get('error', '获取分类统计失败'),
                result.get('error_code', 'GET_CLASSIFICATION_STATS_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"获取分类统计API错误: {str(e)}")
        return error_response('获取分类统计服务异常', 'CLASSIFICATION_STATS_SERVICE_ERROR', 500)

# 获取关键词规则
@classification_bp.route('/keyword-rules', methods=['GET'])
@jwt_required()
def get_keyword_rules(current_user):
    """
    获取关键词匹配规则
    """
    try:
        # 验证用户权限（需要管理员权限）
        current_user_id = get_current_user_id()
        permission_check = security_service.check_permission(
            current_user_id, 
            'classification', 
            'admin'
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        result = classification_service.get_keyword_rules()
        
        if result['success']:
            return success_response('获取关键词规则成功', {
                'keyword_rules': result['data']
            })
        else:
            return error_response(
                result.get('error', '获取关键词规则失败'),
                result.get('error_code', 'GET_KEYWORD_RULES_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"获取关键词规则API错误: {str(e)}")
        return error_response('获取关键词规则服务异常', 'KEYWORD_RULES_SERVICE_ERROR', 500)

# 更新关键词规则
@classification_bp.route('/keyword-rules', methods=['PUT'])
@jwt_required()
def update_keyword_rules(current_user):
    """
    更新关键词匹配规则
    
    请求体:
    {
        "category_code": "voucher",
        "keywords": ["记账凭证", "转账凭证"],
        "patterns": [r"记\\d{4}号"],
        "confidence_threshold": 0.8
    }
    """
    try:
        # 验证用户权限（需要管理员权限）
        current_user_id = get_current_user_id()
        permission_check = security_service.check_permission(
            current_user_id, 
            'classification', 
            'admin'
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        # 获取请求参数
        data = request.get_json()
        category_code = data.get('category_code')
        keywords = data.get('keywords', [])
        patterns = data.get('patterns', [])
        confidence_threshold = data.get('confidence_threshold', 0.7)
        
        if not category_code:
            return error_response('缺少分类代码', 'MISSING_CATEGORY_CODE', 400)
        
        # 更新关键词规则
        result = classification_service.update_keyword_rules(
            category_code=category_code,
            keywords=keywords,
            patterns=patterns,
            confidence_threshold=confidence_threshold,
            user_id=current_user_id
        )
        
        if result['success']:
            return success_response('关键词规则更新成功', {
                'category_code': category_code,
                'updated_by': current_user_id,
                'updated_at': datetime.utcnow().isoformat()
            })
        else:
            return error_response(
                result.get('error', '更新关键词规则失败'),
                result.get('error_code', 'UPDATE_KEYWORD_RULES_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"更新关键词规则API错误: {str(e)}")
        return error_response('更新关键词规则服务异常', 'UPDATE_KEYWORD_RULES_SERVICE_ERROR', 500)

# 获取模型性能信息
@classification_bp.route('/model-performance', methods=['GET'])
@jwt_required()
def get_model_performance(current_user):
    """
    获取分类模型性能信息
    """
    try:
        # 验证用户权限（需要管理员权限）
        current_user_id = get_current_user_id()
        permission_check = security_service.check_permission(
            current_user_id, 
            'classification', 
            'admin'
        )
        
        if not permission_check['allowed']:
            return error_response('权限不足', 'INSUFFICIENT_PERMISSIONS', 403)
        
        result = classification_service.get_model_performance()
        
        if result['success']:
            return success_response('获取模型性能成功', {
                'performance': result['data']
            })
        else:
            return error_response(
                result.get('error', '获取模型性能失败'),
                result.get('error_code', 'GET_MODEL_PERFORMANCE_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"获取模型性能API错误: {str(e)}")
        return error_response('获取模型性能服务异常', 'MODEL_PERFORMANCE_SERVICE_ERROR', 500)

# 错误处理
@classification_bp.errorhandler(400)
def bad_request(error):
    return error_response('请求参数错误', 'BAD_REQUEST', 400)

@classification_bp.errorhandler(403)
def forbidden(error):
    return error_response('访问被禁止', 'FORBIDDEN', 403)

@classification_bp.errorhandler(500)
def internal_error(error):
    return error_response('服务器内部错误', 'INTERNAL_SERVER_ERROR', 500)