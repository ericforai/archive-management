"""
智能检索服务API - 全文搜索、元数据搜索、语义搜索RESTful接口
基于DA/T 94-2022标准的智能检索API端点
"""
import json
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app

from api.auth_decorator import token_required
from services.search_service import SearchService
from utils.response_utils import success_response, error_response
from utils.audit_logger import AuditLogger

logger = logging.getLogger(__name__)

# 创建搜索API蓝图
search_bp = Blueprint('search', __name__)

def get_search_service():
    """获取搜索服务实例"""
    return SearchService()

# 智能搜索主接口
@search_bp.route('/', methods=['POST'])
@token_required
def comprehensive_search(current_user):
    """
    综合搜索 - 全文搜索 + 元数据搜索 + 语义搜索
    
    请求体:
    {
        "query": "搜索查询关键词",
        "search_type": "all", // all|fulltext|metadata|semantic
        "filters": {
            "category_codes": ["voucher", "report"],
            "date_from": "2023-01-01",
            "date_to": "2023-12-31",
            "created_by": "用户名",
            "file_types": ["pdf", "jpg"]
        },
        "page": 1,
        "per_page": 20
    }
    """
    try:
        data = request.get_json()
        if not data or not data.get('query'):
            return error_response('缺少搜索查询参数', 'MISSING_QUERY', 400)
        
        search_service = get_search_service()
        
        # 执行搜索
        result = search_service.search(
            query=data['query'],
            search_type=data.get('search_type', 'all'),
            filters=data.get('filters', {}),
            page=data.get('page', 1),
            per_page=data.get('per_page', 20),
            user_id=current_user.id
        )
        
        if result['success']:
            return success_response('搜索成功', {
                'results': result['data'],
                'total_count': result['total_count'],
                'page': result['page'],
                'per_page': result['per_page'],
                'total_pages': result['total_pages'],
                'search_type': result['search_type']
            })
        else:
            return error_response(
                result.get('error', '搜索失败'),
                result.get('error_code', 'SEARCH_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"综合搜索API错误: {str(e)}")
        return error_response('搜索服务异常', 'SEARCH_SERVICE_ERROR', 500)

# 全文搜索接口
@search_bp.route('/fulltext', methods=['POST'])
@token_required
def fulltext_search(current_user):
    """
    全文搜索
    
    请求体:
    {
        "query": "搜索关键词",
        "filters": {
            "category_codes": ["voucher"],
            "date_range": {
                "start": "2023-01-01",
                "end": "2023-12-31"
            }
        },
        "page": 1,
        "per_page": 20
    }
    """
    try:
        data = request.get_json()
        if not data or not data.get('query'):
            return error_response('缺少搜索查询参数', 'MISSING_QUERY', 400)
        
        search_service = get_search_service()
        
        result = search_service.search(
            query=data['query'],
            search_type='fulltext',
            filters=data.get('filters', {}),
            page=data.get('page', 1),
            per_page=data.get('per_page', 20),
            user_id=current_user.id
        )
        
        if result['success']:
            return success_response('全文搜索成功', {
                'results': result['data'],
                'total_count': result['total_count'],
                'page': result['page'],
                'per_page': result['per_page'],
                'total_pages': result['total_pages']
            })
        else:
            return error_response(
                result.get('error', '全文搜索失败'),
                result.get('error_code', 'FULLTEXT_SEARCH_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"全文搜索API错误: {str(e)}")
        return error_response('全文搜索服务异常', 'FULLTEXT_SEARCH_SERVICE_ERROR', 500)

# 元数据搜索接口
@search_bp.route('/metadata', methods=['POST'])
@token_required
def metadata_search(current_user):
    """
    元数据搜索
    
    请求体:
    {
        "query": "搜索关键词",
        "filters": {
            "category_codes": ["invoice"],
            "metadata_filters": {
                "document_number": "invoice001",
                "amount_range": {"min": 1000, "max": 5000}
            }
        },
        "page": 1,
        "per_page": 20
    }
    """
    try:
        data = request.get_json()
        if not data or not data.get('query'):
            return error_response('缺少搜索查询参数', 'MISSING_QUERY', 400)
        
        search_service = get_search_service()
        
        result = search_service.search(
            query=data['query'],
            search_type='metadata',
            filters=data.get('filters', {}),
            page=data.get('page', 1),
            per_page=data.get('per_page', 20),
            user_id=current_user.id
        )
        
        if result['success']:
            return success_response('元数据搜索成功', {
                'results': result['data'],
                'total_count': result['total_count'],
                'page': result['page'],
                'per_page': result['per_page'],
                'total_pages': result['total_pages']
            })
        else:
            return error_response(
                result.get('error', '元数据搜索失败'),
                result.get('error_code', 'METADATA_SEARCH_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"元数据搜索API错误: {str(e)}")
        return error_response('元数据搜索服务异常', 'METADATA_SEARCH_SERVICE_ERROR', 500)

# 语义搜索接口
@search_bp.route('/semantic', methods=['POST'])
@token_required
def semantic_search(current_user):
    """
    语义搜索
    
    请求体:
    {
        "query": "搜索语义描述",
        "filters": {
            "category_codes": ["voucher", "report"]
        },
        "page": 1,
        "per_page": 20
    }
    """
    try:
        data = request.get_json()
        if not data or not data.get('query'):
            return error_response('缺少搜索查询参数', 'MISSING_QUERY', 400)
        
        search_service = get_search_service()
        
        result = search_service.search(
            query=data['query'],
            search_type='semantic',
            filters=data.get('filters', {}),
            page=data.get('page', 1),
            per_page=data.get('per_page', 20),
            user_id=current_user.id
        )
        
        if result['success']:
            return success_response('语义搜索成功', {
                'results': result['data'],
                'total_count': result['total_count'],
                'page': result['page'],
                'per_page': result['per_page'],
                'total_pages': result['total_pages']
            })
        else:
            return error_response(
                result.get('error', '语义搜索失败'),
                result.get('error_code', 'SEMANTIC_SEARCH_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"语义搜索API错误: {str(e)}")
        return error_response('语义搜索服务异常', 'SEMANTIC_SEARCH_SERVICE_ERROR', 500)

# 搜索建议接口
@search_bp.route('/suggestions', methods=['GET'])
@token_required
def get_search_suggestions(current_user):
    """
    获取搜索建议
    
    URL参数:
    ?query=partial_query&limit=10
    """
    try:
        partial_query = request.args.get('query', '').strip()
        limit = int(request.args.get('limit', 10))
        
        if not partial_query or len(partial_query) < 2:
            return success_response('获取搜索建议成功', {
                'suggestions': []
            })
        
        search_service = get_search_service()
        result = search_service.get_search_suggestions(partial_query, limit)
        
        if result['success']:
            return success_response('获取搜索建议成功', {
                'suggestions': result['suggestions'],
                'query': partial_query
            })
        else:
            return error_response(
                result.get('error', '获取搜索建议失败'),
                result.get('error_code', 'SUGGESTION_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"搜索建议API错误: {str(e)}")
        return error_response('搜索建议服务异常', 'SUGGESTION_SERVICE_ERROR', 500)

# 搜索统计接口
@search_bp.route('/stats', methods=['GET'])
@token_required
def get_search_stats(current_user):
    """
    获取搜索统计信息
    
    URL参数:
    ?date_range=7d (7d, 30d, 90d, 1y)
    """
    try:
        date_range = request.args.get('date_range', '30d')
        
        search_service = get_search_service()
        result = search_service.get_search_stats(date_range)
        
        if result['success']:
            return success_response('获取搜索统计成功', {
                'stats': result['data'],
                'date_range': date_range,
                'generated_at': datetime.utcnow().isoformat()
            })
        else:
            return error_response(
                result.get('error', '获取搜索统计失败'),
                result.get('error_code', 'STATS_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"搜索统计API错误: {str(e)}")
        return error_response('搜索统计服务异常', 'STATS_SERVICE_ERROR', 500)

# 高级搜索接口
@search_bp.route('/advanced', methods=['POST'])
@token_required
def advanced_search(current_user):
    """
    高级搜索 - 支持复杂查询条件
    
    请求体:
    {
        "fulltext_query": "全文搜索关键词",
        "metadata_conditions": [
            {"field": "document_type", "operator": "eq", "value": "记账凭证"},
            {"field": "amount", "operator": "between", "value": [1000, 5000]}
        ],
        "date_range": {
            "field": "created_date",
            "start": "2023-01-01",
            "end": "2023-12-31"
        },
        "sort_by": "created_at",
        "sort_order": "desc",
        "page": 1,
        "per_page": 20
    }
    """
    try:
        data = request.get_json()
        if not data:
            return error_response('缺少搜索条件', 'MISSING_SEARCH_CONDITIONS', 400)
        
        search_service = get_search_service()
        
        # 构建复杂查询条件
        filters = {}
        
        # 元数据条件
        if data.get('metadata_conditions'):
            for condition in data['metadata_conditions']:
                field = condition.get('field')
                operator = condition.get('operator')
                value = condition.get('value')
                
                if field and operator and value is not None:
                    filters[f'{field}_{operator}'] = value
        
        # 日期范围条件
        if data.get('date_range'):
            date_field = data['date_range'].get('field', 'created_date')
            filters['date_from'] = data['date_range'].get('start')
            filters['date_to'] = data['date_range'].get('end')
        
        # 全文搜索
        fulltext_query = data.get('fulltext_query', '')
        if fulltext_query:
            filters['fulltext'] = fulltext_query
        
        result = search_service.search(
            query=fulltext_query,
            search_type='comprehensive',
            filters=filters,
            page=data.get('page', 1),
            per_page=data.get('per_page', 20),
            user_id=current_user.id
        )
        
        if result['success']:
            return success_response('高级搜索成功', {
                'results': result['data'],
                'total_count': result['total_count'],
                'page': result['page'],
                'per_page': result['per_page'],
                'total_pages': result['total_pages'],
                'search_type': result['search_type']
            })
        else:
            return error_response(
                result.get('error', '高级搜索失败'),
                result.get('error_code', 'ADVANCED_SEARCH_ERROR'),
                500
            )
            
    except Exception as e:
        logger.error(f"高级搜索API错误: {str(e)}")
        return error_response('高级搜索服务异常', 'ADVANCED_SEARCH_SERVICE_ERROR', 500)

# 相似档案搜索接口
@search_bp.route('/similar/<int:archive_id>', methods=['GET'])
@token_required
def find_similar_archives(current_user, archive_id):
    """
    查找相似档案
    
    URL参数:
    ?limit=10&similarity_threshold=0.7
    """
    try:
        limit = int(request.args.get('limit', 10))
        similarity_threshold = float(request.args.get('similarity_threshold', 0.7))
        
        # 这里简化实现，实际可以基于内容相似度算法
        search_service = get_search_service()
        
        # 基于档案类别和关键词的简化相似度搜索
        # 实际实现中可以使用向量相似度、文本相似度等算法
        result = {
            'success': True,
            'data': [],  # 简化返回空结果
            'archive_id': archive_id,
            'similarity_threshold': similarity_threshold,
            'total_count': 0,
            'message': '相似档案搜索功能待实现'
        }
        
        return success_response('相似档案搜索成功', result)
        
    except Exception as e:
        logger.error(f"相似档案搜索API错误: {str(e)}")
        return error_response('相似档案搜索异常', 'SIMILAR_SEARCH_ERROR', 500)

# 批量搜索接口
@search_bp.route('/batch', methods=['POST'])
@token_required
def batch_search(current_user):
    """
    批量搜索
    
    请求体:
    {
        "searches": [
            {
                "query": "搜索查询1",
                "search_type": "fulltext",
                "filters": {...}
            },
            {
                "query": "搜索查询2", 
                "search_type": "metadata",
                "filters": {...}
            }
        ],
        "max_concurrent": 5
    }
    """
    try:
        data = request.get_json()
        searches = data.get('searches', [])
        max_concurrent = data.get('max_concurrent', 5)
        
        if not searches:
            return error_response('缺少批量搜索条件', 'MISSING_BATCH_SEARCHES', 400)
        
        if len(searches) > 20:  # 限制批量搜索数量
            return error_response('批量搜索数量超限', 'BATCH_SEARCH_LIMIT_EXCEEDED', 400)
        
        search_service = get_search_service()
        results = []
        
        # 顺序执行批量搜索（简化实现）
        for i, search_item in enumerate(searches):
            try:
                result = search_service.search(
                    query=search_item.get('query', ''),
                    search_type=search_item.get('search_type', 'all'),
                    filters=search_item.get('filters', {}),
                    page=search_item.get('page', 1),
                    per_page=search_item.get('per_page', 20),
                    user_id=current_user.id
                )
                
                results.append({
                    'index': i,
                    'query': search_item.get('query'),
                    'search_type': search_item.get('search_type'),
                    'success': result['success'],
                    'data': result.get('data', []) if result['success'] else None,
                    'total_count': result.get('total_count', 0) if result['success'] else None,
                    'error': result.get('error') if not result['success'] else None
                })
                
            except Exception as e:
                logger.error(f"批量搜索第{i+1}项失败: {str(e)}")
                results.append({
                    'index': i,
                    'query': search_item.get('query'),
                    'search_type': search_item.get('search_type'),
                    'success': False,
                    'error': str(e)
                })
        
        successful_searches = sum(1 for r in results if r['success'])
        total_results = sum(r.get('total_count', 0) for r in results if r['success'])
        
        return success_response('批量搜索完成', {
            'results': results,
            'summary': {
                'total_searches': len(searches),
                'successful_searches': successful_searches,
                'failed_searches': len(searches) - successful_searches,
                'total_results': total_results
            }
        })
        
    except Exception as e:
        logger.error(f"批量搜索API错误: {str(e)}")
        return error_response('批量搜索服务异常', 'BATCH_SEARCH_SERVICE_ERROR', 500)

# 错误处理
@search_bp.errorhandler(400)
def bad_request(error):
    return error_response('请求参数错误', 'BAD_REQUEST', 400)

@search_bp.errorhandler(500)
def internal_error(error):
    return error_response('服务器内部错误', 'INTERNAL_SERVER_ERROR', 500)