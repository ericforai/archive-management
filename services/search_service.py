"""
智能检索服务 - 全文搜索、元数据搜索、语义搜索
基于DA/T 94-2022标准的智能检索模块
"""
import re
import json
import jieba
import logging
from datetime import datetime
from collections import defaultdict
from flask import current_app
from sqlalchemy import func, text, or_, and_
from sqlalchemy.orm import joinedload

from models.archive import ElectronicArchive, ArchiveFile, ArchiveMetadata
from models.audit import AuditLog
from models.user import User
from models import db
from utils.audit_logger import AuditLogger

logger = logging.getLogger(__name__)

class SearchService:
    """智能检索服务"""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
        self.search_history = defaultdict(int)  # 搜索历史统计
        self.hot_keywords = defaultdict(int)    # 热门关键词统计
        
        # 初始化中文分词词典
        self._init_jieba()
    
    def _init_jieba(self):
        """初始化jieba分词词典"""
        # 添加会计专业术语
        accounting_terms = [
            '记账凭证', '会计凭证', '借方', '贷方', '借', '贷', '借方科目', '贷方科目',
            '会计科目', '会计分录', '原始凭证', '记账凭证', '总账', '明细账', '日记账',
            '资产负债表', '利润表', '现金流量表', '所有者权益变动表', '财务报表',
            '营业收入', '营业成本', '期间费用', '管理费用', '财务费用', '销售费用',
            '资产减值损失', '公允价值变动收益', '投资收益', '营业外收入', '营业外支出',
            '利润总额', '所得税费用', '净利润', '未分配利润', '盈余公积',
            '库存现金', '银行存款', '应收账款', '预付账款', '其他应收款', '存货',
            '固定资产', '累计折旧', '无形资产', '长期股权投资', '投资性房地产',
            '短期借款', '长期借款', '应付账款', '预收账款', '其他应付款', '应付职工薪酬',
            '应交税费', '实收资本', '资本公积', '盈余公积'
        ]
        
        for term in accounting_terms:
            jieba.add_word(term)
    
    def search(self, query, search_type='all', filters=None, page=1, per_page=20, user_id=None):
        """
        智能搜索
        
        Args:
            query: 搜索查询
            search_type: 搜索类型 (all|fulltext|metadata|semantic)
            filters: 搜索过滤器
            page: 页码
            per_page: 每页数量
            user_id: 用户ID
            
        Returns:
            dict: 搜索结果
        """
        try:
            # 记录搜索历史
            if user_id:
                self._record_search_history(query, user_id)
            
            # 预处理搜索查询
            processed_query = self._preprocess_query(query)
            
            # 根据搜索类型执行搜索
            if search_type == 'fulltext':
                result = self._fulltext_search(processed_query, filters, page, per_page)
            elif search_type == 'metadata':
                result = self._metadata_search(processed_query, filters, page, per_page)
            elif search_type == 'semantic':
                result = self._semantic_search(processed_query, filters, page, per_page)
            else:  # all
                result = self._comprehensive_search(processed_query, filters, page, per_page)
            
            # 记录搜索操作审计
            if user_id:
                self.audit_logger.log_operation(
                    user_id=user_id,
                    operation_type='search',
                    resource_type='archive',
                    operation_details={
                        'query': query,
                        'processed_query': processed_query,
                        'search_type': search_type,
                        'result_count': result.get('total_count', 0),
                        'filters': filters,
                        'page': page,
                        'per_page': per_page
                    }
                )
            
            return result
            
        except Exception as e:
            logger.error(f"智能搜索失败: {str(e)}")
            return {
                'success': False,
                'error': f'搜索失败: {str(e)}',
                'error_code': 'SEARCH_ERROR',
                'data': [],
                'total_count': 0
            }
    
    def _preprocess_query(self, query):
        """
        预处理搜索查询
        """
        # 去除首尾空格
        query = query.strip()
        
        # 转换为中文分词结果
        if self._contains_chinese(query):
            words = jieba.lcut(query)
            # 过滤停用词
            filtered_words = self._filter_stop_words(words)
            return ' '.join(filtered_words)
        else:
            # 英文处理：转小写，移除标点
            query = re.sub(r'[^\w\s]', ' ', query.lower())
            words = query.split()
            return ' '.join(words)
    
    def _fulltext_search(self, processed_query, filters, page, per_page):
        """
        全文搜索
        """
        try:
            # 获取文本内容（从数据库中的content字段或OCR结果）
            query = db.session.query(ElectronicArchive)\
                .options(joinedload(ElectronicArchive.category))\
                .filter(ElectronicArchive.status == 'active')
            
            # 应用全文搜索条件
            if processed_query:
                search_words = processed_query.split()
                fulltext_conditions = []
                
                for word in search_words:
                    if len(word) >= 2:  # 忽略单字符搜索词
                        fulltext_conditions.extend([
                            ElectronicArchive.title.ilike(f'%{word}%'),
                            ElectronicArchive.description.ilike(f'%{word}%'),
                            ElectronicArchive.content.ilike(f'%{word}%'),
                            ElectronicArchive.ocr_text.ilike(f'%{word}%')
                        ])
                
                if fulltext_conditions:
                    query = query.filter(or_(*fulltext_conditions))
            
            # 应用过滤器
            query = self._apply_filters(query, filters)
            
            # 排序：匹配度优先，然后按创建时间倒序
            if processed_query:
                query = query.order_by(
                    ElectronicArchive.created_at.desc(),
                    ElectronicArchive.title.asc()
                )
            else:
                query = query.order_by(ElectronicArchive.created_at.desc())
            
            # 分页查询
            total_count = query.count()
            archives = query.offset((page - 1) * per_page).limit(per_page).all()
            
            # 构建结果
            results = self._format_search_results(archives, processed_query, 'fulltext')
            
            return {
                'success': True,
                'data': results,
                'total_count': total_count,
                'page': page,
                'per_page': per_page,
                'total_pages': (total_count + per_page - 1) // per_page,
                'search_type': 'fulltext'
            }
            
        except Exception as e:
            logger.error(f"全文搜索失败: {str(e)}")
            return {
                'success': False,
                'error': f'全文搜索失败: {str(e)}',
                'error_code': 'FULLTEXT_SEARCH_ERROR',
                'data': [],
                'total_count': 0
            }
    
    def _metadata_search(self, processed_query, filters, page, per_page):
        """
        元数据搜索
        """
        try:
            query = db.session.query(ElectronicArchive)\
                .options(joinedload(ElectronicArchive.category))\
                .join(ArchiveMetadata)\
                .filter(
                    ElectronicArchive.status == 'active',
                    ArchiveMetadata.metadata_value.ilike(f'%{processed_query}%')
                )\
                .distinct()
            
            # 应用过滤器
            query = self._apply_filters(query, filters)
            
            # 排序
            query = query.order_by(ElectronicArchive.created_at.desc())
            
            # 分页查询
            total_count = query.count()
            archives = query.offset((page - 1) * per_page).limit(per_page).all()
            
            # 构建结果
            results = self._format_search_results(archives, processed_query, 'metadata')
            
            return {
                'success': True,
                'data': results,
                'total_count': total_count,
                'page': page,
                'per_page': per_page,
                'total_pages': (total_count + per_page - 1) // per_page,
                'search_type': 'metadata'
            }
            
        except Exception as e:
            logger.error(f"元数据搜索失败: {str(e)}")
            return {
                'success': False,
                'error': f'元数据搜索失败: {str(e)}',
                'error_code': 'METADATA_SEARCH_ERROR',
                'data': [],
                'total_count': 0
            }
    
    def _semantic_search(self, processed_query, filters, page, per_page):
        """
        语义搜索（简化版本，使用关键词扩展和同义词匹配）
        """
        try:
            # 扩展查询关键词
            expanded_query = self._expand_query_semantic(processed_query)
            
            query = db.session.query(ElectronicArchive)\
                .options(joinedload(ElectronicArchive.category))\
                .filter(ElectronicArchive.status == 'active')
            
            # 构建语义搜索条件
            semantic_conditions = []
            for word in expanded_query:
                if len(word) >= 2:
                    semantic_conditions.extend([
                        ElectronicArchive.title.ilike(f'%{word}%'),
                        ElectronicArchive.description.ilike(f'%{word}%'),
                        ElectronicArchive.ocr_text.ilike(f'%{word}%'),
                        ElectronicArchive.content.ilike(f'%{word}%')
                    ])
            
            if semantic_conditions:
                query = query.filter(or_(*semantic_conditions))
            
            # 应用过滤器
            query = self._apply_filters(query, filters)
            
            # 语义排序（基于相关性评分）
            query = query.order_by(ElectronicArchive.created_at.desc())
            
            # 分页查询
            total_count = query.count()
            archives = query.offset((page - 1) * per_page).limit(per_page).all()
            
            # 构建结果
            results = self._format_search_results(archives, expanded_query, 'semantic')
            
            return {
                'success': True,
                'data': results,
                'total_count': total_count,
                'page': page,
                'per_page': per_page,
                'total_pages': (total_count + per_page - 1) // per_page,
                'search_type': 'semantic'
            }
            
        except Exception as e:
            logger.error(f"语义搜索失败: {str(e)}")
            return {
                'success': False,
                'error': f'语义搜索失败: {str(e)}',
                'error_code': 'SEMANTIC_SEARCH_ERROR',
                'data': [],
                'total_count': 0
            }
    
    def _comprehensive_search(self, processed_query, filters, page, per_page):
        """
        综合搜索（全文+元数据+语义）
        """
        try:
            # 并行执行多种搜索
            fulltext_result = self._fulltext_search(processed_query, filters, 1, 100)
            metadata_result = self._metadata_search(processed_query, filters, 1, 100)
            semantic_result = self._semantic_search(processed_query, filters, 1, 100)
            
            # 合并结果并去重
            all_results = {}
            
            # 添加全文搜索结果（权重最高）
            for item in fulltext_result.get('data', []):
                all_results[item['id']] = {
                    **item,
                    'relevance_score': item.get('relevance_score', 100) + 100,
                    'match_type': 'fulltext'
                }
            
            # 添加元数据搜索结果（权重中等）
            for item in metadata_result.get('data', []):
                if item['id'] not in all_results:
                    all_results[item['id']] = {
                        **item,
                        'relevance_score': item.get('relevance_score', 100) + 50,
                        'match_type': 'metadata'
                    }
                else:
                    # 如果已存在，增加权重
                    all_results[item['id']]['relevance_score'] += 30
                    all_results[item['id']]['match_type'] += ',metadata'
            
            # 添加语义搜索结果（权重较低）
            for item in semantic_result.get('data', []):
                if item['id'] not in all_results:
                    all_results[item['id']] = {
                        **item,
                        'relevance_score': item.get('relevance_score', 100) + 20,
                        'match_type': 'semantic'
                    }
                else:
                    # 如果已存在，增加权重
                    all_results[item['id']]['relevance_score'] += 10
                    all_results[item['id']]['match_type'] += ',semantic'
            
            # 排序和分页
            sorted_results = sorted(
                all_results.values(),
                key=lambda x: x['relevance_score'],
                reverse=True
            )
            
            total_count = len(sorted_results)
            start_idx = (page - 1) * per_page
            end_idx = start_idx + per_page
            paged_results = sorted_results[start_idx:end_idx]
            
            return {
                'success': True,
                'data': paged_results,
                'total_count': total_count,
                'page': page,
                'per_page': per_page,
                'total_pages': (total_count + per_page - 1) // per_page,
                'search_type': 'comprehensive'
            }
            
        except Exception as e:
            logger.error(f"综合搜索失败: {str(e)}")
            return {
                'success': False,
                'error': f'综合搜索失败: {str(e)}',
                'error_code': 'COMPREHENSIVE_SEARCH_ERROR',
                'data': [],
                'total_count': 0
            }
    
    def _apply_filters(self, query, filters):
        """
        应用搜索过滤器
        """
        if not filters:
            return query
        
        # 分类过滤器
        if filters.get('category_codes'):
            category_codes = filters['category_codes']
            if isinstance(category_codes, str):
                category_codes = [category_codes]
            query = query.join(ElectronicArchive.category).filter(
                ArchiveCategory.code.in_(category_codes)
            )
        
        # 日期范围过滤器
        if filters.get('date_from'):
            query = query.filter(ElectronicArchive.created_date >= filters['date_from'])
        if filters.get('date_to'):
            query = query.filter(ElectronicArchive.created_date <= filters['date_to'])
        
        # 创建者过滤器
        if filters.get('created_by'):
            created_by = filters['created_by']
            if isinstance(created_by, str):
                # 根据用户名查找用户ID
                user = User.query.filter_by(username=created_by).first()
                if user:
                    query = query.filter(ElectronicArchive.created_by == user.id)
        
        # 文件类型过滤器
        if filters.get('file_types'):
            file_types = filters['file_types']
            if isinstance(file_types, str):
                file_types = [file_types]
            query = query.join(ElectronicArchive.files).filter(
                ArchiveFile.file_type.in_(file_types)
            )
        
        # 关键词过滤器
        if filters.get('keyword_filters'):
            keyword_filters = filters['keyword_filters']
            for keyword, field in keyword_filters.items():
                if field == 'title':
                    query = query.filter(ElectronicArchive.title.ilike(f'%{keyword}%'))
                elif field == 'description':
                    query = query.filter(ElectronicArchive.description.ilike(f'%{keyword}%'))
        
        return query
    
    def _format_search_results(self, archives, query, search_type):
        """
        格式化搜索结果
        """
        results = []
        query_words = query.split() if query else []
        
        for archive in archives:
            # 计算相关性评分
            relevance_score = self._calculate_relevance_score(archive, query_words)
            
            # 提取关键词高亮
            highlighted_title = self._highlight_keywords(archive.title, query_words)
            highlighted_description = self._highlight_keywords(archive.description or '', query_words)
            
            # 提取匹配片段
            snippet = self._extract_snippet(archive, query_words)
            
            result = {
                'id': archive.id,
                'archive_no': archive.archive_no,
                'title': archive.title,
                'highlighted_title': highlighted_title,
                'description': archive.description,
                'highlighted_description': highlighted_description,
                'snippet': snippet,
                'category': archive.category.name if archive.category else None,
                'created_date': archive.created_date.isoformat() if archive.created_date else None,
                'created_at': archive.created_at.isoformat() if archive.created_at else None,
                'file_count': len(archive.files),
                'file_types': list(set([f.file_type for f in archive.files])),
                'relevance_score': relevance_score,
                'search_type': search_type
            }
            results.append(result)
        
        return results
    
    def _calculate_relevance_score(self, archive, query_words):
        """
        计算相关性评分
        """
        score = 0
        title_lower = archive.title.lower()
        description_lower = (archive.description or '').lower()
        
        for word in query_words:
            if len(word) >= 2:
                word_lower = word.lower()
                
                # 标题精确匹配得分最高
                if word_lower in title_lower:
                    if word_lower == title_lower:
                        score += 100
                    elif title_lower.startswith(word_lower):
                        score += 80
                    else:
                        score += 60
                
                # 描述匹配得分中等
                if word_lower in description_lower:
                    score += 40
                
                # OCR文本匹配得分较低
                if archive.ocr_text and word_lower in archive.ocr_text.lower():
                    score += 20
                
                # 元数据匹配得分
                for metadata in archive.metadata_list:
                    if word_lower in metadata.metadata_value.lower():
                        score += 30
        
        return score
    
    def _highlight_keywords(self, text, keywords):
        """
        关键词高亮显示
        """
        if not text or not keywords:
            return text
        
        highlighted_text = text
        for keyword in keywords:
            if len(keyword) >= 2:
                pattern = re.compile(re.escape(keyword), re.IGNORECASE)
                highlighted_text = pattern.sub(f'<mark>{keyword}</mark>', highlighted_text)
        
        return highlighted_text
    
    def _extract_snippet(self, archive, query_words):
        """
        提取匹配片段
        """
        # 优先从OCR文本中提取
        content = archive.ocr_text or archive.content or archive.description or ''
        if not content or not query_words:
            return None
        
        # 找到第一个匹配关键词的位置
        match_pos = None
        for word in query_words:
            if len(word) >= 2:
                pos = content.lower().find(word.lower())
                if pos != -1:
                    match_pos = pos
                    break
        
        if match_pos is None:
            return None
        
        # 提取片段（前后各50个字符）
        start = max(0, match_pos - 50)
        end = min(len(content), match_pos + len(word) + 50)
        
        snippet = content[start:end]
        
        # 如果不是从开头开始，添加省略号
        if start > 0:
            snippet = '...' + snippet
        if end < len(content):
            snippet = snippet + '...'
        
        # 高亮关键词
        snippet = self._highlight_keywords(snippet, query_words)
        
        return snippet
    
    def _expand_query_semantic(self, query):
        """
        语义查询扩展（简化版本）
        """
        # 同义词词典（会计专业术语）
        synonyms = {
            '记账凭证': ['会计凭证', '凭证', 'voucher'],
            '会计凭证': ['记账凭证', '凭证', 'voucher'],
            '财务报表': ['报表', '财务报告', 'financial statements'],
            '资产负债表': ['资产负债表', 'balance sheet'],
            '利润表': ['损益表', 'income statement'],
            '银行存款': ['银行', 'bank deposit'],
            '应收账款': ['应收款', 'receivables'],
            '应付账款': ['应付款', 'payables'],
            '营业收入': ['收入', 'revenue'],
            '营业成本': ['成本', 'cost'],
            '管理费用': ['管理费', 'administrative expense'],
            '财务费用': ['财务费', 'financial expense']
        }
        
        expanded_words = set(query.split())
        
        # 添加同义词
        for word in query.split():
            if word in synonyms:
                expanded_words.update(synonyms[word])
        
        return list(expanded_words)
    
    def _contains_chinese(self, text):
        """
        检查是否包含中文
        """
        return bool(re.search(r'[\u4e00-\u9fff]', text))
    
    def _filter_stop_words(self, words):
        """
        过滤停用词
        """
        stop_words = {'的', '了', '是', '在', '有', '和', '与', '或', '但', '等', '对', '于', '及', '为', '以', '个', '用', '这', '那', '上', '中', '下'}
        return [word for word in words if word not in stop_words and len(word.strip()) > 0]
    
    def _record_search_history(self, query, user_id):
        """
        记录搜索历史
        """
        try:
            self.search_history[user_id] += 1
            words = query.split()
            for word in words:
                if len(word) >= 2:
                    self.hot_keywords[word] += 1
        except Exception as e:
            logger.error(f"记录搜索历史失败: {str(e)}")
    
    def get_search_suggestions(self, partial_query, limit=10):
        """
        获取搜索建议
        """
        try:
            if len(partial_query) < 2:
                return {'success': True, 'suggestions': []}
            
            # 从档案标题中匹配建议
            suggestions = []
            
            # 基于部分匹配的建议
            query = db.session.query(ElectronicArchive.title)\
                .filter(ElectronicArchive.title.ilike(f'%{partial_query}%'))\
                .limit(limit)\
                .all()
            
            suggestions.extend([item[0] for item in query])
            
            # 基于热门关键词的建议
            if len(suggestions) < limit:
                for keyword, count in sorted(self.hot_keywords.items(), key=lambda x: x[1], reverse=True):
                    if partial_query.lower() in keyword.lower() and keyword not in suggestions:
                        suggestions.append(keyword)
                        if len(suggestions) >= limit:
                            break
            
            return {
                'success': True,
                'suggestions': suggestions[:limit]
            }
            
        except Exception as e:
            logger.error(f"获取搜索建议失败: {str(e)}")
            return {
                'success': False,
                'error': f'获取搜索建议失败: {str(e)}',
                'suggestions': []
            }
    
    def get_search_stats(self, date_range=None):
        """
        获取搜索统计信息
        """
        try:
            stats = {
                'total_searches': sum(self.search_history.values()),
                'hot_keywords': dict(sorted(self.hot_keywords.items(), key=lambda x: x[1], reverse=True)[:20]),
                'search_trends': {},  # 可以扩展为时间序列数据
                'popular_searches': []  # 热门搜索查询
            }
            
            return {
                'success': True,
                'data': stats
            }
            
        except Exception as e:
            logger.error(f"获取搜索统计失败: {str(e)}")
            return {
                'success': False,
                'error': f'获取搜索统计失败: {str(e)}',
                'data': {}
            }