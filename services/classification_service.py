"""
自动归类引擎 - 智能分类、OCR结果分析
基于DA/T 94-2022标准的自动归类模块
"""
import os
import json
import re
import logging
from datetime import datetime
from flask import current_app
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import numpy as np

from models.archive import ElectronicArchive, ArchiveCategory
from models import db
from utils.audit_logger import AuditLogger

logger = logging.getLogger(__name__)

class AutoClassifierService:
    """自动归类引擎服务"""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
        self.model = None
        self.vectorizer = None
        self.categories_map = {}
        self.is_trained = False
        
        # 关键词匹配规则
        self.keyword_rules = self._load_keyword_rules()
        
    def _load_keyword_rules(self):
        """
        加载关键词匹配规则
        基于DA/T 94-2022标准的档案分类体系
        """
        return {
            # 会计凭证类
            'voucher': {
                'keywords': ['记账凭证', '转账凭证', '收款凭证', '付款凭证', '凭证', 'voucher'],
                'patterns': [r'记\d{4}号', r'转\d{4}号', r'收\d{4}号', r'付\d{4}号'],
                'confidence_threshold': 0.8
            },
            # 账簿类
            'ledger': {
                'keywords': ['总账', '明细账', '日记账', '现金账', '银行存款账', '科目余额表'],
                'patterns': [r'总账\d{4}年\d{1,2}月', r'明细账\d{4}年'],
                'confidence_threshold': 0.7
            },
            # 财务报表类
            'report': {
                'keywords': ['资产负债表', '利润表', '现金流量表', '所有者权益变动表', '财务报表'],
                'patterns': [r'\d{4}年度?财务报表', r'资产负债表.*\d{4}', r'利润表.*\d{4}'],
                'confidence_threshold': 0.85
            },
            # 合同类
            'contract': {
                'keywords': ['合同', '协议', '契约', '订购单', '采购合同'],
                'patterns': [r'合同编号[：:]\s*\w+', r'合同.*\d{4}', r'甲方.*乙方'],
                'confidence_threshold': 0.75
            },
            # 发票类
            'invoice': {
                'keywords': ['增值税发票', '普通发票', '电子发票', '发票联', '记账联'],
                'patterns': [r'发票号码[：:]\s*\d+', r'\d{8}', r'开票日期.*\d{4}[-/]\d{1,2}[-/]\d{1,2}'],
                'confidence_threshold': 0.9
            },
            # 税务申报类
            'tax_return': {
                'keywords': ['纳税申报表', '增值税申报表', '企业所得税', '个人所得税', '申报表'],
                'patterns': [r'纳税申报表', r'申报日期.*\d{4}[-/]\d{1,2}[-/]\d{1,2}'],
                'confidence_threshold': 0.8
            },
            # 银行对账单类
            'bank_statement': {
                'keywords': ['银行对账单', '对账单', '账户明细', '银行流水'],
                'patterns': [r'银行对账单', r'账号.*\d{10,}', r'交易日期.*\d{4}[-/]\d{1,2}[-/]\d{1,2}'],
                'confidence_threshold': 0.85
            },
            # 资产类
            'asset': {
                'keywords': ['固定资产', '无形资产', '资产清单', '盘点表', '折旧'],
                'patterns': [r'资产编号[：:]\s*\w+', r'固定资产.*\d{4}', r'折旧.*\d{4}'],
                'confidence_threshold': 0.7
            },
            # 工资表类
            'payroll': {
                'keywords': ['工资表', '工资单', '薪酬表', '薪资表', '员工工资'],
                'patterns': [r'工资表.*\d{4}年\d{1,2}月', r'员工.*工资.*\d+'],
                'confidence_threshold': 0.75
            },
            # 其他类
            'other': {
                'keywords': ['其他', '杂项', '附件', '说明'],
                'patterns': [],
                'confidence_threshold': 0.5
            }
        }
    
    def classify_archive(self, archive_id, force_retrain=False):
        """
        对档案进行自动归类
        
        Args:
            archive_id: 档案ID
            force_retrain: 是否强制重新训练模型
            
        Returns:
            dict: 归类结果
        """
        try:
            archive = ElectronicArchive.query.get(archive_id)
            if not archive:
                return {
                    'success': False,
                    'error': '档案不存在',
                    'error_code': 'ARCHIVE_NOT_FOUND'
                }
            
            # 获取档案文本内容
            archive_text = self._get_archive_text_content(archive)
            
            # 执行自动归类
            classification_result = self._classify_text(archive_text)
            
            # 如果置信度足够高，自动更新分类
            if classification_result['confidence'] >= 0.6:
                old_category_id = archive.category_id
                archive.category_id = classification_result['category_id']
                
                # 记录归类变更
                self.audit_logger.log_operation(
                    user_id=archive.created_by,
                    operation_type='auto_classify',
                    resource_type='archive',
                    resource_id=archive_id,
                    operation_details={
                        'old_category_id': old_category_id,
                        'new_category_id': classification_result['category_id'],
                        'classification_method': 'automatic',
                        'confidence': classification_result['confidence'],
                        'evidence': classification_result.get('evidence', [])
                    }
                )
                
                db.session.commit()
                
                return {
                    'success': True,
                    'auto_classified': True,
                    'category_id': classification_result['category_id'],
                    'confidence': classification_result['confidence'],
                    'evidence': classification_result.get('evidence', [])
                }
            else:
                return {
                    'success': True,
                    'auto_classified': False,
                    'suggested_category_id': classification_result['category_id'],
                    'suggested_category_name': self._get_category_name(classification_result['category_id']),
                    'confidence': classification_result['confidence'],
                    'reason': '置信度较低，需要人工确认'
                }
                
        except Exception as e:
            logger.error(f"自动归类失败: {str(e)}")
            return {
                'success': False,
                'error': f'归类过程出错: {str(e)}',
                'error_code': 'CLASSIFICATION_ERROR'
            }
    
    def train_classifier_model(self, force_retrain=False):
        """
        训练归类模型
        
        Args:
            force_retrain: 是否强制重新训练
            
        Returns:
            dict: 训练结果
        """
        try:
            # 检查是否需要重新训练
            if self.is_trained and not force_retrain:
                return {
                    'success': True,
                    'message': '模型已存在，跳过训练',
                    'model_exists': True
                }
            
            # 获取已分类的档案数据
            training_data = self._prepare_training_data()
            
            if len(training_data) < 10:
                return {
                    'success': False,
                    'error': '训练数据不足，需要至少10个已分类的档案',
                    'error_code': 'INSUFFICIENT_DATA',
                    'available_count': len(training_data)
                }
            
            # 分割训练和测试数据
            texts = [item['text'] for item in training_data]
            labels = [item['category'] for item in training_data]
            
            X_train, X_test, y_train, y_test = train_test_split(
                texts, labels, test_size=0.2, random_state=42, stratify=labels
            )
            
            # 训练模型
            self.model = Pipeline([
                ('tfidf', TfidfVectorizer(max_features=10000, ngram_range=(1, 2))),
                ('classifier', MultinomialNB(alpha=0.1))
            ])
            
            self.model.fit(X_train, y_train)
            
            # 评估模型
            y_pred = self.model.predict(X_test)
            accuracy = (y_pred == y_test).mean()
            
            # 保存模型
            model_path = self._get_model_path()
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            joblib.dump(self.model, model_path)
            
            self.is_trained = True
            
            # 记录训练日志
            self.audit_logger.log_system_operation(
                operation_type='model_training',
                operation_details={
                    'training_data_count': len(training_data),
                    'test_accuracy': accuracy,
                    'model_path': model_path,
                    'categories': list(set(labels))
                }
            )
            
            return {
                'success': True,
                'message': f'模型训练完成，准确率: {accuracy:.3f}',
                'accuracy': accuracy,
                'training_count': len(training_data),
                'test_count': len(X_test)
            }
            
        except Exception as e:
            logger.error(f"模型训练失败: {str(e)}")
            return {
                'success': False,
                'error': f'训练过程出错: {str(e)}',
                'error_code': 'TRAINING_ERROR'
            }
    
    def batch_classify(self, archive_ids):
        """
        批量归类档案
        
        Args:
            archive_ids: 档案ID列表
            
        Returns:
            dict: 批量归类结果
        """
        try:
            results = []
            successful_classifications = 0
            
            for archive_id in archive_ids:
                try:
                    result = self.classify_archive(archive_id)
                    results.append({
                        'archive_id': archive_id,
                        'success': result['success'],
                        'result': result
                    })
                    
                    if result.get('success') and result.get('auto_classified'):
                        successful_classifications += 1
                        
                except Exception as e:
                    results.append({
                        'archive_id': archive_id,
                        'success': False,
                        'error': str(e)
                    })
            
            return {
                'success': True,
                'total_count': len(archive_ids),
                'successful_count': successful_classifications,
                'results': results
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'批量归类失败: {str(e)}',
                'error_code': 'BATCH_CLASSIFICATION_ERROR'
            }
    
    def _get_archive_text_content(self, archive):
        """
        获取档案的文本内容
        """
        text_content = []
        
        # 标题
        text_content.append(archive.title or '')
        
        # 描述
        text_content.append(archive.description or '')
        
        # 关键词
        text_content.append(archive.keywords or '')
        
        # OCR文本（如果有）
        if hasattr(archive, 'files'):
            for file in archive.files:
                if hasattr(file, 'ocr_text') and file.ocr_text:
                    text_content.append(file.ocr_text[:1000])  # 限制长度
        
        # 元数据
        if hasattr(archive, 'metadata'):
            metadata_text = []
            for meta in archive.metadata_list:
                if meta.metadata_value:
                    metadata_text.append(f"{meta.metadata_key}: {meta.metadata_value}")
            text_content.extend(metadata_text)
        
        return ' '.join(text_content)
    
    def _classify_text(self, text):
        """
        对文本进行分类
        """
        if not text:
            return {
                'category_id': self._get_default_category_id(),
                'confidence': 0.0,
                'method': 'default'
            }
        
        # 关键词匹配
        keyword_result = self._keyword_classify(text)
        
        # 机器学习模型分类
        ml_result = self._ml_classify(text)
        
        # 合并结果
        if keyword_result['confidence'] >= 0.8:
            return {
                'category_id': keyword_result['category_id'],
                'confidence': keyword_result['confidence'],
                'method': 'keyword_matching',
                'evidence': keyword_result.get('evidence', [])
            }
        elif ml_result['confidence'] >= 0.5 and self.is_trained:
            return {
                'category_id': ml_result['category_id'],
                'confidence': ml_result['confidence'],
                'method': 'ml_model',
                'evidence': ml_result.get('evidence', [])
            }
        else:
            # 返回置信度较高的结果
            if keyword_result['confidence'] >= ml_result['confidence']:
                return {
                    'category_id': keyword_result['category_id'],
                    'confidence': keyword_result['confidence'],
                    'method': 'keyword_matching',
                    'evidence': keyword_result.get('evidence', [])
                }
            else:
                return {
                    'category_id': ml_result['category_id'],
                    'confidence': ml_result['confidence'],
                    'method': 'ml_model',
                    'evidence': ml_result.get('evidence', [])
                }
    
    def _keyword_classify(self, text):
        """
        基于关键词的分类
        """
        text_lower = text.lower()
        category_scores = {}
        evidence = []
        
        for category_key, rule in self.keyword_rules.items():
            score = 0
            
            # 关键词匹配
            for keyword in rule['keywords']:
                if keyword.lower() in text_lower:
                    score += 1
                    evidence.append(f"关键词匹配: {keyword}")
            
            # 正则表达式匹配
            for pattern in rule['patterns']:
                if re.search(pattern, text_lower):
                    score += 1
                    evidence.append(f"模式匹配: {pattern}")
            
            # 计算置信度
            if score > 0:
                category_scores[category_key] = score / (len(rule['keywords']) + len(rule['patterns']))
        
        if not category_scores:
            return {
                'category_id': self._get_default_category_id(),
                'confidence': 0.0,
                'evidence': []
            }
        
        # 选择得分最高的分类
        best_category = max(category_scores.keys(), key=lambda x: category_scores[x])
        category_id = self._map_category_key_to_id(best_category)
        
        return {
            'category_id': category_id,
            'confidence': min(category_scores[best_category], 0.95),
            'evidence': evidence
        }
    
    def _ml_classify(self, text):
        """
        基于机器学习模型的分类
        """
        if not self.model or not self.is_trained:
            return {
                'category_id': self._get_default_category_id(),
                'confidence': 0.0
            }
        
        try:
            # 预测
            prediction = self.model.predict([text])[0]
            probabilities = self.model.predict_proba([text])[0]
            confidence = probabilities.max()
            
            category_id = self._map_category_key_to_id(prediction)
            
            return {
                'category_id': category_id,
                'confidence': confidence
            }
            
        except Exception as e:
            logger.error(f"ML分类失败: {str(e)}")
            return {
                'category_id': self._get_default_category_id(),
                'confidence': 0.0
            }
    
    def _prepare_training_data(self):
        """
        准备训练数据
        """
        training_data = []
        
        # 获取已分类的档案
        classified_archives = ElectronicArchive.query.filter(
            ElectronicArchive.category_id.isnot(None)
        ).all()
        
        for archive in classified_archives:
            if archive.category:
                text_content = self._get_archive_text_content(archive)
                if text_content.strip():
                    training_data.append({
                        'text': text_content,
                        'category': archive.category.code or 'other'
                    })
        
        return training_data
    
    def _map_category_key_to_id(self, category_key):
        """
        将分类键映射到数据库ID
        """
        if not self.categories_map:
            # 缓存分类映射
            categories = ArchiveCategory.query.all()
            self.categories_map = {cat.code: cat.id for cat in categories}
        
        # 默认映射
        default_mapping = {
            'voucher': 1,      # 记账凭证
            'ledger': 2,       # 账簿
            'report': 3,       # 财务报表
            'contract': 4,     # 合同协议
            'invoice': 5,      # 发票
            'tax_return': 6,   # 税务申报
            'bank_statement': 7, # 银行对账单
            'asset': 8,        # 资产清单
            'payroll': 9,      # 工资表
            'other': 10        # 其他
        }
        
        return self.categories_map.get(category_key, default_mapping.get(category_key, 10))
    
    def _get_default_category_id(self):
        """
        获取默认分类ID
        """
        return self._map_category_key_to_id('other')
    
    def _get_category_name(self, category_id):
        """
        获取分类名称
        """
        category = ArchiveCategory.query.get(category_id)
        return category.name if category else '未知分类'
    
    def _get_model_path(self):
        """
        获取模型保存路径
        """
        return os.path.join(
            current_app.config.get('MODEL_STORAGE', './models'),
            'auto_classifier.pkl'
        )