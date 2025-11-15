"""
审计日志服务 - 操作记录、数据变更跟踪、安全事件监控
基于DA/T 94-2022标准的电子会计档案审计系统
"""
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from flask import current_app
from sqlalchemy import and_, or_, desc, asc
from collections import defaultdict

from models.audit import AuditLog, IntegrityRecord, LifecycleRecord, StorageMedia
from models import db
from utils.audit_logger import AuditLogger
from utils.audit_analyzer import AuditAnalyzer
from utils.audit_archiver import AuditArchiver

logger = logging.getLogger(__name__)

class AuditService:
    """审计日志服务"""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
        self.audit_analyzer = AuditAnalyzer()
        self.audit_archiver = AuditArchiver()
        
        # 默认配置（如果应用上下文不可用）
        self._retention_period_days = 2555  # 7年
        self._auto_archive_days = 365  # 1年
        self._max_batch_size = 1000
        self._enable_real_time_analysis = True
        
        # 敏感操作类型
        self.sensitive_operations = {
            'data_export': {'risk_level': 'high', 'require_approval': True},
            'bulk_delete': {'risk_level': 'high', 'require_approval': True},
            'user_management': {'risk_level': 'medium', 'require_approval': False},
            'system_config': {'risk_level': 'high', 'require_approval': True},
            'permission_change': {'risk_level': 'medium', 'require_approval': True},
            'archive_delete': {'risk_level': 'medium', 'require_approval': True},
            'login_failure': {'risk_level': 'medium', 'require_approval': False},
            'privilege_escalation': {'risk_level': 'high', 'require_approval': True}
        }
        
        # 操作类型分类
        self.operation_categories = {
            'authentication': ['login', 'logout', 'password_change', 'password_reset'],
            'data_access': ['read', 'search', 'export', 'download'],
            'data_modification': ['create', 'update', 'delete', 'bulk_import', 'bulk_export'],
            'administration': ['user_management', 'role_management', 'system_config', 'backup'],
            'security': ['permission_change', 'privilege_escalation', 'account_lock', 'unlock'],
            'system': ['system_start', 'system_stop', 'maintenance', 'update']
        }
    
    @property
    def retention_period_days(self):
        """获取审计保留天数配置"""
        try:
            if hasattr(current_app, '_get_current_object'):
                return current_app.config.get('AUDIT_RETENTION_DAYS', self._retention_period_days)
        except:
            pass
        return self._retention_period_days
    
    @property
    def auto_archive_days(self):
        """获取自动归档天数配置"""
        try:
            if hasattr(current_app, '_get_current_object'):
                return current_app.config.get('AUDIT_AUTO_ARCHIVE_DAYS', self._auto_archive_days)
        except:
            pass
        return self._auto_archive_days
    
    @property
    def max_batch_size(self):
        """获取最大批处理大小配置"""
        try:
            if hasattr(current_app, '_get_current_object'):
                return current_app.config.get('AUDIT_MAX_BATCH_SIZE', self._max_batch_size)
        except:
            pass
        return self._max_batch_size
    
    @property
    def enable_real_time_analysis(self):
        """获取实时分析启用配置"""
        try:
            if hasattr(current_app, '_get_current_object'):
                return current_app.config.get('ENABLE_REAL_TIME_ANALYSIS', self._enable_real_time_analysis)
        except:
            pass
        return self._enable_real_time_analysis
    
    def log_operation(self, 
                     user_id: int,
                     operation_type: str,
                     resource_type: str,
                     resource_id: int = None,
                     operation_details: Dict = None,
                     ip_address: str = None,
                     user_agent: str = None,
                     session_id: str = None) -> Dict:
        """
        记录操作日志
        
        Args:
            user_id: 用户ID
            operation_type: 操作类型
            resource_type: 资源类型
            resource_id: 资源ID
            operation_details: 操作详情
            ip_address: IP地址
            user_agent: 用户代理
            session_id: 会话ID
            
        Returns:
            dict: 记录结果
        """
        try:
            # 构建操作详情
            details = operation_details or {}
            details.update({
                'ip_address': ip_address,
                'user_agent': user_agent,
                'session_id': session_id,
                'timestamp': datetime.utcnow().isoformat()
            })
            
            # 判断操作风险级别
            risk_level = self._assess_operation_risk(operation_type, resource_type, details)
            
            # 创建审计日志记录
            audit_log = AuditLog(
                user_id=user_id,
                operation_type=operation_type,
                resource_type=resource_type,
                resource_id=resource_id,
                operation_details=details,
                risk_level=risk_level,
                created_at=datetime.utcnow()
            )
            
            # 保存到数据库
            db.session.add(audit_log)
            db.session.commit()
            
            # 实时安全分析
            if self.enable_real_time_analysis and risk_level in ['medium', 'high']:
                self._perform_real_time_analysis(audit_log)
            
            # 检查是否需要触发告警
            alert_result = self._check_alert_conditions(audit_log)
            
            return {
                'success': True,
                'audit_log_id': audit_log.id,
                'risk_level': risk_level,
                'alert_triggered': alert_result['triggered'],
                'alert_type': alert_result.get('alert_type')
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"记录操作日志失败: {str(e)}")
            return {
                'success': False,
                'error': f'记录操作日志失败: {str(e)}',
                'error_code': 'AUDIT_LOG_ERROR'
            }
    
    def log_data_change(self,
                       user_id: int,
                       table_name: str,
                       record_id: int,
                       operation: str,  # INSERT, UPDATE, DELETE
                       old_values: Dict = None,
                       new_values: Dict = None,
                       change_details: Dict = None) -> Dict:
        """
        记录数据变更
        
        Args:
            user_id: 用户ID
            table_name: 表名
            record_id: 记录ID
            operation: 操作类型
            old_values: 旧值
            new_values: 新值
            change_details: 变更详情
            
        Returns:
            dict: 记录结果
        """
        try:
            # 构建变更详情
            details = change_details or {}
            details.update({
                'table_name': table_name,
                'record_id': record_id,
                'operation': operation,
                'old_values': old_values,
                'new_values': new_values,
                'changed_fields': self._get_changed_fields(old_values, new_values) if old_values and new_values else []
            })
            
            # 计算变更敏感度
            sensitivity = self._assess_data_sensitivity(table_name, details)
            
            # 记录变更日志（使用AuditLog记录数据变更）
            log_result = self.log_operation(
                user_id=user_id,
                operation_type=f'data_change_{operation.lower()}',
                resource_type='data_record',
                resource_id=record_id,
                operation_details=details
            )
            
            return {
                'success': True,
                'audit_log_id': log_result.get('audit_log_id'),
                'data_sensitivity': sensitivity,
                'changed_fields_count': len(details['changed_fields'])
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"记录数据变更失败: {str(e)}")
            return {
                'success': False,
                'error': f'记录数据变更失败: {str(e)}',
                'error_code': 'AUDIT_TRAIL_ERROR'
            }
    
    def log_security_event(self,
                          event_type: str,
                          severity: str,  # LOW, MEDIUM, HIGH, CRITICAL
                          user_id: int = None,
                          ip_address: str = None,
                          event_details: Dict = None,
                          source: str = 'system') -> Dict:
        """
        记录安全事件
        
        Args:
            event_type: 事件类型
            severity: 严重程度
            user_id: 用户ID
            ip_address: IP地址
            event_details: 事件详情
            source: 事件来源
            
        Returns:
            dict: 记录结果
        """
        try:
            # 构建事件详情
            details = event_details or {}
            details.update({
                'event_type': event_type,
                'severity': severity,
                'source': source,
                'timestamp': datetime.utcnow().isoformat()
            })
            
            # 记录安全事件（使用AuditLog记录）
            log_result = self.log_operation(
                user_id=user_id or 0,  # 系统用户
                operation_type=f'security_event_{event_type.lower()}',
                resource_type='security',
                operation_details=details
            )
            
            return {
                'success': True,
                'audit_log_id': log_result.get('audit_log_id'),
                'severity': severity,
                'requires_attention': severity in ['HIGH', 'CRITICAL']
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"记录安全事件失败: {str(e)}")
            return {
                'success': False,
                'error': f'记录安全事件失败: {str(e)}',
                'error_code': 'SECURITY_EVENT_ERROR'
            }
    
    def get_audit_logs(self, 
                      filters: Dict = None,
                      page: int = 1,
                      per_page: int = 20,
                      sort_by: str = 'created_at',
                      sort_order: str = 'desc') -> Dict:
        """
        获取审计日志
        
        Args:
            filters: 过滤条件
            page: 页码
            per_page: 每页数量
            sort_by: 排序字段
            sort_order: 排序方向
            
        Returns:
            dict: 日志列表
        """
        try:
            # 构建查询
            query = AuditLog.query
            
            # 应用过滤条件
            if filters:
                # 时间范围过滤
                if 'start_date' in filters:
                    query = query.filter(AuditLog.created_at >= filters['start_date'])
                if 'end_date' in filters:
                    query = query.filter(AuditLog.created_at <= filters['end_date'])
                
                # 用户过滤
                if 'user_id' in filters:
                    query = query.filter(AuditLog.user_id == filters['user_id'])
                
                # 操作类型过滤
                if 'operation_type' in filters:
                    if isinstance(filters['operation_type'], list):
                        query = query.filter(AuditLog.operation_type.in_(filters['operation_type']))
                    else:
                        query = query.filter(AuditLog.operation_type == filters['operation_type'])
                
                # 资源类型过滤
                if 'resource_type' in filters:
                    query = query.filter(AuditLog.resource_type == filters['resource_type'])
                
                # 风险级别过滤
                if 'risk_level' in filters:
                    query = query.filter(AuditLog.risk_level == filters['risk_level'])
                
                # IP地址过滤
                if 'ip_address' in filters:
                    query = query.filter(
                        AuditLog.operation_details['ip_address'].astext == filters['ip_address']
                    )
            
            # 排序
            if sort_order == 'desc':
                query = query.order_by(desc(getattr(AuditLog, sort_by)))
            else:
                query = query.order_by(asc(getattr(AuditLog, sort_by)))
            
            # 分页
            pagination = query.paginate(
                page=page,
                per_page=per_page,
                error_out=False
            )
            
            # 格式化结果
            logs = []
            for log in pagination.items:
                logs.append({
                    'id': log.id,
                    'user_id': log.user_id,
                    'username': log.user.username if log.user else '系统',
                    'operation_type': log.operation_type,
                    'resource_type': log.resource_type,
                    'resource_id': log.resource_id,
                    'risk_level': log.risk_level,
                    'created_at': log.created_at.isoformat() if log.created_at else None,
                    'operation_details': log.operation_details
                })
            
            return {
                'success': True,
                'logs': logs,
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': pagination.total,
                    'pages': pagination.pages,
                    'has_prev': pagination.has_prev,
                    'has_next': pagination.has_next
                }
            }
            
        except Exception as e:
            logger.error(f"获取审计日志失败: {str(e)}")
            return {
                'success': False,
                'error': f'获取审计日志失败: {str(e)}',
                'error_code': 'AUDIT_QUERY_ERROR'
            }
    
    def get_audit_statistics(self, time_period: str = '7d') -> Dict:
        """
        获取审计统计信息
        
        Args:
            time_period: 时间期间 (1d, 7d, 30d, 90d, 1y)
            
        Returns:
            dict: 统计信息
        """
        try:
            # 计算时间范围
            time_delta = {
                '1d': timedelta(days=1),
                '7d': timedelta(days=7),
                '30d': timedelta(days=30),
                '90d': timedelta(days=90),
                '1y': timedelta(days=365)
            }.get(time_period, timedelta(days=7))
            
            start_date = datetime.utcnow() - time_delta
            
            # 基础统计
            total_logs = AuditLog.query.filter(AuditLog.created_at >= start_date).count()
            
            # 操作类型统计
            operation_stats = {}
            operation_counts = db.session.query(
                AuditLog.operation_type,
                db.func.count(AuditLog.id)
            ).filter(
                AuditLog.created_at >= start_date
            ).group_by(AuditLog.operation_type).all()
            
            for operation, count in operation_counts:
                operation_stats[operation] = count
            
            # 风险级别统计
            risk_stats = {}
            risk_counts = db.session.query(
                AuditLog.risk_level,
                db.func.count(AuditLog.id)
            ).filter(
                AuditLog.created_at >= start_date
            ).group_by(AuditLog.risk_level).all()
            
            for risk_level, count in risk_counts:
                risk_stats[risk_level] = count
            
            # 用户活动统计
            user_activity = {}
            user_counts = db.session.query(
                AuditLog.user_id,
                db.func.count(AuditLog.id)
            ).filter(
                AuditLog.created_at >= start_date
            ).group_by(AuditLog.user_id).limit(10).all()
            
            for user_id, count in user_counts:
                user = User.query.get(user_id)
                username = user.username if user else f'User_{user_id}'
                user_activity[username] = count
            
            # 安全事件统计（通过审计日志统计）
            security_events = AuditLog.query.filter(
                AuditLog.operation_type.like('security_event_%'),
                AuditLog.created_at >= start_date
            ).count()
            
            critical_events = AuditLog.query.filter(
                AuditLog.operation_type.like('security_event_%'),
                AuditLog.created_at >= start_date,
                AuditLog.risk_level >= 3
            ).count()
            
            # 数据变更统计（通过审计日志统计）
            data_changes = AuditLog.query.filter(
                AuditLog.operation_type.like('data_change_%'),
                AuditLog.created_at >= start_date
            ).count()
            
            statistics = {
                'time_period': time_period,
                'start_date': start_date.isoformat(),
                'end_date': datetime.utcnow().isoformat(),
                'total_logs': total_logs,
                'operation_statistics': operation_stats,
                'risk_level_statistics': risk_stats,
                'user_activity': user_activity,
                'security_events': {
                    'total': security_events,
                    'critical': critical_events
                },
                'data_changes': data_changes,
                'generated_at': datetime.utcnow().isoformat()
            }
            
            return {
                'success': True,
                'statistics': statistics
            }
            
        except Exception as e:
            logger.error(f"获取审计统计失败: {str(e)}")
            return {
                'success': False,
                'error': f'获取审计统计失败: {str(e)}',
                'error_code': 'AUDIT_STATISTICS_ERROR'
            }
    
    def search_audit_logs(self, search_query: str, filters: Dict = None) -> Dict:
        """
        搜索审计日志
        
        Args:
            search_query: 搜索关键词
            filters: 过滤条件
            
        Returns:
            dict: 搜索结果
        """
        try:
            # 构建搜索查询
            query = AuditLog.query
            
            # 关键词搜索
            search_conditions = []
            if search_query:
                # 搜索操作类型
                search_conditions.append(AuditLog.operation_type.ilike(f'%{search_query}%'))
                # 搜索操作详情
                search_conditions.append(AuditLog.operation_details.cast(db.String).ilike(f'%{search_query}%'))
                # 搜索用户名
                search_conditions.append(
                    db.exists().where(
                        and_(
                            User.id == AuditLog.user_id,
                            User.username.ilike(f'%{search_query}%')
                        )
                    )
                )
            
            if search_conditions:
                query = query.filter(or_(*search_conditions))
            
            # 应用其他过滤条件
            if filters:
                if 'start_date' in filters:
                    query = query.filter(AuditLog.created_at >= filters['start_date'])
                if 'end_date' in filters:
                    query = query.filter(AuditLog.created_at <= filters['end_date'])
                if 'user_id' in filters:
                    query = query.filter(AuditLog.user_id == filters['user_id'])
                if 'risk_level' in filters:
                    query = query.filter(AuditLog.risk_level == filters['risk_level'])
            
            # 执行搜索
            results = query.order_by(desc(AuditLog.created_at)).limit(100).all()
            
            # 格式化结果
            search_results = []
            for log in results:
                search_results.append({
                    'id': log.id,
                    'user_id': log.user_id,
                    'username': log.user.username if log.user else '系统',
                    'operation_type': log.operation_type,
                    'resource_type': log.resource_type,
                    'resource_id': log.resource_id,
                    'risk_level': log.risk_level,
                    'created_at': log.created_at.isoformat() if log.created_at else None,
                    'operation_details': log.operation_details,
                    'relevance_score': self._calculate_relevance_score(log, search_query)
                })
            
            return {
                'success': True,
                'results': search_results,
                'total_found': len(search_results),
                'search_query': search_query
            }
            
        except Exception as e:
            logger.error(f"搜索审计日志失败: {str(e)}")
            return {
                'success': False,
                'error': f'搜索审计日志失败: {str(e)}',
                'error_code': 'AUDIT_SEARCH_ERROR'
            }
    
    def archive_old_audit_logs(self) -> Dict:
        """
        归档旧的审计日志
        
        Returns:
            dict: 归档结果
        """
        try:
            # 计算归档时间点
            archive_date = datetime.utcnow() - timedelta(days=self.auto_archive_days)
            
            # 查询需要归档的日志
            logs_to_archive = AuditLog.query.filter(
                AuditLog.created_at < archive_date,
                AuditLog.archived == False
            ).limit(self.max_batch_size).all()
            
            if not logs_to_archive:
                return {
                    'success': True,
                    'archived_count': 0,
                    'message': '没有需要归档的日志'
                }
            
            # 归档数据
            archive_result = self.audit_archiver.archive_logs(logs_to_archive)
            
            if archive_result['success']:
                # 标记为已归档
                for log in logs_to_archive:
                    log.archived = True
                    log.archived_at = datetime.utcnow()
                
                db.session.commit()
                
                return {
                    'success': True,
                    'archived_count': len(logs_to_archive),
                    'archive_path': archive_result['archive_path']
                }
            else:
                return {
                    'success': False,
                    'error': f'归档失败: {archive_result.get("error")}',
                    'error_code': 'ARCHIVE_ERROR'
                }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"归档审计日志失败: {str(e)}")
            return {
                'success': False,
                'error': f'归档审计日志失败: {str(e)}',
                'error_code': 'ARCHIVE_ERROR'
            }
    
    def generate_audit_report(self, 
                            report_type: str,
                            parameters: Dict = None) -> Dict:
        """
        生成审计报告
        
        Args:
            report_type: 报告类型 (compliance, security, user_activity, data_changes)
            parameters: 报告参数
            
        Returns:
            dict: 报告结果
        """
        try:
            from utils.report_generator import ReportGenerator
            
            report_generator = ReportGenerator()
            
            # 根据报告类型生成报告
            if report_type == 'compliance':
                result = report_generator.generate_compliance_report(parameters)
            elif report_type == 'security':
                result = report_generator.generate_security_report(parameters)
            elif report_type == 'user_activity':
                result = report_generator.generate_user_activity_report(parameters)
            elif report_type == 'data_changes':
                result = report_generator.generate_data_changes_report(parameters)
            else:
                return {
                    'success': False,
                    'error': f'不支持的报告类型: {report_type}',
                    'error_code': 'UNSUPPORTED_REPORT_TYPE'
                }
            
            # 记录报告生成日志
            if result['success']:
                self.log_operation(
                    user_id=parameters.get('user_id', 0),
                    operation_type='generate_audit_report',
                    resource_type='audit_report',
                    operation_details={
                        'report_type': report_type,
                        'parameters': parameters,
                        'report_path': result.get('report_path')
                    }
                )
            
            return result
            
        except Exception as e:
            logger.error(f"生成审计报告失败: {str(e)}")
            return {
                'success': False,
                'error': f'生成审计报告失败: {str(e)}',
                'error_code': 'REPORT_GENERATION_ERROR'
            }
    
    def _assess_operation_risk(self, operation_type: str, resource_type: str, details: Dict) -> str:
        """评估操作风险级别"""
        # 检查敏感操作
        if operation_type in self.sensitive_operations:
            return self.sensitive_operations[operation_type]['risk_level']
        
        # 基于操作类型和资源类型评估风险
        risk_matrix = {
            'authentication': 'LOW',
            'data_access': 'LOW',
            'data_modification': 'MEDIUM',
            'administration': 'HIGH',
            'security': 'HIGH',
            'system': 'MEDIUM'
        }
        
        # 确定操作类别
        operation_category = 'authentication'  # 默认类别
        for category, operations in self.operation_categories.items():
            if operation_type in operations:
                operation_category = category
                break
        
        return risk_matrix.get(operation_category, 'LOW')
    
    def _assess_data_sensitivity(self, table_name: str, details: Dict) -> str:
        """评估数据敏感度"""
        # 敏感表列表
        sensitive_tables = [
            'user', 'user_role', 'role', 'permission',
            'archive', 'archive_content', 'audit_log'
        ]
        
        if table_name in sensitive_tables:
            return 'HIGH'
        elif 'password' in str(details.get('new_values', {})):
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def _get_changed_fields(self, old_values: Dict, new_values: Dict) -> List[str]:
        """获取变更字段列表"""
        changed_fields = []
        
        if not old_values or not new_values:
            return changed_fields
        
        # 比较新旧值
        all_keys = set(old_values.keys()) | set(new_values.keys())
        
        for key in all_keys:
            old_val = old_values.get(key)
            new_val = new_values.get(key)
            
            if old_val != new_val:
                changed_fields.append(key)
        
        return changed_fields
    
    def _perform_real_time_analysis(self, audit_log: AuditLog):
        """执行实时安全分析"""
        try:
            # 异常行为检测
            self.audit_analyzer.detect_anomalous_behavior(audit_log)
            
            # 权限滥用检测
            self.audit_analyzer.detect_privilege_abuse(audit_log)
            
            # 异常登录检测
            if audit_log.operation_type == 'login':
                self.audit_analyzer.detect_abnormal_login(audit_log)
            
        except Exception as e:
            logger.error(f"实时安全分析失败: {str(e)}")
    
    def _check_alert_conditions(self, audit_log: AuditLog) -> Dict:
        """检查告警条件"""
        triggered = False
        alert_type = None
        
        # 高风险操作告警
        if audit_log.risk_level == 'HIGH':
            triggered = True
            alert_type = 'HIGH_RISK_OPERATION'
        
        # 多次失败登录告警
        if audit_log.operation_type == 'login_failure':
            # 检查用户在指定时间内的失败次数
            recent_failures = AuditLog.query.filter(
                AuditLog.user_id == audit_log.user_id,
                AuditLog.operation_type == 'login_failure',
                AuditLog.created_at >= datetime.utcnow() - timedelta(minutes=15)
            ).count()
            
            if recent_failures >= 3:
                triggered = True
                alert_type = 'MULTIPLE_LOGIN_FAILURES'
        
        # 异常位置登录告警
        if audit_log.operation_type == 'login_success':
            # 这里可以添加地理位置异常检测逻辑
            pass
        
        return {
            'triggered': triggered,
            'alert_type': alert_type
        }
    
    def _handle_critical_security_event(self, audit_log: AuditLog):
        """处理严重安全事件"""
        try:
            # 记录严重事件
            logger.critical(f"严重安全事件: {audit_log.operation_type}, 用户: {audit_log.user_id}, 详情: {audit_log.operation_details}")
            
            # 触发应急响应流程
            self._trigger_emergency_response(audit_log)
            
            # 发送紧急通知
            self._send_emergency_notification(audit_log)
            
        except Exception as e:
            logger.error(f"处理严重安全事件失败: {str(e)}")
    
    def _trigger_emergency_response(self, audit_log: AuditLog):
        """触发应急响应"""
        # 简化实现，实际可以调用应急响应系统
        pass
    
    def _send_emergency_notification(self, audit_log: AuditLog):
        """发送紧急通知"""
        # 简化实现，实际可以发送邮件、短信等通知
        pass
    
    def _calculate_relevance_score(self, log: AuditLog, search_query: str) -> float:
        """计算搜索相关性得分"""
        score = 0.0
        
        if not search_query:
            return 1.0
        
        query_lower = search_query.lower()
        
        # 操作类型匹配得分
        if query_lower in log.operation_type.lower():
            score += 0.5
        
        # 操作详情匹配得分
        details_str = str(log.operation_details).lower()
        if query_lower in details_str:
            score += 0.3
        
        # 用户名匹配得分
        if log.user and query_lower in log.user.username.lower():
            score += 0.2
        
        return min(score, 1.0)