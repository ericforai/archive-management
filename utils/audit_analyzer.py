"""
审计分析器 - 审计日志分析、风险评估、异常检测
基于DA/T 94-2022标准的审计分析模块
"""
import logging
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Tuple
from collections import defaultdict, Counter
from sqlalchemy import and_, or_, desc, func

logger = logging.getLogger(__name__)

class AuditAnalyzer:
    """审计日志分析器"""
    
    def __init__(self):
        self.anomaly_threshold = 0.8  # 异常阈值
        self.risk_weights = {
            'high_frequency': 0.3,
            'unusual_time': 0.2,
            'multiple_failures': 0.3,
            'suspicious_pattern': 0.2
        }
        
        # 定义异常模式
        self.suspicious_patterns = {
            'brute_force': {
                'operation': 'login',
                'time_window': 300,  # 5分钟
                'failure_threshold': 5
            },
            'after_hours': {
                'start_hour': 22,
                'end_hour': 6
            },
            'bulk_operations': {
                'operation_types': ['delete', 'export'],
                'count_threshold': 10
            }
        }
    
    def analyze_user_behavior(self, user_id: str, days: int = 30) -> Dict:
        """
        分析用户行为模式
        
        Args:
            user_id: 用户ID
            days: 分析天数
            
        Returns:
            dict: 分析结果
        """
        try:
            from models.audit import AuditLog
            from models import db
            
            start_date = datetime.utcnow() - timedelta(days=days)
            
            # 获取用户操作记录
            user_logs = AuditLog.query.filter(
                AuditLog.user_id == user_id,
                AuditLog.created_at >= start_date
            ).all()
            
            if not user_logs:
                return {
                    'user_id': user_id,
                    'analysis_period': days,
                    'total_operations': 0,
                    'anomalies': [],
                    'risk_score': 0
                }
            
            # 行为模式分析
            behavior_analysis = self._analyze_behavior_patterns(user_logs)
            
            # 异常检测
            anomalies = self._detect_anomalies(user_logs)
            
            # 风险评分
            risk_score = self._calculate_risk_score(behavior_analysis, anomalies)
            
            return {
                'user_id': user_id,
                'analysis_period': days,
                'total_operations': len(user_logs),
                'behavior_patterns': behavior_analysis,
                'anomalies': anomalies,
                'risk_score': risk_score,
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"用户行为分析失败: {str(e)}")
            return {
                'user_id': user_id,
                'error': str(e),
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
    
    def detect_suspicious_activities(self, hours: int = 24) -> List[Dict]:
        """
        检测可疑活动
        
        Args:
            hours: 检测时间范围（小时）
            
        Returns:
            list: 可疑活动列表
        """
        try:
            from models.audit import AuditLog
            
            start_time = datetime.utcnow() - timedelta(hours=hours)
            
            # 查询最近的审计日志
            recent_logs = AuditLog.query.filter(
                AuditLog.created_at >= start_time
            ).all()
            
            suspicious_activities = []
            
            # 检测各种异常模式
            suspicious_activities.extend(self._detect_brute_force_attempts(recent_logs))
            suspicious_activities.extend(self._detect_after_hours_activities(recent_logs))
            suspicious_activities.extend(self._detect_bulk_operations(recent_logs))
            suspicious_activities.extend(self._detect_unusual_failures(recent_logs))
            
            return suspicious_activities
            
        except Exception as e:
            logger.error(f"可疑活动检测失败: {str(e)}")
            return []
    
    def analyze_risk_trends(self, days: int = 30) -> Dict:
        """
        分析风险趋势
        
        Args:
            days: 分析天数
            
        Returns:
            dict: 风险趋势分析
        """
        try:
            from models.audit import AuditLog
            
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            # 按日期统计风险级别分布
            daily_risk_stats = db.session.query(
                func.date(AuditLog.created_at).label('date'),
                AuditLog.risk_level,
                func.count(AuditLog.id).label('count')
            ).filter(
                AuditLog.created_at >= start_date,
                AuditLog.created_at <= end_date
            ).group_by(
                func.date(AuditLog.created_at),
                AuditLog.risk_level
            ).all()
            
            # 处理统计数据
            risk_trends = defaultdict(lambda: defaultdict(int))
            for date, risk_level, count in daily_risk_stats:
                risk_trends[date.isoformat()][risk_level] = count
            
            # 计算趋势
            trend_analysis = self._calculate_risk_trend(risk_trends)
            
            return {
                'analysis_period': days,
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'daily_risk_trends': dict(risk_trends),
                'trend_analysis': trend_analysis,
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"风险趋势分析失败: {str(e)}")
            return {
                'analysis_period': days,
                'error': str(e),
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
    
    def _analyze_behavior_patterns(self, logs: List) -> Dict:
        """分析行为模式"""
        patterns = {
            'operation_frequency': defaultdict(int),
            'time_distribution': defaultdict(int),
            'resource_access': defaultdict(int),
            'success_rate': {'total': 0, 'successful': 0}
        }
        
        for log in logs:
            # 操作频率
            patterns['operation_frequency'][log.operation_type] += 1
            
            # 时间分布
            hour = log.created_at.hour
            patterns['time_distribution'][hour] += 1
            
            # 资源访问
            patterns['resource_access'][log.resource_type] += 1
            
            # 成功率
            patterns['success_rate']['total'] += 1
            if log.result == 'success':
                patterns['success_rate']['successful'] += 1
        
        return patterns
    
    def _detect_anomalies(self, logs: List) -> List[Dict]:
        """检测异常"""
        anomalies = []
        
        # 检测异常时间操作
        anomalies.extend(self._detect_unusual_timing(logs))
        
        # 检测异常操作频率
        anomalies.extend(self._detect_unusual_frequency(logs))
        
        # 检测异常资源访问
        anomalies.extend(self._detect_unusual_resource_access(logs))
        
        return anomalies
    
    def _detect_brute_force_attempts(self, logs: List) -> List[Dict]:
        """检测暴力破解尝试"""
        brute_force_pattern = self.suspicious_patterns['brute_force']
        attempts = defaultdict(list)
        
        for log in logs:
            if log.operation_type == 'login' and log.result == 'failure':
                attempts[log.user_id].append(log.created_at)
        
        suspicious = []
        for user_id, failure_times in attempts.items():
            # 按时间窗口分组失败尝试
            windowed_failures = self._group_by_time_window(
                failure_times, 
                brute_force_pattern['time_window']
            )
            
            for window_failures in windowed_failures:
                if len(window_failures) >= brute_force_pattern['failure_threshold']:
                    suspicious.append({
                        'type': 'brute_force_attempt',
                        'user_id': user_id,
                        'failure_count': len(window_failures),
                        'time_window': brute_force_pattern['time_window'],
                        'first_attempt': min(window_failures).isoformat(),
                        'last_attempt': max(window_failures).isoformat(),
                        'severity': 'high'
                    })
        
        return suspicious
    
    def _detect_after_hours_activities(self, logs: List) -> List[Dict]:
        """检测非工作时间活动"""
        after_hours_pattern = self.suspicious_patterns['after_hours']
        suspicious = []
        
        for log in logs:
            hour = log.created_at.hour
            if (hour >= after_hours_pattern['start_hour'] or 
                hour <= after_hours_pattern['end_hour']):
                suspicious.append({
                    'type': 'after_hours_activity',
                    'user_id': log.user_id,
                    'operation_type': log.operation_type,
                    'timestamp': log.created_at.isoformat(),
                    'hour': hour,
                    'severity': 'medium'
                })
        
        return suspicious
    
    def _detect_bulk_operations(self, logs: List) -> List[Dict]:
        """检测批量操作"""
        bulk_pattern = self.suspicious_patterns['bulk_operations']
        operation_counts = defaultdict(int)
        
        for log in logs:
            if log.operation_type in bulk_pattern['operation_types']:
                operation_counts[log.user_id] += 1
        
        suspicious = []
        for user_id, count in operation_counts.items():
            if count >= bulk_pattern['count_threshold']:
                suspicious.append({
                    'type': 'bulk_operations',
                    'user_id': user_id,
                    'operation_count': count,
                    'threshold': bulk_pattern['count_threshold'],
                    'severity': 'high'
                })
        
        return suspicious
    
    def _detect_unusual_timing(self, logs: List) -> List[Dict]:
        """检测异常时间操作"""
        # 简化的异常时间检测逻辑
        return []
    
    def _detect_unusual_frequency(self, logs: List) -> List[Dict]:
        """检测异常操作频率"""
        # 简化的异常频率检测逻辑
        return []
    
    def _detect_unusual_resource_access(self, logs: List) -> List[Dict]:
        """检测异常资源访问"""
        # 简化的异常资源访问检测逻辑
        return []
    
    def _detect_unusual_failures(self, logs: List) -> List[Dict]:
        """检测异常失败"""
        failure_counts = defaultdict(int)
        
        for log in logs:
            if log.result == 'failure':
                failure_counts[log.user_id] += 1
        
        suspicious = []
        for user_id, failure_count in failure_counts.items():
            if failure_count >= 10:  # 阈值可配置
                suspicious.append({
                    'type': 'unusual_failure_rate',
                    'user_id': user_id,
                    'failure_count': failure_count,
                    'severity': 'medium'
                })
        
        return suspicious
    
    def _group_by_time_window(self, timestamps: List, window_seconds: int) -> List[List]:
        """按时间窗口分组时间戳"""
        if not timestamps:
            return []
        
        timestamps.sort()
        groups = []
        current_group = [timestamps[0]]
        
        for i in range(1, len(timestamps)):
            if (timestamps[i] - current_group[-1]).total_seconds() <= window_seconds:
                current_group.append(timestamps[i])
            else:
                groups.append(current_group)
                current_group = [timestamps[i]]
        
        if current_group:
            groups.append(current_group)
        
        return groups
    
    def _calculate_risk_score(self, behavior_analysis: Dict, anomalies: List) -> float:
        """计算风险评分"""
        risk_score = 0.0
        
        # 基于异常数量计算风险
        anomaly_count = len(anomalies)
        if anomaly_count > 0:
            risk_score += min(anomaly_count * 0.1, 0.5)
        
        # 基于成功率计算风险
        success_rate = behavior_analysis.get('success_rate', {})
        total_ops = success_rate.get('total', 1)
        successful_ops = success_rate.get('successful', 0)
        failure_rate = (total_ops - successful_ops) / total_ops
        
        if failure_rate > 0.3:  # 失败率超过30%
            risk_score += failure_rate * 0.3
        
        return min(risk_score, 1.0)
    
    def _calculate_risk_trend(self, risk_trends: Dict) -> Dict:
        """计算风险趋势"""
        # 简化的趋势分析
        return {
            'trend_direction': 'stable',
            'risk_level_change': 0,
            'peak_risk_day': None
        }