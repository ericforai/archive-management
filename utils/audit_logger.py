"""
审计日志工具模块
"""
import logging
from datetime import datetime
from typing import Optional, Dict, Any


class AuditLogger:
    """审计日志记录器"""
    
    def __init__(self):
        self.logger = logging.getLogger('audit')
        if not self.logger.handlers:
            handler = logging.FileHandler('logs/audit.log', encoding='utf-8')
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def log_operation(self, 
                     user_id: str,
                     operation_type: str,
                     target_type: str,
                     target_id: str,
                     description: str,
                     details: Optional[Dict[str, Any]] = None,
                     ip_address: Optional[str] = None,
                     user_agent: Optional[str] = None):
        """
        记录操作审计日志
        
        Args:
            user_id: 用户ID
            operation_type: 操作类型
            target_type: 目标类型
            target_id: 目标ID
            description: 操作描述
            details: 详细信息
            ip_address: IP地址
            user_agent: 用户代理
        """
        try:
            log_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'user_id': user_id,
                'operation_type': operation_type,
                'target_type': target_type,
                'target_id': target_id,
                'description': description,
                'details': details or {},
                'ip_address': ip_address,
                'user_agent': user_agent
            }
            
            log_message = f"AUDIT: {user_id} - {operation_type} - {target_type}:{target_id} - {description}"
            if details:
                log_message += f" - Details: {details}"
            
            self.logger.info(log_message)
            
        except Exception as e:
            # 确保审计日志记录失败不会影响业务逻辑
            print(f"审计日志记录失败: {str(e)}")
    
    def log_system_event(self,
                        event_type: str,
                        level: str = 'INFO',
                        message: str = '',
                        details: Optional[Dict[str, Any]] = None):
        """
        记录系统事件日志
        
        Args:
            event_type: 事件类型
            level: 日志级别
            message: 消息内容
            details: 详细信息
        """
        try:
            log_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': event_type,
                'message': message,
                'details': details or {}
            }
            
            log_message = f"SYSTEM_EVENT: {event_type} - {message}"
            if details:
                log_message += f" - Details: {details}"
            
            if level == 'ERROR':
                self.logger.error(log_message)
            elif level == 'WARNING':
                self.logger.warning(log_message)
            else:
                self.logger.info(log_message)
                
        except Exception as e:
            print(f"系统事件日志记录失败: {str(e)}")
    
    def log_error(self, error: Exception, context: Optional[Dict[str, Any]] = None):
        """
        记录错误日志
        
        Args:
            error: 异常对象
            context: 上下文信息
        """
        try:
            log_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'error_type': type(error).__name__,
                'error_message': str(error),
                'context': context or {}
            }
            
            log_message = f"ERROR: {type(error).__name__} - {str(error)}"
            if context:
                log_message += f" - Context: {context}"
            
            self.logger.error(log_message)
            
        except Exception as e:
            print(f"错误日志记录失败: {str(e)}")
    
    def log_user_action(self,
                       user_id: str,
                       action: str,
                       details: Optional[Dict[str, Any]] = None,
                       ip_address: Optional[str] = None,
                       user_agent: Optional[str] = None):
        """
        记录用户操作日志
        
        Args:
            user_id: 用户ID
            action: 用户动作
            details: 详细信息
            ip_address: IP地址
            user_agent: 用户代理
        """
        try:
            log_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'user_id': user_id,
                'action': action,
                'details': details or {},
                'ip_address': ip_address,
                'user_agent': user_agent
            }
            
            log_message = f"USER_ACTION: {user_id} - {action}"
            if details:
                log_message += f" - Details: {details}"
            
            self.logger.info(log_message)
            
        except Exception as e:
            print(f"用户操作日志记录失败: {str(e)}")
    
    def log_security_event(self,
                          event_type: str,
                          severity: str = 'MEDIUM',
                          details: Optional[Dict[str, Any]] = None,
                          ip_address: Optional[str] = None,
                          user_agent: Optional[str] = None):
        """
        记录安全事件日志
        
        Args:
            event_type: 安全事件类型
            severity: 严重程度 (LOW, MEDIUM, HIGH, CRITICAL)
            details: 详细信息
            ip_address: IP地址
            user_agent: 用户代理
        """
        try:
            log_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': event_type,
                'severity': severity,
                'details': details or {},
                'ip_address': ip_address,
                'user_agent': user_agent
            }
            
            log_message = f"SECURITY_EVENT: {severity} - {event_type}"
            if details:
                log_message += f" - Details: {details}"
            
            # 根据严重程度设置日志级别
            if severity == 'CRITICAL':
                self.logger.error(log_message)
            elif severity == 'HIGH':
                self.logger.warning(log_message)
            else:
                self.logger.info(log_message)
                
        except Exception as e:
            print(f"安全事件日志记录失败: {str(e)}")


# 创建全局审计日志实例
audit_logger = AuditLogger()