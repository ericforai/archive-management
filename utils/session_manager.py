"""
会话管理工具
用于管理用户会话、令牌黑名单等
"""
import secrets
import json
import time
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from flask import session, request

logger = __import__('logging').getLogger(__name__)

class SessionManager:
    """会话管理器"""
    
    def __init__(self, session_timeout_hours: int = 24):
        """
        初始化会话管理器
        
        Args:
            session_timeout_hours: 会话超时时间（小时）
        """
        self.session_timeout_hours = session_timeout_hours
        # 内存存储（实际应用应使用Redis或数据库）
        self.sessions = {}  # session_id -> session_data
        self.token_blacklist = set()  # 已撤销的令牌
        self.user_sessions = {}  # user_id -> set(session_ids)
    
    def create_session(self, user_id: int, session_data: Dict[str, Any]) -> str:
        """
        创建用户会话
        
        Args:
            user_id: 用户ID
            session_data: 会话数据
            
        Returns:
            str: 会话ID
        """
        try:
            # 生成唯一会话ID
            session_id = f"session_{secrets.token_hex(16)}"
            
            # 准备会话数据
            session_info = {
                'user_id': user_id,
                'session_data': session_data,
                'created_at': datetime.utcnow().isoformat(),
                'last_activity': time.time(),
                'expires_at': time.time() + (self.session_timeout_hours * 3600)
            }
            
            # 存储会话
            self.sessions[session_id] = session_info
            
            # 维护用户会话映射
            if user_id not in self.user_sessions:
                self.user_sessions[user_id] = set()
            self.user_sessions[user_id].add(session_id)
            
            logger.debug(f"创建会话成功: {session_id}, 用户: {user_id}")
            return session_id
            
        except Exception as e:
            logger.error(f"创建会话失败: {str(e)}")
            raise
    
    def get_session_data(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        获取用户最新的活跃会话数据
        
        Args:
            user_id: 用户ID
            
        Returns:
            dict: 会话数据，没有活跃会话返回None
        """
        try:
            if user_id not in self.user_sessions:
                return None
            
            # 查找最新的活跃会话
            latest_session = None
            latest_time = 0
            
            for session_id in self.user_sessions[user_id]:
                session_info = self.sessions.get(session_id)
                if session_info:
                    # 检查会话是否过期
                    if session_info['expires_at'] > time.time():
                        activity_time = session_info['last_activity']
                        if activity_time > latest_time:
                            latest_time = activity_time
                            latest_session = session_info
                    else:
                        # 会话已过期，清理
                        self.revoke_session(session_id)
            
            if latest_session:
                return latest_session['session_data']
            
            return None
            
        except Exception as e:
            logger.error(f"获取会话数据失败: {str(e)}")
            return None
    
    def update_session_activity(self, session_id: str) -> bool:
        """
        更新会话活动时间
        
        Args:
            session_id: 会话ID
            
        Returns:
            bool: 更新是否成功
        """
        try:
            if session_id in self.sessions:
                self.sessions[session_id]['last_activity'] = time.time()
                return True
            return False
            
        except Exception as e:
            logger.error(f"更新会话活动时间失败: {str(e)}")
            return False
    
    def revoke_session(self, session_id: str) -> bool:
        """
        撤销会话
        
        Args:
            session_id: 会话ID
            
        Returns:
            bool: 撤销是否成功
        """
        try:
            if session_id in self.sessions:
                session_info = self.sessions[session_id]
                user_id = session_info['user_id']
                
                # 从会话存储中删除
                del self.sessions[session_id]
                
                # 从用户会话映射中删除
                if user_id in self.user_sessions:
                    self.user_sessions[user_id].discard(session_id)
                    if not self.user_sessions[user_id]:
                        del self.user_sessions[user_id]
                
                logger.debug(f"撤销会话成功: {session_id}, 用户: {user_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"撤销会话失败: {str(e)}")
            return False
    
    def invalidate_user_sessions(self, user_id: int) -> int:
        """
        撤销用户所有会话
        
        Args:
            user_id: 用户ID
            
        Returns:
            int: 被撤销的会话数量
        """
        try:
            revoked_count = 0
            
            if user_id in self.user_sessions:
                # 复制会话ID集合，避免迭代时修改
                session_ids = self.user_sessions[user_id].copy()
                
                for session_id in session_ids:
                    if self.revoke_session(session_id):
                        revoked_count += 1
            
            logger.info(f"撤销用户会话成功: 用户{user_id}, 撤销数量: {revoked_count}")
            return revoked_count
            
        except Exception as e:
            logger.error(f"撤销用户会话失败: {str(e)}")
            return 0
    
    def is_owner(self, session_id: str, user_id: int) -> bool:
        """
        检查用户是否为会话拥有者
        
        Args:
            session_id: 会话ID
            user_id: 用户ID
            
        Returns:
            bool: 是否为拥有者
        """
        try:
            if session_id in self.sessions:
                return self.sessions[session_id]['user_id'] == user_id
            return False
            
        except Exception as e:
            logger.error(f"检查会话拥有者失败: {str(e)}")
            return False
    
    def get_active_session_count(self) -> int:
        """
        获取活跃会话数量
        
        Returns:
            int: 活跃会话数量
        """
        try:
            current_time = time.time()
            active_count = 0
            
            for session_info in self.sessions.values():
                if session_info['expires_at'] > current_time:
                    active_count += 1
            
            return active_count
            
        except Exception as e:
            logger.error(f"获取活跃会话数量失败: {str(e)}")
            return 0
    
    def cleanup_expired_sessions(self) -> int:
        """
        清理过期会话
        
        Returns:
            int: 清理的会话数量
        """
        try:
            current_time = time.time()
            expired_sessions = []
            
            # 查找过期会话
            for session_id, session_info in self.sessions.items():
                if session_info['expires_at'] <= current_time:
                    expired_sessions.append(session_id)
            
            # 清理过期会话
            cleaned_count = 0
            for session_id in expired_sessions:
                if self.revoke_session(session_id):
                    cleaned_count += 1
            
            if cleaned_count > 0:
                logger.info(f"清理过期会话成功: {cleaned_count}个")
            
            return cleaned_count
            
        except Exception as e:
            logger.error(f"清理过期会话失败: {str(e)}")
            return 0
    
    def blacklist_token(self, token: str):
        """
        将令牌加入黑名单
        
        Args:
            token: 要加入黑名单的令牌
        """
        try:
            self.token_blacklist.add(token)
            logger.debug(f"令牌加入黑名单: {token[:20]}...")
            
        except Exception as e:
            logger.error(f"令牌加入黑名单失败: {str(e)}")
    
    def is_token_blacklisted(self, token: str) -> bool:
        """
        检查令牌是否在黑名单中
        
        Args:
            token: 要检查的令牌
            
        Returns:
            bool: 是否在黑名单中
        """
        try:
            return token in self.token_blacklist
            
        except Exception as e:
            logger.error(f"检查令牌黑名单失败: {str(e)}")
            return False
    
    def get_user_sessions(self, user_id: int) -> List[Dict[str, Any]]:
        """
        获取用户的所有会话
        
        Args:
            user_id: 用户ID
            
        Returns:
            list: 会话信息列表
        """
        try:
            sessions_list = []
            
            if user_id in self.user_sessions:
                current_time = time.time()
                
                for session_id in self.user_sessions[user_id]:
                    session_info = self.sessions.get(session_id)
                    if session_info:
                        # 计算剩余时间
                        time_remaining = max(0, session_info['expires_at'] - current_time)
                        
                        session_data = {
                            'session_id': session_id,
                            'user_id': session_info['user_id'],
                            'created_at': session_info['created_at'],
                            'last_activity': session_info['last_activity'],
                            'expires_at': session_info['expires_at'],
                            'time_remaining_hours': time_remaining / 3600,
                            'is_active': session_info['expires_at'] > current_time
                        }
                        sessions_list.append(session_data)
            
            return sessions_list
            
        except Exception as e:
            logger.error(f"获取用户会话失败: {str(e)}")
            return []