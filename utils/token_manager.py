"""
令牌管理工具
用于生成、验证和管理JWT令牌
"""
import jwt
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
from flask import current_app

logger = __import__('logging').getLogger(__name__)

class TokenManager:
    """JWT令牌管理器"""
    
    def __init__(self, secret_key: str = None, algorithm: str = 'HS256'):
        """
        初始化令牌管理器
        
        Args:
            secret_key: JWT密钥，如果为None则自动生成
            algorithm: JWT算法
        """
        self.secret_key = secret_key or secrets.token_hex(32)
        self.algorithm = algorithm
    
    def generate_token(self, payload: Dict[str, Any], expiry_hours: int = 24) -> str:
        """
        生成JWT令牌
        
        Args:
            payload: 令牌数据
            expiry_hours: 过期时间（小时）
            
        Returns:
            str: JWT令牌
        """
        try:
            # 添加标准声明
            payload_copy = payload.copy()
            payload_copy.update({
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + timedelta(hours=expiry_hours),
                'jti': secrets.token_hex(16)  # 令牌唯一标识
            })
            
            # 生成令牌
            token = jwt.encode(
                payload_copy,
                self.secret_key,
                algorithm=self.algorithm
            )
            
            logger.debug(f"生成令牌成功，payload: {payload_copy}")
            return token
            
        except Exception as e:
            logger.error(f"生成令牌失败: {str(e)}")
            raise
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        验证JWT令牌
        
        Args:
            token: JWT令牌
            
        Returns:
            dict: 令牌载荷，如果验证失败返回None
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )
            
            logger.debug(f"令牌验证成功，jti: {payload.get('jti')}")
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning(f"令牌已过期: {token[:20]}...")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"无效令牌: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"令牌验证错误: {str(e)}")
            return None
    
    def refresh_token(self, old_token: str) -> Optional[str]:
        """
        刷新令牌
        
        Args:
            old_token: 原令牌
            
        Returns:
            str: 新令牌，刷新失败返回None
        """
        try:
            payload = self.verify_token(old_token)
            if not payload:
                return None
            
            # 移除标准声明
            payload.pop('iat', None)
            payload.pop('exp', None)
            payload.pop('jti', None)
            
            # 生成新令牌
            return self.generate_token(payload)
            
        except Exception as e:
            logger.error(f"刷新令牌失败: {str(e)}")
            return None
    
    def revoke_token(self, token: str) -> bool:
        """
        撤销令牌（标记为无效）
        注意：此实现为简化版本，实际应用中应使用令牌黑名单
        
        Args:
            token: 要撤销的令牌
            
        Returns:
            bool: 撤销是否成功
        """
        try:
            # 简化的撤销实现，实际应维护令牌黑名单
            logger.info(f"令牌撤销: {token[:20]}...")
            return True
            
        except Exception as e:
            logger.error(f"撤销令牌失败: {str(e)}")
            return False
    
    def get_token_info(self, token: str) -> Optional[Dict[str, Any]]:
        """
        获取令牌信息（不解码验证）
        
        Args:
            token: JWT令牌
            
        Returns:
            dict: 令牌信息，解析失败返回None
        """
        try:
            # 解码但不验证（仅用于信息查看）
            payload = jwt.decode(
                token,
                options={"verify_signature": False}
            )
            
            info = {
                'issuer': payload.get('iss'),
                'subject': payload.get('sub'),
                'audience': payload.get('aud'),
                'issued_at': payload.get('iat'),
                'expires_at': payload.get('exp'),
                'jwt_id': payload.get('jti')
            }
            
            # 添加自定义载荷信息
            for key, value in payload.items():
                if key not in ['iss', 'sub', 'aud', 'iat', 'exp', 'jti']:
                    info[key] = value
            
            return info
            
        except Exception as e:
            logger.error(f"获取令牌信息失败: {str(e)}")
            return None