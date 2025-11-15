#!/usr/bin/env python3
"""
直接查询数据库检查用户状态
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models.user import User

def check_database():
    print("=== 检查数据库状态 ===")
    
    app = create_app()
    
    with app.app_context():
        try:
            # 检查用户表是否存在
            print("1. 检查用户表...")
            user_count = User.query.count()
            print(f"   用户总数: {user_count}")
            
            # 列出所有用户
            print("\n2. 列出所有用户:")
            all_users = User.query.all()
            for user in all_users:
                print(f"   ID: {user.id}")
                print(f"   用户名: {user.username}")
                print(f"   邮箱: {user.email}")
                print(f"   姓名: {user.full_name}")
                print(f"   角色: {user.role}")
                print(f"   是否激活: {user.is_active}")
                print(f"   密码哈希: {user.password_hash[:20]}...")
                print("   ---")
            
            # 查找admin用户
            print("\n3. 查找admin用户:")
            admin_user = User.query.filter_by(username='admin').first()
            if admin_user:
                print(f"   找到admin用户:")
                print(f"   ID: {admin_user.id}")
                print(f"   用户名: {admin_user.username}")
                print(f"   是否激活: {admin_user.is_active}")
                print(f"   密码哈希长度: {len(admin_user.password_hash)}")
                
                # 验证密码
                from werkzeug.security import check_password_hash
                is_valid = admin_user.check_password('admin123')
                print(f"   admin123密码验证: {is_valid}")
            else:
                print("   未找到admin用户!")
            
            # 测试密码验证
            print("\n4. 测试密码验证:")
            if admin_user:
                print(f"   检查密码方法: {admin_user.check_password('admin123')}")
                
                # 手动验证
                hash_test = check_password_hash(admin_user.password_hash, 'admin123')
                print(f"   手动验证: {hash_test}")
            
        except Exception as e:
            print(f"数据库查询错误: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    check_database()