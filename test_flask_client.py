#!/usr/bin/env python3
"""
使用Flask测试客户端来避免网络层问题
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app

def test_with_flask_client():
    print("=== 使用Flask测试客户端 ===")
    
    app = create_app()
    
    with app.test_client() as client:
        # 测试健康检查
        print("1. 测试健康检查...")
        response = client.get('/health')
        print(f"   状态码: {response.status_code}")
        print(f"   响应: {response.get_json()}")
        
        # 测试登录
        print("\n2. 测试登录...")
        response = client.post(
            '/api/v1/security/login',
            json={
                'username': 'admin',
                'password': 'admin123'
            },
            content_type='application/json'
        )
        print(f"   状态码: {response.status_code}")
        print(f"   响应头: {dict(response.headers)}")
        
        # 尝试获取JSON响应
        try:
            json_data = response.get_json()
            print(f"   JSON响应: {json_data}")
        except Exception as e:
            print(f"   JSON解析错误: {e}")
            print(f"   原始响应: {response.data}")
        
        # 如果有错误，打印详细信息
        if response.status_code >= 400:
            print(f"\n   错误详情:")
            print(f"   状态码: {response.status_code}")
            print(f"   响应数据: {response.data}")
            print(f"   响应头: {dict(response.headers)}")

if __name__ == "__main__":
    test_with_flask_client()