#!/usr/bin/env python3
"""
测试API路由修复
"""
import requests
import json

def test_api_endpoints():
    """测试各个API端点"""
    base_url = "http://localhost:5001"
    
    print("=== 测试API端点 ===")
    
    # 测试健康检查
    print("\n1. 测试健康检查端点:")
    try:
        response = requests.get(f"{base_url}/health")
        print(f"状态码: {response.status_code}")
        print(f"响应: {response.json()}")
    except Exception as e:
        print(f"错误: {e}")
    
    # 测试登录端点
    print("\n2. 测试登录端点:")
    try:
        data = {
            "username": "admin",
            "password": "admin123"
        }
        headers = {"Content-Type": "application/json"}
        
        response = requests.post(
            f"{base_url}/api/v1/security/login",
            json=data,
            headers=headers
        )
        print(f"状态码: {response.status_code}")
        print(f"响应: {response.json()}")
        
        if response.status_code == 200:
            print("✅ 登录API修复成功!")
        else:
            print("❌ 登录API仍有问题")
            
    except Exception as e:
        print(f"错误: {e}")
    
    # 测试其他API端点
    print("\n3. 测试信息端点:")
    try:
        response = requests.get(f"{base_url}/api/v1/info")
        print(f"状态码: {response.status_code}")
        print(f"响应: {response.json()}")
    except Exception as e:
        print(f"错误: {e}")

if __name__ == "__main__":
    test_api_endpoints()