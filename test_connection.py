#!/usr/bin/env python3
"""
测试基本连接
"""
import requests

def test_basic_connection():
    print("=== 测试基本连接 ===")
    
    # 测试根路径
    try:
        response = requests.get("http://localhost:5001/", timeout=5)
        print(f"根路径状态码: {response.status_code}")
        print(f"根路径响应: {response.text[:200]}...")
    except Exception as e:
        print(f"根路径连接错误: {e}")
    
    # 测试健康检查路径
    try:
        response = requests.get("http://localhost:5001/health", timeout=5)
        print(f"健康检查状态码: {response.status_code}")
        print(f"健康检查响应: {response.text}")
    except Exception as e:
        print(f"健康检查连接错误: {e}")
    
    # 测试API基础路径
    try:
        response = requests.get("http://localhost:5001/api/v1/", timeout=5)
        print(f"API基础路径状态码: {response.status_code}")
        print(f"API基础路径响应: {response.text[:200]}...")
    except Exception as e:
        print(f"API基础路径连接错误: {e}")

if __name__ == "__main__":
    test_basic_connection()