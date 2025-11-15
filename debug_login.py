#!/usr/bin/env python3
"""
调试登录API的详细问题
"""
import requests
import json

def test_login_detailed():
    print("=== 详细测试登录API ===")
    
    url = "http://localhost:5001/api/v1/security/login"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    data = {
        "username": "admin",
        "password": "admin123"
    }
    
    print(f"请求URL: {url}")
    print(f"请求头: {headers}")
    print(f"请求数据: {data}")
    print()
    
    try:
        # 使用详细模式发送请求
        session = requests.Session()
        session.headers.update(headers)
        
        response = session.post(url, json=data, timeout=10)
        
        print(f"响应状态码: {response.status_code}")
        print(f"响应头: {dict(response.headers)}")
        print(f"响应内容: {response.text}")
        
        # 尝试解析JSON响应
        try:
            json_response = response.json()
            print(f"解析后的JSON: {json_response}")
        except Exception as e:
            print(f"JSON解析错误: {e}")
            
    except requests.exceptions.ConnectionError as e:
        print(f"连接错误: {e}")
    except requests.exceptions.Timeout as e:
        print(f"超时错误: {e}")
    except Exception as e:
        print(f"其他错误: {e}")

if __name__ == "__main__":
    test_login_detailed()