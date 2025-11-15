#!/usr/bin/env python3
"""
电子会计档案管理系统API测试脚本
基于DA/T 94-2022标准的RESTful API测试用例
"""
import requests
import json
import time
from datetime import datetime
import sys

class ArchiveAPITester:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.token = None
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.test_results = []
    
    def log_test(self, test_name, success, message="", response_data=None):
        """记录测试结果"""
        result = {
            'test_name': test_name,
            'success': success,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'response_data': response_data
        }
        self.test_results.append(result)
        status = "✓ 通过" if success else "✗ 失败"
        print(f"[{status}] {test_name}: {message}")
    
    def get_token(self):
        """获取认证令牌"""
        try:
            login_data = {
                'username': 'admin',
                'password': 'admin123'
            }
            response = requests.post(
                f"{self.base_url}/api/v1/security/login",
                json=login_data,
                headers=self.headers
            )
            if response.status_code == 200:
                data = response.json()
                self.token = data.get('access_token')
                if self.token:
                    self.headers['Authorization'] = f'Bearer {self.token}'
                    self.log_test("用户登录", True, "成功获取认证令牌")
                    return True
            else:
                self.log_test("用户登录", False, f"登录失败: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("用户登录", False, f"登录异常: {str(e)}")
            return False
    
    def test_health_endpoint(self):
        """测试健康检查端点"""
        try:
            response = requests.get(f"{self.base_url}/api/v1/health", headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'healthy':
                    self.log_test("API健康检查", True, "API服务正常")
                else:
                    self.log_test("API健康检查", False, "API服务状态异常")
            else:
                self.log_test("API健康检查", False, f"请求失败: {response.status_code}")
        except Exception as e:
            self.log_test("API健康检查", False, f"请求异常: {str(e)}")
    
    def test_api_info(self):
        """测试API信息端点"""
        try:
            response = requests.get(f"{self.base_url}/api/v1/info", headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                if 'name' in data and 'endpoints' in data:
                    self.log_test("API信息", True, "API信息获取成功")
                else:
                    self.log_test("API信息", False, "API信息格式异常")
            else:
                self.log_test("API信息", False, f"请求失败: {response.status_code}")
        except Exception as e:
            self.log_test("API信息", False, f"请求异常: {str(e)}")
    
    def test_archive_library_apis(self):
        """测试档案库管理API"""
        if not self.token:
            self.get_token()
        
        # 测试创建档案库
        try:
            library_data = {
                'name': '测试档案库',
                'description': '用于API测试的档案库',
                'storage_location': '/storage/test',
                'retention_period': 10,
                'access_level': 'standard'
            }
            response = requests.post(
                f"{self.base_url}/api/v1/libraries",
                json=library_data,
                headers=self.headers
            )
            if response.status_code == 201:
                data = response.json()
                self.log_test("创建档案库", True, "档案库创建成功")
                return data.get('data', {}).get('id')
            else:
                self.log_test("创建档案库", False, f"创建失败: {response.status_code}")
                return None
        except Exception as e:
            self.log_test("创建档案库", False, f"创建异常: {str(e)}")
            return None
    
    def test_search_apis(self):
        """测试搜索API"""
        if not self.token:
            self.get_token()
        
        try:
            search_data = {
                'query': '测试',
                'search_type': 'fulltext',
                'filters': {},
                'page': 1,
                'per_page': 10
            }
            response = requests.post(
                f"{self.base_url}/api/v1/search",
                json=search_data,
                headers=self.headers
            )
            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    self.log_test("全文搜索", True, "搜索功能正常")
                else:
                    self.log_test("全文搜索", False, "搜索结果格式异常")
            else:
                self.log_test("全文搜索", False, f"搜索失败: {response.status_code}")
        except Exception as e:
            self.log_test("全文搜索", False, f"搜索异常: {str(e)}")
    
    def test_metadata_apis(self):
        """测试元数据管理API"""
        if not self.token:
            self.get_token()
        
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/metadata/templates",
                headers=self.headers
            )
            if response.status_code == 200:
                data = response.json()
                self.log_test("获取元数据模板", True, "元数据模板获取成功")
            else:
                self.log_test("获取元数据模板", False, f"获取失败: {response.status_code}")
        except Exception as e:
            self.log_test("获取元数据模板", False, f"获取异常: {str(e)}")
    
    def test_audit_apis(self):
        """测试审计日志API"""
        if not self.token:
            self.get_token()
        
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/audit/logs?page=1&per_page=10",
                headers=self.headers
            )
            if response.status_code == 200:
                data = response.json()
                self.log_test("获取审计日志", True, "审计日志获取成功")
            else:
                self.log_test("获取审计日志", False, f"获取失败: {response.status_code}")
        except Exception as e:
            self.log_test("获取审计日志", False, f"获取异常: {str(e)}")
    
    def test_classification_apis(self):
        """测试档案分类API"""
        if not self.token:
            self.get_token()
        
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/classification/statistics",
                headers=self.headers
            )
            if response.status_code == 200:
                data = response.json()
                self.log_test("获取分类统计", True, "分类统计获取成功")
            else:
                self.log_test("获取分类统计", False, f"获取失败: {response.status_code}")
        except Exception as e:
            self.log_test("获取分类统计", False, f"获取异常: {str(e)}")
    
    def test_collection_apis(self):
        """测试档案采集API"""
        if not self.token:
            self.get_token()
        
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/collection/categories",
                headers=self.headers
            )
            if response.status_code == 200:
                data = response.json()
                self.log_test("获取档案分类", True, "档案分类获取成功")
            else:
                self.log_test("获取档案分类", False, f"获取失败: {response.status_code}")
        except Exception as e:
            self.log_test("获取档案分类", False, f"获取异常: {str(e)}")
    
    def run_all_tests(self):
        """运行所有测试"""
        print("开始电子会计档案管理系统API测试...")
        print("=" * 50)
        
        # 基础端点测试
        self.test_health_endpoint()
        self.test_api_info()
        
        # 认证测试
        self.get_token()
        
        # API功能测试
        self.test_archive_library_apis()
        self.test_search_apis()
        self.test_metadata_apis()
        self.test_audit_apis()
        self.test_classification_apis()
        self.test_collection_apis()
        
        # 输出测试报告
        self.print_test_report()
    
    def print_test_report(self):
        """输出测试报告"""
        print("\n" + "=" * 50)
        print("API测试报告")
        print("=" * 50)
        
        passed = sum(1 for r in self.test_results if r['success'])
        total = len(self.test_results)
        
        print(f"总测试用例: {total}")
        print(f"通过: {passed}")
        print(f"失败: {total - passed}")
        print(f"成功率: {(passed/total*100):.1f}%")
        
        if total > passed:
            print("\n失败的测试用例:")
            for result in self.test_results:
                if not result['success']:
                    print(f"- {result['test_name']}: {result['message']}")
        
        # 保存测试报告到文件
        self.save_test_report()
    
    def save_test_report(self):
        """保存测试报告到文件"""
        try:
            report_data = {
                'test_summary': {
                    'total_tests': len(self.test_results),
                    'passed': sum(1 for r in self.test_results if r['success']),
                    'failed': sum(1 for r in self.test_results if not r['success']),
                    'success_rate': f"{(sum(1 for r in self.test_results if r['success'])/len(self.test_results)*100):.1f}%"
                },
                'test_details': self.test_results,
                'timestamp': datetime.now().isoformat()
            }
            
            with open('api_test_report.json', 'w', encoding='utf-8') as f:
                json.dump(report_data, f, ensure_ascii=False, indent=2)
            
            print(f"\n测试报告已保存到: api_test_report.json")
        except Exception as e:
            print(f"保存测试报告失败: {str(e)}")

def main():
    """主函数"""
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = input("请输入API服务器地址 (默认: http://localhost:5000): ").strip()
        if not base_url:
            base_url = "http://localhost:5000"
    
    tester = ArchiveAPITester(base_url)
    tester.run_all_tests()

if __name__ == "__main__":
    main()