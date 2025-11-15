#!/usr/bin/env python3
"""
电子会计档案系统 - 数据库初始化和测试数据创建脚本
"""

import sys
import os
from datetime import datetime, timedelta, date
from werkzeug.security import generate_password_hash

# 添加应用路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from models.user import User, Permission, Organization
from models.archive import ArchiveCategory, ElectronicArchive, ArchiveFile
from models.workflow import WorkflowRecord
# LifecycleRecord 在 audit.py 中定义
from models import audit
from models.audit import AuditLog
from utils.audit_logger import audit_logger

def create_initial_data():
    """创建初始数据"""
    
    # 1. 创建权限配置（使用Permission模型）
    permissions_data = [
        # 档案相关权限
        {'user_id': 'admin_user', 'resource_type': 'archive', 'operation': 'read', 'granted_by': 'admin_user'},
        {'user_id': 'admin_user', 'resource_type': 'archive', 'operation': 'write', 'granted_by': 'admin_user'},
        {'user_id': 'admin_user', 'resource_type': 'archive', 'operation': 'delete', 'granted_by': 'admin_user'},
        {'user_id': 'archiver_user', 'resource_type': 'archive', 'operation': 'read', 'granted_by': 'admin_user'},
        {'user_id': 'archiver_user', 'resource_type': 'archive', 'operation': 'write', 'granted_by': 'admin_user'},
        {'user_id': 'user1', 'resource_type': 'archive', 'operation': 'read', 'granted_by': 'admin_user'},
        {'user_id': 'auditor', 'resource_type': 'archive', 'operation': 'read', 'granted_by': 'admin_user'},
        
        # 分类管理权限
        {'user_id': 'admin_user', 'resource_type': 'category', 'operation': 'admin', 'granted_by': 'admin_user'},
        {'user_id': 'archiver_user', 'resource_type': 'category', 'operation': 'admin', 'granted_by': 'admin_user'},
        
        # 工作流权限
        {'user_id': 'admin_user', 'resource_type': 'workflow', 'operation': 'admin', 'granted_by': 'admin_user'},
        {'user_id': 'archiver_user', 'resource_type': 'workflow', 'operation': 'admin', 'granted_by': 'admin_user'},
        {'user_id': 'user1', 'resource_type': 'workflow', 'operation': 'read', 'granted_by': 'admin_user'},
        
        # 统计权限
        {'user_id': 'admin_user', 'resource_type': 'statistics', 'operation': 'read', 'granted_by': 'admin_user'},
        {'user_id': 'archiver_user', 'resource_type': 'statistics', 'operation': 'read', 'granted_by': 'admin_user'},
        {'user_id': 'user1', 'resource_type': 'statistics', 'operation': 'read', 'granted_by': 'admin_user'},
        {'user_id': 'auditor', 'resource_type': 'statistics', 'operation': 'read', 'granted_by': 'admin_user'},
        
        # 审计权限
        {'user_id': 'admin_user', 'resource_type': 'audit', 'operation': 'read', 'granted_by': 'admin_user'},
        {'user_id': 'auditor', 'resource_type': 'audit', 'operation': 'read', 'granted_by': 'admin_user'},
        
        # 用户管理权限
        {'user_id': 'admin_user', 'resource_type': 'user', 'operation': 'admin', 'granted_by': 'admin_user'},
        
        # 生命周期权限
        {'user_id': 'admin_user', 'resource_type': 'lifecycle', 'operation': 'read', 'granted_by': 'admin_user'},
        {'user_id': 'archiver_user', 'resource_type': 'lifecycle', 'operation': 'read', 'granted_by': 'admin_user'},
        {'user_id': 'user1', 'resource_type': 'lifecycle', 'operation': 'read', 'granted_by': 'admin_user'},
        {'user_id': 'auditor', 'resource_type': 'lifecycle', 'operation': 'read', 'granted_by': 'admin_user'}
    ]
    
    # 2. 创建用户
    users_data = [
        {
            'username': 'admin',
            'email': 'admin@company.com',
            'password': 'admin123',
            'role': 'admin',
            'full_name': '系统管理员',
            'department': 'IT部门'
        },
        {
            'username': 'archiver',
            'email': 'archiver@company.com', 
            'password': 'archive123',
            'role': 'archivist',
            'full_name': '档案管理员',
            'department': '档案管理部'
        },
        {
            'username': 'user1',
            'email': 'user1@company.com',
            'password': 'user123',
            'role': 'user', 
            'full_name': '张三',
            'department': '财务部'
        },
        {
            'username': 'auditor',
            'email': 'auditor@company.com',
            'password': 'audit123',
            'role': 'auditor',
            'full_name': '审计员',
            'department': '审计部'
        }
    ]
    
    for user_data in users_data:
        user = User.query.filter_by(username=user_data['username']).first()
        if not user:
            user = User(
                username=user_data['username'],
                email=user_data['email'],
                role=user_data['role'],
                full_name=user_data['full_name'],
                department=user_data['department'],
                is_active=True
            )
            user.set_password(user_data['password'])
            db.session.add(user)
            print(f"创建用户: {user_data['username']}")
    
    db.session.commit()
    
    # 3. 创建权限记录（在用户创建后）
    for perm_data in permissions_data:
        # 获取实际的用户ID
        if perm_data['user_id'] == 'admin_user':
            user = User.query.filter_by(username='admin').first()
        elif perm_data['user_id'] == 'archiver_user':
            user = User.query.filter_by(username='archiver').first()
        elif perm_data['user_id'] == 'user1':
            user = User.query.filter_by(username='user1').first()
        elif perm_data['user_id'] == 'auditor':
            user = User.query.filter_by(username='auditor').first()
        else:
            continue
        
        if not user:
            continue
            
        # 检查权限是否已存在
        existing_perm = Permission.query.filter_by(
            user_id=user.id,
            resource_type=perm_data['resource_type'],
            operation=perm_data['operation']
        ).first()
        
        if not existing_perm:
            permission = Permission(
                user_id=user.id,
                resource_type=perm_data['resource_type'],
                operation=perm_data['operation'],
                granted_by=user.id,  # 使用自己作为授权者
                is_active=True
            )
            db.session.add(permission)
    
    db.session.commit()

def create_lifecycle_records():
    """创建生命周期记录"""
    print("正在创建生命周期记录...")
    
    # 获取所有档案
    archives = ElectronicArchive.query.all()
    
    for archive in archives:
        # 创建记录 - 从audit模块导入LifecycleRecord
        lifecycle_record = audit.LifecycleRecord(
            archive_id=archive.id,
            event_type='created',
            event_date=date.today(),
            description=f'档案 {archive.title} 创建',
            operator_id=archive.created_by,
            event_metadata={'source': 'system'}
        )
        db.session.add(lifecycle_record)
        
        # 模拟一些档案的归档操作
        if archive.status == 'archived':
            admin_user = User.query.filter_by(username='admin').first()
            lifecycle_record = audit.LifecycleRecord(
                archive_id=archive.id,
                event_type='archived',
                event_date=date.today() - timedelta(days=30),
                description=f'档案 {archive.title} 归档',
                operator_id=admin_user.id if admin_user else archive.created_by,
                event_metadata={'reason': '保存期限到期'}
            )
            db.session.add(lifecycle_record)
    
    db.session.commit()
    print(f"生命周期记录: {len(archives)} 个档案的记录已创建")

def create_test_data():
    """创建测试数据"""
    
    # 获取用户ID
    admin_user = User.query.filter_by(username='admin').first()
    archiver_user = User.query.filter_by(username='archiver').first()
    normal_user = User.query.filter_by(username='user1').first()
    
    if not admin_user or not archiver_user:
        print("缺少管理员用户，请先创建初始数据")
        return
    
    # 1. 创建档案分类
    categories_data = [
        {
            'code': 'FIN',
            'name': '财务档案',
            'description': '财务相关档案',
            'parent_id': None,
            'retention_period': '10_years'
        },
        {
            'code': 'ACC',
            'name': '会计凭证',
            'description': '会计凭证档案',
            'parent_id': None,
            'retention_period': '30_years'
        },
        {
            'code': 'RPT',
            'name': '财务报表',
            'description': '财务报表档案',
            'parent_id': None,
            'retention_period': '10_years'
        },
        {
            'code': 'HR',
            'name': '人事档案',
            'description': '人事相关档案',
            'parent_id': None,
            'retention_period': 'permanent'
        },
        {
            'code': 'EMP',
            'name': '员工档案',
            'description': '员工个人档案',
            'parent_id': None,
            'retention_period': 'permanent'
        },
        {
            'code': 'CON',
            'name': '合同档案',
            'description': '劳动合同档案',
            'parent_id': None,
            'retention_period': '10_years'
        }
    ]
    
    categories = {}
    for cat_data in categories_data:
        category = ArchiveCategory.query.filter_by(name=cat_data['name']).first()
        if not category:
            category = ArchiveCategory(
                code=cat_data['code'],
                name=cat_data['name'],
                description=cat_data['description'],
                parent_id=cat_data['parent_id'],
                retention_period=cat_data['retention_period'],
                is_active=True
            )
            db.session.add(category)
            categories[cat_data['name']] = category
            print(f"创建分类: {cat_data['name']}")
        else:
            categories[cat_data['name']] = category
    
    db.session.commit()
    print(f"可用分类: {list(categories.keys())}")
    
    # 1.5 创建默认组织机构
    default_org = Organization.query.filter_by(code='DEFAULT').first()
    if not default_org:
        default_org = Organization(
            name='默认组织',
            code='DEFAULT',
            description='系统默认组织机构'
        )
        db.session.add(default_org)
        db.session.commit()
        print(f"创建默认组织: {default_org.name}")
    
    # 2. 创建测试档案
    archives_data = [
        {
            'title': '2024年第一季度财务报表',
            'archive_no': 'FIN-2024-Q1-001',
            'category_id': 'categories["财务档案"]',  # 获取分类ID
            'description': '2024年第一季度的完整财务报表',
            'confidentiality_level': 3,  # 秘密级别
            'status': 'draft',
            'created_by': archiver_user.id,
            'retention_period': '10_years',
            'created_date': date.today(),
            'file_info': {
                'file_name': 'Q1_Financial_Report_2024.pdf',
                'file_size': 2048576,
                'file_type': 'pdf',
                'original_name': 'Q1_Financial_Report_2024.pdf'
            }
        },
        {
            'title': '员工劳动合同-张三',
            'archive_no': 'HR-CT-001',
            'category_id': 'categories[\"合同档案\"]',  # 获取分类ID
            'description': '张三的劳动合同文件',
            'confidentiality_level': 4,  # 机密级别
            'status': 'draft',
            'created_by': archiver_user.id,
            'retention_period': '10_years',
            'created_date': date.today(),
            'file_info': {
                'file_name': 'ZhangSan_Contract.pdf',
                'file_size': 1024768,
                'file_type': 'pdf',
                'original_name': 'ZhangSan_Contract.pdf'
            }
        },
        {
            'title': '2024年3月会计凭证',
            'archive_no': 'ACC-2024-03-001',
            'category_id': 'categories[\"会计凭证\"]',  # 获取分类ID
            'description': '2024年3月份的会计凭证合集',
            'confidentiality_level': 2,  # 内部级别
            'status': 'draft',
            'created_by': archiver_user.id,
            'retention_period': '30_years',
            'created_date': date.today(),
            'file_info': {
                'file_name': 'March_2024_Accounting_Vouchers.zip',
                'file_size': 5242880,
                'file_type': 'zip',
                'original_name': 'March_2024_Accounting_Vouchers.zip'
            }
        },
        {
            'title': '2023年度审计报告',
            'archive_no': 'AUD-2023-001',
            'category_id': 'categories[\"财务档案\"]',  # 获取分类ID
            'description': '2023年度公司审计报告',
            'confidentiality_level': 5,  # 绝密级别
            'status': 'archived',
            'created_by': admin_user.id,
            'retention_period': '10_years',
            'created_date': date(2023, 12, 31),
            'archive_date': date(2024, 1, 15),
            'file_info': {
                'file_name': 'Annual_Audit_Report_2023.pdf',
                'file_size': 4194304,
                'file_type': 'pdf',
                'original_name': 'Annual_Audit_Report_2023.pdf'
            }
        }
    ]
    
    for archive_data in archives_data:
        # 获取实际分类ID
        category_id = None
        category_name = archive_data['category_id'].replace('categories["', '').replace('"]', '')
        if category_name in categories:
            category_id = categories[category_name].id
        
        archive = ElectronicArchive.query.filter_by(
            archive_no=archive_data['archive_no']
        ).first()
        if not archive:
            archive = ElectronicArchive(
                title=archive_data['title'],
                archive_no=archive_data['archive_no'],
                category_id=category_id,
                description=archive_data['description'],
                confidentiality_level=archive_data['confidentiality_level'],
                status=archive_data['status'],
                created_by=archive_data['created_by'],
                retention_period=archive_data['retention_period'],
                created_date=archive_data['created_date'],
                archive_date=archive_data.get('archive_date'),
                organization_id=default_org.id
            )
            db.session.add(archive)
            db.session.flush()  # 立即获取 archive.id
            
            # 创建档案文件记录
            archive_file = ArchiveFile(
                archive_id=archive.id,
                file_name=archive_data['file_info']['file_name'],
                original_name=archive_data['file_info']['original_name'],
                file_path=f"/archives/{archive_data['file_info']['file_name']}",
                file_size=archive_data['file_info']['file_size'],
                file_type=archive_data['file_info']['file_type'],
                file_hash="abc123def456789",  # 模拟哈希值
                mime_type=f"application/{archive_data['file_info']['file_type']}",
                sort_order=1,
                is_main=True
            )
            db.session.add(archive_file)
            
            print(f"创建档案: {archive_data['title']}")
    
    db.session.commit()
    
    # 3. 创建生命周期记录
    lifecycle_events = [
        {
            'archive_id': str(archive.id),
            'event_type': 'created',
            'event_date': date.today(),
            'description': f'档案 {archive.title} 创建',
            'operator_id': str(admin_user.id if admin_user else archive.created_by),
            'metadata': {'source': 'system'}
        },
        {
            'archive_id': str(archive.id),
            'event_type': 'archived',
            'event_date': date.today(),
            'description': f'档案 {archive.title} 归档',
            'operator_id': str(admin_user.id if admin_user else archive.created_by),
            'metadata': {'source': 'system'}
        }
    ]
    
    import json
    for event_data in lifecycle_events:
        lifecycle_record = audit.LifecycleRecord(
            archive_id=event_data['archive_id'],
            event_type=event_data['event_type'],
            event_date=event_data['event_date'],
            description=event_data['description'],
            operator_id=event_data['operator_id'],
            event_metadata=json.dumps(event_data['metadata']),
            created_at=datetime.utcnow() - timedelta(hours=1)
        )
        db.session.add(lifecycle_record)
    
    db.session.commit()
    
    # 4. 创建工作流记录
    workflow_data = [
        {
            'title': '审核2024年第一季度财务报表',
            'workflow_type': 'review',
            'target_resource_type': 'archive',
            'target_resource_id': 1,
            'description': '需要对Q1财务报表进行审核',
            'initiator_id': str(normal_user.id),
            'status': 'pending',
            'priority': 'high',
            'config': {'auto_approve': False}
        },
        {
            'title': '审批员工转正申请',
            'workflow_type': 'approval',
            'target_resource_type': 'user',
            'target_resource_id': 3,
            'description': '张三的转正申请审批',
            'initiator_id': str(admin_user.id),
            'status': 'pending',
            'priority': 'normal',
            'config': {'auto_approve': False}
        }
    ]
    
    import json
    for wf_data in workflow_data:
        workflow = WorkflowRecord.query.filter_by(title=wf_data['title']).first()
        if not workflow:
            workflow = WorkflowRecord(
                title=wf_data['title'],
                workflow_type=wf_data['workflow_type'],
                target_resource_type=wf_data['target_resource_type'],
                target_resource_id=wf_data['target_resource_id'],
                description=wf_data['description'],
                initiator_id=wf_data['initiator_id'],
                status=wf_data['status'],
                priority=wf_data['priority'],
                due_date=datetime.utcnow().date() + timedelta(days=7),
                workflow_config=json.dumps(wf_data['config'])
            )
            db.session.add(workflow)
            print(f"创建工作流: {wf_data['title']}")
    
    db.session.commit()
    
    # 5. 创建审计日志
    audit_events = [
        {
            'user_id': str(archiver_user.id),
            'operation_type': 'create',
            'resource_type': 'archive',
            'resource_id': str(archive.id),
            'operation_details': {'archive_number': 'FIN-2024-Q1-001', 'title': archive.title},
            'ip_address': '192.168.1.100',
            'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            'result': 'success'
        },
        {
            'user_id': str(admin_user.id),
            'operation_type': 'login',
            'resource_type': 'user',
            'resource_id': str(admin_user.id),
            'operation_details': {'login_time': datetime.utcnow().isoformat()},
            'ip_address': '192.168.1.100',
            'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            'result': 'success'
        }
    ]
    
    for audit_data in audit_events:
        audit_log = AuditLog(
            user_id=audit_data['user_id'],
            operation_type=audit_data['operation_type'],
            resource_type=audit_data['resource_type'],
            resource_id=audit_data['resource_id'],
            operation_details=audit_data['operation_details'],
            ip_address=audit_data['ip_address'],
            user_agent=audit_data['user_agent'],
            result=audit_data['result'],
            created_at=datetime.utcnow() - timedelta(hours=2)
        )
        db.session.add(audit_log)
    
    db.session.commit()
    
    print("\n✅ 测试数据创建完成!")
    print("📊 创建了以下数据:")
    print(f"   - 权限: {Permission.query.count()} 个")
    print(f"   - 用户: {User.query.count()} 个")
    print(f"   - 分类: {ArchiveCategory.query.count()} 个")
    print(f"   - 档案: {ElectronicArchive.query.count()} 个")
    print(f"   - 文件: {ArchiveFile.query.count()} 个")
    print(f"   - 生命周期记录: {audit.LifecycleRecord.query.count()} 个")
    print(f"   - 工作流: {WorkflowRecord.query.count()} 个")
    print(f"   - 审计日志: {AuditLog.query.count()} 个")

def main():
    """主函数"""
    app = create_app()
    
    with app.app_context():
        print("🚀 开始初始化数据库...")
        
        try:
            # 创建表
            db.create_all()
            print("✅ 数据库表创建成功")
            
            # 创建初始数据
            create_initial_data()
            
            # 创建测试数据
            create_test_data()
            
            print("\n🎉 数据库初始化完成!")
            print("\n🔐 测试账户信息:")
            print("   管理员: admin / admin123")
            print("   档案员: archiver / archive123") 
            print("   普通用户: user1 / user123")
            print("   审计员: auditor / audit123")
            
        except Exception as e:
            print(f"❌ 初始化失败: {str(e)}")
            db.session.rollback()

if __name__ == '__main__':
    main()