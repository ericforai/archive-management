"""
工作流模型 - 实现档案审批和管理工作流
"""
from datetime import datetime
from models import db

class WorkflowRecord(db.Model):
    """工作流记录模型"""
    __tablename__ = 'workflow_records'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(datetime.utcnow().timestamp()))
    title = db.Column(db.String(200), nullable=False)
    workflow_type = db.Column(db.String(50), nullable=False)  # review, approval, process
    target_resource_type = db.Column(db.String(50), nullable=False)  # archive, user, file
    target_resource_id = db.Column(db.String(36), nullable=False)
    description = db.Column(db.Text)
    initiator_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected, completed
    priority = db.Column(db.String(20), default='normal')  # low, normal, high, urgent
    due_date = db.Column(db.Date)
    workflow_config = db.Column(db.Text)  # JSON格式的流程配置
    approved_by = db.Column(db.String(36), db.ForeignKey('users.id'))
    approved_at = db.Column(db.DateTime)
    approval_comments = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 关系
    initiator = db.relationship('User', foreign_keys=[initiator_id], backref='initiated_workflows')
    approver = db.relationship('User', foreign_keys=[approved_by], backref='approved_workflows')
    
    def __repr__(self):
        return f'<WorkflowRecord {self.title} {self.status}>'
    
    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'title': self.title,
            'workflow_type': self.workflow_type,
            'target_resource_type': self.target_resource_type,
            'target_resource_id': self.target_resource_id,
            'description': self.description,
            'initiator_id': self.initiator_id,
            'status': self.status,
            'priority': self.priority,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'workflow_config': self.workflow_config,
            'approved_by': self.approved_by,
            'approved_at': self.approved_at.isoformat() if self.approved_at else None,
            'approval_comments': self.approval_comments,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'initiator_name': self.initiator.full_name if self.initiator else None,
            'approver_name': self.approver.full_name if self.approver else None
        }