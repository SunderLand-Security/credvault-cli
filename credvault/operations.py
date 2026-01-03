# credvault/operations.py
import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
import secrets

class Operation:
    def __init__(self, name: str, client: str = "", description: str = ""):
        self.name = name
        self.client = client
        self.description = description
        self.created = datetime.utcnow().isoformat() + 'Z'
        self.modified = self.created
        self.status = 'active'  # active, completed, archived
        self.tags = []
        self.metadata = {}
        self.credential_ids = []  # References to credentials in this op
        
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'client': self.client,
            'description': self.description,
            'created': self.created,
            'modified': self.modified,
            'status': self.status,
            'tags': self.tags,
            'metadata': self.metadata,
            'credential_ids': self.credential_ids
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Operation':
        op = cls(data['name'], data.get('client', ''), data.get('description', ''))
        op.created = data.get('created', op.created)
        op.modified = data.get('modified', op.modified)
        op.status = data.get('status', 'active')
        op.tags = data.get('tags', [])
        op.metadata = data.get('metadata', {})
        op.credential_ids = data.get('credential_ids', [])
        return op


class OperationManager:
    OPERATIONS_DIR = Path.home() / '.credvault' / 'operations'
    CURRENT_OP_FILE = OPERATIONS_DIR / 'current'
    
    def __init__(self):
        self.operations_dir = Path(self.OPERATIONS_DIR)
        self.current_op_file = Path(self.CURRENT_OP_FILE)
        self.operations = {}
        self.current_operation = None
        
        # Ensure operations directory exists
        self.operations_dir.mkdir(parents=True, exist_ok=True)
        
    def load_operations(self):
        """Load all operations from disk"""
        self.operations = {}
        
        if not self.operations_dir.exists():
            return
        
        for op_file in self.operations_dir.glob('*.json'):
            if op_file.name == 'current':
                continue
                
            try:
                with open(op_file, 'r') as f:
                    data = json.load(f)
                    op = Operation.from_dict(data)
                    self.operations[op.name] = op
            except:
                continue
        
        # Load current operation
        self.load_current_operation()
    
    def save_operation(self, operation: Operation):
        """Save an operation to disk"""
        operation.modified = datetime.utcnow().isoformat() + 'Z'
        op_file = self.operations_dir / f"{operation.name}.json"
        
        with open(op_file, 'w') as f:
            json.dump(operation.to_dict(), f, indent=2)
        
        # Update in-memory cache
        self.operations[operation.name] = operation
    
    def create_operation(self, name: str, client: str = "", 
                        description: str = "", tags: List[str] = None) -> Operation:
        """Create a new operation"""
        if name in self.operations:
            raise ValueError(f"Operation '{name}' already exists")
        
        # Clean operation name (no special chars, spaces become underscores)
        clean_name = ''.join(c if c.isalnum() or c in '_-' else '_' for c in name)
        clean_name = clean_name.replace(' ', '_')
        
        op = Operation(clean_name, client, description)
        if tags:
            op.tags = tags
        
        self.save_operation(op)
        return op
    
    def get_operation(self, name: str) -> Optional[Operation]:
        """Get an operation by name"""
        return self.operations.get(name)
    
    def list_operations(self, status: str = None, tag: str = None) -> List[Operation]:
        """List operations with optional filtering"""
        ops = list(self.operations.values())
        
        if status:
            ops = [op for op in ops if op.status == status]
        
        if tag:
            ops = [op for op in ops if tag in op.tags]
        
        return sorted(ops, key=lambda x: x.modified, reverse=True)
    
    def set_current_operation(self, operation_name: str):
        """Set the current active operation"""
        if operation_name not in self.operations:
            raise ValueError(f"Operation '{operation_name}' not found")
        
        self.current_operation = self.operations[operation_name]
        
        # Save to file
        with open(self.current_op_file, 'w') as f:
            f.write(operation_name)
    
    def load_current_operation(self):
        """Load the current operation from file"""
        if not self.current_op_file.exists():
            self.current_operation = None
            return
        
        try:
            with open(self.current_op_file, 'r') as f:
                op_name = f.read().strip()
            
            if op_name in self.operations:
                self.current_operation = self.operations[op_name]
            else:
                self.current_operation = None
        except:
            self.current_operation = None
    
    def get_current_operation(self) -> Optional[Operation]:
        """Get the current active operation"""
        return self.current_operation
    
    def delete_operation(self, name: str, force: bool = False):
        """Delete an operation"""
        if name not in self.operations:
            raise ValueError(f"Operation '{name}' not found")
        
        # Check if it's the current operation
        if self.current_operation and self.current_operation.name == name:
            if not force:
                raise ValueError(f"Cannot delete current operation '{name}'. Switch first or use --force")
            self.current_operation = None
            if self.current_op_file.exists():
                self.current_op_file.unlink()
        
        # Delete operation file
        op_file = self.operations_dir / f"{name}.json"
        if op_file.exists():
            op_file.unlink()
        
        # Remove from memory
        del self.operations[name]
    
    def archive_operation(self, name: str):
        """Archive an operation (mark as completed)"""
        if name not in self.operations:
            raise ValueError(f"Operation '{name}' not found")
        
        op = self.operations[name]
        op.status = 'archived'
        op.modified = datetime.utcnow().isoformat() + 'Z'
        self.save_operation(op)
        
        # If it was current, clear current
        if self.current_operation and self.current_operation.name == name:
            self.current_operation = None
            if self.current_op_file.exists():
                self.current_op_file.unlink()
    
    def update_operation_metadata(self, name: str, key: str, value: Any):
        """Update operation metadata"""
        if name not in self.operations:
            raise ValueError(f"Operation '{name}' not found")
        
        op = self.operations[name]
        op.metadata[key] = value
        op.modified = datetime.utcnow().isoformat() + 'Z'
        self.save_operation(op)
    
    def add_credential_to_operation(self, op_name: str, cred_id: str):
        """Add a credential reference to an operation"""
        if op_name not in self.operations:
            raise ValueError(f"Operation '{op_name}' not found")
        
        op = self.operations[op_name]
        if cred_id not in op.credential_ids:
            op.credential_ids.append(cred_id)
            op.modified = datetime.utcnow().isoformat() + 'Z'
            self.save_operation(op)
    
    def remove_credential_from_operation(self, op_name: str, cred_id: str):
        """Remove a credential reference from an operation"""
        if op_name not in self.operations:
            raise ValueError(f"Operation '{op_name}' not found")
        
        op = self.operations[op_name]
        if cred_id in op.credential_ids:
            op.credential_ids.remove(cred_id)
            op.modified = datetime.utcnow().isoformat() + 'Z'
            self.save_operation(op)
    
    def get_operation_credentials(self, op_name: str) -> List[str]:
        """Get all credential IDs for an operation"""
        if op_name not in self.operations:
            raise ValueError(f"Operation '{op_name}' not found")
        
        return self.operations[op_name].credential_ids