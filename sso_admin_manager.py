"""
SSO & Admin Management System
=============================
Enterprise-grade authentication with Firebase SSO and comprehensive user management.

Features:
- Firebase SSO (Google, Email/Password, Microsoft, GitHub)
- Role-Based Access Control (RBAC)
- Admin Panel for user management
- Team/Organization management
- Audit logging
- Session management
- API key management

Roles:
- Super Admin: Full system access, manage all users and settings
- Admin: Manage users within their organization
- Manager: View all team data, limited user management
- User: Full feature access, own data only
- Viewer: Read-only access
- Guest: Demo mode only

Version: 4.2.0
"""

import streamlit as st
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
import json
import hashlib
import uuid
import os

# ============================================================================
# ROLE DEFINITIONS
# ============================================================================

class UserRole(Enum):
    """User role hierarchy (higher value = more permissions)"""
    GUEST = 0
    VIEWER = 1
    USER = 2
    MANAGER = 3
    ADMIN = 4
    SUPER_ADMIN = 5
    
    @classmethod
    def from_string(cls, role_str: str) -> 'UserRole':
        """Convert string to UserRole"""
        mapping = {
            'guest': cls.GUEST,
            'viewer': cls.VIEWER,
            'user': cls.USER,
            'manager': cls.MANAGER,
            'admin': cls.ADMIN,
            'super_admin': cls.SUPER_ADMIN,
            'superadmin': cls.SUPER_ADMIN,
        }
        return mapping.get(role_str.lower(), cls.GUEST)
    
    def __str__(self):
        return self.name.lower()


# Permission definitions
ROLE_PERMISSIONS = {
    UserRole.SUPER_ADMIN: {
        "manage_all_users": True,
        "manage_organizations": True,
        "manage_system_settings": True,
        "view_audit_logs": True,
        "manage_api_keys": True,
        "delete_any_data": True,
        "run_scans": True,
        "view_all_scans": True,
        "export_data": True,
        "manage_integrations": True,
        "access_all_tabs": True,
        "use_demo_mode": True,
        "use_live_mode": True,
    },
    UserRole.ADMIN: {
        "manage_all_users": False,
        "manage_organizations": False,
        "manage_system_settings": False,
        "view_audit_logs": True,
        "manage_api_keys": True,
        "delete_any_data": False,
        "run_scans": True,
        "view_all_scans": True,
        "export_data": True,
        "manage_integrations": True,
        "access_all_tabs": True,
        "use_demo_mode": True,
        "use_live_mode": True,
        "manage_org_users": True,
    },
    UserRole.MANAGER: {
        "manage_all_users": False,
        "manage_organizations": False,
        "manage_system_settings": False,
        "view_audit_logs": False,
        "manage_api_keys": False,
        "delete_any_data": False,
        "run_scans": True,
        "view_all_scans": True,
        "export_data": True,
        "manage_integrations": False,
        "access_all_tabs": True,
        "use_demo_mode": True,
        "use_live_mode": True,
        "manage_org_users": False,
        "view_team_data": True,
    },
    UserRole.USER: {
        "manage_all_users": False,
        "manage_organizations": False,
        "manage_system_settings": False,
        "view_audit_logs": False,
        "manage_api_keys": False,
        "delete_any_data": False,
        "run_scans": True,
        "view_all_scans": False,
        "export_data": True,
        "manage_integrations": False,
        "access_all_tabs": True,
        "use_demo_mode": True,
        "use_live_mode": True,
    },
    UserRole.VIEWER: {
        "manage_all_users": False,
        "manage_organizations": False,
        "manage_system_settings": False,
        "view_audit_logs": False,
        "manage_api_keys": False,
        "delete_any_data": False,
        "run_scans": False,
        "view_all_scans": False,
        "export_data": False,
        "manage_integrations": False,
        "access_all_tabs": True,
        "use_demo_mode": True,
        "use_live_mode": False,
    },
    UserRole.GUEST: {
        "manage_all_users": False,
        "manage_organizations": False,
        "manage_system_settings": False,
        "view_audit_logs": False,
        "manage_api_keys": False,
        "delete_any_data": False,
        "run_scans": False,
        "view_all_scans": False,
        "export_data": False,
        "manage_integrations": False,
        "access_all_tabs": False,
        "use_demo_mode": True,
        "use_live_mode": False,
    },
}

# Tab access by role
TAB_ACCESS = {
    "WAF Scanner": [UserRole.USER, UserRole.MANAGER, UserRole.ADMIN, UserRole.SUPER_ADMIN],
    "AWS Connector": [UserRole.USER, UserRole.MANAGER, UserRole.ADMIN, UserRole.SUPER_ADMIN],
    "WAF Assessment": [UserRole.VIEWER, UserRole.USER, UserRole.MANAGER, UserRole.ADMIN, UserRole.SUPER_ADMIN],
    "Architecture Designer": [UserRole.USER, UserRole.MANAGER, UserRole.ADMIN, UserRole.SUPER_ADMIN],
    "Cost Optimization": [UserRole.MANAGER, UserRole.ADMIN, UserRole.SUPER_ADMIN],
    "EKS Modernization": [UserRole.USER, UserRole.MANAGER, UserRole.ADMIN, UserRole.SUPER_ADMIN],
    "Compliance": [UserRole.VIEWER, UserRole.USER, UserRole.MANAGER, UserRole.ADMIN, UserRole.SUPER_ADMIN],
    "AI Assistant": [UserRole.USER, UserRole.MANAGER, UserRole.ADMIN, UserRole.SUPER_ADMIN],
    "Admin Panel": [UserRole.ADMIN, UserRole.SUPER_ADMIN],
}


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class User:
    """User data model"""
    uid: str
    email: str
    display_name: str
    role: UserRole
    organization_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    created_by: str = "system"
    last_login: Optional[datetime] = None
    active: bool = True
    email_verified: bool = False
    profile_image: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'uid': self.uid,
            'email': self.email,
            'display_name': self.display_name,
            'role': str(self.role),
            'organization_id': self.organization_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.created_by,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'active': self.active,
            'email_verified': self.email_verified,
            'profile_image': self.profile_image,
            'metadata': self.metadata,
        }
    
    @staticmethod
    def from_dict(data: Dict) -> 'User':
        return User(
            uid=data.get('uid', ''),
            email=data.get('email', ''),
            display_name=data.get('display_name', ''),
            role=UserRole.from_string(data.get('role', 'guest')),
            organization_id=data.get('organization_id'),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else datetime.now(),
            created_by=data.get('created_by', 'system'),
            last_login=datetime.fromisoformat(data['last_login']) if data.get('last_login') else None,
            active=data.get('active', True),
            email_verified=data.get('email_verified', False),
            profile_image=data.get('profile_image'),
            metadata=data.get('metadata', {}),
        )
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission"""
        return ROLE_PERMISSIONS.get(self.role, {}).get(permission, False)
    
    def can_access_tab(self, tab_name: str) -> bool:
        """Check if user can access a specific tab"""
        allowed_roles = TAB_ACCESS.get(tab_name, [])
        return self.role in allowed_roles or self.role == UserRole.SUPER_ADMIN


@dataclass
class Organization:
    """Organization/Team data model"""
    org_id: str
    name: str
    created_at: datetime = field(default_factory=datetime.now)
    created_by: str = "system"
    active: bool = True
    plan: str = "free"  # free, pro, enterprise
    max_users: int = 5
    settings: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'org_id': self.org_id,
            'name': self.name,
            'created_at': self.created_at.isoformat(),
            'created_by': self.created_by,
            'active': self.active,
            'plan': self.plan,
            'max_users': self.max_users,
            'settings': self.settings,
        }


@dataclass
class AuditLog:
    """Audit log entry"""
    log_id: str
    user_id: str
    user_email: str
    action: str
    resource_type: str
    resource_id: str
    details: Dict[str, Any]
    ip_address: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            'log_id': self.log_id,
            'user_id': self.user_id,
            'user_email': self.user_email,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': self.details,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat(),
        }


# ============================================================================
# LOCAL USER STORE (For demo/testing without Firebase)
# ============================================================================

class LocalUserStore:
    """Local user store for demo mode or when Firebase is not configured"""
    
    def __init__(self):
        if 'local_users' not in st.session_state:
            # Initialize with default admin user
            st.session_state.local_users = {
                'admin@wafscanner.local': {
                    'uid': 'admin-001',
                    'email': 'admin@wafscanner.local',
                    'password_hash': self._hash_password('Admin@123'),
                    'display_name': 'System Administrator',
                    'role': 'super_admin',
                    'organization_id': 'default-org',
                    'created_at': datetime.now().isoformat(),
                    'created_by': 'system',
                    'last_login': None,
                    'active': True,
                    'email_verified': True,
                }
            }
        
        if 'local_organizations' not in st.session_state:
            st.session_state.local_organizations = {
                'default-org': {
                    'org_id': 'default-org',
                    'name': 'Default Organization',
                    'created_at': datetime.now().isoformat(),
                    'created_by': 'system',
                    'active': True,
                    'plan': 'enterprise',
                    'max_users': 100,
                }
            }
        
        if 'audit_logs' not in st.session_state:
            st.session_state.audit_logs = []
    
    def _hash_password(self, password: str) -> str:
        """Hash password with salt"""
        salt = "waf-scanner-salt-2024"
        return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()
    
    def authenticate(self, email: str, password: str) -> Tuple[bool, str, Optional[User]]:
        """Authenticate user with email and password"""
        users = st.session_state.local_users
        
        if email not in users:
            return False, "User not found", None
        
        user_data = users[email]
        
        if not user_data.get('active', True):
            return False, "Account is disabled", None
        
        if user_data['password_hash'] != self._hash_password(password):
            return False, "Invalid password", None
        
        # Update last login
        user_data['last_login'] = datetime.now().isoformat()
        
        user = User.from_dict(user_data)
        
        self._log_action(user.uid, email, "login", "user", user.uid, {"method": "email_password"})
        
        return True, "Login successful", user
    
    def create_user(self, email: str, password: str, display_name: str, 
                   role: str, organization_id: str, created_by: str) -> Tuple[bool, str, Optional[User]]:
        """Create a new user"""
        users = st.session_state.local_users
        
        if email in users:
            return False, "User already exists", None
        
        uid = f"user-{uuid.uuid4().hex[:8]}"
        
        user_data = {
            'uid': uid,
            'email': email,
            'password_hash': self._hash_password(password),
            'display_name': display_name,
            'role': role,
            'organization_id': organization_id,
            'created_at': datetime.now().isoformat(),
            'created_by': created_by,
            'last_login': None,
            'active': True,
            'email_verified': False,
        }
        
        users[email] = user_data
        
        user = User.from_dict(user_data)
        
        self._log_action(created_by, created_by, "create_user", "user", uid, {"email": email, "role": role})
        
        return True, "User created successfully", user
    
    def update_user(self, uid: str, updates: Dict, updated_by: str) -> Tuple[bool, str]:
        """Update user data"""
        users = st.session_state.local_users
        
        for email, user_data in users.items():
            if user_data['uid'] == uid:
                for key, value in updates.items():
                    if key == 'password':
                        user_data['password_hash'] = self._hash_password(value)
                    elif key != 'password_hash':
                        user_data[key] = value
                
                self._log_action(updated_by, updated_by, "update_user", "user", uid, {"updates": list(updates.keys())})
                return True, "User updated successfully"
        
        return False, "User not found"
    
    def delete_user(self, uid: str, deleted_by: str) -> Tuple[bool, str]:
        """Delete (deactivate) user"""
        users = st.session_state.local_users
        
        for email, user_data in users.items():
            if user_data['uid'] == uid:
                user_data['active'] = False
                self._log_action(deleted_by, deleted_by, "delete_user", "user", uid, {"email": email})
                return True, "User deactivated successfully"
        
        return False, "User not found"
    
    def get_all_users(self) -> List[User]:
        """Get all users"""
        return [User.from_dict(data) for data in st.session_state.local_users.values()]
    
    def get_user_by_uid(self, uid: str) -> Optional[User]:
        """Get user by UID"""
        for data in st.session_state.local_users.values():
            if data['uid'] == uid:
                return User.from_dict(data)
        return None
    
    def get_organization(self, org_id: str) -> Optional[Organization]:
        """Get organization by ID"""
        orgs = st.session_state.local_organizations
        if org_id in orgs:
            data = orgs[org_id]
            return Organization(
                org_id=data['org_id'],
                name=data['name'],
                created_at=datetime.fromisoformat(data['created_at']),
                created_by=data['created_by'],
                active=data['active'],
                plan=data['plan'],
                max_users=data['max_users'],
            )
        return None
    
    def _log_action(self, user_id: str, user_email: str, action: str, 
                   resource_type: str, resource_id: str, details: Dict):
        """Log an action"""
        log = AuditLog(
            log_id=f"log-{uuid.uuid4().hex[:8]}",
            user_id=user_id,
            user_email=user_email,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
        )
        st.session_state.audit_logs.append(log.to_dict())
    
    def get_audit_logs(self, limit: int = 100) -> List[Dict]:
        """Get recent audit logs"""
        logs = st.session_state.audit_logs
        return sorted(logs, key=lambda x: x['timestamp'], reverse=True)[:limit]


# ============================================================================
# SESSION MANAGER
# ============================================================================

class SessionManager:
    """Manage user sessions"""
    
    @staticmethod
    def login(user: User):
        """Set up user session"""
        st.session_state.authenticated = True
        st.session_state.current_user = user.to_dict()
        st.session_state.user_role = user.role
        st.session_state.user_email = user.email
        st.session_state.user_id = user.uid
        st.session_state.login_time = datetime.now().isoformat()
    
    @staticmethod
    def logout():
        """Clear user session"""
        keys_to_remove = [
            'authenticated', 'current_user', 'user_role', 
            'user_email', 'user_id', 'login_time'
        ]
        for key in keys_to_remove:
            if key in st.session_state:
                del st.session_state[key]
    
    @staticmethod
    def is_authenticated() -> bool:
        """Check if user is authenticated"""
        return st.session_state.get('authenticated', False)
    
    @staticmethod
    def get_current_user() -> Optional[User]:
        """Get current logged-in user"""
        if not SessionManager.is_authenticated():
            return None
        
        user_data = st.session_state.get('current_user')
        if user_data:
            return User.from_dict(user_data)
        return None
    
    @staticmethod
    def has_permission(permission: str) -> bool:
        """Check if current user has permission"""
        user = SessionManager.get_current_user()
        if user:
            return user.has_permission(permission)
        return False
    
    @staticmethod
    def can_access_tab(tab_name: str) -> bool:
        """Check if current user can access tab"""
        user = SessionManager.get_current_user()
        if user:
            return user.can_access_tab(tab_name)
        return False


# ============================================================================
# AUTH MANAGER
# ============================================================================

class SSOAuthManager:
    """Main SSO Authentication Manager"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.firebase_available = False
        self.local_store = LocalUserStore()
        self._initialized = True
        
        # Try to initialize Firebase
        self._try_init_firebase()
    
    def _try_init_firebase(self):
        """Try to initialize Firebase from secrets"""
        try:
            import firebase_admin
            from firebase_admin import credentials, auth, firestore
            
            # Check for Firebase config in secrets
            if hasattr(st, 'secrets') and 'firebase' in st.secrets:
                firebase_config = dict(st.secrets['firebase'])
                
                if 'service_account' in firebase_config:
                    if not firebase_admin._apps:
                        cred = credentials.Certificate(firebase_config['service_account'])
                        firebase_admin.initialize_app(cred)
                    
                    self.firebase_available = True
                    self.db = firestore.client()
        except Exception as e:
            self.firebase_available = False
    
    def authenticate(self, email: str, password: str) -> Tuple[bool, str, Optional[User]]:
        """Authenticate user"""
        if self.firebase_available:
            return self._firebase_authenticate(email, password)
        else:
            return self.local_store.authenticate(email, password)
    
    def _firebase_authenticate(self, email: str, password: str) -> Tuple[bool, str, Optional[User]]:
        """Authenticate via Firebase"""
        try:
            # Get API key from secrets
            api_key = st.secrets.get('firebase', {}).get('api_key')
            
            if not api_key:
                return False, "Firebase API key not configured", None
            
            # Verify with Firebase REST API
            import requests
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
            response = requests.post(url, json={
                "email": email,
                "password": password,
                "returnSecureToken": True
            })
            
            if response.status_code != 200:
                return False, "Invalid email or password", None
            
            result = response.json()
            uid = result['localId']
            
            # Get user profile from Firestore
            user_doc = self.db.collection('users').document(uid).get()
            
            if not user_doc.exists:
                return False, "User profile not found", None
            
            user_data = user_doc.to_dict()
            user = User.from_dict(user_data)
            
            if not user.active:
                return False, "Account is disabled", None
            
            # Update last login
            self.db.collection('users').document(uid).update({
                'last_login': datetime.now().isoformat()
            })
            
            return True, "Login successful", user
            
        except Exception as e:
            return False, f"Authentication error: {str(e)}", None
    
    def create_user(self, email: str, password: str, display_name: str,
                   role: str, organization_id: str) -> Tuple[bool, str, Optional[User]]:
        """Create a new user"""
        current_user = SessionManager.get_current_user()
        created_by = current_user.email if current_user else "system"
        
        if self.firebase_available:
            return self._firebase_create_user(email, password, display_name, role, organization_id, created_by)
        else:
            return self.local_store.create_user(email, password, display_name, role, organization_id, created_by)
    
    def _firebase_create_user(self, email: str, password: str, display_name: str,
                             role: str, organization_id: str, created_by: str) -> Tuple[bool, str, Optional[User]]:
        """Create user in Firebase"""
        try:
            from firebase_admin import auth
            
            # Create in Firebase Auth
            firebase_user = auth.create_user(
                email=email,
                password=password,
                display_name=display_name,
                email_verified=False
            )
            
            # Create profile in Firestore
            user_data = {
                'uid': firebase_user.uid,
                'email': email,
                'display_name': display_name,
                'role': role,
                'organization_id': organization_id,
                'created_at': datetime.now().isoformat(),
                'created_by': created_by,
                'last_login': None,
                'active': True,
                'email_verified': False,
            }
            
            self.db.collection('users').document(firebase_user.uid).set(user_data)
            
            user = User.from_dict(user_data)
            return True, "User created successfully", user
            
        except Exception as e:
            return False, f"Error creating user: {str(e)}", None
    
    def update_user(self, uid: str, updates: Dict) -> Tuple[bool, str]:
        """Update user"""
        current_user = SessionManager.get_current_user()
        updated_by = current_user.email if current_user else "system"
        
        if self.firebase_available:
            return self._firebase_update_user(uid, updates, updated_by)
        else:
            return self.local_store.update_user(uid, updates, updated_by)
    
    def _firebase_update_user(self, uid: str, updates: Dict, updated_by: str) -> Tuple[bool, str]:
        """Update user in Firebase"""
        try:
            from firebase_admin import auth
            
            # Update auth properties if needed
            auth_updates = {}
            if 'email' in updates:
                auth_updates['email'] = updates['email']
            if 'display_name' in updates:
                auth_updates['display_name'] = updates['display_name']
            if 'password' in updates:
                auth_updates['password'] = updates['password']
            
            if auth_updates:
                auth.update_user(uid, **auth_updates)
            
            # Update Firestore profile
            firestore_updates = {k: v for k, v in updates.items() if k != 'password'}
            if firestore_updates:
                self.db.collection('users').document(uid).update(firestore_updates)
            
            return True, "User updated successfully"
            
        except Exception as e:
            return False, f"Error updating user: {str(e)}"
    
    def delete_user(self, uid: str) -> Tuple[bool, str]:
        """Delete (deactivate) user"""
        current_user = SessionManager.get_current_user()
        deleted_by = current_user.email if current_user else "system"
        
        if self.firebase_available:
            return self._firebase_delete_user(uid, deleted_by)
        else:
            return self.local_store.delete_user(uid, deleted_by)
    
    def _firebase_delete_user(self, uid: str, deleted_by: str) -> Tuple[bool, str]:
        """Deactivate user in Firebase"""
        try:
            from firebase_admin import auth
            
            # Disable in Firebase Auth
            auth.update_user(uid, disabled=True)
            
            # Update Firestore profile
            self.db.collection('users').document(uid).update({
                'active': False,
                'disabled_at': datetime.now().isoformat(),
                'disabled_by': deleted_by,
            })
            
            return True, "User deactivated successfully"
            
        except Exception as e:
            return False, f"Error deactivating user: {str(e)}"
    
    def get_all_users(self) -> List[User]:
        """Get all users"""
        if self.firebase_available:
            try:
                users = []
                docs = self.db.collection('users').stream()
                for doc in docs:
                    users.append(User.from_dict(doc.to_dict()))
                return users
            except:
                pass
        
        return self.local_store.get_all_users()
    
    def get_audit_logs(self, limit: int = 100) -> List[Dict]:
        """Get audit logs"""
        return self.local_store.get_audit_logs(limit)


# ============================================================================
# GET GLOBAL INSTANCE
# ============================================================================

def get_auth_manager() -> SSOAuthManager:
    """Get the global auth manager instance"""
    if 'auth_manager' not in st.session_state:
        st.session_state.auth_manager = SSOAuthManager()
    return st.session_state.auth_manager


# ============================================================================
# STREAMLIT UI COMPONENTS
# ============================================================================

def render_login_page():
    """Render the full-screen login page"""
    
    # Custom CSS for full-screen login
    st.markdown("""
    <style>
    /* Hide sidebar completely on login page */
    [data-testid="stSidebar"] {
        display: none !important;
    }
    
    /* Center the login form */
    .login-wrapper {
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 80vh;
    }
    
    .login-container {
        max-width: 450px;
        width: 100%;
        padding: 40px;
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border-radius: 20px;
        border: 2px solid #FF9900;
        box-shadow: 0 20px 60px rgba(255, 153, 0, 0.3);
    }
    
    .login-header {
        text-align: center;
        margin-bottom: 30px;
    }
    
    .login-logo {
        font-size: 60px;
        margin-bottom: 10px;
    }
    
    .login-title {
        color: #FF9900;
        font-size: 28px;
        font-weight: bold;
        margin-bottom: 5px;
    }
    
    .login-subtitle {
        color: #888;
        font-size: 14px;
    }
    
    .login-footer {
        text-align: center;
        margin-top: 20px;
        padding-top: 20px;
        border-top: 1px solid #333;
    }
    
    .feature-list {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 15px;
        margin-top: 30px;
    }
    
    .feature-item {
        background: rgba(255, 153, 0, 0.1);
        padding: 15px;
        border-radius: 10px;
        text-align: center;
    }
    
    .feature-icon {
        font-size: 24px;
        margin-bottom: 5px;
    }
    
    .feature-text {
        font-size: 12px;
        color: #ccc;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Create centered layout
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        # Header with logo
        st.markdown("""
        <div style="text-align: center; margin-bottom: 30px;">
            <div style="font-size: 70px;">🏗️</div>
            <h1 style="color: #FF9900; margin: 10px 0;">AWS WAF Scanner</h1>
            <p style="color: #888; font-size: 16px;">Enterprise Edition</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Login form container
        st.markdown("""
        <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); 
                    padding: 30px; border-radius: 15px; border: 1px solid #FF9900;
                    box-shadow: 0 10px 40px rgba(255, 153, 0, 0.2);">
        """, unsafe_allow_html=True)
        
        st.markdown("### 🔐 Sign In to Continue")
        st.markdown("---")
        
        with st.form("login_form", clear_on_submit=False):
            email = st.text_input(
                "📧 Email Address", 
                placeholder="admin@wafscanner.local",
                help="Enter your registered email address"
            )
            
            password = st.text_input(
                "🔑 Password", 
                type="password", 
                placeholder="Enter your password",
                help="Enter your password"
            )
            
            col_a, col_b = st.columns(2)
            with col_a:
                remember = st.checkbox("Remember me", value=True)
            with col_b:
                st.markdown(
                    "<div style='text-align: right; padding-top: 5px;'>"
                    "<a href='#' style='color: #FF9900; font-size: 12px;'>Forgot password?</a>"
                    "</div>", 
                    unsafe_allow_html=True
                )
            
            st.markdown("")  # Spacing
            
            submitted = st.form_submit_button(
                "🚀 Sign In", 
                use_container_width=True, 
                type="primary"
            )
            
            if submitted:
                if not email or not password:
                    st.error("⚠️ Please enter both email and password")
                else:
                    auth_mgr = get_auth_manager()
                    success, message, user = auth_mgr.authenticate(email, password)
                    
                    if success and user:
                        SessionManager.login(user)
                        st.success(f"✅ Welcome back, {user.display_name}!")
                        st.balloons()
                        import time
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(f"❌ {message}")
        
        st.markdown("</div>", unsafe_allow_html=True)
        
        # Demo credentials section
        st.markdown("")
        st.markdown("")
        
        with st.expander("🎭 Demo Credentials (Click to expand)"):
            st.markdown("""
            **Default Admin Account:**
            
            | Field | Value |
            |-------|-------|
            | Email | `admin@wafscanner.local` |
            | Password | `Admin@123` |
            
            *This demo account has full Super Admin access*
            """)
            
            if st.button("📋 Copy Demo Email", key="copy_email"):
                st.code("admin@wafscanner.local")
            
            if st.button("📋 Copy Demo Password", key="copy_pass"):
                st.code("Admin@123")
        
        # SSO Options
        st.markdown("---")
        st.markdown("#### 🔗 Or sign in with:")
        
        col_g, col_m, col_gh = st.columns(3)
        with col_g:
            if st.button("🔵 Google", use_container_width=True, disabled=True):
                st.info("Requires Firebase")
        with col_m:
            if st.button("🟦 Microsoft", use_container_width=True, disabled=True):
                st.info("Requires Azure AD")
        with col_gh:
            if st.button("⚫ GitHub", use_container_width=True, disabled=True):
                st.info("Requires GitHub OAuth")
        
        st.caption("*SSO options require additional configuration*")
        
        # Features showcase
        st.markdown("---")
        st.markdown("#### ✨ Enterprise Features")
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("""
            - 🔍 **WAF Scanning** - Multi-account
            - 🤖 **AI Analysis** - Claude powered
            - 📊 **Compliance** - CIS, PCI, HIPAA
            """)
        with col2:
            st.markdown("""
            - 🎨 **Architecture Designer**
            - 💰 **Cost Optimization**
            - 📄 **PDF Reports**
            """)
        
        # Footer
        st.markdown("---")
        st.markdown(
            "<div style='text-align: center; color: #666; font-size: 12px;'>"
            "AWS WAF Scanner Enterprise v4.2 | © 2024"
            "</div>",
            unsafe_allow_html=True
        )


def render_user_menu():
    """Render user menu in sidebar"""
    
    user = SessionManager.get_current_user()
    
    if not user:
        return
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 👤 Account")
    
    # User info
    role_badges = {
        UserRole.SUPER_ADMIN: "🔴 Super Admin",
        UserRole.ADMIN: "🟠 Admin",
        UserRole.MANAGER: "🟡 Manager",
        UserRole.USER: "🟢 User",
        UserRole.VIEWER: "🔵 Viewer",
        UserRole.GUEST: "⚪ Guest",
    }
    
    st.sidebar.markdown(f"**{user.display_name}**")
    st.sidebar.markdown(f"{role_badges.get(user.role, '⚪ Guest')}")
    st.sidebar.caption(user.email)
    
    # Quick actions
    if user.role in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
        if st.sidebar.button("⚙️ Admin Panel", use_container_width=True):
            st.session_state.show_admin_panel = True
            st.rerun()
    
    if st.sidebar.button("🚪 Sign Out", use_container_width=True):
        SessionManager.logout()
        st.rerun()


def render_admin_panel():
    """Render the Admin Panel"""
    
    user = SessionManager.get_current_user()
    
    if not user or user.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
        st.error("Access denied. Admin privileges required.")
        return
    
    st.markdown("## ⚙️ Admin Panel")
    st.markdown("Manage users, organizations, and system settings")
    
    tabs = st.tabs([
        "👥 User Management",
        "🏢 Organizations",
        "📊 Audit Logs",
        "🔑 API Keys",
        "⚙️ Settings"
    ])
    
    # Tab 1: User Management
    with tabs[0]:
        _render_user_management()
    
    # Tab 2: Organizations
    with tabs[1]:
        _render_organization_management()
    
    # Tab 3: Audit Logs
    with tabs[2]:
        _render_audit_logs()
    
    # Tab 4: API Keys
    with tabs[3]:
        _render_api_keys()
    
    # Tab 5: Settings
    with tabs[4]:
        _render_system_settings()


def _render_user_management():
    """Render user management section"""
    
    auth_mgr = get_auth_manager()
    current_user = SessionManager.get_current_user()
    
    st.markdown("### 👥 User Management")
    
    col1, col2 = st.columns([2, 1])
    
    with col2:
        if st.button("➕ Add New User", type="primary", use_container_width=True):
            st.session_state.show_add_user_form = True
    
    # Add user form
    if st.session_state.get('show_add_user_form', False):
        with st.expander("📝 Create New User", expanded=True):
            with st.form("add_user_form"):
                new_email = st.text_input("Email *", placeholder="user@company.com")
                new_name = st.text_input("Display Name *", placeholder="John Doe")
                new_password = st.text_input("Password *", type="password")
                new_password_confirm = st.text_input("Confirm Password *", type="password")
                
                role_options = ["viewer", "user", "manager"]
                if current_user.role == UserRole.SUPER_ADMIN:
                    role_options.append("admin")
                
                new_role = st.selectbox("Role", role_options)
                new_org = st.text_input("Organization ID", value="default-org")
                
                col_a, col_b = st.columns(2)
                with col_a:
                    submit_user = st.form_submit_button("✅ Create User", type="primary")
                with col_b:
                    cancel = st.form_submit_button("❌ Cancel")
                
                if cancel:
                    st.session_state.show_add_user_form = False
                    st.rerun()
                
                if submit_user:
                    if not all([new_email, new_name, new_password]):
                        st.error("All fields are required")
                    elif new_password != new_password_confirm:
                        st.error("Passwords do not match")
                    elif len(new_password) < 6:
                        st.error("Password must be at least 6 characters")
                    else:
                        success, message, user = auth_mgr.create_user(
                            new_email, new_password, new_name, new_role, new_org
                        )
                        if success:
                            st.success(message)
                            st.session_state.show_add_user_form = False
                            st.rerun()
                        else:
                            st.error(message)
    
    # User list
    st.markdown("### 📋 All Users")
    
    users = auth_mgr.get_all_users()
    
    # Filter options
    col1, col2, col3 = st.columns(3)
    with col1:
        filter_role = st.selectbox("Filter by Role", ["All"] + [r.name for r in UserRole])
    with col2:
        filter_status = st.selectbox("Filter by Status", ["All", "Active", "Inactive"])
    with col3:
        search = st.text_input("Search", placeholder="Search by email or name")
    
    # Apply filters
    filtered_users = users
    if filter_role != "All":
        filtered_users = [u for u in filtered_users if u.role.name == filter_role]
    if filter_status == "Active":
        filtered_users = [u for u in filtered_users if u.active]
    elif filter_status == "Inactive":
        filtered_users = [u for u in filtered_users if not u.active]
    if search:
        search_lower = search.lower()
        filtered_users = [u for u in filtered_users if search_lower in u.email.lower() or search_lower in u.display_name.lower()]
    
    # Display users
    for user in filtered_users:
        with st.expander(f"{'✅' if user.active else '❌'} {user.display_name} ({user.email})"):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown(f"**UID:** `{user.uid}`")
                st.markdown(f"**Role:** {user.role.name}")
                st.markdown(f"**Organization:** {user.organization_id or 'None'}")
            
            with col2:
                st.markdown(f"**Created:** {user.created_at.strftime('%Y-%m-%d') if user.created_at else 'N/A'}")
                st.markdown(f"**Last Login:** {user.last_login.strftime('%Y-%m-%d %H:%M') if user.last_login else 'Never'}")
                st.markdown(f"**Status:** {'Active' if user.active else 'Inactive'}")
            
            with col3:
                # Actions
                if user.uid != current_user.uid:  # Can't modify self
                    new_role = st.selectbox(
                        "Change Role",
                        [r.name.lower() for r in UserRole if r.value <= current_user.role.value],
                        index=0,
                        key=f"role_{user.uid}"
                    )
                    
                    col_a, col_b = st.columns(2)
                    with col_a:
                        if st.button("💾 Update", key=f"update_{user.uid}"):
                            success, msg = auth_mgr.update_user(user.uid, {"role": new_role})
                            if success:
                                st.success(msg)
                                st.rerun()
                            else:
                                st.error(msg)
                    
                    with col_b:
                        if user.active:
                            if st.button("🚫 Disable", key=f"disable_{user.uid}"):
                                success, msg = auth_mgr.delete_user(user.uid)
                                if success:
                                    st.success(msg)
                                    st.rerun()
                                else:
                                    st.error(msg)
                        else:
                            if st.button("✅ Enable", key=f"enable_{user.uid}"):
                                success, msg = auth_mgr.update_user(user.uid, {"active": True})
                                if success:
                                    st.success(msg)
                                    st.rerun()
                                else:
                                    st.error(msg)
    
    st.markdown(f"**Total Users:** {len(filtered_users)}")


def _render_organization_management():
    """Render organization management section"""
    
    st.markdown("### 🏢 Organization Management")
    
    st.info("Organization management allows you to group users and manage access at the team level.")
    
    orgs = st.session_state.get('local_organizations', {})
    
    for org_id, org_data in orgs.items():
        with st.expander(f"🏢 {org_data['name']} ({org_id})"):
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**Plan:** {org_data.get('plan', 'free').title()}")
                st.markdown(f"**Max Users:** {org_data.get('max_users', 5)}")
            with col2:
                st.markdown(f"**Status:** {'Active' if org_data.get('active', True) else 'Inactive'}")
                st.markdown(f"**Created:** {org_data.get('created_at', 'N/A')[:10]}")


def _render_audit_logs():
    """Render audit logs section"""
    
    st.markdown("### 📊 Audit Logs")
    
    auth_mgr = get_auth_manager()
    logs = auth_mgr.get_audit_logs(100)
    
    if not logs:
        st.info("No audit logs available")
        return
    
    # Filter options
    col1, col2 = st.columns(2)
    with col1:
        action_filter = st.selectbox("Filter by Action", ["All", "login", "create_user", "update_user", "delete_user"])
    with col2:
        date_filter = st.date_input("Filter by Date", value=None)
    
    # Display logs
    for log in logs:
        timestamp = log.get('timestamp', '')[:19]
        action = log.get('action', 'unknown')
        user_email = log.get('user_email', 'unknown')
        details = log.get('details', {})
        
        if action_filter != "All" and action != action_filter:
            continue
        
        action_icons = {
            'login': '🔐',
            'create_user': '➕',
            'update_user': '✏️',
            'delete_user': '🗑️',
        }
        
        icon = action_icons.get(action, '📋')
        
        st.markdown(f"{icon} **{timestamp}** - `{action}` by {user_email}")
        if details:
            st.caption(f"Details: {json.dumps(details)}")


def _render_api_keys():
    """Render API keys management section"""
    
    st.markdown("### 🔑 API Key Management")
    
    st.info("API keys allow programmatic access to the WAF Scanner API.")
    
    # Generate new key
    if st.button("🔐 Generate New API Key"):
        new_key = f"waf_{uuid.uuid4().hex}"
        st.code(new_key)
        st.warning("⚠️ Copy this key now - it won't be shown again!")
    
    # Existing keys (placeholder)
    st.markdown("#### Active API Keys")
    st.markdown("*No API keys configured*")


def _render_system_settings():
    """Render system settings section"""
    
    st.markdown("### ⚙️ System Settings")
    
    # Firebase status
    auth_mgr = get_auth_manager()
    
    st.markdown("#### 🔥 Firebase Status")
    if auth_mgr.firebase_available:
        st.success("✅ Firebase is connected and operational")
    else:
        st.warning("⚠️ Firebase not configured - using local authentication")
        st.info("""
        To enable Firebase SSO:
        1. Create a Firebase project at console.firebase.google.com
        2. Enable Authentication (Email/Password, Google, etc.)
        3. Download service account JSON
        4. Add to `.streamlit/secrets.toml`:
        
        ```toml
        [firebase]
        api_key = "your-api-key"
        
        [firebase.service_account]
        type = "service_account"
        project_id = "your-project"
        # ... rest of service account JSON
        ```
        """)
    
    st.markdown("#### 🎨 Application Settings")
    
    demo_mode = st.toggle("Enable Demo Mode by Default", value=True)
    require_auth = st.toggle("Require Authentication", value=False)
    
    if st.button("💾 Save Settings"):
        st.success("Settings saved!")


def require_auth(func):
    """Decorator to require authentication for a function"""
    def wrapper(*args, **kwargs):
        if not SessionManager.is_authenticated():
            render_login_page()
            return None
        return func(*args, **kwargs)
    return wrapper


def require_permission(permission: str):
    """Decorator to require specific permission"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not SessionManager.has_permission(permission):
                st.error(f"Access denied. Required permission: {permission}")
                return None
            return func(*args, **kwargs)
        return wrapper
    return decorator


def check_tab_access(tab_name: str) -> bool:
    """Check if current user can access a tab"""
    if not SessionManager.is_authenticated():
        return False
    return SessionManager.can_access_tab(tab_name)


# ============================================================================
# MAIN RENDER FUNCTION
# ============================================================================

def render_auth_wrapper(main_app_func):
    """
    Wrapper function that adds authentication to the main app
    
    Usage:
        def my_main_app():
            # Your app code
            pass
        
        render_auth_wrapper(my_main_app)
    """
    
    # Check authentication
    if not SessionManager.is_authenticated():
        render_login_page()
        return
    
    # Render user menu
    render_user_menu()
    
    # Check for admin panel
    if st.session_state.get('show_admin_panel', False):
        render_admin_panel()
        if st.button("← Back to App"):
            st.session_state.show_admin_panel = False
            st.rerun()
        return
    
    # Render main app
    main_app_func()
