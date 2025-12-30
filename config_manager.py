"""
SecureIT - Configuration Manager Module
Manages application settings and user preferences
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime


class ConfigManager:
    """
    Manages application configuration and user preferences
    """
    
    DEFAULT_CONFIG = {
        "version": "1.0",
        "settings": {
            "default_output_directory": "",
            "secure_delete_default": False,
            "password_requirements": {
                "minimum_length": 8,
                "require_uppercase": True,
                "require_lowercase": True,
                "require_numbers": True,
                "require_special_chars": True
            },
            "audit_log": {
                "enabled": True,
                "retention_days": 365,
                "database_path": ""
            },
            "ui_preferences": {
                "show_file_extensions": True,
                "confirm_before_delete": True,
                "theme": "light"
            },
            "performance": {
                "chunk_size_kb": 1024,
                "max_batch_files": 1000
            }
        },
        "last_modified": ""
    }
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager
        
        Args:
            config_path: Path to config file (defaults to AppData folder)
        """
        if config_path is None:
            appdata = os.getenv('APPDATA')
            secureit_dir = os.path.join(appdata, 'SecureIT')
            os.makedirs(secureit_dir, exist_ok=True)
            config_path = os.path.join(secureit_dir, 'config.json')
            
        self.config_path = config_path
        self.config = self._load_config()
        
    def _load_config(self) -> Dict:
        """
        Load configuration from file or create default
        
        Returns:
            Configuration dictionary
        """
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    # Merge with defaults to ensure all keys exist
                    return self._merge_configs(self.DEFAULT_CONFIG.copy(), config)
            except Exception as e:
                print(f"Error loading config: {e}")
                return self._create_default_config()
        else:
            return self._create_default_config()
            
    def _create_default_config(self) -> Dict:
        """
        Create default configuration
        
        Returns:
            Default configuration dictionary
        """
        config = self.DEFAULT_CONFIG.copy()
        
        # Set default paths
        appdata = os.getenv('APPDATA')
        secureit_dir = os.path.join(appdata, 'SecureIT')
        
        documents = os.path.join(os.path.expanduser('~'), 'Documents', 'SecureIT')
        os.makedirs(documents, exist_ok=True)
        config['settings']['default_output_directory'] = documents
        
        config['settings']['audit_log']['database_path'] = os.path.join(secureit_dir, 'audit.db')
        config['last_modified'] = datetime.utcnow().isoformat() + 'Z'
        
        # Save default config
        self.save_config(config)
        
        return config
        
    def _merge_configs(self, default: Dict, user: Dict) -> Dict:
        """
        Recursively merge user config with default config
        
        Args:
            default: Default configuration
            user: User configuration
            
        Returns:
            Merged configuration
        """
        for key, value in user.items():
            if key in default:
                if isinstance(value, dict) and isinstance(default[key], dict):
                    default[key] = self._merge_configs(default[key], value)
                else:
                    default[key] = value
                    
        return default
        
    def save_config(self, config: Optional[Dict] = None):
        """
        Save configuration to file
        
        Args:
            config: Configuration dictionary to save (uses self.config if None)
        """
        if config is None:
            config = self.config
            
        config['last_modified'] = datetime.utcnow().isoformat() + 'Z'
        
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            raise IOError(f"Failed to save configuration: {e}")
            
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value by key path
        
        Args:
            key_path: Dot-separated path (e.g., 'settings.secure_delete_default')
            default: Default value if key doesn't exist
            
        Returns:
            Configuration value
        """
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
                
        return value
        
    def set(self, key_path: str, value: Any):
        """
        Set configuration value by key path
        
        Args:
            key_path: Dot-separated path (e.g., 'settings.secure_delete_default')
            value: Value to set
        """
        keys = key_path.split('.')
        config = self.config
        
        # Navigate to the parent dictionary
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
            
        # Set the value
        config[keys[-1]] = value
        
        # Save configuration
        self.save_config()
        
    def get_default_output_directory(self) -> str:
        """Get default output directory"""
        return self.get('settings.default_output_directory', os.path.expanduser('~'))
        
    def set_default_output_directory(self, path: str):
        """Set default output directory"""
        if os.path.exists(path) and os.path.isdir(path):
            self.set('settings.default_output_directory', path)
        else:
            raise ValueError(f"Invalid directory path: {path}")
            
    def get_secure_delete_default(self) -> bool:
        """Get secure delete default setting"""
        return self.get('settings.secure_delete_default', False)
        
    def set_secure_delete_default(self, enabled: bool):
        """Set secure delete default setting"""
        self.set('settings.secure_delete_default', enabled)
        
    def get_password_requirements(self) -> Dict:
        """Get password requirements"""
        return self.get('settings.password_requirements', {})
        
    def set_password_requirements(self, requirements: Dict):
        """Set password requirements"""
        self.set('settings.password_requirements', requirements)
        
    def get_audit_log_settings(self) -> Dict:
        """Get audit log settings"""
        return self.get('settings.audit_log', {})
        
    def get_ui_preferences(self) -> Dict:
        """Get UI preferences"""
        return self.get('settings.ui_preferences', {})
        
    def set_ui_preference(self, key: str, value: Any):
        """Set UI preference"""
        self.set(f'settings.ui_preferences.{key}', value)
        
    def get_performance_settings(self) -> Dict:
        """Get performance settings"""
        return self.get('settings.performance', {})
        
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        self.config = self._create_default_config()
        self.save_config()
        
    def export_config(self, export_path: str):
        """
        Export configuration to specified path
        
        Args:
            export_path: Path to export configuration
        """
        with open(export_path, 'w', encoding='utf-8') as f:
            json.dump(self.config, f, indent=4)
            
    def import_config(self, import_path: str):
        """
        Import configuration from specified path
        
        Args:
            import_path: Path to import configuration from
        """
        if not os.path.exists(import_path):
            raise FileNotFoundError(f"Config file not found: {import_path}")
            
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                imported_config = json.load(f)
                
            # Merge with defaults to ensure validity
            self.config = self._merge_configs(self.DEFAULT_CONFIG.copy(), imported_config)
            self.save_config()
            
        except Exception as e:
            raise ValueError(f"Invalid configuration file: {e}")
            
    def validate_config(self) -> bool:
        """
        Validate current configuration
        
        Returns:
            True if configuration is valid
        """
        try:
            # Check required keys
            required_keys = [
                'version',
                'settings',
                'settings.password_requirements',
                'settings.audit_log',
                'settings.ui_preferences',
                'settings.performance'
            ]
            
            for key in required_keys:
                if self.get(key) is None:
                    return False
                    
            # Validate paths
            output_dir = self.get_default_output_directory()
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)
                
            return True
            
        except Exception:
            return False


# Test function
def test_config_manager():
    """Test configuration manager functionality"""
    import tempfile
    
    # Create temporary config file
    temp_config = os.path.join(tempfile.gettempdir(), 'test_config.json')
    
    try:
        print("Testing Configuration Manager\n")
        print("=" * 60)
        
        # Initialize config manager
        config = ConfigManager(temp_config)
        
        # Test getting values
        print("\nDefault Configuration:")
        print(f"  Output Directory: {config.get_default_output_directory()}")
        print(f"  Secure Delete Default: {config.get_secure_delete_default()}")
        print(f"  Password Requirements: {config.get_password_requirements()}")
        
        # Test setting values
        print("\nSetting new values...")
        config.set_secure_delete_default(True)
        config.set('settings.ui_preferences.theme', 'dark')
        
        print(f"  Secure Delete Default: {config.get_secure_delete_default()}")
        print(f"  Theme: {config.get('settings.ui_preferences.theme')}")
        
        # Test export/import
        export_path = os.path.join(tempfile.gettempdir(), 'exported_config.json')
        config.export_config(export_path)
        print(f"\nExported config to: {export_path}")
        
        # Test validation
        print(f"\nConfiguration valid: {config.validate_config()}")
        
        # Test reset
        print("\nResetting to defaults...")
        config.reset_to_defaults()
        print(f"  Secure Delete Default: {config.get_secure_delete_default()}")
        
        print("\nTest completed!")
        
    finally:
        # Cleanup
        if os.path.exists(temp_config):
            os.remove(temp_config)


if __name__ == "__main__":
    test_config_manager()