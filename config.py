import os
from datetime import timedelta

class Config:
    # Base configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
    LOOKOUT_APP_KEY = os.getenv('LOOKOUT_APP_KEY')
    
    # Cache configuration
    CACHE_TYPE = 'SimpleCache'
    CACHE_DEFAULT_TIMEOUT = 900  # 15 minutes in seconds
    
    # Logging configuration
    LOG_LEVEL = 'INFO'
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

class DevelopmentConfig(Config):
    DEBUG = True
    ENV = 'development'
    LOG_LEVEL = 'DEBUG'

class ProductionConfig(Config):
    DEBUG = False
    ENV = 'production'
    # Use a more robust cache in production if available
    CACHE_TYPE = os.getenv('CACHE_TYPE', 'SimpleCache')
    # Increase cache timeout in production
    CACHE_DEFAULT_TIMEOUT = int(os.getenv('CACHE_TIMEOUT', 3600))  # 1 hour

# Export configs
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}