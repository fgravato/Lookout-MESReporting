# Lookout Security Reporting Application

A Flask application that generates security reports from the Lookout API.

## Features

- Real-time security metrics dashboard
- CSV report export functionality
- Configurable time ranges for reporting
- Caching system for improved performance
- Production-ready configuration

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Lookout API credentials

## Installation

1. Clone the repository:
```bash
git clone [your-repository-url]
cd [repository-name]
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
```
Edit `.env` file and add your configuration:
- LOOKOUT_APP_KEY: Your Lookout API key
- SECRET_KEY: A secure random string for Flask
- Other optional configurations

## Development

Run the development server:
```bash
flask run
```

The application will be available at `http://localhost:5000`

## Production Deployment

1. Set environment variables for production:
```bash
export FLASK_ENV=production
export FLASK_APP=app.py
```

2. Configure your production settings in `.env`:
- Set FLASK_ENV=production
- Configure proper SECRET_KEY
- Set appropriate CACHE settings
- Configure Gunicorn settings if needed

3. Run with Gunicorn:
```bash
gunicorn -c gunicorn.conf.py app:app
```

### Production Considerations

1. **Environment Variables**:
   - Never commit `.env` file to version control
   - Use proper secret management in production
   - Rotate SECRET_KEY and API keys regularly

2. **Security**:
   - Enable HTTPS in production
   - Set secure headers
   - Configure proper firewall rules

3. **Monitoring**:
   - Set up application monitoring
   - Configure proper logging
   - Set up alerts for errors

4. **Caching**:
   - Consider using Redis or Memcached in production
   - Configure appropriate cache timeouts

5. **Performance**:
   - Adjust Gunicorn workers based on server capacity
   - Monitor memory usage
   - Set up proper load balancing if needed

## API Documentation

The application provides two main endpoints:

1. `/api/report`
   - GET request
   - Query parameter: timeframe (optional)
   - Returns JSON security report

2. `/api/report/export`
   - GET request
   - Query parameter: timeframe (optional)
   - Returns CSV file

Valid timeframe values:
- LAST_30_DAYS (default)
- LAST_60_DAYS
- LAST_90_DAYS
- LAST_6_MONTHS
- ALL

## Maintenance

- Regularly update dependencies
- Monitor API rate limits
- Review and rotate API keys
- Check logs for errors and issues
- Update security patches

## Support

For issues and support, please contact your system administrator or create an issue in the repository.