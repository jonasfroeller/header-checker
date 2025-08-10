import os
import logging
from flask import Flask, request, jsonify, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from services.humble_service import HumbleService
from services.cache_service import CacheService
from utils.validators import URLValidator

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get(
    "SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)

humble_service = HumbleService()
cache_service = CacheService()
url_validator = URLValidator()


@app.route('/')
def index():
    """Render the main web interface"""
    is_dev_mode = app.debug or os.environ.get(
        'FLASK_ENV') == 'development' or os.environ.get('REPL_SLUG')
    shared_url = request.args.get('url')
    return render_template('index.html', is_dev_mode=is_dev_mode, shared_url=shared_url)


@app.route('/api/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def analyze_url():
    """
    Analyze a URL for HTTP security headers

    Expected JSON payload:
    {
        "url": "https://example.com",
        "force_refresh": false
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'error': 'Invalid JSON payload',
                'message': 'Request must contain valid JSON data'
            }), 400

        url = data.get('url')
        if not url:
            return jsonify({
                'error': 'Missing URL',
                'message': 'URL field is required'
            }), 400

        validation_result = url_validator.validate(url)
        if not validation_result['valid']:
            return jsonify({
                'error': 'Invalid URL',
                'message': validation_result['message']
            }), 400

        normalized_url = validation_result['normalized_url']
        try_fallback = validation_result.get('try_fallback', False)
        force_refresh = data.get('force_refresh', False)

        if not force_refresh:
            cached_result = cache_service.get(normalized_url)
            if cached_result:
                logger.info(f"Cache hit for URL: {normalized_url}")
                return jsonify({
                    'url': normalized_url,
                    'cached': True,
                    **cached_result
                })

        # Analyze with humble (with automatic protocol fallback)
        logger.info(f"Analyzing URL with humble: {normalized_url}")
        analysis_result = humble_service.analyze(
            normalized_url, try_fallback=try_fallback)

        if analysis_result['success']:
            cache_service.set(normalized_url, analysis_result['data'])

            return jsonify({
                'url': normalized_url,
                'cached': False,
                **analysis_result['data']
            })
        else:
            return jsonify({
                'error': 'Analysis failed',
                'message': analysis_result['error']
            }), 500

    except Exception as e:
        logger.error(f"Unexpected error in analyze_url: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': 'An unexpected error occurred'
        }), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        humble_available = humble_service.check_availability()

        return jsonify({
            'status': 'healthy',
            'services': {
                'humble': 'available' if humble_available else 'unavailable',
                'cache': 'available'
            },
            'cache_stats': cache_service.get_stats()
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500


@app.route('/api/cache/clear', methods=['POST'])
@limiter.limit("5 per minute")
def clear_cache():
    """Clear the analysis cache"""
    try:
        is_dev_mode = app.debug or os.environ.get('FLASK_ENV') == 'development' or os.environ.get('REPL_SLUG')
        if not is_dev_mode:
            return jsonify({
                'error': 'Forbidden',
                'message': 'Cache clearing is disabled in production'
            }), 403
        cache_service.clear()
        return jsonify({
            'message': 'Cache cleared successfully'
        })
    except Exception as e:
        logger.error(f"Failed to clear cache: {str(e)}")
        return jsonify({
            'error': 'Failed to clear cache',
            'message': str(e)
        }), 500


@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded"""
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.'
    }), 429


@app.errorhandler(404)
def not_found_handler(e):
    """Handle 404 errors"""
    return jsonify({
        'error': 'Not found',
        'message': 'The requested endpoint does not exist'
    }), 404


@app.errorhandler(500)
def internal_error_handler(e):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {str(e)}")
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
