def transform_to_minimal(data, url, cached):
    """
    Transforms the full analysis data into a minimal, de-duplicated structure.
    """
    humble_data = data.get('humble', {})
    
    present_headers = {
        header: details.get('value')
        for header, details in data.get('security_headers', {}).items()
        if details.get('present')
    }

    minimal_data = {
        'url': url,
        'status_code': data.get('status_code'),
        'grade': data.get('grade'),
        'score': data.get('score'),
        'scan_summary': {
            'timestamp': data.get('timestamp'),
            'scan_time_seconds': data.get('scan_time'),
            'source': data.get('analysis_source'),
            'cached': cached
        },
        'headers': {
            'present': present_headers,
            'missing': data.get('missing_headers', [])
        },
        'analysis': {
            'warnings': data.get('warnings', []),
            'deprecated_or_insecure': humble_data.get('deprecated_or_insecure', []),
            'fingerprint': humble_data.get('fingerprint_headers', [])
        },
        'browser_compatibility': humble_data.get('browser_compat_map', [])
    }
    return minimal_data
