import json
import yaml
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Any, Tuple
import re
import argparse
import os

def extract_schema_from_json(json_str: str) -> Dict:
    """Extract a JSON schema from a JSON string."""
    try:
        data = json.loads(json_str)
        return generate_schema(data)
    except:
        return {}

def generate_schema(data: Any) -> Dict:
    """Generate a JSON schema from Python data."""
    if isinstance(data, dict):
        properties = {}
        required = []
        for key, value in data.items():
            properties[key] = generate_schema(value)
            if value is not None:  # Consider non-null values as required
                required.append(key)
        return {
            "type": "object",
            "properties": properties,
            "required": required if required else None
        }
    elif isinstance(data, list):
        if data:
            return {
                "type": "array",
                "items": generate_schema(data[0])
            }
        return {"type": "array"}
    elif isinstance(data, bool):
        return {"type": "boolean"}
    elif isinstance(data, int):
        return {"type": "integer"}
    elif isinstance(data, float):
        return {"type": "number"}
    elif isinstance(data, str):
        return {"type": "string"}
    return {"type": "null"}

def extract_path_parameters(url: str) -> List[str]:
    """Extract path parameters from URL patterns."""
    # Look for patterns like /users/{id} or /users/:id
    path_params = re.findall(r'/{([^/]+)}|/:([^/]+)', url)
    return [param[0] or param[1] for param in path_params]

def generate_endpoint_description(path: str, method: str, request: Dict, response: Dict) -> str:
    """Generate a descriptive summary for an endpoint based on its path, method, and data."""
    # Extract resource name from path
    path_parts = [p for p in path.split('/') if p]
    resource = path_parts[-1] if path_parts else 'resource'
    
    # Get response status and content type
    status = response.get('status', 200)
    content_type = response.get('content', {}).get('mimeType', '')
    
    # Basic description based on HTTP method
    method_desc = {
        'get': 'Retrieve',
        'post': 'Create',
        'put': 'Update',
        'patch': 'Partially update',
        'delete': 'Delete'
    }.get(method.lower(), 'Process')
    
    # Analyze request body if present
    request_body = request.get('postData', {}).get('text', '{}')
    try:
        request_data = json.loads(request_body)
        if isinstance(request_data, dict):
            fields = list(request_data.keys())
            if fields:
                field_desc = f" with fields: {', '.join(fields)}"
            else:
                field_desc = ""
        else:
            field_desc = ""
    except:
        field_desc = ""
    
    # Analyze response if present
    response_body = response.get('content', {}).get('text', '{}')
    try:
        response_data = json.loads(response_body)
        if isinstance(response_data, dict):
            response_fields = list(response_data.keys())
            if response_fields:
                response_desc = f" Returns data with fields: {', '.join(response_fields)}"
            else:
                response_desc = ""
        elif isinstance(response_data, list):
            response_desc = f" Returns a list of {resource}s"
        else:
            response_desc = ""
    except:
        response_desc = ""
    
    # Build the description
    description = f"{method_desc} {resource}"
    if field_desc:
        description += field_desc
    if response_desc:
        description += response_desc
    
    # Add status code information
    if status >= 200 and status < 300:
        description += f" (Success: {status})"
    elif status >= 400:
        description += f" (Error: {status})"
    
    return description

def standardize_path(path: str) -> Tuple[str, Dict[str, str]]:
    """Convert path segments with IDs into OpenAPI path parameters.
    
    Args:
        path: Original path string
        
    Returns:
        Tuple of (standardized_path, parameter_mapping)
        Example: ('/api/users/{id}', {'1000140': 'id'})
    """
    # Split path into segments
    segments = path.split('/')
    param_mapping = {}
    
    # Patterns to identify parameter segments
    patterns = [
        (r'^\d+$', 'id'),  # Numeric IDs
        (r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', 'uuid'),  # UUIDs
        (r'^[a-f0-9]{32}$', 'hash'),  # MD5-like hashes
        (r'^[a-zA-Z0-9_-]{20,}$', 'token'),  # Long tokens
    ]
    
    # Process each segment
    for i, segment in enumerate(segments):
        if not segment:  # Skip empty segments
            continue
            
        # Check if segment matches any parameter pattern
        for pattern, param_type in patterns:
            if re.match(pattern, segment):
                # Create parameter name based on type and position
                param_name = f"{param_type}_{i}" if i > 0 else param_type
                segments[i] = f"{{{param_name}}}"
                param_mapping[segment] = param_name
                break
    
    return '/'.join(segments), param_mapping

def convert_har_to_openapi(har_file: str, path_prefix: str = None) -> Dict:
    """Convert HAR file to OpenAPI specification.
    
    Args:
        har_file: Path to the HAR file
        path_prefix: Optional path prefix to filter endpoints (e.g., '/api')
    """
    with open(har_file, 'r') as f:
        har_data = json.load(f)

    # Initialize OpenAPI spec
    openapi_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "API Specification",
            "version": "1.0.0",
            "description": f"Generated from HAR file{f' (filtered by path prefix: {path_prefix})' if path_prefix else ''}"
        },
        "paths": {},
        "components": {
            "schemas": {},
            "securitySchemes": {
                "cookieAuth": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "session"
                }
            }
        },
        "security": [{"cookieAuth": []}]
    }

    # Track standardized paths to merge similar endpoints
    path_mapping = {}

    # Process each entry in the HAR file
    for entry in har_data.get('log', {}).get('entries', []):
        request = entry.get('request', {})
        response = entry.get('response', {})
        
        # Parse URL
        url = request.get('url', '')
        parsed_url = urlparse(url)
        original_path = parsed_url.path
        
        # Skip non-HTTP(S) URLs
        if not parsed_url.scheme.startswith('http'):
            continue

        # Skip paths that don't match the prefix if specified
        if path_prefix and not original_path.startswith(path_prefix):
            continue

        # Standardize path and get parameter mapping
        path, param_mapping = standardize_path(original_path)
        
        # Get HTTP method
        method = request.get('method', 'GET').lower()
        
        # Initialize path if not exists
        if path not in openapi_spec['paths']:
            openapi_spec['paths'][path] = {}
        
        # Generate description
        description = generate_endpoint_description(path, method, request, response)
        
        # Create operation
        operation = {
            "summary": f"{method.upper()} {path}",
            "description": description,
            "operationId": f"{method}_{path.replace('/', '_')}",
            "responses": {
                str(response.get('status', 200)): {
                    "description": response.get('statusText', ''),
                    "content": {
                        "application/json": {
                            "schema": extract_schema_from_json(response.get('content', {}).get('text', '{}'))
                        }
                    }
                }
            }
        }

        # Add request body if present
        if request.get('postData'):
            operation['requestBody'] = {
                "description": "Request body containing the data to be processed",
                "content": {
                    "application/json": {
                        "schema": extract_schema_from_json(request['postData'].get('text', '{}'))
                    }
                }
            }

        # Add query parameters
        query_params = parse_qs(parsed_url.query)
        if query_params:
            operation['parameters'] = []
            for param_name, param_values in query_params.items():
                operation['parameters'].append({
                    "name": param_name,
                    "in": "query",
                    "required": True,
                    "description": f"Query parameter: {param_name}",
                    "schema": {"type": "string"}
                })

        # Add path parameters from standardization
        if param_mapping:
            if 'parameters' not in operation:
                operation['parameters'] = []
            for original_value, param_name in param_mapping.items():
                operation['parameters'].append({
                    "name": param_name,
                    "in": "path",
                    "required": True,
                    "description": f"Path parameter: {param_name} (e.g., {original_value})",
                    "schema": {"type": "string"}
                })

        # Add operation to path
        openapi_spec['paths'][path][method] = operation

    return openapi_spec

def merge_openapi_specs(existing_spec: Dict, new_spec: Dict) -> Dict:
    """Merge two OpenAPI specifications, keeping the existing one as base."""
    merged = existing_spec.copy()
    
    # Merge paths
    if 'paths' not in merged:
        merged['paths'] = {}
    
    # Add or update paths from new spec
    for path, methods in new_spec.get('paths', {}).items():
        if path not in merged['paths']:
            merged['paths'][path] = {}
        merged['paths'][path].update(methods)
    
    # Merge components
    if 'components' not in merged:
        merged['components'] = {'schemas': {}, 'securitySchemes': {}}
    
    # Merge schemas
    if 'schemas' in new_spec.get('components', {}):
        merged['components']['schemas'].update(new_spec['components']['schemas'])
    
    # Merge security schemes
    if 'securitySchemes' in new_spec.get('components', {}):
        merged['components']['securitySchemes'].update(new_spec['components']['securitySchemes'])
    
    return merged

def main():
    """Main function to convert HAR to OpenAPI spec."""
    parser = argparse.ArgumentParser(description='Convert HAR file to OpenAPI specification')
    parser.add_argument('--har-file', default='network_requests.har', help='Path to the HAR file')
    parser.add_argument('--output', default='openapi_spec.yaml', help='Output YAML file path')
    parser.add_argument('--path-prefix', help='Filter endpoints by path prefix (e.g., /api)')
    parser.add_argument('--append', action='store_true', help='Append new endpoints to existing spec file instead of replacing it')
    
    args = parser.parse_args()
    
    print(f"Converting {args.har_file} to OpenAPI specification...")
    if args.path_prefix:
        print(f"Filtering endpoints with path prefix: {args.path_prefix}")
    
    # Generate new spec
    new_spec = convert_har_to_openapi(args.har_file, args.path_prefix)
    
    # Handle appending to existing file
    if args.append and os.path.exists(args.output):
        print(f"Appending to existing spec file: {args.output}")
        try:
            with open(args.output, 'r') as f:
                existing_spec = yaml.safe_load(f)
            final_spec = merge_openapi_specs(existing_spec, new_spec)
        except Exception as e:
            print(f"Error reading existing spec file: {e}")
            print("Creating new spec file instead.")
            final_spec = new_spec
    else:
        final_spec = new_spec
    
    # Write the final spec
    with open(args.output, 'w') as f:
        yaml.dump(final_spec, f, sort_keys=False, allow_unicode=True)
    
    print(f"OpenAPI specification has been written to {args.output}")

if __name__ == "__main__":
    main() 