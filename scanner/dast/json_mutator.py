# scanner/dast/json_mutator.py
import copy

def mutate_json(data, path, payload):
    """
    Recursively navigates a JSON object/list and replaces 
    the value at 'path' with the payload.
    """
    if not path:
        return payload
    
    new_data = copy.deepcopy(data)
    current = new_data
    
    # Walk to the second-to-last key
    for key in path[:-1]:
        current = current[key]
        
    # Replace the target key with our payload
    current[path[-1]] = payload
    return new_data

def get_json_paths(data, current_path=None):
    """
    Yields every possible key path in a JSON object.
    Example: {"user": {"id": 1}} -> [("user", "id")]
    """
    if current_path is None:
        current_path = []
        
    if isinstance(data, dict):
        for k, v in data.items():
            yield from get_json_paths(v, current_path + [k])
    elif isinstance(data, list):
        for i, v in enumerate(data):
            yield from get_json_paths(v, current_path + [i])
    else:
        yield current_path