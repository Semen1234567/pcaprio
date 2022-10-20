from typing import Callable


def get_dumper(format: str) -> Callable:
    if format == "yaml":
        import yaml
        return yaml.dump
    elif format == "json":
        import json
        return json.dump
    else:
        raise ValueError("Unknown format")