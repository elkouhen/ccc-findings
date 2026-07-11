import yaml


def load_config(raw: str) -> dict:
    return yaml.load(raw)
