
from pqcbench import registry

def test_registry_has_placeholders():
    items = registry.list()
    assert "rsa-oaep" in items
    assert "rsa-pss" in items
    assert "kyber" in items
    assert "dilithium" in items
