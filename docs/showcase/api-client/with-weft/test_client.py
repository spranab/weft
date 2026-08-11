from client import build_url


def test_build_url():
    assert build_url("/users") == "https://api.example.com/users"
