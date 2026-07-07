from fastapi.testclient import TestClient

from sentinal_fuzz.web.app import app


client = TestClient(app)


def test_favicon_routes_return_svg() -> None:
    response = client.get("/favicon.png")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
