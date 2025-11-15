import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse


@pytest.mark.django_db
def test_submission_redirects_to_login_when_auth_is_enabled(client, settings):
    """在开启 WEB_AUTHENTICATION 时，访问提交页应被重定向到登录页。"""

    settings.WEB_AUTHENTICATION = True
    response = client.get("/submit/#file")
    assert response.status_code == 302
    assert reverse("login") in response["Location"]


@pytest.mark.django_db
def test_user_can_log_in_and_access_submission(client, settings):
    """成功登录后应能访问受保护的视图。"""

    settings.WEB_AUTHENTICATION = True
    user = get_user_model().objects.create_user(username="tester", password="pass12345")

    login_response = client.post(
        reverse("login"),
        {"username": user.username, "password": "pass12345"},
    )
    assert login_response.status_code == 302
    assert login_response["Location"].endswith("/")

    protected_response = client.get("/submit/#file")
    assert protected_response.status_code == 200
