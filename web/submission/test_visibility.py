import pytest
from django.contrib.auth.models import User


@pytest.mark.django_db
def test_submit_form_renders_visibility_control(cape_db, client):
    u = User.objects.create_user("a", "a@x.com", "x")
    client.force_login(u)
    try:
        from django.urls import reverse
        url = reverse("submission")
    except Exception:
        url = "/submit/"
    r = client.get(url)
    assert r.status_code == 200
    assert b'name="visibility"' in r.content
