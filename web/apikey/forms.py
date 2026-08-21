from django import forms

from .models import ApiKey


class ApiKeyCreateForm(forms.ModelForm):
    class Meta:
        model = ApiKey
        fields = ("name",)
        widgets = {
            "name": forms.TextInput(attrs={
                "class": "form-control",
                "placeholder": "e.g. ci-bot, personal-laptop, automation",
                "autofocus": "autofocus",
                "maxlength": 100,
            }),
        }

    def clean_name(self):
        name = (self.cleaned_data.get("name") or "").strip()
        if not name:
            raise forms.ValidationError("Name is required.")
        return name
