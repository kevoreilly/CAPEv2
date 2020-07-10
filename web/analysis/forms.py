# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from django import forms

from submission.models import Comment, Tag


class CommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        fields = ["message"]


class TagForm(forms.ModelForm):
    class Meta:
        model = Tag
        fields = ["name"]
