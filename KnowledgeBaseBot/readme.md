### CAPE issues knowledge database

* The process has two main phases: a one-time setup you do on your computer, and the automated process that runs on GitHub.

### Phase 1: Local Setup & Knowledge Base Creation
* This is what you need to do on your own machine to prepare the bot's "brain" 🧠.

1. Configure GitHub Secrets
    * Go to your GitHub repository's Settings > Secrets and variables > Actions.
    * Create two new repository secrets:
        * GITHUB_TOKEN: You don't need to create this one from scratch. GitHub provides it automatically to the action, but you will need a Personal Access Token with repo scope for the local script below.
        * GEMINI_API_KEY: Paste your API key from [Gemini](https://aistudio.google.com/apikey).

2. Build the Knowledge Base

Set environment variables: You need to provide your GitHub token so the script can access your repository's issues.

```Bash
# For macOS/Linux
export GITHUB_TOKEN='your_personal_access_token'
```

* Run the script: Execute the builder script. This will read all your docs and issues and may take a few minutes.

```Bash
uv venv --python python3.10 git_venv
source git_venv/bin/activate
uv pip install -r requirements.txt --no-build-isolation
uv run python build_knowledge_base.py
```

* After it finishes, you will see four new files in your folder: unified_index.faiss, metadata.pkl, all_texts.pkl, and kb_state.pkl. These files are your bot's knowledge base.

### Phase 2: Deploy to GitHub
Now you just need to upload everything to your repository.

1. Commit and Push Everything

Add all the files to git—including the new knowledge base files.

```Bash
git add .
git commit -m "feat: Add auto-answer bot and knowledge base"
git push
```

### You're Done! What Happens Now?
* From this moment on, the process is fully automatic.
* A user opens a new issue in your repository.
* The `auto_answer.yml` workflow automatically triggers.
* It runs the `auto_answer_bot.py` script.
* The bot reads the new issue, searches for similar content in your knowledge base files (.faiss and .pkl), generates a helpful response using Google Gemini, and posts it as a comment.


### Maintenance
* Every few months, or after you close many new issues, you should run build_knowledge_base.py again locally and commit the updated knowledge base files to keep the bot's information fresh.
