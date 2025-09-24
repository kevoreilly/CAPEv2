import os
import faiss
import pickle
import numpy as np
from github import Github
from sentence_transformers import SentenceTransformer
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.document_loaders import DirectoryLoader
from datetime import datetime, timezone

# --- Configuration ---
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
# GITHUB_TOKEN =
REPO_NAME = "kevoreilly/CAPEv2"
DOCS_PATH = "../docs" # Path to the folder with your documentation files (e.g., .md)
MODEL_NAME = 'all-MiniLM-L6-v2' # An efficient embedding model

# --- File Paths for State ---
INDEX_FILE = "unified_index.faiss"
METADATA_FILE = "metadata.pkl"
TEXTS_FILE = "all_texts.pkl"
STATE_FILE = "kb_state.pkl" # New file to store the last update time

# init pandoc
from pypandoc.pandoc_download import download_pandoc
download_pandoc()

# --- Initialization ---
g = Github(GITHUB_TOKEN)
# auth=github.Auth.Token(...)
repo = g.get_repo(REPO_NAME)
model = SentenceTransformer(MODEL_NAME)

# --- Load Existing Knowledge Base or Initialize a New One ---
if os.path.exists(INDEX_FILE):
    print("Loading existing knowledge base...")
    index = faiss.read_index(INDEX_FILE)
    with open(METADATA_FILE, "r") as f:
        metadata = json.load(f)
    with open(TEXTS_FILE, "r") as f:
        all_texts = json.load(f)
    with open(STATE_FILE, "r") as f:
        last_update_time = datetime.fromisoformat(json.load(f))
    print(f"Knowledge base loaded. Last update was at: {last_update_time}")
else:
    print("No existing knowledge base found. Creating a new one.")
    index = None
    metadata = []
    all_texts = []
    # Set a very old date to fetch all issues for the first time
    last_update_time = datetime(1970, 1, 1, tzinfo=timezone.utc)

    # Initial processing of documentation (only on first build)
    print("Processing documentation for the first time...")
    loader = DirectoryLoader(DOCS_PATH, glob="**/*.rst")
    docs = loader.load()
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
    doc_chunks = text_splitter.split_documents(docs)
    for chunk in doc_chunks:
        all_texts.append(chunk.page_content)
        metadata.append({'source': 'documentation', 'file': chunk.metadata.get('source', 'N/A')})

# --- Process Documentation ---
print("Processing documentation...")
# Use DirectoryLoader to load all .md files from the directory
loader = DirectoryLoader(DOCS_PATH, glob="**/*.rst")
docs = loader.load()

# Split the documents into smaller, manageable chunks
text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
doc_chunks = text_splitter.split_documents(docs)

for chunk in doc_chunks:
    all_texts.append(chunk.page_content)
    metadata.append({'source': 'documentation', 'file': chunk.metadata.get('source', 'N/A')})

# --- Process GitHub Issues ---
# --- Fetch New Issues from GitHub ---
print(f"Fetching issues updated since {last_update_time.isoformat()}...")
# The 'since' parameter fetches issues updated on or after the given time
new_issues = repo.get_issues(state='all', since=last_update_time)

new_issue_texts = []
new_issue_metadata = []
latest_issue_time = last_update_time

for issue in new_issues:
    # We check the updated_at time to ensure we save the most recent timestamp
    if issue.updated_at.replace(tzinfo=timezone.utc) > latest_issue_time:
        latest_issue_time = issue.updated_at.replace(tzinfo=timezone.utc)

    # Simple logic to avoid adding duplicates. For a robust system, you might check IDs.
    issue_url = issue.html_url
    if issue_url in existing_issue_urls:
        print(f"Skipping issue #{issue.number} as it might be a duplicate or minor update.")
        continue

    print(f"Processing new/updated issue #{issue.number}")
    full_text = f"Title: {issue.title}\nBody: {issue.body}"
    for comment in issue.get_comments():
        full_text += f"\nComment: {comment.body}"

    new_issue_texts.append(full_text)
    new_issue_metadata.append({'source': 'issue', 'number': issue.number, 'url': issue.html_url})

# --- Add New Issues to the Knowledge Base ---
if new_issue_texts:
    print(f"Found {len(new_issue_texts)} new/updated issues to add.")

    # Generate embeddings for new issues only
    new_embeddings = model.encode(new_issue_texts, show_progress_bar=True)
    new_embeddings = np.array(new_embeddings).astype('float32')

    # If the index is new, create it
    if index is None:
        dimension = new_embeddings.shape[1]
        index = faiss.IndexFlatL2(dimension)

    # Add new embeddings to the index and update metadata lists
    index.add(new_embeddings)
    all_texts.extend(new_issue_texts)
    metadata.extend(new_issue_metadata)

    print("Knowledge base updated.")
else:
    print("No new issues found. Knowledge base is already up-to-date.")

# --- Save the Updated Knowledge Base and State ---
print("Saving knowledge base and state...")
faiss.write_index(index, INDEX_FILE)
with open(METADATA_FILE, "w") as f:
    json.dump(metadata, f, indent=2)
with open(TEXTS_FILE, "w") as f:
    json.dump(all_texts, f, indent=2)
# Save the timestamp of the latest issue we processed for the next run
with open(STATE_FILE, "w") as f:
    json.dump(latest_issue_time.isoformat(), f)

print("Process complete!")
