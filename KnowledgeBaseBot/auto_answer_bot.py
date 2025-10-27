import os
import json
import faiss
from github import Github
from sentence_transformers import SentenceTransformer
import google.generativeai as genai

# --- Configuration ---
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
REPO_NAME = os.getenv('REPO_NAME')
try:
    ISSUE_NUMBER = int(os.getenv('ISSUE_NUMBER'))
except (TypeError, ValueError):
    print("Error: Invalid or missing ISSUE_NUMBER environment variable. Exiting.")
    exit(1)
MODEL_NAME = 'all-MiniLM-L6-v2'
K_NEAREST_NEIGHBORS = 5 # Number of similar items to retrieve
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if not GEMINI_API_KEY:
    exit("Missed GEMINI api key")
genai.configure(api_key=GEMINI_API_KEY)

# --- Initialization ---
g = Github(GITHUB_TOKEN)
repo = g.get_repo(REPO_NAME)
issue = repo.get_issue(number=ISSUE_NUMBER)
llm_model = SentenceTransformer(MODEL_NAME)

# --- Load the Unified Knowledge Base ---
index = faiss.read_index("unified_index.faiss")
with open("metadata.json", "rb") as f:
    metadata = json.load(f)
with open("all_texts.json", "rb") as f:
    all_texts = json.load(f)

# --- Process the New Issue ---
new_issue_text = f"Title: {issue.title}\nBody: {issue.body}"
new_issue_embedding = llm_model.encode([new_issue_text]).astype('float32')

# --- Semantic Search ---
distances, indices = index.search(new_issue_embedding, K_NEAREST_NEIGHBORS)
context_pieces = []

for i in indices[0]:
    source_metadata = metadata[i]
    source_text = all_texts[i]

    if source_metadata['source'] == 'documentation':
        context_pieces.append(f"--- Context from Documentation (file: {source_metadata['file']}) ---\n{source_text}")
    elif source_metadata['source'] == 'issue':
        context_pieces.append(f"--- Context from a Similar Issue ({source_metadata['url']}) ---\n{source_text}")

context = "\n\n".join(context_pieces)

# --- Generate Answer with LLM (Improved Prompt) ---
prompt = f"""
You are an expert GitHub Triage Assistant for an open-source project. Your primary goal is to ensure every issue is actionable for the developers. Your secondary goal is to answer questions using the provided context. Follow these steps in order:

**Step 1: Triage the User's Issue Quality**
First, analyze the "New Issue" content. Does it contain enough detail to be actionable?
- **GOOD ISSUE:** It has a clear description, steps to reproduce, error messages, or a specific question.
- **POOR ISSUE:** It's a short, vague question (e.g., "it doesn't work"), it's missing crucial details, or the user has deleted the issue template.

**Step 2: Take Action Based on Triage**

<if_issue_is_poor>
- Gently inform the user that more information is needed for the community to help.
- Explain *why* details are important (e.g., "to understand the context and reproduce the problem").
- Provide a clear, actionable list of what's missing. Use the official issue template as a guide (e.g., "Please provide steps to reproduce, the version you are using, and any error logs.").
- Politely remind them that this is a community-supported open-source project and that clear, detailed reports are the best way to get helpful and fast responses from volunteers.
- **Do NOT attempt to answer the question.** Your only goal is to improve the quality of the issue report.
</if_issue_is_poor>

<if_issue_is_good>
- Acknowledge their well-detailed report.
- Now, analyze the "Relevant Context" provided (from documentation and past issues).
- Generate a clear and helpful response based **strictly** on this context.
- If the documentation provides an answer, summarize it and cite the source file.
- If a past issue offers a solution, explain it and provide the URL to that issue.
- If the context doesn't seem to fully resolve their detailed question, state that and mention a maintainer will look into it.
- Conclude by thanking them for their contribution to the project.
</if_issue_is_good>
**New Issue:**
{new_issue_text}

**Relevant Context (from Documentation and Past Issues):**
{context}

**Suggested Answer (include links to sources if available):**
"""
"""
response = openai.chat.completions.create(
  model="gpt-4", # Or "gpt-3.5-turbo", or any other model you prefer
  messages=[
    {"role": "system", "content": "You are an expert GitHub support assistant. Your mission is to answer user issues based solely on official documentation and the history of resolved issues."},
    {"role": "user", "content": prompt}
  ]
)
"""
# The system prompt from OpenAI is handled by system_instruction in Gemini
system_instruction = "You are an expert GitHub support assistant. Your mission is to answer user issues based solely on official documentation and the history of resolved issues."

# https://ai.google.dev/gemini-api/docs/models
# Create the model with the system instruction
generative_model = genai.GenerativeModel(
    model_name="gemini-2.5-flash",
    system_instruction=system_instruction
)

response = generative_model.generate_content(prompt)
# --- Post the Comment ---
final_comment = f"Hello @{issue.user.login}, thanks for reaching out.\n\n"
final_comment += response.text
final_comment += "\n\n---\n*This is an automated message generated from our documentation and issue history. If this doesn't solve your problem, someone will try to help you soon. Ensure that you checked other issues for the same issue!.* 🤖"

issue.create_comment(final_comment)

print(f"Enriched answer posted to issue #{ISSUE_NUMBER}")
