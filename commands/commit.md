---
allowed-tools: Bash(git status:*), Bash(git log:*), Bash(git diff:*), Bash(git branch:*), Bash(git commit:*)
description: Review staged changes, create commit message, ask for confirmation before committing
---

## Context

- Current git status: !`git status`
- Current git diff (staged and unstaged changes): !`git diff HEAD`
- Current branch: !`git branch --show-current`
- Recent commits: !`git log --oneline -10`

## Your task

Review the staged changes and create a suitable commit message. Follow these steps:

1. First, examine the git status to see what's staged.

2. Review the staged changes in detail.

3. If necessary, examine specific changed files to understand the changes better. Use read tools for key files.

4. Look at recent commit history for context.

5. Analyze the changes and create a concise, descriptive commit message that follows conventional commit format. Focus on the 'why' rather than just the 'what'.

6. Present the proposed commit message to the user and ask for confirmation before committing.

7. If user confirms, execute the commit with the proposed message. If not, ask for adjustments.

IMPORTANT: Always ask for user confirmation before actually running 'git commit'. Provide reasoning for your proposed commit message based on the changes observed.
IMPORTANT: Do NOT add "Co-Authored-By" lines or any other trailers to commit messages.
