# Team Management Lessons Learned

## Session: 2026-02-20 — Glitch Web Server Expansion

### Team Structure Observations

*(Updated as work progresses)*

### Agent Collaboration Patterns

- **Developer agents** work best with clear file/directory boundaries — never assign two agents to the same file
- **QA agents** should receive the full context of what was implemented before review
- **Scope creep risk:** Large feature lists require strict per-branch discipline

### What Worked

*(To be filled during implementation)*

### What Didn't Work

*(To be filled during implementation)*

### Approach: Feature Branch Workflow

1. Create branch from master
2. Implement feature (developer agent)
3. Run build + vet (developer agent)
4. Review + test (qa agent)
5. Fix issues found by QA
6. Merge to master
7. Move to next feature

### Requirements for Agents

- **Developer:** Needs full PLAN.md context for the specific feature, existing handler.go integration points, and the "zero external deps" constraint
- **QA:** Needs the feature spec, the diff of changes, and the test commands
- **Team Lead:** Must track which features are done, coordinate merge order, resolve conflicts
