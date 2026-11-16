# Kordex development guidance

Read [production upgrade requirements](docs/production-upgrade-requirements.md)
when planning or implementing Kordex features. This is the user's prioritized
product direction and acceptance checklist, alongside the historical roadmap in
`docs/mvp-plan.md`.

Address these requirements incrementally. Preserve signed authorization,
independent approvals, local fail-closed safety, durable checkpoints, and verified
recovery as new actions are added. Do not treat completed roadmap phases,
interfaces, mock evidence, or drain drills as proof of production upgrade support.

For relevant changes, identify the requirement IDs addressed and record actual
verification evidence and remaining limitations. Do not mark a requirement
complete without evidence for its acceptance criteria. Do not expand a small task
into implementation of the entire checklist.
