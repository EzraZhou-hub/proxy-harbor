type ApplicationPath = { id: string; executable: string }
export type SubmittedPath = { id: string; path: string }

// Refresh untouched inputs, while retaining drafts and edits made during a save.
export function mergeApplicationPaths(
 paths: Record<string, string>, previous: ApplicationPath[], incoming: ApplicationPath[], submitted?: SubmittedPath,
) {
 const previousPaths = new Map(previous.map(app => [app.id, app.executable]))
 for (const app of incoming) {
  const untouched = !(app.id in paths) || paths[app.id] === previousPaths.get(app.id)
  const saved = submitted?.id === app.id && paths[app.id] === submitted.path
  if (untouched || saved) paths[app.id] = app.executable
 }
}
