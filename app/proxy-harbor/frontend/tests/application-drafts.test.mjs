import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mergeApplicationPaths } from '../src/application-drafts.ts'

// Generic model fixtures only; no installed application is accessed or executed.
const previous = [{ id: 'editor', executable: '' }, { id: 'helper', executable: '' }]

test('saving one item retains the other unsaved draft and accepts server normalization', () => {
 const paths = { editor: ' C:\\fixture\\editor.exe ', helper: 'C:\\fixture\\helper.exe' }
 mergeApplicationPaths(paths, previous, [{ id: 'editor', executable: 'C:\\fixture\\editor.exe' }, previous[1]], { id: 'editor', path: paths.editor })
 assert.equal(paths.editor, 'C:\\fixture\\editor.exe')
 assert.equal(paths.helper, 'C:\\fixture\\helper.exe')
})

test('an unrelated refresh preserves drafts and updates untouched inputs', () => {
 const paths = { editor: 'unsaved.exe', helper: '' }
 mergeApplicationPaths(paths, previous, [{ id: 'editor', executable: '' }, { id: 'helper', executable: 'updated.exe' }])
 assert.deepEqual(paths, { editor: 'unsaved.exe', helper: 'updated.exe' })
})

test('typing during an in-flight save retains the newer draft', () => {
 const paths = { editor: 'newer-draft.exe' }
 mergeApplicationPaths(paths, previous, [{ id: 'editor', executable: 'submitted.exe' }], { id: 'editor', path: 'submitted.exe' })
 assert.equal(paths.editor, 'newer-draft.exe')
})

test('first load and intentionally cleared drafts are preserved correctly', () => {
 const paths = {}
 mergeApplicationPaths(paths, [], [{ id: 'editor', executable: 'registered.exe' }])
 assert.equal(paths.editor, 'registered.exe')
 paths.editor = ''
 mergeApplicationPaths(paths, [{ id: 'editor', executable: 'registered.exe' }], [{ id: 'editor', executable: 'registered.exe' }])
 assert.equal(paths.editor, '')
})
