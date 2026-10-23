// The operations behind `ctx.files` (plugin-files.ts owns grants and path
// resolution). Each op gets a target already resolved inside its folder and
// re-applies the per-op rules: size caps, sensitive names, no op on the folder
// itself, O_EXCL creation.

import fs from 'node:fs'
import path from 'node:path'

import { sensitiveFileBlockReason } from './hardening'
import type { PluginFilesErrorCode, PluginFilesFailure, PluginFilesRequest, PluginFilesResult } from './plugin-files'

const TEXT_MAX_BYTES = 4 * 1024 * 1024
const DATA_URL_MAX_BYTES = 16 * 1024 * 1024
const LIST_MAX_ENTRIES = 10_000

const IMAGE_MIME: Record<string, string> = {
  '.avif': 'image/avif',
  '.bmp': 'image/bmp',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.jpeg': 'image/jpeg',
  '.jpg': 'image/jpeg',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.webp': 'image/webp'
}

export const fail = (error: PluginFilesErrorCode, message: string): PluginFilesFailure => ({ ok: false, error, message })

export class Refusal extends Error {
  constructor(readonly failure: PluginFilesFailure) {
    super(failure.message)
  }
}

export const refuse = (error: PluginFilesErrorCode, message: string): never => {
  throw new Refusal(fail(error, message))
}

export const errnoCode = (error: unknown): string | undefined =>
  error && typeof error === 'object' && 'code' in error ? String((error as { code?: unknown }).code) : undefined

export async function lstatOrNull(target: string): Promise<fs.Stats | null> {
  try {
    return await fs.promises.lstat(target)
  } catch (error) {
    if (errnoCode(error) === 'ENOENT') {
      return null
    }

    throw error
  }
}

export async function realpathOrNull(target: string): Promise<null | string> {
  try {
    return await fs.promises.realpath(target)
  } catch (error) {
    const code = errnoCode(error)

    if (code === 'ENOENT' || code === 'ENOTDIR' || code === 'ELOOP') {
      return null
    }

    throw error
  }
}

export const refuseSensitive = (target: string) => {
  const sensitive = sensitiveFileBlockReason(target)

  if (sensitive) {
    refuse('sensitive-file', sensitive)
  }
}

function mimeFor(target: string): string {
  return IMAGE_MIME[path.extname(target).toLowerCase()] ?? 'application/octet-stream'
}

const toRel = (parts: string[]) => parts.join('/')

export interface Resolved {
  /** The folder's realpath. */
  root: string
  parts: string[]
  /** Realpath of the target's parent (null for the folder itself). */
  parent: null | string
  /** The entry as named (in the real parent), not following a final link. */
  entry: string
  /** What reads/writes act on: the entry, or its in-folder link target. */
  target: string
  stat: fs.Stats | null
}

export interface PluginFileOpsDeps {
  resolve: (pluginId: string, folder: unknown, rel: unknown) => Promise<Resolved>
  inside: (child: string, parent: string) => boolean
  segments: (raw: unknown) => string[]
  trashItem: (target: string) => Promise<void>
}

type PluginFileOp = (pluginId: string, req: any) => Promise<PluginFilesResult>

export function createPluginFileOps({
  resolve,
  inside,
  segments,
  trashItem
}: PluginFileOpsDeps): Record<PluginFilesRequest['op'], PluginFileOp> {
  const requireFile = (resolved: Resolved, maxBytes: number) => {
    if (!resolved.stat) {
      refuse('not-found', 'No such file.')
    }

    if (resolved.stat!.isDirectory()) {
      refuse('is-directory', 'That path is a folder.')
    }

    if (resolved.stat!.size > maxBytes) {
      refuse('too-large', `File is larger than ${Math.round(maxBytes / (1024 * 1024))} MiB.`)
    }

    refuseSensitive(resolved.target)
  }

  const requireChild = (resolved: Resolved) => {
    if (!resolved.parent) {
      refuse('invalid-path', 'This operation needs a path inside the folder, not the folder itself.')
    }
  }

  return {
    async list(pluginId, req) {
      const resolved = await resolve(pluginId, req.folder, req.path)

      if (!resolved.stat?.isDirectory()) {
        return fail(resolved.stat ? 'not-a-directory' : 'not-found', 'That path is not a folder.')
      }

      const dirents = await fs.promises.readdir(resolved.target, { withFileTypes: true })
      const entries: { name: string; path: string; isDirectory: boolean }[] = []

      for (const dirent of dirents.slice(0, LIST_MAX_ENTRIES)) {
        const full = path.join(resolved.target, dirent.name)
        let isDirectory = dirent.isDirectory()

        if (dirent.isSymbolicLink()) {
          const real = await realpathOrNull(full)

          if (!real || !inside(real, resolved.root)) {
            continue
          }

          isDirectory = (await fs.promises.stat(real)).isDirectory()
        }

        entries.push({ name: dirent.name, path: toRel([...resolved.parts, dirent.name]), isDirectory })
      }

      return { ok: true, entries, truncated: dirents.length > LIST_MAX_ENTRIES }
    },

    async stat(pluginId, req) {
      const { stat } = await resolve(pluginId, req.folder, req.path)

      return stat
        ? { ok: true, exists: true, isDirectory: stat.isDirectory(), size: stat.size, mtimeMs: stat.mtimeMs }
        : { ok: true, exists: false }
    },

    async readText(pluginId, req) {
      const resolved = await resolve(pluginId, req.folder, req.path)
      requireFile(resolved, TEXT_MAX_BYTES)
      const data = await fs.promises.readFile(resolved.target)

      if (data.subarray(0, 8000).includes(0)) {
        return fail('binary', 'That file is binary; read it as a data URL.')
      }

      return { ok: true, text: data.toString('utf8'), size: data.length, mtimeMs: resolved.stat!.mtimeMs }
    },

    async readDataUrl(pluginId, req) {
      const resolved = await resolve(pluginId, req.folder, req.path)
      requireFile(resolved, DATA_URL_MAX_BYTES)
      const data = await fs.promises.readFile(resolved.target)

      return { ok: true, url: `data:${mimeFor(resolved.target)};base64,${data.toString('base64')}` }
    },

    async writeText(pluginId, req) {
      const text = typeof req.text === 'string' ? req.text : ''

      if (Buffer.byteLength(text, 'utf8') > TEXT_MAX_BYTES) {
        return fail('too-large', 'Text is larger than 4 MiB.')
      }

      const resolved = await resolve(pluginId, req.folder, req.path)
      requireChild(resolved)

      if (resolved.stat?.isDirectory()) {
        return fail('is-directory', 'That path is a folder.')
      }

      if (resolved.stat && req.exclusive) {
        return fail('exists', 'A file with that name already exists.')
      }

      refuseSensitive(resolved.target)

      // A new file is created with O_EXCL, which also refuses a link planted
      // after the check above; an existing one is written at its in-folder target.
      await fs.promises.writeFile(resolved.stat ? resolved.target : resolved.entry, text, {
        encoding: 'utf8',
        flag: resolved.stat ? 'w' : 'wx'
      })
      const stat = await fs.promises.stat(resolved.target)

      return { ok: true, path: toRel(resolved.parts), size: stat.size, mtimeMs: stat.mtimeMs }
    },

    async rename(pluginId, req) {
      const name = typeof req.name === 'string' ? req.name.trim() : ''

      if (segments(name).length !== 1 || /[\\/]/.test(name) || name === '.') {
        return fail('invalid-path', 'A new name is one plain file or folder name.')
      }

      const resolved = await resolve(pluginId, req.folder, req.path)
      requireChild(resolved)

      if (!resolved.stat) {
        return fail('not-found', 'No such file or folder.')
      }

      const destination = path.join(resolved.parent!, name)
      refuseSensitive(destination)

      if (await lstatOrNull(destination)) {
        return fail('exists', `"${name}" already exists.`)
      }

      await fs.promises.rename(resolved.entry, destination)

      return { ok: true, path: toRel([...resolved.parts.slice(0, -1), name]) }
    },

    async trash(pluginId, req) {
      const resolved = await resolve(pluginId, req.folder, req.path)
      requireChild(resolved)

      if (!resolved.stat) {
        return fail('not-found', 'No such file or folder.')
      }

      await trashItem(resolved.entry)

      return { ok: true }
    }
  }
}
