/**
 * `ctx.files` refusals beyond plain containment: sensitive files moved out of
 * their names, kernel pseudo-filesystems, FIFOs, hard links, a folder or file
 * swapped between the check and the open, and the grants record itself.
 */
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { createPluginFiles, type PluginFiles } from './plugin-files'

const posix = process.platform !== 'win32'
const unprivileged = posix && process.getuid?.() !== 0

let scratch: string
let userData: string
let hermesHome: string
let vault: string
let files: PluginFiles

const make = () =>
  createPluginFiles({
    userDataDir: () => userData,
    protectedRoots: () => [hermesHome],
    trashItem: target => fs.promises.rm(target, { recursive: true })
  })

beforeEach(() => {
  scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-plugin-files-hard-')))
  userData = path.join(scratch, 'userData')
  hermesHome = path.join(scratch, 'home', '.hermes')
  vault = path.join(scratch, 'home', 'Vault')
  fs.mkdirSync(userData, { recursive: true })
  fs.mkdirSync(hermesHome, { recursive: true })
  fs.writeFileSync(path.join(hermesHome, 'config.yaml'), 'model: secret-config\n')
  fs.mkdirSync(path.join(vault, 'notes'), { recursive: true })
  fs.writeFileSync(path.join(vault, 'notes', 'a.md'), '# A\n')
  files = make()
})

afterEach(() => {
  vi.restoreAllMocks()
  fs.chmodSync(scratch, 0o700)
  fs.rmSync(scratch, { recursive: true, force: true })
})

async function grantVault(): Promise<string> {
  const granted = await files.addGrant('plexus', vault)

  expect(granted.ok).toBe(true)

  return (granted as { folder: { id: string } }).folder.id
}

describe('sensitive files cannot be moved out of their names', () => {
  it.each([
    ['.env', 'notes.txt'],
    ['server.pem', 'p.txt'],
    ['id_ed25519', 'key.txt']
  ])('refuses renaming %s to %s, and trashing it', async (name, renamed) => {
    const id = await grantVault()
    fs.writeFileSync(path.join(vault, name), 'SECRET=sk-live\n')

    expect(await files.run('plexus', { op: 'rename', folder: id, path: name, name: renamed })).toMatchObject({
      ok: false,
      error: 'sensitive-file'
    })
    expect(await files.run('plexus', { op: 'trash', folder: id, path: name })).toMatchObject({
      ok: false,
      error: 'sensitive-file'
    })
    expect(fs.existsSync(path.join(vault, name))).toBe(true)
    expect(fs.existsSync(path.join(vault, renamed))).toBe(false)
  })

  it('refuses renaming a key folder so its files lose the rule', async () => {
    const id = await grantVault()
    fs.mkdirSync(path.join(vault, '.ssh'))
    fs.writeFileSync(path.join(vault, '.ssh', 'config'), 'Host x\n')

    expect(await files.run('plexus', { op: 'rename', folder: id, path: '.ssh', name: 'ssh' })).toMatchObject({
      ok: false,
      error: 'sensitive-file'
    })
    expect(await files.run('plexus', { op: 'readText', folder: id, path: '.ssh/config' })).toMatchObject({
      ok: false,
      error: 'sensitive-file'
    })
  })
})

describe('only plain files', () => {
  it.runIf(process.platform === 'linux').each(['/proc', '/sys', '/dev', '/proc/self'])(
    'refuses to grant the kernel pseudo-filesystem %s',
    async folder => {
      expect(await files.addGrant('plexus', folder)).toMatchObject({ ok: false, error: 'protected' })
    }
  )

  it.runIf(posix)('refuses a FIFO instead of blocking on it', async () => {
    const id = await grantVault()
    execFileSync('mkfifo', [path.join(vault, 'pipe')])

    const result = await Promise.race([
      files.run('plexus', { op: 'readText', folder: id, path: 'pipe' }),
      new Promise(resolve => setTimeout(() => resolve('blocked'), 1500))
    ])

    expect(result).toMatchObject({ ok: false, error: 'not-a-file' })
    expect(
      await files.run('plexus', { op: 'writeText', folder: id, path: 'pipe', text: 'x' })
    ).toMatchObject({ ok: false, error: 'not-a-file' })
  })

  it.runIf(posix)('refuses a hard link, which may be a second name for Hermes data', async () => {
    const id = await grantVault()
    fs.linkSync(path.join(hermesHome, 'config.yaml'), path.join(vault, 'notes', 'c.md'))

    expect(await files.run('plexus', { op: 'readText', folder: id, path: 'notes/c.md' })).toMatchObject({
      ok: false,
      error: 'protected'
    })
    expect(
      await files.run('plexus', { op: 'writeText', folder: id, path: 'notes/c.md', text: 'pwned' })
    ).toMatchObject({ ok: false, error: 'protected' })
    expect(fs.readFileSync(path.join(hermesHome, 'config.yaml'), 'utf8')).toBe('model: secret-config\n')
  })
})

describe('a swap between the check and the open is refused', () => {
  // Stands in for another process changing the folder right after `resolve`
  // looked at `checked` (with lstat, or with stat for its last look).
  const swapAfterCheck = (method: 'lstat' | 'stat', checked: string, swap: () => void) => {
    const original = fs.promises[method].bind(fs.promises) as (target: fs.PathLike) => Promise<fs.Stats>
    let done = false

    vi.spyOn(fs.promises, method).mockImplementation((async (target: fs.PathLike) => {
      try {
        return await original(target)
      } finally {
        if (!done && String(target) === checked) {
          done = true
          swap()
        }
      }
    }) as never)
  }

  it.runIf(posix)('a parent folder swapped for a link into the Hermes home: no file lands there', async () => {
    const id = await grantVault()
    const sub = path.join(vault, 'sub')
    fs.mkdirSync(sub)

    swapAfterCheck('lstat', path.join(sub, 'pwn.txt'), () => {
      fs.renameSync(sub, path.join(vault, 'sub-old'))
      fs.symlinkSync(hermesHome, sub)
    })

    expect(
      await files.run('plexus', { op: 'writeText', folder: id, path: 'sub/pwn.txt', text: 'pwned' })
    ).toMatchObject({ ok: false, error: 'outside-folder' })
    expect(fs.existsSync(path.join(hermesHome, 'pwn.txt'))).toBe(false)
  })

  it.runIf(posix)('a checked file swapped for a link to Hermes data is not read or written', async () => {
    const id = await grantVault()
    const note = path.join(vault, 'notes', 'a.md')

    const swap = () => {
      fs.rmSync(note)
      fs.symlinkSync(path.join(hermesHome, 'config.yaml'), note)
    }

    swapAfterCheck('stat', note, swap)
    const read = await files.run('plexus', { op: 'readText', folder: id, path: 'notes/a.md' })

    expect(read).toMatchObject({ ok: false })
    expect(JSON.stringify(read)).not.toContain('secret-config')

    vi.restoreAllMocks()
    fs.rmSync(note)
    fs.writeFileSync(note, '# A\n')
    swapAfterCheck('stat', note, swap)

    expect(
      await files.run('plexus', { op: 'writeText', folder: id, path: 'notes/a.md', text: 'pwned' })
    ).toMatchObject({ ok: false })
    expect(fs.readFileSync(path.join(hermesHome, 'config.yaml'), 'utf8')).toBe('model: secret-config\n')
  })
})

describe('the grants record', () => {
  it.runIf(unprivileged)('a record that cannot be read is not overwritten with nothing', async () => {
    await grantVault()
    const record = path.join(userData, 'plugin-files', 'grants.json')
    const before = fs.readFileSync(record, 'utf8')
    fs.chmodSync(record, 0o000)
    const other = path.join(scratch, 'Other')
    fs.mkdirSync(other)

    expect(await make().addGrant('plexus', other)).toMatchObject({ ok: false, error: 'io-error' })
    fs.chmodSync(record, 0o600)
    expect(fs.readFileSync(record, 'utf8')).toBe(before)
  })

  it('treats an id such as `constructor` as a plain key', async () => {
    expect(await files.addGrant('constructor', vault)).toMatchObject({ ok: true })
    expect(await files.grants('toString')).toEqual([])
  })

  it.each(['foo.', 'con', 'NUL.txt', 'com1'])('refuses the plugin id %s, which Windows would alias', async id => {
    expect(await files.run(id, { op: 'list', folder: 'data', path: '' })).toMatchObject({
      ok: false,
      error: 'invalid-plugin'
    })
  })
})
