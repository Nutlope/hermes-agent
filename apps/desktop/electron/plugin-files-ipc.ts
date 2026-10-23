// IPC for the plugin SDK's folder-scoped file door (`ctx.files`). The only way
// a folder grant is ever minted is `hermes:pluginFiles:request`: main opens
// the native folder picker itself, attached to the window that asked, and
// grants exactly what the user picked. Every file operation goes through
// plugin-files.ts, which re-checks the grant and the path on each call.

import path from 'node:path'

import type { BrowserWindow, Dialog, IpcMain, IpcMainInvokeEvent } from 'electron'

import { createPluginFiles, type PluginFiles, type PluginFilesDeps } from './plugin-files'

const LABEL_MAX = 200

interface PickerLabels {
  buttonLabel?: unknown
  title?: unknown
}

export interface PluginFilesIpcDeps extends Omit<PluginFilesDeps, 'protectedRoots'> {
  ipcMain: Pick<IpcMain, 'handle'>
  dialog: Pick<Dialog, 'showOpenDialog'>
  windowFor: (event: IpcMainInvokeEvent) => BrowserWindow | null
  /** The resolved HERMES_HOME plus the platform-default homes it may differ from. */
  hermesHomes: () => string[]
}

const label = (value: unknown, fallback: string) =>
  typeof value === 'string' && value.trim() ? value.trim().slice(0, LABEL_MAX) : fallback

export function registerPluginFilesIpc(deps: PluginFilesIpcDeps): PluginFiles {
  const files = createPluginFiles({ ...deps, protectedRoots: deps.hermesHomes })

  deps.ipcMain.handle(
    'hermes:pluginFiles:request',
    async (event: IpcMainInvokeEvent, pluginId: unknown, labels: PickerLabels = {}) => {
      const window = deps.windowFor(event)

      const options = {
        buttonLabel: label(labels?.buttonLabel, 'Allow access'),
        properties: ['openDirectory', 'createDirectory'] as Array<'createDirectory' | 'openDirectory'>,
        title: label(labels?.title, 'Choose a folder')
      }

      const picked = window ? await deps.dialog.showOpenDialog(window, options) : await deps.dialog.showOpenDialog(options)

      if (picked.canceled || !picked.filePaths[0]) {
        return { ok: true, folder: null }
      }

      return files.addGrant(pluginId, path.resolve(picked.filePaths[0]))
    }
  )

  deps.ipcMain.handle('hermes:pluginFiles:grants', async (_event, pluginId: unknown) => files.grants(pluginId))

  deps.ipcMain.handle('hermes:pluginFiles:revoke', async (_event, pluginId: unknown, folderId?: unknown) =>
    files.revoke(pluginId, folderId)
  )

  deps.ipcMain.handle('hermes:pluginFiles:op', async (_event, pluginId: unknown, request) =>
    files.run(pluginId, request)
  )

  return files
}
