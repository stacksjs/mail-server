import type { MailServerConfig } from './types'
import { resolve } from 'node:path'
import { loadConfig } from 'bunfig'

export const defaultConfig: MailServerConfig = {
  verbose: true,
}

// @ts-expect-error dtsx issue
// eslint-disable-next-line antfu/no-top-level-await
export const config: MailServerConfig = await loadConfig({
  name: 'post',
  cwd: resolve(__dirname, '..'),
  defaultConfig,
})
