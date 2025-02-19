import type { Buffer } from 'node:buffer'

export interface MailServerConfig {
  verbose: boolean
}

export type MailServerOptions = Partial<MailServerConfig>

export interface Session {
  id: string
  user: any
  transmissionType: string
  secure?: boolean
  envelope?: {
    mailFrom: ParsedAddress | false
    rcptTo: ParsedAddress[]
  }
  transaction?: number
  tlsOptions?: any
  servername?: string
  clientHostname?: string | false
  openingCommand?: string | false
  hostNameAppearsAs?: string | false
  xClient?: Map<string, any>
  xForward?: Map<string, any>
  error?: string
  isWizard?: boolean
  localAddress?: string
  localPort?: number
  remoteAddress?: string
  remotePort?: number
}

export interface ParsedAddress {
  address: string
  args: Record<string, any>
}

// Define handler types
export type CommandHandler = (command: Buffer, callback?: () => void) => void
export type NoArgsHandler = () => void

export interface SMTPConnection {
  id: string
  session: Session
  _server: SMTPServer
  _nextHandler: () => void
  name: string
  send: (code: number, message: string | string[]) => void
  _transmissionType: () => string
}

export interface SMTPServerOptions {
  secure?: boolean
  needsUpgrade?: boolean
  size?: number
  name?: string
  banner?: string
  hideSTARTTLS?: boolean
  hideSize?: boolean
  hidePIPELINING?: boolean
  hide8BITMIME?: boolean
  hideSMTPUTF8?: boolean
  authMethods: string[]
  disabledCommands: string[]
  maxAllowedUnauthenticatedCommands?: number
  useXClient?: boolean
  useXForward?: boolean
  lmtp?: boolean
  socketTimeout?: number
  allowInsecureAuth?: boolean
  maxClients?: number
  disableReverseLookup?: boolean
  authOptional?: boolean
  authRequiredMessage?: string
  [key: string]: any
}

export interface SMTPServer {
  options: SMTPServerOptions
  logger: {
    info: (...args: any[]) => void
    debug: (...args: any[]) => void
    error: (...args: any[]) => void
  }
  connections: Set<SMTPConnection>
  onConnect: (session: Session, callback: (err?: AuthError) => void) => void
  onSecure: (socket: any, session: Session, callback: (err?: AuthError) => void) => void
  onClose: (session: Session) => void
  onAuth: (auth: AuthOptions, session: Session, callback: AuthCallback) => void
  onMailFrom: (parsed: ParsedAddress, session: Session, callback: (err?: AuthError) => void) => void
  onRcptTo: (parsed: ParsedAddress, session: Session, callback: (err?: AuthError) => void) => void
  onData: (stream: any, session: Session, callback: (err?: AuthError, message?: string) => void) => void
  secureContext: Map<string, any>
  server: any
}

export interface AuthOptions {
  method: string
  username?: string
  password?: string
  accessToken?: string
  validatePassword?: (password: string) => boolean
}

export interface AuthResponse {
  user?: any
  data?: {
    status?: string
    schemes?: string
    scope?: string
  }
  message?: string
  responseCode?: number
}

export interface AuthError extends Error {
  responseCode?: number
}

export type AuthCallback = (err: AuthError | null, response?: any) => void
// type SASLHandler = (this: SMTPConnection, args: string[], callback: () => void) => void
