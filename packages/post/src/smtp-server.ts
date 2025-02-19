import type { AddressInfo, Server, Socket } from 'node:net'
import type { SecureContext, TLSSocketOptions } from 'node:tls'
import { Buffer } from 'node:buffer'
import { randomBytes } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { createServer } from 'node:net'
import { createSecureContext, TLSSocket } from 'node:tls'
import { getLogger } from 'nodemailer/lib/shared'
import { toUnicode } from 'ts-punycode'
import { SMTPConnection } from './smtp-connection'
import { getTLSOptions } from './tls-options'

const CLOSE_TIMEOUT = 30 * 1000 // how much to wait until pending connections are terminated

interface SMTPServerOptions {
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
  authMethods?: string[]
  disabledCommands?: string[]
  maxAllowedUnauthenticatedCommands?: number
  useXClient?: boolean
  useXForward?: boolean
  lmtp?: boolean
  socketTimeout?: number
  closeTimeout?: number
  secured?: boolean
  useProxy?: boolean | string[]
  ignoredHosts?: string[]
  SNICallback?: (servername: string, cb: (err: Error | null, ctx?: SecureContext) => void) => void
  logger?: Logger
  component?: string
  server?: Server
  sniOptions?: Map<string, TLSSocketOptions> | Record<string, TLSSocketOptions>
  [key: string]: any // Allow dynamic properties for handler functions
}

interface Logger {
  info: (...args: any[]) => void
  debug: (...args: any[]) => void
  error: (...args: any[]) => void
}

interface SocketOptions {
  id: string
  remoteAddress?: string
  remotePort?: number
  ignore?: boolean
}

interface AuthData {
  method: string
  [key: string]: any
}

interface Session {
  [key: string]: any
}

/**
 * Creates a SMTP server instance.
 *
 * @constructor
 * @param {object} options Connection and SMTP options
 */
export class SMTPServer extends EventEmitter {
  public options: SMTPServerOptions
  public logger: Logger
  public connections: Set<SMTPConnection>
  public server: Server
  public secureContext: Map<string, SecureContext>
  private _closeTimeout: NodeJS.Timeout | null

  constructor(options: SMTPServerOptions = { authMethods: [], disabledCommands: [] }) {
    super()

    this.options = {
      authMethods: [],
      disabledCommands: [],
      ...options,
    }
    this.connections = new Set()
    this.secureContext = new Map()
    this._closeTimeout = null

    this.updateSecureContext({})

    // setup disabled commands list
    this.options.disabledCommands = ([] as string[])
      .concat(this.options.disabledCommands || [])
      .map(command => String(command || '').toUpperCase().trim())

    // setup allowed auth methods
    this.options.authMethods = ([] as string[])
      .concat(this.options.authMethods || [])
      .map(method => String(method || '').toUpperCase().trim())

    if (!this.options.authMethods.length) {
      this.options.authMethods = ['LOGIN', 'PLAIN']
    }

    this.logger = getLogger(this.options, {
      component: this.options.component || 'smtp-server',
    })

    // apply shorthand handlers
    ;['onConnect', 'onSecure', 'onAuth', 'onMailFrom', 'onRcptTo', 'onData', 'onClose'].forEach((handler) => {
      if (typeof this.options[handler] === 'function') {
        this[handler as keyof this] = this.options[handler]
      }
    })

    // setup server listener and connection handler
    if (this.options.secure && !this.options.needsUpgrade) {
      this.server = createServer({}, (socket: Socket) => {
        this._handleProxy(socket, (err: Error | null, socketOptions: SocketOptions) => {
          if (err) {
            // ignore, should not happen
          }
          if (this.options.secured) {
            return this.connect(socket, socketOptions)
          }
          this._upgrade(socket, (err: Error | null, tlsSocket: TLSSocket) => {
            if (err) {
              return this._onError(err)
            }
            this.connect(tlsSocket, socketOptions)
          })
        })
      })
    }
    else {
      this.server = createServer({}, (socket: Socket) =>
        this._handleProxy(socket, (err: Error | null, socketOptions: SocketOptions) => {
          if (err) {
            // ignore, should not happen
          }
          this.connect(socket, socketOptions)
        }))
    }

    this._setListeners()
  }

  connect(socket: Socket | TLSSocket, socketOptions: SocketOptions): void {
    const connection = new SMTPConnection(this as unknown as SMTPServer, socket, socketOptions)
    this.connections.add(connection)
    connection.on('error', (err: Error) => this._onError(err))
    connection.on('connect', (data: any) => this._onClientConnect(data))
    connection.init()
  }

  /**
   * Start listening on selected port and interface
   */
  listen(...args: any[]): Server {
    return this.server.listen(...args)
  }

  /**
   * Closes the server
   *
   * @param {Function} callback Callback to run once the server is fully closed
   */
  close(callback?: () => void): void {
    let connections = this.connections.size
    const timeout = this.options.closeTimeout || CLOSE_TIMEOUT

    // stop accepting new connections
    this.server.close(() => {
      if (this._closeTimeout)
        clearTimeout(this._closeTimeout)
      if (typeof callback === 'function') {
        callback()
      }
    })

    // close active connections
    if (connections) {
      this.logger.info(
        {
          tnx: 'close',
        },
        'Server closing with %s pending connection%s, waiting %s seconds before terminating',
        connections,
        connections !== 1 ? 's' : '',
        timeout / 1000,
      )
    }

    this._closeTimeout = setTimeout(() => {
      connections = this.connections.size
      if (connections) {
        this.logger.info(
          {
            tnx: 'close',
          },
          'Closing %s pending connection%s to close the server',
          connections,
          connections !== 1 ? 's' : '',
        )

        this.connections.forEach((connection) => {
          connection.send(421, 'Server shutting down')
          connection.close()
        })
      }
      if (typeof callback === 'function') {
        callback()
      }
    }, timeout) as unknown as NodeJS.Timeout
  }

  /**
   * Authentication handler. Override this
   *
   * @param {object} auth Authentication options
   * @param {Function} callback Callback to run once the user is authenticated
   */
  onAuth(auth: AuthData, session: Session, callback: (err: Error | null, result?: any) => void): void {
    if (auth.method === 'XOAUTH2') {
      return callback(null, {
        data: {
          status: '401',
          schemes: 'bearer mac',
          scope: 'https://mail.google.com/',
        },
      })
    }

    if (auth.method === 'XCLIENT') {
      return callback() // pass through
    }

    return callback(null, {
      message: 'Authentication not implemented',
    })
  }

  onConnect(session: Session, callback: () => void): void {
    setImmediate(callback)
  }

  onMailFrom(address: string, session: Session, callback: () => void): void {
    setImmediate(callback)
  }

  onRcptTo(address: string, session: Session, callback: () => void): void {
    setImmediate(callback)
  }

  onSecure(socket: Socket | TLSSocket, session: Session, callback: () => void): void {
    setImmediate(callback)
  }

  onData(stream: NodeJS.ReadableStream, session: Session, callback: () => void): void {
    let chunklen = 0

    stream.on('data', (chunk: Buffer) => {
      chunklen += chunk.length
    })

    stream.on('end', () => {
      this.logger.info(
        {
          tnx: 'message',
          size: chunklen,
        },
        '<received %s bytes>',
        chunklen,
      )
      callback()
    })
  }

  onClose(_session?: Session): void {
    // do nothing
  }

  updateSecureContext(options: Partial<SMTPServerOptions>): void {
    Object.keys(options || {}).forEach((key) => {
      this.options[key] = options[key]
    })

    const defaultTlsOptions = getTLSOptions(this.options)

    this.secureContext = new Map()
    this.secureContext.set('*', createSecureContext(defaultTlsOptions))

    const ctxMap = this.options.sniOptions || {}
    // sniOptions is either an object or a Map with domain names as keys and TLS option objects as values
    if (typeof ctxMap.get === 'function') {
      ;(ctxMap as Map<string, TLSSocketOptions>).forEach((ctx, servername) => {
        this.secureContext.set(this._normalizeHostname(servername), createSecureContext(getTLSOptions(ctx)))
      })
    }
    else {
      Object.keys(ctxMap as Record<string, TLSSocketOptions>).forEach((servername) => {
        this.secureContext.set(
          this._normalizeHostname(servername),
          createSecureContext(getTLSOptions((ctxMap as Record<string, TLSSocketOptions>)[servername])),
        )
      })
    }

    if (this.options.secure) {
      // apply changes
      Object.keys(defaultTlsOptions || {}).forEach((key) => {
        if (!(key in this.options)) {
          ;(this.options as Record<string, any>)[key] = (defaultTlsOptions as Record<string, any>)[key]
        }
      })

      // ensure SNICallback method
      if (typeof this.options.SNICallback !== 'function') {
        // create default SNI handler
        this.options.SNICallback = (servername: string, cb: (err: Error | null, ctx?: SecureContext) => void) => {
          cb(null, this.secureContext.get(servername))
        }
      }
    }
  }

  // PRIVATE METHODS

  /**
   * Setup server event handlers
   */
  private _setListeners(): void {
    const server = this.server
    server.once('listening', () => this._onListening())
    server.once('close', () => this._onClose(server))
    server.on('error', (err: Error) => this._onError(err))
  }

  /**
   * Called when server started listening
   *
   * @event
   */
  private _onListening(): void {
    const addr = this.server.address()
    const address: AddressInfo = typeof addr === 'string'
      ? { address: '0.0.0.0', port: 0, family: 'IPv4' }
      : addr || { address: '0.0.0.0', port: 0, family: 'IPv4' }

    this.logger.info(
      {
        tnx: 'listen',
        host: address.address,
        port: address.port,
        secure: !!this.options.secure,
        protocol: this.options.lmtp ? 'LMTP' : 'SMTP',
      },
      '%s%s Server listening on %s:%s',
      this.options.secure ? 'Secure ' : '',
      this.options.lmtp ? 'LMTP' : 'SMTP',
      address.family === 'IPv4' ? address.address : `[${address.address}]`,
      address.port,
    )
  }

  /**
   * Called when server is closed
   *
   * @event
   */
  private _onClose(server: Server): void {
    this.logger.info(
      {
        tnx: 'closed',
      },
      `${this.options.lmtp ? 'LMTP' : 'SMTP'} Server closed`,
    )
    if (server !== this.server) {
      // older instance was closed
      return
    }
    this.emit('close')
  }

  /**
   * Called when an error occurs with the server
   *
   * @event
   */
  private _onError(err: Error): void {
    this.emit('error', err)
  }

  private _handleProxy(socket: Socket, callback: (err: Error | null, socketOptions: SocketOptions) => void): void {
    const socketOptions: SocketOptions = {
      id: Buffer.from(randomBytes(10)).toString('base64').toLowerCase(),
    }

    if (
      !this.options.useProxy
      || (Array.isArray(this.options.useProxy) && !this.options.useProxy.includes(socket.remoteAddress || '') && !this.options.useProxy.includes('*'))
    ) {
      socketOptions.ignore = this.options.ignoredHosts?.includes(socket.remoteAddress || '') || false
      return setImmediate(() => callback(null, socketOptions))
    }

    const chunks: Buffer[] = []
    let chunklen = 0
    const socketReader = () => {
      let chunk: Buffer | null
      let readChunk: Buffer | null
      while ((readChunk = socket.read() as Buffer | null) !== null) {
        chunk = readChunk
        for (let i = 0, len = chunk.length; i < len; i++) {
          const chr = chunk[i]
          if (chr === 0x0A) {
            socket.removeListener('readable', socketReader)
            chunks.push(chunk.slice(0, i + 1))
            chunklen += i + 1
            const remainder = chunk.slice(i + 1)
            if (remainder.length) {
              socket.unshift(remainder)
            }

            const header = Buffer.concat(chunks, chunklen).toString().trim()

            const params = (header || '').toString().split(' ')
            const commandName = params.shift()
            if (!commandName || commandName !== 'PROXY') {
              try {
                socket.end('* BAD Invalid PROXY header\r\n')
              }
              catch {
                // ignore
              }
              return
            }

            if (params[1]) {
              socketOptions.remoteAddress = params[1].trim().toLowerCase()

              socketOptions.ignore = this.options.ignoredHosts?.includes(socketOptions.remoteAddress) || false

              if (!socketOptions.ignore) {
                this.logger.info(
                  {
                    tnx: 'proxy',
                    cid: socketOptions.id,
                    proxy: params[1].trim().toLowerCase(),
                  },
                  '[%s] PROXY from %s through %s (%s)',
                  socketOptions.id,
                  params[1].trim().toLowerCase(),
                  params[2].trim().toLowerCase(),
                  JSON.stringify(params),
                )
              }

              if (params[3]) {
                socketOptions.remotePort = Number(params[3].trim())
              }
            }

            return callback(null, socketOptions)
          }
        }
        chunks.push(chunk)
        chunklen += chunk.length
      }
    }
    socket.on('readable', socketReader)
  }

  /**
   * Called when a new connection is established
   *
   * @event
   */
  private _onClientConnect(data: any): void {
    this.emit('connect', data)
  }

  /**
   * Normalize hostname
   *
   * @event
   */
  private _normalizeHostname(hostname: string): string {
    try {
      hostname = toUnicode((hostname || '').toString().trim()).toLowerCase()
    }
    catch (err) {
      this.logger.error(
        {
          tnx: 'punycode',
        },
        'Failed to process punycode domain "%s". error=%s',
        hostname,
        err instanceof Error ? err.message : String(err),
      )
    }

    return hostname
  }

  private _upgrade(socket: Socket, callback: (err: Error | null, tlsSocket: TLSSocket) => void): void {
    const socketOptions: TLSSocketOptions = {
      secureContext: this.secureContext.get('*'),
      isServer: true,
      server: this.server,
      SNICallback: (servername: string, cb: (err: Error | null, ctx?: SecureContext) => void) => {
        if (!this.options.SNICallback) {
          return cb(null, this.secureContext.get('*'))
        }
        this.options.SNICallback(this._normalizeHostname(servername), (err, context) => {
          if (err) {
            this.logger.error(
              {
                tnx: 'sni',
                servername,
                err,
              },
              'Failed to fetch SNI context for servername %s',
              servername,
            )
          }
          return cb(null, context || this.secureContext.get('*'))
        })
      },
    }

    let returned = false
    const onError = (err: Error) => {
      if (returned) {
        return
      }
      returned = true
      callback(err || new Error('Socket closed unexpectedly'), {} as TLSSocket)
    }

    // remove all listeners from the original socket besides the error handler
    socket.once('error', onError)

    // upgrade connection
    const tlsSocket = new TLSSocket(socket, socketOptions)

    tlsSocket.once('close', () => onError(new Error('Socket closed during TLS handshake')))
    tlsSocket.once('error', onError)
    tlsSocket.once('_tlsError', onError)
    tlsSocket.once('clientError', onError)
    tlsSocket.once('tlsClientError', onError)

    tlsSocket.on('secure', () => {
      socket.removeListener('error', onError)
      tlsSocket.removeListener('close', onError)
      tlsSocket.removeListener('error', onError)
      tlsSocket.removeListener('_tlsError', onError)
      tlsSocket.removeListener('clientError', onError)
      tlsSocket.removeListener('tlsClientError', onError)
      if (returned) {
        try {
          tlsSocket.end()
        }
        catch {
          // ignore
        }
        return
      }
      returned = true
      return callback(null, tlsSocket)
    })
  }
}
