import { createHmac } from 'crypto'
import { encode } from 'querystring'
import { camelize, Context, Dict, Quester, Random, sanitize, Session } from 'koishi'
import {} from '@koishijs/plugin-help'
import {} from '@koishijs/plugin-server'
import GitHub, { ReplySession } from '.'
import { EventFilter } from './events'
import { ReplyHandler } from './reply'

export default function command(ctx: Context, github: GitHub) {
  ctx.i18n.define('zh-CN', require('./locales/zh-CN'))
  const path = sanitize(github.config.path)

  const logger = ctx.logger('github')
  const { root, database } = ctx
  const subscriptions: Dict<Dict<EventFilter>> = {}

  const tokens: Dict<number> = Object.create(null)

  ctx.server.get(path + '/authorize', async (_ctx) => {
    const token = _ctx.query.state
    if (!token || Array.isArray(token)) return _ctx.status = 400
    if (!(token in tokens)) return _ctx.status = 403
    const id = tokens[token]
    delete tokens[token]
    const { code, state } = _ctx.query
    const data = await github.getTokens({ code, state, redirect_uri: github.config.redirect })
    await database.set('user', { id }, {
      'github.accessToken': data.access_token,
      'github.refreshToken': data.refresh_token,
    })
    return _ctx.status = 200
  })

  ctx.command('github.authorize')
    .alias('github.auth')
    .userFields(['id'])
    .action(async ({ session }) => {
      const token = Random.id()
      tokens[token] = session.user.id
      const url = 'https://github.com/login/oauth/authorize?' + encode({
        state: token,
        client_id: github.config.appId,
        redirect_uri: github.config.redirect,
        scope: 'admin:repo_hook,repo',
      })
      return session.text('.follow-link') + '\n' + url
    })

  const repoRegExp = /^[\w.-]+\/[\w.-]+$/

  ctx.command('github.repos [name]')
    .userFields(['github'])
    .option('add', '-a')
    .option('delete', '-d')
    .option('subscribe', '-s')
    .action(async ({ session, options }, name) => {
      if (options.add || options.delete) {
        if (!name) return session.text('github.repo-expected')
        if (!repoRegExp.test(name)) return session.text('github.repo-invalid')
        if (!session.user.github?.accessToken) {
          return github.authorize(session, session.text('github.require-auth'))
        }

        name = name.toLowerCase()
        const url = `https://api.github.com/repos/${name}/hooks`
        const [repo] = await ctx.database.get('github', { name: [name] })
        if (options.add) {
          if (repo) return session.text('.add-unchanged', [name])
          const secret = Random.id()
          let data: any
          try {
            data = await github.request('POST', url, session, {
              events: ['*'],
              config: {
                secret,
                url: ctx.server.config.selfUrl + path + '/webhook',
              },
            })
          } catch (err) {
            if (!Quester.isAxiosError(err) || !err.response) throw err
            if (err.response.status === 404) {
              return session.text('github.repo-not-found', [name])
            } else if (err.response.status === 403) {
              return session.text('github.forbidden')
            } else {
              logger.warn(err)
              return session.text('.add-failed', [name])
            }
          }
          await ctx.database.create('github', { name, id: data.data.id, secret })
          if (!options.subscribe) return session.text('.add-succeeded', [name])
          return session.execute({
            name: 'github',
            args: [name],
            options: { add: true },
          }, true)
        } else {
          if (!repo) return session.text('.delete-unchanged', [name])
          try {
            await github.request('DELETE', `${url}/${repo.id}`, session)
          } catch (err) {
            if (!Quester.isAxiosError(err) || !err.response) throw err
            if (err.response.status !== 404) {
              logger.warn(err)
              return session.text('.delete-failed', [name])
            }
          }

          async function updateChannels() {
            const channels = await ctx.database.get('channel', {}, ['id', 'platform', 'github'])
            return ctx.database.upsert('channel', channels.filter(({ github }) => {
              const shouldUpdate = github.webhooks[name]
              delete github.webhooks[name]
              return shouldUpdate
            }))
          }

          unsubscribe(name)
          await Promise.all([
            updateChannels(),
            ctx.database.remove('github', { name: [name] }),
          ])
          return session.text('.delete-succeeded', [name])
        }
      }

      const repos = await ctx.database.get('github', {})
      if (!repos.length) return session.text('.empty')
      return repos.map(repo => repo.name).join('\n')
    })

  function subscribe(repo: string, cid: string, meta: EventFilter) {
    (subscriptions[repo] ||= {})[cid] = meta
  }

  function unsubscribe(repo: string, id?: string) {
    if (!id) return delete subscriptions[repo]
    delete subscriptions[repo][id]
    if (!Object.keys(subscriptions[repo]).length) {
      delete subscriptions[repo]
    }
  }

  const hidden = (session: Session) => session.isDirect

  ctx.command('github [name]')
    .alias('gh')
    .channelFields(['github'])
    .option('list', '-l', { hidden })
    .option('add', '-a', { hidden, authority: 2 })
    .option('delete', '-d', { hidden, authority: 2 })
    .action(async ({ session, options }, name) => {
      if (options.list) {
        if (!session.channel) return session.text('.private-context')
        const names = Object.keys(session.channel.github.webhooks)
        if (!names.length) return session.text('.empty')
        return names.sort().join('\n')
      }

      if (options.add || options.delete) {
        if (!session.channel) return session.text('.private-context')
        if (!name) return session.text('github.repo-expected')
        if (!repoRegExp.test(name)) return session.text('github.repo-invalid')

        name = name.toLowerCase()
        const webhooks = session.channel.github.webhooks
        if (options.add) {
          if (webhooks[name]) return session.text('.add-unchanged', [name])
          const [repo] = await ctx.database.get('github', { name: [name] })
          if (!repo) {
            const dispose = session.middleware(({ content }, next) => {
              dispose()
              content = content.trim()
              if (content && content !== '.' && content !== '。') return next()
              return session.execute({
                name: 'github.repos',
                args: [name],
                options: { add: true, subscribe: true },
              })
            })
            return session.text('.unknown', [name])
          }
          webhooks[name] = {}
          await session.channel.$update()
          subscribe(name, session.cid, {})
          return session.text('.add-succeeded', [name])
        } else if (options.delete) {
          if (!webhooks[name]) return session.text('.delete-unchanged', [name])
          delete webhooks[name]
          await session.channel.$update()
          unsubscribe(name, session.cid)
          return session.text('.delete-succeeded', [name])
        }
      }

      return session.execute('help github')
    })

  async function request(method: Quester.Method, url: string, session: ReplySession, body: any, message: string) {
    return github.request(method, 'https://api.github.com' + url, session, body)
      .then(() => message + session.text('github.succeeded'))
      .catch((err) => {
        logger.warn(err)
        return message + session.text('github.failed')
      })
  }

  ctx.command('github.issue [title] [body:text]')
    .userFields(['github'])
    .option('repo', '-r [repo:string]')
    .action(async ({ session, options }, title, body) => {
      if (!options.repo) return session.text('github.repo-expected')
      if (!repoRegExp.test(options.repo)) return session.text('github.repo-invalid')
      if (!session.user.github?.accessToken) {
        return github.authorize(session, session.text('github.require-auth'))
      }

      return request('POST', `/repos/${options.repo}/issues`, session, {
        title,
        body,
      }, session.text('github.create'))
    })

  ctx.command('github.star [name]')
    .userFields(['github'])
    .action(async ({ session }, name) => {
      if (!name) return session.text('github.repo-expected')
      if (!repoRegExp.test(name)) return session.text('github.repo-invalid')
      if (!session.user.github?.accessToken) {
        return github.authorize(session, session.text('github.require-auth'))
      }

      return request('PUT', `/user/starred/${name}`, session, null, session.text('github.action'))
    })

  ctx.on('ready', async () => {
    const channels = await ctx.database.get('channel', {}, ['id', 'platform', 'github'])
    for (const { id, platform, github } of channels) {
      for (const repo in github.webhooks) {
        subscribe(repo, `${platform}:${id}`, github.webhooks[repo])
      }
    }
  })

  const reactions = ['+1', '-1', 'laugh', 'confused', 'heart', 'hooray', 'rocket', 'eyes']

  function safeParse(source: string) {
    try {
      return JSON.parse(source)
    } catch {}
  }

  ctx.server.post(path + '/webhook', async (_ctx) => {
    const event = _ctx.headers['x-github-event'].toString()
    const signature = _ctx.headers['x-hub-signature-256']
    const id = _ctx.headers['x-github-delivery']
    const webhookId = +_ctx.headers['x-github-hook-id']
    const payload = safeParse(_ctx.request.body.payload)
    if (!payload) return _ctx.status = 400
    const fullEvent = payload.action ? `${event}/${payload.action}` : event
    logger.debug('received %s (%s)', fullEvent, id)
    const [data] = await database.get('github', [webhookId])
    // 202：服务器已接受请求，但尚未处理
    // 在 github.repos -a 时确保获得一个 2xx 的状态码
    if (!data) return _ctx.status = 202
    if (signature !== `sha256=${createHmac('sha256', data.secret).update((_ctx.request as any).rawBody).digest('hex')}`) {
     return _ctx.status = 403
    }
    const fullName = payload.repository.full_name.toLowerCase()

    if (data.name !== fullName) {
      // repo renamed
      await database.set('github', webhookId, { name: fullName, secret: data.secret })

      unsubscribe(data.name)
      const channels = await ctx.database.get('channel', {}, ['id', 'platform', 'github'])
      await ctx.database.upsert('channel', channels.filter(({ platform, id, github }) => {
        const shouldUpdate = github.webhooks[data.name]
        if (shouldUpdate) {
          github.webhooks[fullName] = shouldUpdate
          subscribe(fullName, `${platform}:${id}`, github.webhooks[fullName])
          delete github.webhooks[data.name]
        }

        return shouldUpdate
      }))
    }

    _ctx.status = 200
    root.emit('github/webhook', event, payload)
  })

  ctx.before('attach-user', (session, fields) => {
    if (!session.quote) return
    if (github.history[session.quote.id]) {
      fields.add('github')
    }
  })

  ctx.middleware((session: ReplySession, next) => {
    if (!session.quote) return next()
    const body = session.stripped.content.trim()
    const payloads = github.history[session.quote.id]
    if (!body || !payloads) return next()

    let name: string, message: string
    if (session.stripped.prefix) {
      name = body.split(' ', 1)[0]
      message = body.slice(name.length).trim()
    } else {
      name = reactions.includes(body) ? 'react' : 'reply'
      message = body
    }

    const payload = payloads[name]
    if (!payload) return next()
    const handler = new ReplyHandler(github, session, message)
    return handler[name](...payload)
  })

  ctx.on('github/webhook', async (event, payload) => {
    // step 1: filter event
    const repoConfig = subscriptions[payload.repository.full_name.toLowerCase()] || {}
    const targets = Object.keys(repoConfig).filter((id) => {
      const baseConfig = repoConfig[id][camelize(event)] || {}
      if (baseConfig === false) return
      // payload.action may be undefined
      if (payload.action && baseConfig !== true) {
        const action = camelize(payload.action)
        const actionConfig = baseConfig[action]
        if (actionConfig === false) return
      }
      return true
    })
    if (!targets.length) return

    // step 2: handle event
    const result = await github.emit(event as any, payload)
    if (!result) return

    // step 3: broadcast message
    logger.debug('broadcast', result[0].split('\n', 1)[0])
    const messageIds = await ctx.broadcast(targets, github.config.messagePrefix + result[0])

    // step 4: save message ids for interactions
    for (const id of messageIds) {
      github.history[id] = result[1]
    }

    ctx.setTimeout(() => {
      for (const id of messageIds) {
        delete github.history[id]
      }
    }, github.config.replyTimeout)
  })
}
