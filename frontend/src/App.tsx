import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react'
import { api, asRecord, body, dateText, dateValue, download, first, getToken, records, setToken, valueText, type JsonRecord } from './api'

type NavItem = { path: string; label: string; group: string; admin?: boolean }
type Flash = { kind: 'success' | 'error'; text: string } | null

const navigation: NavItem[] = [
  { path: '/', label: 'Обзор', group: 'Работа' },
  { path: '/alerts', label: 'Алерты', group: 'Работа' },
  { path: '/scenarios', label: 'Сценарии DEMO', group: 'Работа' },
  { path: '/contexts', label: 'Исключения и работы', group: 'Контроль' },
  { path: '/assets', label: 'Инвентарь активов', group: 'Контроль' },
  { path: '/integrations', label: 'Интеграции', group: 'Контроль' },
  { path: '/sla', label: 'Сроки обработки', group: 'Контроль' },
  { path: '/dead-letters', label: 'Ошибочные задачи', group: 'Контроль' },
  { path: '/shifts', label: 'Смены и отчёты', group: 'Учёт' },
  { path: '/audit', label: 'Аудит', group: 'Учёт' },
  { path: '/settings', label: 'Политика действий', group: 'Управление', admin: true },
]

function wallTimeToIso(value: string, timeZone: string): string {
  const parts = value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/)
  if (!parts) throw new Error('Укажите дату и время')
  const target = Date.UTC(Number(parts[1]), Number(parts[2]) - 1, Number(parts[3]), Number(parts[4]), Number(parts[5]))
  const formatter = new Intl.DateTimeFormat('en-GB', { timeZone, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' })
  const wall = (instant: number) => {
    const formatted = Object.fromEntries(formatter.formatToParts(new Date(instant)).map(part => [part.type, part.value]))
    return Date.UTC(Number(formatted.year), Number(formatted.month) - 1, Number(formatted.day), Number(formatted.hour), Number(formatted.minute))
  }
  let instant = target
  for (let index = 0; index < 3; index++) instant += target - wall(instant)
  if (wall(instant) !== target) throw new Error('Это местное время отсутствует в выбранном часовом поясе')
  return new Date(instant).toISOString()
}

function statusLabel(value: unknown): string {
  const key = valueText(value, 'unknown').toLowerCase()
  const labels: Record<string, string> = {
    new: 'Новый', received: 'Получен', queued: 'В очереди', running: 'В работе', processing: 'В работе', investigating: 'Расследуется',
    completed: 'Завершён', closed: 'Закрыт', auto_closed: 'Автозакрыт', escalated: 'Эскалирован', reported: 'Отчёт утверждён', retried: 'Повторена', failed: 'Ошибка', pending: 'Ожидает',
    succeeded: 'Выполнено', unknown: 'Неизвестно', healthy: 'Доступно', degraded: 'Сбой', unavailable: 'Недоступно', stale: 'Нет сигнала',
    true_positive: 'Подтверждено', false_positive: 'Ложное срабатывание', needs_review: 'Нужна проверка',
    critical: 'Критический', high: 'Высокий', medium: 'Средний', low: 'Низкий',
    open: 'Открыт', resolved: 'Решён', active: 'Активно', context: 'Только контекст', expired: 'Истекло', approved: 'Утверждено', draft: 'Черновик',
    host: 'Хост', ip: 'IP-адрес', user: 'Пользователь', vpn_peer: 'VPN peer', device: 'Устройство',
    reviewed: 'Проверено', not_transferred: 'Не передано', pending_confirmation: 'Ожидает подтверждения', handoff_recorded: 'Подтверждение передачи записано',
    observe: 'Наблюдение', auto_close: 'Автозакрытие', approved_response: 'Разрешённые действия', create_case: 'Создание кейса', evidence_page: 'Страница доказательств', observable: 'Наблюдаемый объект', task: 'Задача кейса', close_alert: 'Закрытие алерта', update_case: 'Смена статуса кейса', disable_account_demo: 'DEMO: блокировка учётной записи', isolate_host_demo: 'DEMO: изоляция хоста',
  }
  return labels[key] ?? valueText(value, 'Неизвестно')
}

function toneFor(value: unknown): string {
  const key = valueText(value, '').toLowerCase()
  if (['critical', 'high', 'true_positive', 'failed', 'unavailable', 'stale', 'overdue', 'error', 'expired'].includes(key)) return 'danger'
  if (['needs_review', 'medium', 'pending', 'degraded', 'unknown', 'processing', 'investigating', 'running', 'queued'].includes(key)) return 'warning'
  if (['false_positive', 'completed', 'closed', 'resolved', 'auto_closed', 'succeeded', 'healthy', 'approved', 'active', 'reported'].includes(key)) return 'success'
  return 'neutral'
}

function Badge({ value, label }: { value: unknown; label?: string }) {
  return <span className={`badge badge--${toneFor(value)}`}>{label ?? statusLabel(value)}</span>
}

function integrationName(value: unknown): string {
  const names: Record<string, string> = {
    splunk: 'Splunk · поступление логов', thehive: 'TheHive · кейсы',
    misp: 'MISP · уведомления', worker: 'Worker · фоновая обработка',
  }
  const name = valueText(value, 'Источник')
  return names[name] ?? name
}

function integrationDetail(item: JsonRecord, mode: unknown): string {
  const detail = valueText(item.detail, '')
  if (detail) return detail
  if (item.status === 'healthy') return mode === 'DEMO' ? 'Демонстрационный адаптер доступен' : 'Проверка API успешна'
  if (item.status === 'unknown') return 'Проверка ещё не выполнялась'
  return 'Подробности не получены'
}

function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return <label className="field"><span className="field__label">{label}</span>{children}{hint && <span className="field__hint">{hint}</span>}</label>
}

function PageHead({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return <header className="page-head"><div><h1>{title}</h1>{description && <p>{description}</p>}</div>{actions && <div className="page-head__actions">{actions}</div>}</header>
}

function Panel({ title, aside, children, className = '' }: { title?: string; aside?: ReactNode; children: ReactNode; className?: string }) {
  return <section className={`panel ${className}`}>{(title || aside) && <div className="panel__head">{title && <h2>{title}</h2>}{aside}</div>}{children}</section>
}

function Empty({ title, detail }: { title: string; detail: string }) {
  return <div className="empty"><strong>{title}</strong><p>{detail}</p></div>
}

function Loading() {
  return <div className="loading" aria-label="Загрузка"><span /><span /><span /></div>
}

function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  return <div className="error-state" role="alert"><strong>Не удалось получить данные</strong><p>{message}</p>{retry && <button className="button button--secondary" onClick={retry}>Повторить</button>}</div>
}

function Notice({ flash }: { flash: Flash }) {
  return flash && <div className={`notice notice--${flash.kind}`} role="status">{flash.text}</div>
}

function Meta({ entries }: { entries: { label: string; value: ReactNode }[] }) {
  return <dl className="meta-grid">{entries.map(item => <div key={item.label}><dt>{item.label}</dt><dd>{item.value}</dd></div>)}</dl>
}

function useResource(path: string | null, intervalMs = 0) {
  const [data, setData] = useState<unknown>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [revision, setRevision] = useState(0)
  const reload = useCallback(() => setRevision(value => value + 1), [])
  useEffect(() => {
    if (!path) { setLoading(false); return }
    let active = true
    const load = async (quiet = false) => {
      if (!quiet) setLoading(true)
      try {
        const result = await api(path)
        if (active) { setData(result); setError('') }
      } catch (reason) {
        if (active) setError(reason instanceof Error ? reason.message : 'Неизвестная ошибка')
      } finally {
        if (active) setLoading(false)
      }
    }
    void load()
    const timer = intervalMs ? window.setInterval(() => void load(true), intervalMs) : null
    return () => { active = false; if (timer !== null) window.clearInterval(timer) }
  }, [path, revision, intervalMs])
  return { data, loading, error, reload }
}

function useMutation() {
  const [busy, setBusy] = useState(false)
  const [flash, setFlash] = useState<Flash>(null)
  const run = async (action: () => Promise<unknown>, success: string, onSuccess?: () => void) => {
    setBusy(true)
    setFlash(null)
    try {
      await action()
      setFlash({ kind: 'success', text: success })
      onSuccess?.()
      return true
    } catch (reason) {
      setFlash({ kind: 'error', text: reason instanceof Error ? reason.message : 'Операция завершилась ошибкой' })
      return false
    } finally { setBusy(false) }
  }
  return { busy, flash, run }
}

function Link({ to, children, className = '' }: { to: string; children: ReactNode; className?: string }) {
  return <a className={className} href={to} onClick={event => {
    if (event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey) {
      event.preventDefault()
      window.history.pushState({}, '', to)
      window.dispatchEvent(new PopStateEvent('popstate'))
    }
  }}>{children}</a>
}

function Shell({ user, onLogout, children }: { user: JsonRecord; onLogout: () => void; children: ReactNode }) {
  const [path, setPath] = useState(window.location.pathname)
  useEffect(() => {
    const change = () => setPath(window.location.pathname)
    window.addEventListener('popstate', change)
    return () => window.removeEventListener('popstate', change)
  }, [])
  const role = valueText(first(user, 'role', 'user_role')).toLowerCase()
  const admin = role === 'admin'
  const mode = valueText(first(user, 'mode', 'system_mode', 'app_mode'), 'unknown').toLowerCase()
  let currentGroup = ''
  return <div className="app-shell">
    <a className="skip-link" href="#main">Перейти к содержимому</a>
    <aside className="sidebar">
      <div className="brand"><span className="brand__symbol" aria-hidden="true">S<span>.</span></span><span><strong>Sauyt.Lab</strong><small>ЦОК / уровень L1</small></span></div>
      <div className="environment"><span className={`environment__dot ${mode === 'demo' ? 'environment__dot--demo' : ''}`} /><div><strong>{mode === 'demo' ? 'DEMO' : mode === 'connected' ? 'CONNECTED' : 'РЕЖИМ НЕИЗВЕСТЕН'}</strong><small>{mode === 'demo' ? 'Симулированные внешние действия' : mode === 'connected' ? 'Подключённые системы' : 'Проверьте настройки сервера'}</small></div></div>
      <nav className="sidebar__nav" aria-label="Основная навигация">
        {navigation.filter(item => (!item.admin || admin) && (item.path !== '/scenarios' || mode === 'demo')).map(item => {
          const showGroup = item.group !== currentGroup
          currentGroup = item.group
          const active = item.path === '/' ? path === '/' : path === item.path || (item.path === '/alerts' && path.startsWith('/investigations/'))
          return <div key={item.path}>{showGroup && <div className="nav-group">{item.group}</div>}<Link to={item.path} className={`nav-link ${active ? 'nav-link--active' : ''}`}>{item.label}</Link></div>
        })}
      </nav>
      <div className="sidebar__footer"><div className="account"><span className="account__avatar">{valueText(first(user, 'username', 'name'), 'A').slice(0, 1).toUpperCase()}</span><div><strong>{valueText(first(user, 'display_name', 'username', 'name'), 'Пользователь')}</strong><small>{admin ? 'Администратор' : 'Аналитик'} · {valueText(first(user, 'tenant_name', 'tenant_id'), 'Заказчик не указан')}</small></div></div><button className="text-button" onClick={onLogout}>Выйти из системы</button></div>
    </aside>
    <div className="main-wrap"><div className="topbar"><span>Sauyt.Lab / {navigation.find(item => item.path === path)?.label ?? (path.startsWith('/investigations/') ? 'Расследование' : 'Рабочая область')}</span><div className="topbar__right"><span className="topbar__mode">{mode === 'demo' ? 'ДЕМО ДАННЫЕ' : mode === 'connected' ? 'ПОДКЛЮЧЕНО' : 'СТАТУС НЕИЗВЕСТЕН'}</span><span>{new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium' }).format(new Date())}</span></div></div><main id="main" className="content">{children}</main></div>
  </div>
}

function Login({ onLogin }: { onLogin: (user: JsonRecord) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setBusy(true); setError('')
    try {
      const response = asRecord(await api('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }))
      const token = valueText(first(response, 'access_token', 'token'), '')
      if (!token) throw new Error('Сервер не вернул токен доступа')
      setToken(token)
      onLogin(asRecord(await api('/auth/me')))
    } catch (reason) {
      setToken(null)
      setError(reason instanceof Error ? reason.message : 'Ошибка входа')
    } finally { setBusy(false) }
  }
  return <div className="login-screen"><div className="login-side"><div className="brand brand--large"><span className="brand__symbol" aria-hidden="true">S<span>.</span></span><span><strong>Sauyt.Lab</strong><small>Центр оперативной кибербезопасности</small></span></div><div className="login-side__message"><h1>Расследования,<br />которые можно проверить.</h1><p>Очередь алертов, доказательства и разрешённые действия в одном рабочем цикле L1.</p></div><div className="login-side__foot">Доступ к данным заказчика определяется учётной записью.</div></div><div className="login-main"><form className="login-card" onSubmit={submit}><div className="login-card__mark">Доступ в консоль</div><h2>Вход в систему</h2><p>Используйте учётную запись аналитика или администратора.</p><Field label="Имя пользователя"><input autoComplete="username" value={username} onChange={event => setUsername(event.target.value)} required autoFocus /></Field><Field label="Пароль"><input type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required /></Field>{error && <div className="form-error" role="alert">{error}</div>}<button className="button button--primary button--wide" disabled={busy}>{busy ? 'Вход…' : 'Войти'}</button><div className="login-card__note">Режим работы и демонстрационный статус определяет сервер после входа.</div></form></div></div>
}

function Dashboard({ user }: { user: JsonRecord }) {
  const overview = useResource('/dashboard', 15000)
  const recent = useResource('/alerts?limit=7', 15000)
  const info = asRecord(overview.data)
  const counts = asRecord(info.queue)
  const alerts = records(recent.data)
  const integrations = records(info.integrations)
  const mode = valueText(user.mode, '').toLowerCase()
  const metrics = [
    { label: 'В очереди', value: counts.queued, caption: 'ожидают обработки' },
    { label: 'Расследуются', value: counts.running, caption: 'активные расследования' },
    { label: 'Нужна проверка', value: counts.needs_review, caption: 'решение аналитика' },
    { label: 'Ошибки', value: counts.failed, caption: 'требуют разбора' },
  ]
  const reload = () => { overview.reload(); recent.reload() }
  return <><PageHead title="Рабочая очередь" description="Текущее состояние поступления, обработки и эскалации алертов." actions={<><button className="button button--secondary" onClick={reload}>Обновить</button>{mode === 'demo' && <Link to="/scenarios" className="button button--primary">Запустить сценарий</Link>}</>} />
    {overview.error && <ErrorState message={overview.error} retry={overview.reload} />}
    {recent.error && <ErrorState message={recent.error} retry={recent.reload} />}
    {(overview.loading && !overview.data) || (recent.loading && !recent.data) ? <Loading /> : <>
      <div className="metric-grid">{metrics.map(metric => <div className="metric" key={metric.label}><div className="metric__label">{metric.label}</div><div className="metric__value">{valueText(metric.value)}</div><div className="metric__caption">{metric.value === undefined ? 'Данные недоступны' : metric.caption}</div></div>)}</div>
      <div className="dashboard-grid"><Panel title="Недавние алерты" aside={<Link to="/alerts" className="inline-link">Вся очередь</Link>}>{alerts.length ? <div className="stack-list">{alerts.map((item, index) => <AlertRow key={valueText(item.id, String(index))} item={item} />)}</div> : <Empty title="Алертов пока нет" detail="Проверьте поступление логов и состояние интеграций. Пустая очередь сама по себе не подтверждает исправность мониторинга." />}</Panel>
        <div className="dashboard-side"><Panel title="Состояние источников" aside={<Link to="/integrations" className="inline-link">Интеграции</Link>}>{integrations.length ? <div className="health-list">{integrations.map((item, index) => <div className="health-row" key={valueText(item.name, String(index))}><div><strong>{integrationName(item.name)}</strong><small>{item.name === 'worker' ? 'Последний сигнал' : 'Последний лог'}: {dateText(item.name === 'worker' ? item.last_checked_at : item.last_received_at)}</small></div><Badge value={item.status} /></div>)}</div> : <Empty title="Состояние неизвестно" detail="Источники ещё не сообщили о доступности и времени последнего лога." />}</Panel><Panel title="Продолжить работу"><div className="quick-links"><Link to="/sla">Проверить сроки обработки <span>→</span></Link><Link to="/dead-letters">Разобрать ошибочные задачи <span>→</span></Link><Link to="/shifts">Подготовить передачу смены <span>→</span></Link></div></Panel></div></div>
    </>}</>
}

function AlertRow({ item }: { item: JsonRecord }) {
  const investigationId = first(item, 'investigation_id', 'investigationId')
  const id = valueText(first(item, 'id', 'alert_id', 'source_event_id', 'source_id'))
  const target = investigationId ? `/investigations/${encodeURIComponent(valueText(investigationId))}` : `/investigations/${encodeURIComponent(id)}`
  return <Link to={target} className="alert-row"><span className={`severity-dot severity-dot--${toneFor(first(item, 'severity', 'priority'))}`} /><span className="alert-row__main"><strong>{valueText(first(item, 'title', 'rule', 'rule_name', 'name', 'event_type'), `Алерт ${id}`)}</strong><small>{valueText(first(item, 'customer_name', 'tenant_name', 'source'), 'Источник не указан')} · {dateText(first(item, 'received_at', 'created_at', 'event_at', 'event_time'))}</small></span><Badge value={first(item, 'status', 'processing_status')} /><span className="alert-row__arrow" aria-hidden="true">→</span></Link>
}

function Alerts({ user }: { user: JsonRecord }) {
  const [status, setStatus] = useState('')
  const [verdict, setVerdict] = useState('')
  const [search, setSearch] = useState('')
  const [query, setQuery] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [uploadKey, setUploadKey] = useState(0)
  const [uploadResult, setUploadResult] = useState<JsonRecord | null>(null)
  const upload = useMutation()
  const admin = valueText(user.role).toLowerCase() === 'admin'
  const path = `/alerts${query ? `?${query}` : ''}`
  const { data, loading, error, reload } = useResource(path, 15000)
  const list = records(data)
  const apply = (event: FormEvent) => {
    event.preventDefault()
    const params = new URLSearchParams()
    if (status) params.set('status', status)
    if (verdict) params.set('verdict', verdict)
    if (search.trim()) params.set('search', search.trim())
    setQuery(params.toString())
  }
  const importAlerts = async () => {
    if (!file) return
    const payload = new FormData()
    payload.append('file', file)
    const result = asRecord(await api('/ingest/import', { method: 'POST', body: payload }))
    setUploadResult(result)
    return result
  }
  const submitImport = async (event: FormEvent) => {
    event.preventDefault()
    const ok = await upload.run(importAlerts, 'Файл принят. Созданные алерты отправлены в обработку.', reload)
    if (ok) { setFile(null); setUploadKey(value => value + 1) }
  }
  return <><PageHead title="Алерты" description="Исходные алерты сохраняются отдельно от расследований и вложенных событий." actions={<button className="button button--secondary" onClick={reload}>Обновить</button>} />
    <Panel className="filter-panel"><form className="filters" onSubmit={apply}><Field label="Поиск по названию"><input placeholder="Название алерта" value={search} onChange={event => setSearch(event.target.value)} /></Field><Field label="Статус"><select value={status} onChange={event => setStatus(event.target.value)}><option value="">Все статусы</option><option value="queued">В очереди</option><option value="running">В работе</option><option value="needs_review">Нужна проверка</option><option value="auto_closed">Автозакрыт</option><option value="escalated">Эскалирован</option><option value="failed">Ошибка</option></select></Field><Field label="Вердикт"><select value={verdict} onChange={event => setVerdict(event.target.value)}><option value="">Все вердикты</option><option value="true_positive">Подтверждено</option><option value="false_positive">Ложное срабатывание</option><option value="needs_review">Нужна проверка</option></select></Field><button className="button button--primary" type="submit">Применить</button></form></Panel>
    {admin && <Panel title="Импорт алертов"><form className="import-form" onSubmit={submitImport}><Field label="JSON или CSV, не более 2 МБ"><input key={uploadKey} type="file" accept=".json,.csv,application/json,text/csv" required onChange={event => setFile(event.target.files?.[0] ?? null)} /></Field><button className="button button--secondary" disabled={!file || upload.busy}>{upload.busy ? 'Импорт…' : 'Импортировать'}</button></form><Notice flash={upload.flash} />{uploadResult && <p className="panel-intro">Новых алертов: {valueText(uploadResult.created_count)}.</p>}</Panel>}
    {error && <ErrorState message={error} retry={reload} />}{loading && !data ? <Loading /> : <Panel title="Список алертов" aside={<span className="quiet">{list.length} записей</span>}>{list.length ? <div className="table-wrap"><table><thead><tr><th>Алерт</th><th>Заказчик / источник</th><th>Критичность</th><th>Поступил</th><th>Обработка</th><th>Вердикт</th><th></th></tr></thead><tbody>{list.map((item, index) => {
      const id = valueText(item.id, String(index))
      const investigationId = valueText(item.investigation_id, '')
      return <tr key={id}><td><strong>{valueText(item.title, 'Без названия')}</strong><small className="cell-sub">{valueText(item.source_event_id)}</small></td><td>{valueText(user.tenant_name)}<small className="cell-sub">{valueText(item.source)}</small></td><td><Badge value={item.severity} /></td><td className="number">{dateText(item.received_at)}</td><td><Badge value={item.status} /></td><td><Badge value={item.verdict} /></td><td>{investigationId && <Link className="inline-link" to={`/investigations/${encodeURIComponent(investigationId)}`}>Открыть</Link>}</td></tr>
    })}</tbody></table></div> : <Empty title="По этому фильтру алертов нет" detail="Измените условия поиска или проверьте приём событий в разделе интеграций." />}</Panel>}</>
}

function CaseStatusControl({ caseId, currentStatus, onUpdated }: { caseId: string; currentStatus: string; onUpdated: () => void }) {
  const statuses = useResource(`/cases/${encodeURIComponent(caseId)}/statuses`)
  const [choice, setChoice] = useState('')
  const [busy, setBusy] = useState(false)
  const [outcome, setOutcome] = useState<{ status: string; message: string } | null>(null)
  const available = records(statuses.data).filter(item => item.hidden !== true && valueText(item.value, '') !== '')
  const selected = available.some(item => item.value === choice)
    ? choice
    : valueText(available.find(item => valueText(item.value).toLowerCase() === currentStatus.toLowerCase())?.value ?? available[0]?.value, '')
  const update = async (event: FormEvent) => {
    event.preventDefault()
    if (!selected || busy || selected.toLowerCase() === currentStatus.toLowerCase()) return
    setBusy(true)
    setOutcome(null)
    try {
      const result = asRecord(await api(`/cases/${encodeURIComponent(caseId)}/status`, { method: 'POST', body: body({ status: selected }) }))
      const status = valueText(result.status, 'unknown').toLowerCase()
      const messages: Record<string, string> = {
        succeeded: `Статус кейса «${statusLabel(selected)}» подтверждён.`,
        pending: 'Запрос принят, изменение статуса ещё не подтверждено.',
        unknown: 'Результат изменения неизвестен. Сверьте состояние кейса перед повтором.',
        failed: 'Изменение статуса не выполнено. Проверьте запись действия.',
      }
      setOutcome({ status, message: messages[status] ?? `Результат операции: ${statusLabel(status)}. Требуется проверка.` })
      onUpdated()
    } catch (reason) {
      setOutcome({ status: 'failed', message: reason instanceof Error ? reason.message : 'Не удалось изменить статус кейса.' })
    } finally { setBusy(false) }
  }
  return <form className="case-status-control" onSubmit={update}>
    <div className="case-status-control__row"><Field label="Новый статус"><select value={selected} onChange={event => { setChoice(event.target.value); setOutcome(null) }} disabled={busy || statuses.loading || !!statuses.error || !available.length}>{!available.length && <option value="">Статусы недоступны</option>}{available.map(item => {
      const value = valueText(item.value)
      const stage = valueText(item.stage, '')
      return <option key={value} value={value}>{statusLabel(value)}{stage && stage.toLowerCase() !== value.toLowerCase() ? ` · ${statusLabel(stage)}` : ''}</option>
    })}</select></Field><button className="button button--small button--secondary" disabled={busy || statuses.loading || !!statuses.error || !selected || selected.toLowerCase() === currentStatus.toLowerCase()}>{busy ? 'Отправка…' : 'Изменить'}</button></div>
    {statuses.loading && <p className="field__hint">Загрузка допустимых статусов…</p>}
    {statuses.error && <div className="case-status-control__error"><span role="alert">{statuses.error}</span><button type="button" className="button button--small button--quiet" onClick={statuses.reload}>Повторить</button></div>}
    {!statuses.loading && !statuses.error && !available.length && <p className="field__hint">Доступных статусов нет.</p>}
    {outcome && <div className="case-status-control__outcome" role={outcome.status === 'failed' ? 'alert' : 'status'}><Badge value={outcome.status} /><span>{outcome.message}</span></div>}
  </form>
}

function Investigation({ id, user }: { id: string; user: JsonRecord }) {
  const { data, loading, error, reload } = useResource(`/investigations/${encodeURIComponent(id)}`)
  const policy = useResource('/settings')
  const [tab, setTab] = useState('evidence')
  const [verdict, setVerdict] = useState('needs_review')
  const [note, setNote] = useState('')
  const [actionBusy, setActionBusy] = useState('')
  const [actionFlash, setActionFlash] = useState<Flash>(null)
  const mutation = useMutation()
  const inv = asRecord(data)
  const alerts = records(inv.alerts)
  const alert = alerts[0] ?? {}
  const evidence = records(inv.evidence)
  const actions = records(inv.actions)
  const caseWrites = records(inv.case_writes)
  const playbooks = records(inv.playbook_runs)
  const cases = records(inv.cases)
  const decisions = records(inv.decisions)
  const decision = decisions[decisions.length - 1] ?? {}
  const admin = valueText(user.role).toLowerCase() === 'admin'
  const settings = asRecord(policy.data)
  const mode = valueText(user.mode, '').toLowerCase()
  const canAct = admin && settings.automation_level !== 'observe' && (mode === 'demo' || settings.connected_writes_enabled === true)
  const timeline: JsonRecord[] = [...evidence.map(item => ({ ...item, timeline_kind: 'Доказательство', timeline_at: item.collected_at ?? item.event_at })),
    ...actions.map(item => ({ ...item, timeline_kind: 'Действие', timeline_at: item.completed_at ?? item.attempted_at })),
    ...caseWrites.map(item => ({ ...item, timeline_kind: 'Запись TheHive', timeline_at: item.completed_at ?? item.attempted_at, summary: statusLabel(item.kind) }))]
    .sort((a, b) => new Date(valueText(a.timeline_at, '1970-01-01')).getTime() - new Date(valueText(b.timeline_at, '1970-01-01')).getTime())
  const reviewed = async (event: FormEvent) => {
    event.preventDefault()
    const ok = await mutation.run(() => api(`/investigations/${encodeURIComponent(id)}/review`, { method: 'POST', body: body({ verdict, note }) }), 'Вердикт аналитика сохранён.', reload)
    if (ok) setNote('')
  }
  const perform = async (kind: string) => {
    setActionBusy(kind); setActionFlash(null)
    try {
      const result = asRecord(await api(`/investigations/${encodeURIComponent(id)}/actions/${kind}`, { method: 'POST' }))
      const status = valueText(result.status, 'unknown')
      setActionFlash(status === 'succeeded'
        ? { kind: 'success', text: 'Действие выполнено и записано в аудит.' }
        : { kind: 'error', text: `Результат действия: ${statusLabel(status)}. Проверьте запись перед повтором.` })
      reload()
    } catch (reason) { setActionFlash({ kind: 'error', text: reason instanceof Error ? reason.message : 'Действие не выполнено' }) }
    finally { setActionBusy('') }
  }
  const reconcile = async (actionId: string) => {
    setActionBusy(actionId); setActionFlash(null)
    try {
      const result = asRecord(await api(`/actions/${encodeURIComponent(actionId)}/reconcile`, { method: 'POST' }))
      const status = valueText(result.status, 'unknown')
      setActionFlash(status === 'succeeded'
        ? { kind: 'success', text: 'Внешнее действие подтверждено сверкой.' }
        : { kind: 'error', text: `Результат сверки: ${statusLabel(status)}. Автоматический повтор не выполнен.` })
      reload()
    } catch (reason) { setActionFlash({ kind: 'error', text: reason instanceof Error ? reason.message : 'Сверка не выполнена' }) }
    finally { setActionBusy('') }
  }
  return <><div className="backline"><Link to="/alerts">← К списку алертов</Link></div>
    <PageHead title={valueText(alert.title, valueText(inv.summary, `Расследование ${id}`))} description={`Расследование ${id} · ${valueText(alert.source_event_id, 'Идентификатор источника не указан')}`} actions={<button className="button button--secondary" onClick={reload}>Обновить</button>} />
    {error && <ErrorState message={error} retry={reload} />}{loading && !data ? <Loading /> : <>
      <div className="detail-top"><Panel title="Состояние"><div className="status-pair"><div><span>Обработка</span><Badge value={inv.status} /></div><div><span>Вердикт</span><Badge value={inv.verdict} /></div></div><Meta entries={[
        { label: 'Заказчик', value: valueText(user.tenant_name) }, { label: 'Критичность', value: <Badge value={inv.priority} /> },
        { label: 'Время события', value: dateText(alert.event_at) }, { label: 'Поступил', value: dateText(alert.received_at) },
        { label: 'Срок обработки', value: dateText(inv.due_at) }, { label: 'Правило', value: valueText(alert.rule) },
      ]} /></Panel><Panel title="Текущее решение"><p className="decision-summary">{valueText(inv.summary, 'Решение ещё не сформировано.')}</p><p className="panel-intro">{valueText(inv.rationale, 'Обоснование пока не записано.')}</p><Meta entries={[
        { label: 'Приоритет', value: <Badge value={inv.priority} /> },
        { label: 'Анализатор', value: valueText(inv.analyzer) },
        { label: 'Доказательства решения', value: Array.isArray(decision.evidence_ids) ? decision.evidence_ids.map(value => valueText(value)).join(', ') || 'Не указаны' : 'Не указаны' },
        { label: 'Недостающие данные', value: Array.isArray(inv.missing_data) ? inv.missing_data.map(value => valueText(value)).join(', ') || 'Не указаны' : 'Не указаны' },
        { label: 'Рекомендуемые действия', value: Array.isArray(inv.recommended_actions) ? inv.recommended_actions.map(value => valueText(value)).join(', ') || 'Не указаны' : 'Не указаны' },
        { label: 'Последнее решение', value: dateText(decision.created_at) },
      ]} /></Panel></div>
      <div className="detail-layout"><div>
        <div className="tabs" role="tablist" aria-label="Разделы расследования">{[['evidence', 'Доказательства'], ['timeline', 'Временная шкала'], ['playbook', 'Плейбук'], ['actions', 'Действия и кейсы']].map(([key, label]) => <button key={key} type="button" role="tab" aria-selected={tab === key} className={tab === key ? 'tab tab--active' : 'tab'} onClick={() => setTab(key)}>{label}<span>{key === 'evidence' ? evidence.length : key === 'timeline' ? timeline.length : key === 'playbook' ? playbooks.length : actions.length + cases.length + caseWrites.length}</span></button>)}</div>
        {tab === 'evidence' && <Panel><div className="evidence-list">{evidence.length ? evidence.map((item, index) => <article className="evidence-item" key={valueText(item.id, String(index))}><div className="evidence-item__head"><div><span className="record-index">EV-{String(index + 1).padStart(2, '0')}</span><h3>{valueText(item.kind, 'Доказательство')}</h3></div><time>{dateText(item.event_at ?? item.collected_at)}</time></div><p className="panel-intro">{valueText(item.summary)}</p><div className="evidence-item__source">{valueText(item.source, 'Источник не указан')} · ID {valueText(item.id)}</div>{item.data !== undefined && <pre className="evidence-data">{JSON.stringify(item.data, null, 2)}</pre>}</article>) : <Empty title="Доказательства ещё не собраны" detail="Проверьте ход плейбука и доступность источников. Без достаточных данных решение должно требовать проверки." />}</div></Panel>}
        {tab === 'timeline' && <Panel><ol className="timeline">{timeline.length ? timeline.map((item, index) => <li key={valueText(item.id, String(index))}><div className="timeline__pin" /><div><time>{dateText(item.timeline_at)}</time><strong>{valueText(item.timeline_kind)}</strong><p>{valueText(item.summary ?? item.kind, valueText(item.status))}</p></div></li>) : <li className="timeline__empty"><Empty title="Шкала пока пуста" detail="Записи появятся после сохранения доказательств или действий." /></li>}</ol></Panel>}
        {tab === 'playbook' && <Panel>{playbooks.length ? <div className="playbook-list">{playbooks.map((item, index) => {
          const steps = Array.isArray(item.steps) ? item.steps.map(step => typeof step === 'string' ? { title: step } : asRecord(step)) : []
          return <article key={valueText(item.id, String(index))}><div className="playbook-list__head"><div><h3>{valueText(item.key, 'Общий плейбук')}</h3><p>Версия {valueText(item.version)}</p></div><Badge value={item.status} /></div><Meta entries={[{ label: 'Начат', value: dateText(item.started_at) }, { label: 'Завершён', value: dateText(item.completed_at) }]} />{steps.length > 0 && <ol className="steps">{steps.map((step, stepIndex) => <li key={stepIndex}><span>{stepIndex + 1}</span><div><strong>{valueText(first(step, 'title', 'name', 'step'), 'Шаг')}</strong><small>{valueText(first(step, 'detail', 'result', 'description'), '')}</small></div><Badge value={step.status} /></li>)}</ol>}</article>
        })}</div> : <Empty title="Плейбук не запускался" detail="Запись выполнения появится после обработки алерта фоновым worker." />}</Panel>}
        {tab === 'actions' && <div className="action-grid"><Panel title="Действия">{actions.length ? <div className="stack-list">{actions.map((item, index) => <div className="operation-row" key={valueText(item.id, String(index))}><div><strong>{statusLabel(item.kind)}</strong><small>{dateText(item.completed_at ?? item.attempted_at)} · {valueText(item.external_id)}</small>{valueText(asRecord(item.detail).message, '') && <small>{valueText(asRecord(item.detail).message)}</small>}{item.status === 'unknown' && admin && <button className="button button--small button--secondary" disabled={!!actionBusy} onClick={() => void reconcile(valueText(item.id))}>Сверить результат</button>}</div><Badge value={item.status} /></div>)}</div> : <Empty title="Действий нет" detail="Автоматические действия выполняются только если их разрешает политика." />}</Panel><Panel title="Кейсы TheHive">{cases.length ? <div className="stack-list">{cases.map((item, index) => <div className="operation-row" key={valueText(item.id, String(index))}><div><strong>{valueText(item.title, 'Кейс')}</strong><small>Внешний ID: {valueText(item.external_id)}</small>{admin && settings.automation_level === 'approved_response' && (mode === 'demo' || settings.connected_writes_enabled === true) && valueText(item.external_id, '') && <CaseStatusControl key={valueText(item.id)} caseId={valueText(item.id)} currentStatus={valueText(item.status, '')} onUpdated={reload} />}</div><Badge value={item.status} /></div>)}</div> : <Empty title="Кейс не создан" detail="Кейс появится при подтверждённой эскалации и успешном ответе TheHive." />}</Panel></div>}
        {tab === 'actions' && caseWrites.length > 0 && <Panel title="Этапы записи TheHive"><div className="stack-list">{caseWrites.map((item, index) => <div className="operation-row" key={valueText(item.id, String(index))}><div><strong>{valueText(item.sequence)}. {statusLabel(item.kind)}</strong><small>Попыток: {valueText(item.attempts)} · ID операции: {valueText(item.id)}</small><small>Подтверждение: {valueText(item.external_id, 'не получено')} · {dateText(item.completed_at ?? item.attempted_at)}</small>{typeof item.error_type === 'string' && item.error_type && <small>Ошибка: {item.error_type}</small>}</div><Badge value={item.status} /></div>)}</div></Panel>}
      </div><aside className="detail-aside"><Panel title="Проверка аналитика"><p className="panel-intro">Сохранённое решение фиксируется в аудите. Действия по итогам решения проверяет серверная политика.</p><form className="form-stack" onSubmit={reviewed}><Field label="Вердикт"><select value={verdict} onChange={event => setVerdict(event.target.value)}><option value="needs_review">Нужна проверка</option><option value="true_positive">Подтверждено</option><option value="false_positive">Ложное срабатывание</option></select></Field><Field label="Обоснование"><textarea value={note} onChange={event => setNote(event.target.value)} required minLength={3} maxLength={2000} rows={5} placeholder="Укажите наблюдения и основания решения" /></Field><button className="button button--primary button--wide" disabled={mutation.busy}>{mutation.busy ? 'Сохранение…' : 'Сохранить решение'}</button><Notice flash={mutation.flash} /></form></Panel>
        <Panel title="Разрешённые действия">{policy.error && <ErrorState message={policy.error} retry={policy.reload} />}{!policy.error && !canAct && <p className="panel-intro">Действия недоступны при текущей политике. Администратор может изменить уровень в настройках.</p>}{canAct && <div className="action-buttons"><button className="button button--secondary" disabled={!!actionBusy || inv.verdict !== 'true_positive'} onClick={() => void perform('create_case')}>Создать кейс</button><button className="button button--secondary" disabled={!!actionBusy || inv.verdict !== 'false_positive'} onClick={() => void perform('close_alert')}>Закрыть алерт</button>{mode === 'demo' && <><button className="button button--quiet" disabled={!!actionBusy} onClick={() => void perform('disable_account_demo')}>DEMO: блокировать учётную запись</button><button className="button button--quiet" disabled={!!actionBusy} onClick={() => void perform('isolate_host_demo')}>DEMO: изолировать хост</button></>}</div>}<Notice flash={actionFlash} /></Panel>
        <Panel title="Связанные алерты">{alerts.length ? <div className="related-list">{alerts.map((item, index) => <div key={valueText(item.id, String(index))}><strong>{valueText(item.title, 'Связанный алерт')}</strong><small>{valueText(item.source_event_id)} · {dateText(item.event_at)}</small></div>)}</div> : <p className="quiet">Связанные алерты не указаны.</p>}</Panel>
      </aside></div>
    </>}</>
}

const scopeFields = [
  ['host', 'Хост'], ['src_ip', 'IP источника'], ['auth_method', 'Метод входа'], ['peer', 'VPN peer'],
  ['device', 'Устройство'], ['tunnel', 'Туннель'], ['user', 'Пользователь'], ['command_line', 'Командная строка'],
] as const

function ScopeEditor({ scope, onChange }: { scope: Record<string, string>; onChange: (value: Record<string, string>) => void }) {
  return <fieldset className="scope-editor"><legend>Область действия</legend><p className="field__hint">Укажите поля исходного события для точного совпадения. Без области запись служит только контекстом и не разрешает автозакрытие.</p><div className="form-grid">{scopeFields.map(([key, label]) => <Field key={key} label={label}><input value={scope[key] ?? ''} onChange={event => onChange({ ...scope, [key]: event.target.value })} /></Field>)}</div></fieldset>
}

function filledScope(scope: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(scope).map(([key, value]) => [key, value.trim()]).filter(([, value]) => value))
}

function scopeText(value: unknown): string {
  const entries = Object.entries(asRecord(value))
  return entries.length ? entries.map(([key, item]) => `${key}=${valueText(item)}`).join(' · ') : 'Область не задана — только контекст'
}

function Contexts({ user }: { user: JsonRecord }) {
  const exceptions = useResource('/exceptions')
  const maintenance = useResource('/maintenance')
  const [rule, setRule] = useState('*')
  const [indicator, setIndicator] = useState('')
  const [reason, setReason] = useState('')
  const [exceptionScope, setExceptionScope] = useState<Record<string, string>>({})
  const [validFrom, setValidFrom] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [workTitle, setWorkTitle] = useState('')
  const [workEntity, setWorkEntity] = useState('')
  const [workReason, setWorkReason] = useState('')
  const [maintenanceScope, setMaintenanceScope] = useState<Record<string, string>>({})
  const [startsAt, setStartsAt] = useState('')
  const [endsAt, setEndsAt] = useState('')
  const exceptionMutation = useMutation()
  const maintenanceMutation = useMutation()
  const admin = valueText(first(user, 'role')).toLowerCase() === 'admin'
  const addException = async (event: FormEvent) => {
    event.preventDefault()
    const payload: JsonRecord = { rule, entity: indicator, reason, scope: filledScope(exceptionScope), valid_from: new Date(validFrom).toISOString(), valid_until: new Date(expiresAt).toISOString() }
    const ok = await exceptionMutation.run(() => api('/exceptions', { method: 'POST', body: body(payload) }), 'Исключение создано.', exceptions.reload)
    if (ok) { setIndicator(''); setReason(''); setExceptionScope({}); setValidFrom(''); setExpiresAt('') }
  }
  const addMaintenance = async (event: FormEvent) => {
    event.preventDefault()
    const payload: JsonRecord = { title: workTitle, entity: workEntity, reason: workReason, scope: filledScope(maintenanceScope), valid_from: new Date(startsAt).toISOString(), valid_until: new Date(endsAt).toISOString() }
    const ok = await maintenanceMutation.run(() => api('/maintenance', { method: 'POST', body: body(payload) }), 'Согласованная работа сохранена.', maintenance.reload)
    if (ok) { setWorkTitle(''); setWorkEntity(''); setWorkReason(''); setMaintenanceScope({}); setStartsAt(''); setEndsAt('') }
  }
  const exceptionList = records(exceptions.data, 'exceptions')
  const workList = records(maintenance.data, 'maintenance', 'works')
  return <><PageHead title="Исключения и согласованные работы" description="Каждое основание ограничено по времени и привязано к заказчику." /><div className="two-column"><Panel title="Исключения" aside={<span className="quiet">{exceptionList.length} записей</span>}>{exceptions.error && <ErrorState message={exceptions.error} retry={exceptions.reload} />}{exceptions.loading && !exceptions.data ? <Loading /> : exceptionList.length ? <div className="simple-list">{exceptionList.map((item, index) => <div className="simple-row" key={valueText(first(item, 'id'), String(index))}><div><strong>{valueText(first(item, 'entity', 'indicator', 'value', 'pattern'))}</strong><small>{valueText(first(item, 'rule'))} · {valueText(first(item, 'reason'))}</small><small>До {dateText(first(item, 'valid_until', 'expires_at'))}</small><small>{scopeText(item.scope)}</small></div><Badge value={!Object.keys(asRecord(item.scope)).length ? 'context' : new Date(valueText(item.valid_until)).getTime() < Date.now() ? 'expired' : 'active'} /></div>)}</div> : <Empty title="Исключений нет" detail="Исторические ложные срабатывания не становятся действующими исключениями автоматически." />}{admin && <form className="inline-form" onSubmit={addException}><h3>Новое исключение</h3><div className="form-grid"><Field label="Правило"><input required value={rule} onChange={event => setRule(event.target.value)} placeholder="* или ключ плейбука" /></Field><Field label="Сущность"><input required value={indicator} onChange={event => setIndicator(event.target.value)} placeholder="IP, хост или пользователь" /></Field><Field label="Основание"><input required value={reason} onChange={event => setReason(event.target.value)} /></Field><Field label="Действует с"><input type="datetime-local" required value={validFrom} onChange={event => setValidFrom(event.target.value)} /></Field><Field label="Действует до"><input type="datetime-local" min={validFrom} required value={expiresAt} onChange={event => setExpiresAt(event.target.value)} /></Field></div><ScopeEditor scope={exceptionScope} onChange={setExceptionScope} /><button className="button button--secondary" disabled={exceptionMutation.busy}>Создать исключение</button><Notice flash={exceptionMutation.flash} /></form>}</Panel><Panel title="Согласованные работы" aside={<span className="quiet">{workList.length} записей</span>}>{maintenance.error && <ErrorState message={maintenance.error} retry={maintenance.reload} />}{maintenance.loading && !maintenance.data ? <Loading /> : workList.length ? <div className="simple-list">{workList.map((item, index) => <div className="simple-row" key={valueText(first(item, 'id'), String(index))}><div><strong>{valueText(first(item, 'title', 'name'))}</strong><small>{dateText(first(item, 'valid_from', 'starts_at'))} — {dateText(first(item, 'valid_until', 'ends_at'))}</small><small>{valueText(first(item, 'entity'))} · {valueText(first(item, 'reason'))}</small><small>{scopeText(item.scope)}</small></div><Badge value={!Object.keys(asRecord(item.scope)).length ? 'context' : new Date(valueText(item.valid_until)).getTime() < Date.now() ? 'expired' : 'active'} /></div>)}</div> : <Empty title="Работы не зарегистрированы" detail="Согласованное окно должно быть явно сохранено, прежде чем плейбук сможет использовать его как контекст." />}{admin && <form className="inline-form" onSubmit={addMaintenance}><h3>Добавить работу</h3><div className="form-grid"><Field label="Название"><input required value={workTitle} onChange={event => setWorkTitle(event.target.value)} /></Field><Field label="Сущность"><input required value={workEntity} onChange={event => setWorkEntity(event.target.value)} placeholder="IP, хост или пользователь" /></Field><Field label="Основание"><input required value={workReason} onChange={event => setWorkReason(event.target.value)} /></Field><Field label="Начало"><input type="datetime-local" required value={startsAt} onChange={event => setStartsAt(event.target.value)} /></Field><Field label="Конец"><input type="datetime-local" required min={startsAt} value={endsAt} onChange={event => setEndsAt(event.target.value)} /></Field></div><ScopeEditor scope={maintenanceScope} onChange={setMaintenanceScope} /><button className="button button--secondary" disabled={maintenanceMutation.busy}>Сохранить работу</button><Notice flash={maintenanceMutation.flash} /></form>}</Panel></div></>
}

const assetKinds = ['host', 'ip', 'user', 'vpn_peer', 'device'] as const
const assetCriticalities = ['unknown', 'low', 'medium', 'high', 'critical'] as const

function assetAttributesText(value: unknown): string {
  const labels: Record<string, string> = { allowed: 'Разрешён', tunnel: 'Туннель', device: 'Устройство' }
  const entries = Object.entries(asRecord(value))
  return entries.length ? entries.map(([key, entry]) => `${labels[key] ?? key}: ${entry !== null && typeof entry === 'object' ? JSON.stringify(entry) : valueText(entry)}`).join(' · ') : 'Атрибуты не указаны'
}

function AssetEditor({ asset, onSaved, onCancel }: { asset: JsonRecord | null; onSaved: () => void; onCancel: () => void }) {
  const initial = asRecord(asset)
  const initialAttributes = asRecord(initial.attributes)
  const [kind, setKind] = useState(valueText(initial.kind, 'host'))
  const [value, setValue] = useState(valueText(initial.value, ''))
  const [owner, setOwner] = useState(valueText(initial.owner, ''))
  const [criticality, setCriticality] = useState(valueText(initial.criticality, 'unknown'))
  const [allowed, setAllowed] = useState(initialAttributes.allowed === true)
  const [tunnel, setTunnel] = useState(valueText(initialAttributes.tunnel, ''))
  const [device, setDevice] = useState(valueText(initialAttributes.device, ''))
  const [extraAttributes, setExtraAttributes] = useState(() => JSON.stringify(Object.fromEntries(Object.entries(initialAttributes).filter(([key]) => initial.kind !== 'vpn_peer' || !['allowed', 'tunnel', 'device'].includes(key))), null, 2))
  const [validation, setValidation] = useState('')
  const mutation = useMutation()
  const id = valueText(initial.id, '')
  const save = async (event: FormEvent) => {
    event.preventDefault()
    setValidation('')
    let attributes: JsonRecord
    try {
      const parsed: unknown = JSON.parse(extraAttributes.trim() || '{}')
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Атрибуты должны быть JSON-объектом')
      attributes = { ...parsed as JsonRecord }
    } catch (reason) {
      setValidation(reason instanceof SyntaxError ? 'Проверьте синтаксис JSON в атрибутах.' : reason instanceof Error ? reason.message : 'Неверные атрибуты')
      return
    }
    if (kind === 'vpn_peer') {
      attributes.allowed = allowed
      if (tunnel.trim()) attributes.tunnel = tunnel.trim()
      else delete attributes.tunnel
      if (device.trim()) attributes.device = device.trim()
      else delete attributes.device
      if (allowed && (!tunnel.trim() || !device.trim())) { setValidation('Разрешённый VPN peer требует туннель и устройство.'); return }
    }
    const payload = { kind, value: value.trim(), owner: owner.trim(), criticality, attributes }
    await mutation.run(() => api(id ? `/assets/${encodeURIComponent(id)}` : '/assets', { method: id ? 'PUT' : 'POST', body: body(payload) }), id ? 'Актив обновлён.' : 'Актив добавлен.', onSaved)
  }
  return <Panel title={id ? 'Изменить актив' : 'Новый актив'}><form id="asset-editor" className="form-stack" onSubmit={save}>
    <div className="form-grid"><Field label="Тип"><select value={kind} onChange={event => setKind(event.target.value)}>{assetKinds.map(option => <option key={option} value={option}>{statusLabel(option)}</option>)}</select></Field><Field label="Критичность"><select value={criticality} onChange={event => setCriticality(event.target.value)}>{assetCriticalities.map(option => <option key={option} value={option}>{statusLabel(option)}</option>)}</select></Field></div>
    <Field label="Значение"><input required maxLength={256} value={value} onChange={event => setValue(event.target.value)} placeholder={kind === 'ip' ? '198.51.100.10' : kind === 'vpn_peer' ? 'peer.example' : 'Имя или идентификатор'} /></Field>
    <Field label="Владелец"><input maxLength={256} value={owner} onChange={event => setOwner(event.target.value)} placeholder="Команда или ответственный" /></Field>
    {kind === 'vpn_peer' && <div className="asset-vpn-fields"><label className="check-row"><input type="checkbox" checked={allowed} onChange={event => setAllowed(event.target.checked)} />Разрешённый VPN peer</label><div className="form-grid"><Field label="Туннель"><input value={tunnel} required={allowed} onChange={event => setTunnel(event.target.value)} placeholder="Имя туннеля" /></Field><Field label="Устройство"><input value={device} required={allowed} onChange={event => setDevice(event.target.value)} placeholder="Шлюз или устройство" /></Field></div></div>}
    <Field label="Другие атрибуты (JSON)" hint="Объект с дополнительным контекстом. Для VPN peer разрешение, туннель и устройство задаются полями выше."><textarea value={extraAttributes} onChange={event => { setExtraAttributes(event.target.value); setValidation('') }} rows={4} spellCheck={false} /></Field>
    {validation && <div className="form-error" role="alert">{validation}</div>}
    <div className="asset-editor__actions"><button className="button button--primary" disabled={mutation.busy}>{mutation.busy ? 'Сохранение…' : id ? 'Сохранить изменения' : 'Добавить актив'}</button>{id && <button type="button" className="button button--secondary" onClick={onCancel}>Отмена</button>}</div><Notice flash={mutation.flash} />
  </form></Panel>
}

function Assets({ user }: { user: JsonRecord }) {
  const { data, loading, error, reload } = useResource('/assets')
  const list = records(data)
  const admin = valueText(user.role).toLowerCase() === 'admin'
  const [editing, setEditing] = useState<JsonRecord | null>(null)
  const [editorRevision, setEditorRevision] = useState(0)
  const [flash, setFlash] = useState<Flash>(null)
  const edit = (item: JsonRecord) => {
    setEditing(item)
    setEditorRevision(value => value + 1)
    window.requestAnimationFrame(() => document.getElementById('asset-editor')?.scrollIntoView({ block: 'start' }))
  }
  const saved = () => {
    setFlash({ kind: 'success', text: editing ? 'Актив обновлён и записан в аудит.' : 'Актив добавлен в инвентарь.' })
    setEditing(null)
    setEditorRevision(value => value + 1)
    reload()
  }
  return <><PageHead title="Инвентарь активов" description="Сведения об активах заказчика помогают проверять события; изменения доступны администратору." actions={<button className="button button--secondary" onClick={reload}>Обновить</button>} /><Notice flash={flash} />{error && <ErrorState message={error} retry={reload} />}
    <div className={admin ? 'asset-layout' : ''}>{admin && <AssetEditor key={`${valueText(editing?.id, 'new')}-${editorRevision}`} asset={editing} onSaved={saved} onCancel={() => { setEditing(null); setEditorRevision(value => value + 1) }} />}
      <Panel title="Активы" aside={<span className="quiet">{list.length} записей</span>}>{loading && !data ? <Loading /> : list.length ? <div className="asset-list">{list.map((item, index) => <article className="asset-row" key={valueText(item.id, String(index))}><div className="asset-row__main"><span className="asset-row__kind">{statusLabel(item.kind)}</span><h3>{valueText(item.value)}</h3><p>Владелец: {valueText(item.owner, 'не указан')}</p><p>{assetAttributesText(item.attributes)}</p></div><div className="asset-row__side"><Badge value={item.criticality} />{admin && <button className="button button--small button--secondary" onClick={() => edit(item)}>Изменить</button>}</div></article>)}</div> : <Empty title="Инвентарь пуст" detail="Добавьте активы, чтобы плейбуки могли учитывать владельца, критичность и разрешённые VPN peer." />}</Panel>
    </div></>
}

const mispL1Statuses = [
  { value: 'pending', label: 'Ожидает' }, { value: 'reviewed', label: 'Проверено' },
  { value: 'needs_review', label: 'Нужна проверка' }, { value: 'escalated', label: 'Передано на L2' },
] as const
const mispL2Statuses = [
  { value: 'not_transferred', label: 'Не передано' }, { value: 'pending_confirmation', label: 'Ожидает подтверждения' },
  { value: 'handoff_recorded', label: 'Подтверждение передачи записано' },
] as const

function mispStatusLabel(value: unknown, level: 'l1' | 'l2'): string {
  const options = level === 'l1' ? mispL1Statuses : mispL2Statuses
  return options.find(option => option.value === value)?.label ?? statusLabel(value)
}

function MispNoticeRow({ item, role, onUpdated }: { item: JsonRecord; role: string; onUpdated: () => void }) {
  const [l1, setL1] = useState(valueText(item.l1_status, 'pending'))
  const [l2, setL2] = useState(valueText(item.l2_status, 'not_transferred'))
  const [handoffReference, setHandoffReference] = useState('')
  const l1Mutation = useMutation()
  const l2Mutation = useMutation()
  const id = valueText(item.id, '')
  const canL1 = role === 'admin' || role === 'analyst'
  const admin = role === 'admin'
  useEffect(() => setL1(valueText(item.l1_status, 'pending')), [item.l1_status])
  useEffect(() => setL2(valueText(item.l2_status, 'not_transferred')), [item.l2_status])
  const saveL1 = async (event: FormEvent) => {
    event.preventDefault()
    await l1Mutation.run(() => api(`/misp/notices/${encodeURIComponent(id)}`, { method: 'PATCH', body: body({ l1_status: l1 }) }), 'Решение L1 сохранено в аудите.', onUpdated)
  }
  const saveL2 = async (event: FormEvent) => {
    event.preventDefault()
    const payload: JsonRecord = { l2_status: l2 }
    if (l2 === 'handoff_recorded') payload.handoff_reference = handoffReference.trim()
    const ok = await l2Mutation.run(() => api(`/misp/notices/${encodeURIComponent(id)}`, { method: 'PATCH', body: body(payload) }), 'Статус передачи L2 сохранён в аудите.', onUpdated)
    if (ok) setHandoffReference('')
  }
  return <article className="misp-notice"><div className="misp-notice__head"><div><h3>{valueText(item.title, 'Уведомление MISP')}</h3><p>ID MISP: {valueText(item.external_id)} · {dateText(item.received_at)}</p></div><Badge value={item.received_status} /></div>
    <div className="misp-notice__statuses"><div><span>Поступление</span><Badge value={item.received_status} /></div><div><span>Решение L1</span><Badge value={item.l1_status} label={mispStatusLabel(item.l1_status, 'l1')} /></div><div><span>Передача L2</span><Badge value={item.l2_status} label={mispStatusLabel(item.l2_status, 'l2')} /></div></div>
    {(canL1 || admin) && <div className="misp-notice__forms">{canL1 && <form className="misp-notice__form" onSubmit={saveL1}><Field label="Решение L1"><select value={l1} onChange={event => setL1(event.target.value)}>{mispL1Statuses.map(option => <option key={option.value} value={option.value}>{option.label}</option>)}</select></Field><button className="button button--small button--secondary" disabled={l1Mutation.busy || l1 === item.l1_status}>{l1Mutation.busy ? 'Сохранение…' : 'Сохранить L1'}</button><Notice flash={l1Mutation.flash} /></form>}
      {admin && <form className="misp-notice__form" onSubmit={saveL2}><Field label="Передача L2"><select value={l2} onChange={event => setL2(event.target.value)}>{mispL2Statuses.map(option => <option key={option.value} value={option.value}>{option.label}</option>)}</select></Field>{l2 === 'handoff_recorded' && item.l2_status !== 'handoff_recorded' && <Field label="Подтверждение передачи" hint="Номер тикета или ссылка на подтверждение L2"><input required minLength={3} maxLength={200} value={handoffReference} onChange={event => setHandoffReference(event.target.value)} /></Field>}<button className="button button--small button--secondary" disabled={l2Mutation.busy || l2 === item.l2_status}>{l2Mutation.busy ? 'Сохранение…' : 'Сохранить L2'}</button><Notice flash={l2Mutation.flash} /></form>}</div>}
  </article>
}

function Integrations({ user }: { user: JsonRecord }) {
  const { data, loading, error, reload } = useResource('/integrations', 15000)
  const notices = useResource('/misp/notices', 30000)
  const list = records(data)
  const noticeList = records(notices.data)
  const mutation = useMutation()
  const admin = valueText(user.role).toLowerCase() === 'admin'
  const role = valueText(user.role).toLowerCase()
  const refresh = () => { reload(); notices.reload() }
  const check = () => void mutation.run(() => api('/integrations/check', { method: 'POST' }), 'Проверка поставлена в очередь. Результат появится после обработки.', refresh)
  return <><PageHead title="Интеграции и поступление логов" description="Доступность API и свежесть источников показываются отдельно от числа алертов." actions={<>{admin && <button className="button button--primary" disabled={mutation.busy} onClick={check}>{mutation.busy ? 'Запуск…' : 'Запустить проверку'}</button>}<button className="button button--secondary" onClick={refresh}>Обновить данные</button></>} />
    <Notice flash={mutation.flash} />{error && <ErrorState message={error} retry={reload} />}
    {loading && !data ? <Loading /> : list.length ? <div className="integration-grid">{list.map((item, index) => <Panel key={valueText(item.name, String(index))} className="integration-card"><div className="integration-card__top"><div><h2>{integrationName(item.name)}</h2><p>{integrationDetail(item, user.mode)}</p></div><Badge value={item.status} /></div><Meta entries={item.name === 'worker' ? [
      { label: 'Последний сигнал', value: dateText(item.last_checked_at) },
      { label: 'Подробности', value: valueText(item.detail, 'Нет данных') },
    ] : [
      { label: 'Последняя проверка', value: dateText(item.last_checked_at) },
      { label: 'Последнее поступление', value: dateText(item.last_received_at) },
      { label: 'Подробности', value: valueText(item.detail, 'Нет данных') },
    ]} />{item.status === 'unknown' && <p className="unknown-note">{item.name === 'worker' ? 'Сигнал worker ещё не поступал. Обработка очереди не подтверждена.' : 'Статус неизвестен. Отсутствие алертов не подтверждает работу источника.'}</p>}{item.status === 'stale' && item.name === 'worker' && <p className="unknown-note">Сигнал worker не поступал более 3 минут. Проверьте обработку очереди.</p>}</Panel>)}</div> : <Empty title="Состояние интеграций неизвестно" detail="Сервер не вернул ни одного источника. Отсутствие алертов не означает, что сбор работает." />}
    <Panel title="Уведомления НКЦКБ (MISP)" aside={<span className="quiet">{noticeList.length} записей</span>}><p className="panel-intro">Поступление, решение L1 и подтверждение передачи L2 учитываются отдельно.</p>{notices.error && <ErrorState message={notices.error} retry={notices.reload} />}{notices.loading && !notices.data ? <Loading /> : noticeList.length ? <div className="misp-notice-list">{noticeList.map((item, index) => <MispNoticeRow key={valueText(item.id, String(index))} item={item} role={role} onUpdated={notices.reload} />)}</div> : <Empty title="Уведомлений нет" detail="Проверьте доступность MISP и запустите проверку интеграций. Пустой список не подтверждает работу источника." />}</Panel></>
}

function Sla() {
  const { data, loading, error, reload } = useResource('/sla', 15000)
  const list = records(data)
  const now = Date.now()
  const hour = 60 * 60 * 1000
  const overdue = list.filter(item => item.overdue === true).length
  const soon = list.filter(item => {
    const due = dateValue(item.due_at)
    return !item.overdue && due !== null && due - now <= hour
  }).length
  const onTime = list.length - overdue - soon
  return <><PageHead title="Сроки обработки" description="Активные расследования и сроки по данным сервера. Близкий срок — в течение часа." actions={<button className="button button--secondary" onClick={reload}>Обновить</button>} />{error && <ErrorState message={error} retry={reload} />}{loading && !data ? <Loading /> : <>
    <div className="metric-grid metric-grid--three">{[
      { label: 'Более часа', value: onTime, caption: 'до срока' },
      { label: 'Менее часа', value: soon, caption: 'требуют внимания' },
      { label: 'Просрочено', value: overdue, caption: 'превышен срок' },
    ].map(metric => <div className="metric" key={metric.label}><div className="metric__label">{metric.label}</div><div className="metric__value">{metric.value}</div><div className="metric__caption">{metric.caption}</div></div>)}</div>
    <Panel title="Контрольные сроки">{list.length ? <div className="table-wrap"><table><thead><tr><th>Расследование</th><th>Приоритет</th><th>Срок</th><th>Состояние</th><th></th></tr></thead><tbody>{list.map((item, index) => <tr key={valueText(item.id, String(index))}><td><strong>{valueText(item.summary, valueText(item.id))}</strong><small className="cell-sub">{valueText(item.id)}</small></td><td><Badge value={item.priority} /></td><td className="number">{dateText(item.due_at)}</td><td><Badge value={item.overdue ? 'overdue' : item.status} label={item.overdue ? 'Просрочено' : undefined} /></td><td><Link to={`/investigations/${encodeURIComponent(valueText(item.id))}`} className="inline-link">Открыть</Link></td></tr>)}</tbody></table></div> : <Empty title="Активных сроков нет" detail="Если очередь пуста, проверьте свежесть логов и состояние интеграций." />}</Panel>
  </>}</>
}

function Shifts({ user }: { user: JsonRecord }) {
  const { data, loading, error, reload } = useResource('/shifts')
  const shifts = records(data, 'shifts')
  const [selected, setSelected] = useState('')
  const [preview, setPreview] = useState<unknown>(null)
  const [previewBusy, setPreviewBusy] = useState(false)
  const [previewError, setPreviewError] = useState('')
  const [startsAt, setStartsAt] = useState('')
  const [endsAt, setEndsAt] = useState('')
  const [timezone, setTimezone] = useState('Asia/Qyzylorda')
  const [outgoingName, setOutgoingName] = useState('')
  const [incomingName, setIncomingName] = useState('')
  const [approvedId, setApprovedId] = useState('')
  const createMutation = useMutation()
  const reportMutation = useMutation()
  const admin = valueText(first(user, 'role')).toLowerCase() === 'admin'
  const activeId = selected || valueText(first(shifts[0] ?? {}, 'id'), '')
  const selectedShift = shifts.find(item => valueText(first(item, 'id')) === activeId)
  const loadPreview = async (id = activeId) => {
    if (!id) return
    setPreviewBusy(true); setPreviewError('')
    try { setPreview(await api(`/shifts/${encodeURIComponent(id)}/report/preview`)); setSelected(id) }
    catch (reason) { setPreviewError(reason instanceof Error ? reason.message : 'Не удалось сформировать отчёт') }
    finally { setPreviewBusy(false) }
  }
  const createShift = async (event: FormEvent) => {
    event.preventDefault()
    if (endsAt <= startsAt) { await createMutation.run(async () => { throw new Error('Конец смены должен быть позже начала') }, ''); return }
    let payload: JsonRecord
    try {
      payload = { starts_at: wallTimeToIso(startsAt, timezone), ends_at: wallTimeToIso(endsAt, timezone), timezone, outgoing_name: outgoingName || null, incoming_name: incomingName || null }
    } catch (reason) {
      await createMutation.run(async () => { throw reason }, '')
      return
    }
    const ok = await createMutation.run(() => api('/shifts', { method: 'POST', body: body(payload) }), 'Смена создана.', reload)
    if (ok) { setStartsAt(''); setEndsAt(''); setOutgoingName(''); setIncomingName('') }
  }
  const approve = () => reportMutation.run(() => api(`/shifts/${encodeURIComponent(activeId)}/report/approve`, { method: 'POST' }), 'Версия отчёта утверждена.', () => { setApprovedId(activeId); void loadPreview(); reload() })
  const exportFile = async (format: 'txt' | 'docx') => reportMutation.run(() => download(`/shifts/${encodeURIComponent(activeId)}/report/export?format=${format}`, `sauyt-shift-${activeId}.${format}`), `Отчёт ${format.toUpperCase()} скачан.`)
  const report = asRecord(first(asRecord(preview), 'report') ?? preview)
  const reportBody = first(report, 'text', 'content', 'body', 'preview')
  const sections = records(first(report, 'sections'), 'sections')
  return <><PageHead title="Смены и передача" description="Отчёт формируется из фактических записей; интервал смены включает начало и исключает конец." />{error && <ErrorState message={error} retry={reload} />}{loading && !data ? <Loading /> : <div className="shift-layout"><div><Panel title="Смены" aside={<span className="quiet">{shifts.length} записей</span>}>{shifts.length ? <div className="shift-list">{shifts.map((item, index) => {
    const id = valueText(first(item, 'id'), String(index))
    const zone = valueText(first(item, 'timezone'), 'Asia/Qyzylorda')
    return <button key={id} className={`shift-row ${activeId === id ? 'shift-row--active' : ''}`} onClick={() => { setSelected(id); setPreview(null); setPreviewError('') }}><div><strong>{dateText(first(item, 'starts_at', 'start_at'), zone)} — {dateText(first(item, 'ends_at', 'end_at'), zone)}</strong><small>{zone} · Статус {statusLabel(item.status)}</small></div><Badge value={first(item, 'status', 'report_status')} /></button>
  })}</div> : <Empty title="Смен пока нет" detail="Создайте смену, чтобы собрать отчёт из алертов, расследований и записей аудита." />}</Panel><Panel title="Новая смена"><form className="form-stack" onSubmit={createShift}><div className="form-grid"><Field label="Начало"><input type="datetime-local" required value={startsAt} onChange={event => setStartsAt(event.target.value)} /></Field><Field label="Конец"><input type="datetime-local" required value={endsAt} onChange={event => setEndsAt(event.target.value)} /></Field></div><Field label="Часовой пояс"><input required value={timezone} onChange={event => setTimezone(event.target.value)} placeholder="Asia/Qyzylorda" /></Field><div className="form-grid"><Field label="Сдаёт смену"><input value={outgoingName} onChange={event => setOutgoingName(event.target.value)} /></Field><Field label="Принимает смену"><input value={incomingName} onChange={event => setIncomingName(event.target.value)} /></Field></div><button className="button button--secondary" disabled={createMutation.busy}>Создать смену</button><Notice flash={createMutation.flash} /></form></Panel></div><Panel title="Отчёт передачи смены" className="report-panel"><div className="report-toolbar"><button className="button button--primary" disabled={!activeId || previewBusy} onClick={() => void loadPreview()}>{previewBusy ? 'Формирование…' : 'Предпросмотр'}</button><button className="button button--secondary" disabled={!activeId || (selectedShift?.status !== 'reported' && approvedId !== activeId) || reportMutation.busy} onClick={() => void exportFile('txt')}>Экспорт TXT</button><button className="button button--secondary" disabled={!activeId || (selectedShift?.status !== 'reported' && approvedId !== activeId) || reportMutation.busy} onClick={() => void exportFile('docx')}>Экспорт DOCX</button>{admin && <button className="button button--quiet" disabled={!activeId || !preview || reportMutation.busy} onClick={approve}>Утвердить версию</button>}</div>{selectedShift && <div className="report-meta">Смена {activeId} · {valueText(first(selectedShift, 'timezone'))} · версия предпросмотра {valueText(report.version)}</div>}{previewError && <ErrorState message={previewError} retry={() => void loadPreview()} />}<Notice flash={reportMutation.flash} />{preview ? <article className="report-preview">{typeof reportBody === 'string' ? <pre>{reportBody}</pre> : <><h3>ОТЧЁТ — L1 ЦОК ТОО „Sauyt.Lab“ (передача смены)</h3>{sections.length ? sections.map((section, index) => <section key={index}><h4>{valueText(first(section, 'title', 'name'), `Раздел ${index + 1}`)}</h4><p>{valueText(first(section, 'content', 'text', 'body'), 'Данные не указаны')}</p></section>) : <pre>{JSON.stringify(report, null, 2)}</pre>}</>}</article> : <Empty title="Отчёт ещё не открыт" detail="Выберите смену и сформируйте предпросмотр. Утверждение сохранит версию отчёта." />}</Panel></div>}</>
}

function Audit() {
  const { data, loading, error, reload } = useResource('/audit')
  const list = records(data)
  return <><PageHead title="Журнал аудита" description="Изменения решений, политики и внешние действия с зафиксированным результатом." actions={<button className="button button--secondary" onClick={reload}>Обновить</button>} />
    {error && <ErrorState message={error} retry={reload} />}{loading && !data ? <Loading /> : <Panel title="Последние записи">{list.length ? <div className="table-wrap"><table><thead><tr><th>Время</th><th>Операция</th><th>Исполнитель</th><th>Объект</th><th>Подробности</th></tr></thead><tbody>{list.map((item, index) => <tr key={valueText(item.id, String(index))}><td className="number">{dateText(item.created_at)}</td><td><strong>{valueText(item.operation)}</strong></td><td>{valueText(item.actor, 'Система')}</td><td>{valueText(item.subject_type)}<small className="cell-sub">{valueText(item.subject_id, '')}</small></td><td><pre className="audit-detail">{item.detail && typeof item.detail === 'object' ? JSON.stringify(item.detail, null, 2) : valueText(item.detail, '')}</pre></td></tr>)}</tbody></table></div> : <Empty title="Записей аудита нет" detail="Операции появятся здесь после обработки алертов и действий пользователей." />}</Panel>}</>
}

function Settings({ user }: { user: JsonRecord }) {
  const { data, loading, error, reload } = useResource('/settings')
  const current = asRecord(data)
  const [mode, setMode] = useState('')
  const [level, setLevel] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const mutation = useMutation()
  const admin = valueText(first(user, 'role')).toLowerCase() === 'admin'
  useEffect(() => { if (data) { setMode(valueText(first(current, 'mode', 'system_mode'), 'unknown').toLowerCase()); setLevel(valueText(first(current, 'automation_level', 'autonomy_level', 'action_level'), 'observe')) } }, [data])
  const save = async (event: FormEvent) => {
    event.preventDefault()
    const previousLevel = valueText(first(current, 'automation_level', 'autonomy_level', 'action_level'), 'observe')
    if (level !== previousLevel && !confirmed) {
      await mutation.run(async () => { throw new Error('Подтвердите изменение политики действий') }, '')
      return
    }
    const payload = { automation_level: level }
    const ok = await mutation.run(() => api('/settings', { method: 'PATCH', body: body(payload) }), 'Политика сохранена и записана в аудит.', reload)
    if (ok) setConfirmed(false)
  }
  return <><PageHead title="Политика действий" description="Уровень автономности определяет сервер. Изменение доступно только администратору и записывается в аудит." />{error && <ErrorState message={error} retry={reload} />}{loading && !data ? <Loading /> : <div className="settings-layout"><Panel title="Режим и автономность"><form className="form-stack" onSubmit={save}><Field label="Режим"><div className="read-only-field">{mode === 'demo' ? 'DEMO — симуляторы' : mode === 'connected' ? 'CONNECTED — реальные API' : 'Неизвестно'}</div></Field><Field label="Уровень действий"><select disabled={!admin} value={level} onChange={event => setLevel(event.target.value)}><option value="observe">observe — анализ и рекомендации</option><option value="auto_close">auto_close — разрешённое автозакрытие</option><option value="approved_response">approved_response — действия по политике</option></select></Field><div className="policy-callout"><strong>Проверка выполняется сервером</strong><p>Вердикт аналитика или модели сам по себе не разрешает внешнее действие. Для автозакрытия дополнительно нужна включённая глобальная настройка AUTO_CLOSE_ENABLED и проверка правил.</p></div>{admin && <><label className="check-row"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} />Подтверждаю изменение политики и понимаю режим внешних действий.</label><button className="button button--primary" disabled={mutation.busy}>{mutation.busy ? 'Сохранение…' : 'Сохранить политику'}</button></>}<Notice flash={mutation.flash} /></form></Panel><Panel title="Текущее состояние"><Meta entries={[{ label: 'Режим', value: <Badge value={mode} label={mode ? mode.toUpperCase() : 'Неизвестно'} /> }, { label: 'Автономность', value: <Badge value={level} /> }, { label: 'Глобальное автозакрытие', value: valueText(current.auto_close_enabled, 'Неизвестно') }, { label: 'Реальные операции записи', value: valueText(first(current, 'connected_writes_enabled', 'connected_write_enabled', 'write_enabled'), 'Неизвестно') }, { label: 'Источник настроек', value: 'Сервер' }]} /><p className="panel-intro">Режим определяется конфигурацией сервера. Настройка API ключей выполняется через переменные окружения; секреты не показываются в интерфейсе.</p></Panel></div>}</>
}

function Scenarios({ user }: { user: JsonRecord }) {
  const { data, loading, error, reload } = useResource('/scenarios')
  const dataset = useResource('/dataset')
  const [running, setRunning] = useState('')
  const [flash, setFlash] = useState<Flash>(null)
  const [datasetFile, setDatasetFile] = useState<File | null>(null)
  const [datasetPath, setDatasetPath] = useState('')
  const [datasetInputKey, setDatasetInputKey] = useState(0)
  const [datasetResult, setDatasetResult] = useState<JsonRecord | null>(null)
  const datasetMutation = useMutation()
  const list = records(data)
  const datasetInfo = asRecord(dataset.data)
  const admin = valueText(user.role).toLowerCase() === 'admin'
  useEffect(() => {
    if (datasetInfo.recommended_path && !datasetPath) setDatasetPath(valueText(datasetInfo.recommended_path))
  }, [dataset.data])
  const run = async (key: string) => {
    setRunning(key); setFlash(null)
    try {
      const response = asRecord(await api(`/scenarios/${encodeURIComponent(key)}/run`, { method: 'POST' }))
      setFlash({ kind: 'success', text: `Сценарий отправлен в обработку. Создано алертов: ${valueText(response.created_count)}.` })
    } catch (reason) { setFlash({ kind: 'error', text: reason instanceof Error ? reason.message : 'Сценарий не запущен' }) }
    finally { setRunning('') }
  }
  const importDataset = async (event: FormEvent) => {
    event.preventDefault()
    if (!datasetFile) return
    const payload = new FormData()
    payload.append('file', datasetFile)
    const ok = await datasetMutation.run(async () => {
      const result = asRecord(await api(`/dataset/import?path=${encodeURIComponent(datasetPath)}`, { method: 'POST', body: payload }))
      if (typeof result.created_count !== 'number') throw new Error('Сервер не вернул результат импорта')
      setDatasetResult(result)
      return result
    }, 'Файл обработан. Созданные алерты отправлены в очередь; учебные метки не влияют на решение.')
    if (ok) { setDatasetFile(null); setDatasetInputKey(value => value + 1) }
  }
  return <><PageHead title="Демонстрационные сценарии" description="Каждый запуск отправляет алерт через backend, очередь и worker. Внешние действия в DEMO симулируются." actions={<button className="button button--secondary" onClick={reload}>Обновить</button>} />
    <div className="demo-banner"><strong>DEMO</strong><span>Результаты расследований сохраняются в БД. Симуляторы не меняют реальные Splunk, TheHive, MISP, учётные записи и хосты.</span></div>
    {dataset.error && <ErrorState message={dataset.error} retry={dataset.reload} />}
    <Panel title="Учебный набор Wazuh JSONL"><p className="panel-intro">Источник: {typeof datasetInfo.source === 'string' ? <a className="inline-link" href={datasetInfo.source} target="_blank" rel="noreferrer">llm-soc-alert-triage</a> : 'недоступен'} · commit {valueText(datasetInfo.commit)}</p><p className="panel-intro">{valueText(datasetInfo.note, 'Учебные метки используются только для сравнения.')}</p>
      {admin && <form className="dataset-form" onSubmit={importDataset}><Field label="Путь файла в наборе"><input required value={datasetPath} onChange={event => setDatasetPath(event.target.value)} /></Field><Field label="Wazuh JSONL, не более 2 МБ"><input key={datasetInputKey} required type="file" accept=".jsonl,.ndjson,application/x-ndjson" onChange={event => setDatasetFile(event.target.files?.[0] ?? null)} /></Field><button className="button button--secondary" disabled={!datasetFile || datasetMutation.busy}>{datasetMutation.busy ? 'Импорт…' : 'Импортировать файл'}</button></form>}
      <Notice flash={datasetMutation.flash} />{datasetResult && <Meta entries={[{ label: 'Записей прочитано', value: valueText(datasetResult.records) }, { label: 'Новых алертов', value: valueText(datasetResult.created_count) }, { label: 'Учебных меток TP / FP', value: `${valueText(asRecord(datasetResult.reference_labels).TP)} / ${valueText(asRecord(datasetResult.reference_labels).FP)}` }]} />}
    </Panel>
    {error && <ErrorState message={error} retry={reload} />}{loading && !data ? <Loading /> : <><Notice flash={flash} />{list.length ? <div className="scenario-grid">{list.map((item, index) => {
      const key = valueText(item.key, String(index))
      return <article className="scenario" key={key}><div className="scenario__top"><span className="scenario__key">{key}</span><Badge value={item.expected_verdict} /></div><h2>{valueText(item.title, 'Сценарий')}</h2><p>{valueText(item.description, 'Демонстрационный алерт')}</p><button className="button button--secondary" disabled={!!running} onClick={() => void run(key)}>{running === key ? 'Отправка…' : 'Отправить алерт'}</button></article>
    })}</div> : <Empty title="Сценарии не загружены" detail="Проверьте демонстрационные fixtures на сервере." />}</>}</>
}

function DeadLetters({ user }: { user: JsonRecord }) {
  const { data, loading, error, reload } = useResource('/dead-letters')
  const list = records(data)
  const admin = valueText(user.role).toLowerCase() === 'admin'
  const [running, setRunning] = useState('')
  const [flash, setFlash] = useState<Flash>(null)
  const retry = async (id: string) => {
    setRunning(id); setFlash(null)
    try {
      const result = asRecord(await api(`/dead-letters/${encodeURIComponent(id)}/retry`, { method: 'POST' }))
      setFlash({ kind: 'success', text: result.status === 'queued' ? 'Задача возвращена в очередь.' : 'Повтор сохранён; задача ожидает доступности очереди.' })
      reload()
    } catch (reason) { setFlash({ kind: 'error', text: reason instanceof Error ? reason.message : 'Повтор не выполнен' }) }
    finally { setRunning('') }
  }
  return <><PageHead title="Ошибочные задачи" description="Окончательно ошибочные задания сохраняются для ручного повтора после устранения причины." actions={<button className="button button--secondary" onClick={reload}>Обновить</button>} />{error && <ErrorState message={error} retry={reload} />}{loading && !data ? <Loading /> : <Panel title="Очередь ошибок"><Notice flash={flash} />{list.length ? <div className="table-wrap"><table><thead><tr><th>Задача</th><th>Алерт</th><th>Причина</th><th>Попытки</th><th>Время</th><th></th></tr></thead><tbody>{list.map((item, index) => {
    const id = valueText(item.id, String(index))
    return <tr key={id}><td className="number">{id}</td><td>{valueText(item.alert_id)}</td><td>{valueText(item.error)}</td><td className="number">{valueText(item.attempts)}</td><td className="number">{dateText(item.created_at)}</td><td>{admin && item.status === 'open' && <button className="button button--small button--secondary" disabled={!!running} onClick={() => void retry(id)}>{running === id ? 'Повтор…' : 'Повторить'}</button>}{item.status !== 'open' && <Badge value={item.status} />}</td></tr>
  })}</tbody></table></div> : <Empty title="Ошибочных задач нет" detail="Это состояние относится только к очереди ошибок; состояние поступления логов проверяется отдельно." />}</Panel>}</>
}

export default function App() {
  const [user, setUser] = useState<JsonRecord | null>(null)
  const [checking, setChecking] = useState(true)
  const [path, setPath] = useState(window.location.pathname)
  useEffect(() => {
    const change = () => setPath(window.location.pathname)
    window.addEventListener('popstate', change)
    return () => window.removeEventListener('popstate', change)
  }, [])
  useEffect(() => {
    if (!getToken()) { setChecking(false); return }
    api('/auth/me').then(result => setUser(asRecord(result))).catch(() => setToken(null)).finally(() => setChecking(false))
  }, [])
  useEffect(() => {
    const expired = () => setUser(null)
    window.addEventListener('soc-auth-expired', expired)
    return () => window.removeEventListener('soc-auth-expired', expired)
  }, [])
  const logout = () => { setToken(null); setUser(null); window.history.replaceState({}, '', '/'); setPath('/') }
  const page = useMemo(() => {
    if (!user) return null
    if (path === '/') return <Dashboard user={user} />
    if (path === '/alerts') return <Alerts user={user} />
    if (path.startsWith('/investigations/')) return <Investigation id={decodeURIComponent(path.split('/')[2] || '')} user={user} />
    if (path === '/contexts') return <Contexts user={user} />
    if (path === '/assets') return <Assets user={user} />
    if (path === '/integrations') return <Integrations user={user} />
    if (path === '/sla') return <Sla />
    if (path === '/shifts') return <Shifts user={user} />
    if (path === '/audit') return <Audit />
    if (path === '/settings' && user.role === 'admin') return <Settings user={user} />
    if (path === '/scenarios' && valueText(user.mode).toLowerCase() === 'demo') return <Scenarios user={user} />
    if (path === '/dead-letters') return <DeadLetters user={user} />
    return <><PageHead title="Страница не найдена" description="Проверьте адрес или вернитесь к рабочей очереди." /><Link className="button button--primary" to="/">К обзору</Link></>
  }, [path, user])
  if (checking) return <div className="startup"><Loading /></div>
  if (!user) return <Login onLogin={setUser} />
  return <Shell user={user} onLogout={logout}>{page}</Shell>
}
