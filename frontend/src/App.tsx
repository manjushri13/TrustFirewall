import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import './App.css'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'
type User = { user_id: string; full_name: string; email: string; provider: string; email_verified: boolean; created_at: string }
type Document = { document_id: string; filename: string; classification: string; status: string; findings: Finding[]; created_at: string }
type Finding = { filename: string; line_number: number; detected_text: string; severity: string; explanation: string; rule_id: string }
type Activity = { event_type?: string; decision?: string; status: string; detail?: string; created_at: string }
type Connection = { connection_id: string; provider: string; display_name: string; status: string }

const api = async (path: string, init?: RequestInit) => {
  const response = await fetch(`${API}${path}`, { ...init, credentials: 'include', headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) } })
  if (!response.ok) throw new Error((await response.json().catch(() => null))?.detail ?? 'Request failed.')
  return response.status === 204 ? null : response.json()
}

function Auth({ onLogin }: { onLogin: (user: User) => void }) {
  const [registering, setRegistering] = useState(false)
  const [form, setForm] = useState({ full_name: '', email: '', password: '' })
  const [error, setError] = useState('')
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setError('')
    try { const result = await api(registering ? '/api/auth/register' : '/api/auth/login', { method: 'POST', body: JSON.stringify(form) }); onLogin(result.user) }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to authenticate.') }
  }
  return <main className="auth-page"><div className="auth-card"><div className="logo">TRUST<span>FIREWALL</span></div><p className="kicker">AI SECURITY GATEWAY</p><h1>{registering ? 'Create your account' : 'Welcome back'}</h1><p className="muted">Monitor the security boundary around your connected AI agents.</p>
    <form onSubmit={submit}>{registering && <input required placeholder="Full name" value={form.full_name} onChange={e => setForm({ ...form, full_name: e.target.value })} />}<input required type="email" placeholder="Email address" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} /><input required minLength={12} type="password" placeholder="Password (12+ characters)" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} />{error && <p className="error">{error}</p>}<button className="primary">{registering ? 'Create account' : 'Sign in'}</button></form>
    {!registering && <button className="google-button" onClick={() => { window.location.href = `${API}/api/auth/google` }}>Continue with Google</button>}<button className="link" onClick={() => setRegistering(!registering)}>{registering ? 'Already have an account? Sign in' : 'Need an account? Register'}</button><p className="small">Google sign-in requires administrator OAuth configuration.</p>
  </div></main>
}

function App() {
  const [user, setUser] = useState<User | null>(null); const [section, setSection] = useState('overview'); const [documents, setDocuments] = useState<Document[]>([]); const [activity, setActivity] = useState<Activity[]>([]); const [connections, setConnections] = useState<Connection[]>([]); const [error, setError] = useState('')
  const load = async () => { try { const [docs, events, links] = await Promise.all([api('/api/documents/monitoring'), api('/api/audit'), api('/api/agents/connections')]); setDocuments(docs); setActivity(events); setConnections(links); setError('') } catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to load dashboard.') } }
  useEffect(() => { api('/api/auth/me').then(result => setUser(result.user)).catch(() => setUser(null)) }, [])
  useEffect(() => { if (user) void load() }, [user])
  if (!user) return <Auth onLogin={setUser} />
  const findings = documents.flatMap(document => document.findings.map(finding => ({ document, finding }))); const blocked = activity.filter(event => event.decision === 'block' || event.status === 'blocked').length
  const connect = async (provider: string) => { try { await api('/api/agents/connections', { method: 'POST', body: JSON.stringify({ provider, status: provider === 'custom' ? 'connected' : 'selected' }) }); await load() } catch (reason) { setError(reason instanceof Error ? reason.message : 'Connection failed.') } }
  const saveProfile = async (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); const data = new FormData(event.currentTarget); try { const result = await api('/api/users/me', { method: 'PATCH', body: JSON.stringify({ full_name: data.get('full_name') }) }); setUser(result.user) } catch (reason) { setError(reason instanceof Error ? reason.message : 'Profile update failed.') } }
  const changePassword = async (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); const data = new FormData(event.currentTarget); try { await api('/api/auth/change-password', { method: 'POST', body: JSON.stringify({ current_password: data.get('current_password'), new_password: data.get('new_password'), confirm_password: data.get('confirm_password') }) }); setError('Password changed. Other sessions were signed out.') } catch (reason) { setError(reason instanceof Error ? reason.message : 'Password change failed.') } }
  const logout = async () => { await api('/api/auth/logout', { method: 'POST' }); setUser(null) }
  return <div className="shell"><aside><div className="logo">TRUST<span>FIREWALL</span></div><p className="kicker">SECURITY MONITORING</p><nav>{[['overview', 'Overview'], ['documents', 'Documents'], ['threats', 'Detected threats'], ['activity', 'Recent activity'], ['agents', 'AI agent connections'], ['settings', 'Settings']].map(([key, label]) => <button className={section === key ? 'active' : ''} onClick={() => setSection(key)} key={key}>{label}</button>)}</nav><div className="profile"><strong>{user.full_name}</strong><small>{user.email}</small><button className="link" onClick={logout}>Sign out</button></div></aside><main className="content"><header><div><p className="kicker">TRUSTFIREWALL</p><h1>{section === 'overview' ? 'Security overview' : section === 'agents' ? 'AI agent connections' : section.replace('-', ' ')}</h1></div><span className="online">● Protection active</span></header>{error && <div className="notice error">{error}</div>}
    {section === 'overview' && <><div className="metrics"><Metric label="Documents received" value={documents.length} /><Metric label="Safe documents" value={documents.filter(d => d.classification === 'SAFE').length} tone="safe" /><Metric label="Detected threats" value={documents.filter(d => d.classification !== 'SAFE').length} tone="warn" /><Metric label="Actions blocked" value={blocked} tone="danger" /></div><div className="panel"><h2>Recent security activity</h2><ActivityList items={activity.slice(0, 8)} /></div></>}
    {section === 'documents' && <div className="panel"><h2>Documents received through integrations</h2>{documents.length ? documents.map(d => <div className="row" key={d.document_id}><strong>{d.filename}</strong><span>{d.classification} · {d.findings.length} findings</span><small>{new Date(d.created_at).toLocaleString()}</small></div>) : <Empty text="Documents appear here when they pass through a connected AI-agent integration." />}</div>}
    {section === 'threats' && <div className="panel"><h2>Detected threats</h2>{findings.length ? findings.map(({ document, finding }, index) => <details className="threat" key={`${document.document_id}-${index}`}><summary><strong>{finding.rule_id}</strong><span>{document.filename} · {finding.severity}</span></summary><p><b>Line {finding.line_number}</b> — {finding.detected_text}</p><p>{finding.explanation}</p></details>) : <Empty text="No threats detected in your monitored documents." />}</div>}
    {section === 'activity' && <div className="panel"><h2>Recent security activity</h2><ActivityList items={activity} /></div>}
    {section === 'agents' && <div className="panel"><h2>Connected AI agents</h2><p className="muted">Selecting an agent does not imply a connection. Only the custom MCP proxy is currently supported.</p>{['chatgpt', 'claude', 'gemini', 'custom'].map(provider => { const link = connections.find(c => c.provider === provider); return <div className="row" key={provider}><strong>{link?.display_name ?? provider}</strong><span className={`status ${link?.status ?? 'not selected'}`}>{link?.status ?? 'Not selected'}</span><button onClick={() => void connect(provider)}>{link ? 'Reconnect' : 'Select'}</button></div> })}</div>}
    {section === 'settings' && <div className="panel"><h2>Profile and settings</h2>{!user.email_verified && <div className="notice">Email verification is pending. Configure SMTP to send a verification email.</div>}<form onSubmit={saveProfile} className="profile-form"><label>Full name<input name="full_name" defaultValue={user.full_name} required /></label><button className="primary">Save profile</button></form>{user.provider === 'password' && <form onSubmit={changePassword} className="profile-form"><h3>Change password</h3><input name="current_password" type="password" placeholder="Current password" required /><input name="new_password" type="password" minLength={12} placeholder="New password (12+ characters)" required /><input name="confirm_password" type="password" minLength={12} placeholder="Confirm new password" required /><button className="primary">Change password</button></form>}{user.provider !== 'password' && <p className="muted">Password management is handled by your identity provider.</p>}<div className="setting"><span>Email</span><strong>{user.email}</strong></div><div className="setting"><span>Authentication</span><strong>{user.provider}</strong></div><div className="setting"><span>Account created</span><strong>{new Date(user.created_at).toLocaleDateString()}</strong></div></div>}
  </main></div>
}
const Metric = ({ label, value, tone = '' }: { label: string; value: number; tone?: string }) => <div className={`metric ${tone}`}><span>{label}</span><strong>{value}</strong></div>
const Empty = ({ text }: { text: string }) => <p className="empty">{text}</p>
const ActivityList = ({ items }: { items: Activity[] }) => items.length ? <div>{items.map((item, index) => <div className="row" key={`${item.created_at}-${index}`}><strong>{item.event_type ?? item.decision ?? 'Security event'}</strong><span>{item.detail ?? item.status}</span><small>{new Date(item.created_at).toLocaleString()}</small></div>)}</div> : <Empty text="No security activity recorded yet." />
export default App
