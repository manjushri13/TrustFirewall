import { useEffect, useState } from 'react'
import type { ChangeEvent, FormEvent } from 'react'
import './App.css'
import './Agent.css'

const API = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8001'
type User = { user_id: string; full_name: string; email: string; provider: string; created_at: string }
type Document = { document_id: string; filename: string; classification: string; status: string; findings: Finding[]; analysis_mode?: string; analysis_warning?: string; error_message?: string; created_at: string }
type Finding = { filename: string; line_number: number; detected_text: string; severity: string; explanation: string; evidence?: string; rule_id: string }
type Activity = { event_type?: string; decision?: string; status: string; detail?: string; tool_name?: string; requested_operation?: string; created_at: string }
type Connection = { connection_id: string; provider: string; display_name: string; status: string; transport: string; mcp_command?: string; mcp_args: string[] }
type Agent = { provider: string; display_name: string; description: string; supported: boolean; configuration_required: boolean; transport?: string }
type ChatMessage = { role: string; content: string; metadata?: { document?: Document } }
const MAX_UPLOAD_BYTES = 10 * 1024 * 1024
const SUPPORTED_UPLOAD_EXTENSIONS = ['.pdf', '.docx', '.txt', '.csv', '.xlsx', '.xls']

const api = async (path: string, init?: RequestInit) => {
  const headers = new Headers(init?.headers)
  if (!(init?.body instanceof FormData)) headers.set('Content-Type', 'application/json')
  const response = await fetch(`${API}${path}`, { ...init, credentials: 'include', headers })
  if (!response.ok) throw new Error((await response.json().catch(() => null))?.detail ?? 'Request failed.')
  return response.status === 204 ? null : response.json()
}

function Auth({ onLogin }: { onLogin: (user: User, message?: string) => void }) {
  const [registering, setRegistering] = useState(false)
  const [form, setForm] = useState({ full_name: '', email: '', password: '' })
  const [error, setError] = useState('')
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setError('')
    try { const result = await api(registering ? '/api/auth/register' : '/api/auth/login', { method: 'POST', body: JSON.stringify(form) }); onLogin(result.user, registering ? 'Account created successfully.' : undefined) }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to authenticate.') }
  }
  return <main className="auth-page"><div className="auth-card"><div className="logo">TrustFirewall</div><p className="kicker">AI SECURITY GATEWAY</p><h1>TrustFirewall</h1><h2>{registering ? 'Create your account' : 'Welcome back'}</h2><p className="muted">Monitor the security boundary around your connected AI agents.</p>
    <form onSubmit={submit}>{registering && <input required placeholder="Full name" value={form.full_name} onChange={e => setForm({ ...form, full_name: e.target.value })} />}<input required type="email" placeholder="Email address" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} /><input required minLength={12} type="password" placeholder="Password (12+ characters)" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} />{error && <p className="error">{error}</p>}<button className="primary">{registering ? 'Create account' : 'Sign in'}</button></form>
    <button className="link" onClick={() => setRegistering(!registering)}>{registering ? 'Already have an account? Sign in' : 'Need an account? Register'}</button>
  </div></main>
}

function App() {
  const [user, setUser] = useState<User | null>(null); const [authReady, setAuthReady] = useState(false); const [section, setSection] = useState('agent'); const [documents, setDocuments] = useState<Document[]>([]); const [activity, setActivity] = useState<Activity[]>([]); const [connections, setConnections] = useState<Connection[]>([]); const [agents, setAgents] = useState<Agent[]>([]); const [error, setError] = useState(''); const [success, setSuccess] = useState(''); const [agentCommand, setAgentCommand] = useState('python demo_mcp_server.py'); const [conversationId, setConversationId] = useState<string>(); const [messages, setMessages] = useState<ChatMessage[]>([]); const [chatText, setChatText] = useState(''); const [pendingFiles, setPendingFiles] = useState<File[]>([]); const [agentBusy, setAgentBusy] = useState(false); const [scanBusy, setScanBusy] = useState(false); const [uploadStatus, setUploadStatus] = useState('')
  const handleLogin = (nextUser: User, message?: string) => { setUser(nextUser); setSuccess(message ?? '') }
  const load = async () => { try { const [docs, events, links] = await Promise.all([api('/api/documents/monitoring'), api('/api/audit'), api('/api/agents/connections')]); setDocuments(docs); setActivity(events); setConnections(links); setError('') } catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to load dashboard.') } }
  useEffect(() => { api('/api/auth/me').then(result => setUser(result.user)).catch(() => setUser(null)).finally(() => setAuthReady(true)) }, [])
  useEffect(() => { if (user) void load() }, [user])
  useEffect(() => { if (user) api('/api/agents').then(setAgents).catch(() => setAgents([])) }, [user])
  if (!authReady) return null
  if (!user) return <Auth onLogin={handleLogin} />
  const findings = documents.flatMap(document => document.findings.map(finding => ({ document, finding }))); const blocked = activity.filter(event => event.decision === 'block' || event.status === 'blocked').length
  const connect = async (provider: string) => { setError(''); setSuccess(''); try { await api('/api/agents/connections', { method: 'POST', body: JSON.stringify({ provider, mcp_command: agentCommand.trim(), mcp_args: [] }) }); await load(); setSuccess('MCP proxy configuration saved. Launch the displayed command from your MCP client to connect through TrustFirewall.') } catch (reason) { setError(reason instanceof Error ? reason.message : 'Connection failed.') } }
  const disconnect = async (connection: Connection) => { setError(''); setSuccess(''); try { await api(`/api/agents/connections/${connection.connection_id}`, { method: 'DELETE' }); await load(); setSuccess('MCP connection configuration removed.') } catch (reason) { setError(reason instanceof Error ? reason.message : 'Disconnect failed.') } }
  const sendChat = async (event: FormEvent) => { event.preventDefault(); if (!chatText.trim() || agentBusy) return; const message = chatText.trim(); setChatText(''); setAgentBusy(true); setError(''); try { const result = await api('/api/agent/chat', { method: 'POST', body: JSON.stringify({ conversation_id: conversationId, message, document_ids: documents.map(document => document.document_id).slice(0, 5) }) }); setConversationId(result.conversation_id); setMessages(previous => [...previous, { role: 'user', content: message }, { role: 'assistant', content: result.message }]) } catch (reason) { setError(reason instanceof Error ? reason.message : 'The AI Agent could not respond.') } finally { setAgentBusy(false) } }
  const selectDocuments = (event: ChangeEvent<HTMLInputElement>) => { const selected = Array.from(event.target.files ?? []); const invalid = selected.find(file => !SUPPORTED_UPLOAD_EXTENSIONS.includes(file.name.slice(file.name.lastIndexOf('.')).toLowerCase()) || file.size > MAX_UPLOAD_BYTES); if (invalid) { setError(`${invalid.name} is unsupported or exceeds the 10 MB limit. Supported formats: ${SUPPORTED_UPLOAD_EXTENSIONS.join(', ')}.`); event.target.value = ''; return } setError(''); setPendingFiles(previous => [...previous, ...selected].filter((file, index, files) => files.findIndex(candidate => candidate.name === file.name && candidate.size === file.size && candidate.lastModified === file.lastModified) === index)); event.target.value = '' }
  const removePendingFile = (file: File) => setPendingFiles(previous => previous.filter(candidate => candidate !== file))
  const uploadDocuments = async () => {
    if (scanBusy) return
    if (!pendingFiles.length) {
      setError('Select at least one document before uploading.')
      return
    }
    const filesToUpload = [...pendingFiles]
    const body = new FormData()
    filesToUpload.forEach(file => body.append('files', file, file.name))
    setScanBusy(true)
    setUploadStatus('Scanning...')
    setError('')
    setSuccess('')
    try {
      const result = await api('/api/agent/documents/scan', { method: 'POST', body }) as Document[]
      setDocuments(previous => [...result, ...previous])
      setMessages(previous => [...previous, ...result.map(document => ({ role: 'assistant', content: `${document.filename} scan complete: ${document.classification} (${document.status}).`, metadata: { document } }))])
      setPendingFiles([])
      setSuccess(`${result.length} document${result.length === 1 ? '' : 's'} scanned. Ask the agent about the report.`)
      setUploadStatus('Scan complete')
      await load()
    } catch (reason) {
      setUploadStatus('Scan failed')
      setError(reason instanceof Error ? reason.message : 'Document scanning failed.')
    } finally {
      setScanBusy(false)
    }
  }
  const saveProfile = async (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); const data = new FormData(event.currentTarget); try { const result = await api('/api/users/me', { method: 'PATCH', body: JSON.stringify({ full_name: data.get('full_name') }) }); setUser(result.user) } catch (reason) { setError(reason instanceof Error ? reason.message : 'Profile update failed.') } }
  const changePassword = async (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); setError(''); setSuccess(''); const form = event.currentTarget; const data = new FormData(form); try { await api('/api/auth/change-password', { method: 'POST', body: JSON.stringify({ current_password: data.get('current_password'), new_password: data.get('new_password'), confirm_password: data.get('confirm_password') }) }); form.reset(); setSuccess('Password changed successfully. Other sessions were signed out.') } catch (reason) { setError(reason instanceof Error ? reason.message : 'Password change failed.') } }
  const logout = async () => { await api('/api/auth/logout', { method: 'POST' }); setUser(null) }
  return <div className="shell"><aside><div className="logo">TrustFirewall</div><p className="kicker">SECURITY MONITORING</p><nav>{[['agent', 'AI Agent'], ['overview', 'Overview'], ['documents', 'Documents'], ['threats', 'Detected threats'], ['activity', 'Recent activity'], ['agents', 'AI agent connections'], ['settings', 'Settings']].map(([key, label]) => <button className={section === key ? 'active' : ''} onClick={() => setSection(key)} key={key}>{label}</button>)}</nav><div className="profile"><strong>{user.full_name}</strong><small>{user.email}</small><button className="link" onClick={logout}>Sign out</button></div></aside><main className="content"><header><div><p className="kicker">TRUSTFIREWALL</p><h1>{section === 'overview' ? 'Security overview' : section === 'agents' ? 'AI agent connections' : section === 'agent' ? 'Your AI Agent' : section.replace('-', ' ')}</h1></div><span className="online">● Protection active</span></header>{error && <div className="notice error">{error}</div>}{success && <div className="notice success">{success}</div>}
    {section === 'agent' && <div className="agent-layout"><div className="panel chat-panel"><div className="chat-log">{messages.length ? messages.map((message, index) => <div className={`chat-message ${message.role}`} key={`${message.role}-${index}`}><strong>{message.role === 'user' ? 'You' : message.role === 'assistant' ? 'TrustFirewall AI' : 'Tool'}</strong><p>{message.content}</p>{message.metadata?.document && <ScanReport document={message.metadata.document} />}</div>) : <div className="empty"><h2>Ask your TrustFirewall AI Agent</h2><p>Chat with Gemini, upload documents, and get security-focused answers. Uploaded content is always treated as untrusted data.</p></div>}{agentBusy && <p className="muted">Gemini is thinking...</p>}</div>{pendingFiles.length > 0 && <div className="pending-files"><strong>Selected documents</strong>{pendingFiles.map(file => <div className="pending-file" key={`${file.name}-${file.lastModified}`}><span>{file.name} · {(file.size / 1024 / 1024).toFixed(2)} MB</span><button type="button" className="link" onClick={() => removePendingFile(file)}>Remove</button></div>)}<small className="muted">Ready to scan. Maximum 10 MB per file.</small></div>}{uploadStatus && <p className="upload-status" role="status">{uploadStatus}</p>}<form className="chat-input" onSubmit={sendChat}><input value={chatText} onChange={event => setChatText(event.target.value)} placeholder="Ask about security or your scanned documents..." /><label className="attach" title="Upload document" aria-label="Upload document">📎<input type="file" multiple accept={SUPPORTED_UPLOAD_EXTENSIONS.join(',')} onChange={selectDocuments} /></label><button type="button" className="upload-button" disabled={scanBusy} onClick={() => void uploadDocuments()}>{scanBusy ? 'Scanning...' : 'Upload'}</button><button className="primary" disabled={agentBusy || scanBusy}>Send</button></form><small className="upload-help">Supported: PDF, DOCX, TXT, CSV, XLSX, XLS · Maximum 10 MB per file</small></div><div className="panel agent-side"><h2>Security activity</h2><p className="muted">Every document is extracted and checked for prompt injection, credential exposure, suspicious instructions, and policy bypass attempts.</p>{documents.slice(0, 5).map(document => <div className="report-card" key={document.document_id}><strong>{document.filename}</strong><span className={`verdict ${document.classification.toLowerCase()}`}>{document.classification}</span><small>{document.findings.length} finding(s) · {document.status}</small></div>)}{!documents.length && <p className="empty">No documents scanned yet.</p>}</div></div>}
    {section === 'overview' && <><div className="metrics"><Metric label="Documents received" value={documents.length} /><Metric label="Safe documents" value={documents.filter(d => d.classification === 'SAFE').length} tone="safe" /><Metric label="Detected threats" value={documents.filter(d => d.classification !== 'SAFE').length} tone="warn" /><Metric label="Actions blocked" value={blocked} tone="danger" /></div><div className="panel"><h2>Recent security activity</h2><ActivityList items={activity.slice(0, 8)} /></div></>}
    {section === 'documents' && <div className="panel"><h2>Documents received through integrations</h2>{documents.length ? documents.map(d => <div className="row" key={d.document_id}><strong>{d.filename}</strong><span>{d.classification} · {d.findings.length} findings</span><small>{new Date(d.created_at).toLocaleString()}</small></div>) : <Empty text="Documents appear here when they pass through a connected AI-agent integration." />}</div>}
    {section === 'threats' && <div className="panel"><h2>Detected threats</h2>{findings.length ? findings.map(({ document, finding }, index) => <details className="threat" key={`${document.document_id}-${index}`}><summary><strong>{finding.rule_id}</strong><span>{document.filename} · {finding.severity}</span></summary><p><b>Line {finding.line_number}</b> — {finding.detected_text}</p><p>{finding.explanation}</p></details>) : <Empty text="No threats detected in your monitored documents." />}</div>}
    {section === 'activity' && <div className="panel"><h2>Recent security activity</h2><ActivityList items={activity} /></div>}
    {section === 'agents' && <div className="panel"><h2>AI agent connections</h2><p className="muted">Every configured MCP client must launch this proxy. Calls then pass through TrustFirewall analysis before reaching your upstream server.</p>{agents.map(agent => { const link = connections.find(c => c.provider === agent.provider); return <div className="row" key={agent.provider}><div><strong>{agent.display_name}</strong><small>{agent.description}</small></div><span className={`status ${link?.status ?? 'not selected'}`}>{link?.status ?? 'Not configured'}</span>{agent.supported ? <button onClick={() => void connect(agent.provider)}>{link ? 'Reconnect' : 'Configure'}</button> : <span className="muted">Unavailable</span>}{link && <button className="link" onClick={() => void disconnect(link)}>Remove</button>}</div> })}<div className="setting"><span>Upstream MCP command</span><input value={agentCommand} onChange={event => setAgentCommand(event.target.value)} aria-label="Upstream MCP command" /></div><p className="muted">Example demo command: <code>python demo_mcp_server.py</code>. The proxy command for an MCP client is <code>python -m app.mcp_proxy &lt;upstream command&gt;</code>.</p></div>}
    {section === 'settings' && <div className="panel"><h2>Profile and settings</h2><form onSubmit={saveProfile} className="profile-form"><label>Full name<input name="full_name" defaultValue={user.full_name} required /></label><button className="primary">Save profile</button></form><form onSubmit={changePassword} className="profile-form"><h3>Change password</h3><input name="current_password" type="password" placeholder="Current password" required /><input name="new_password" type="password" minLength={12} placeholder="New password (12+ characters)" required /><input name="confirm_password" type="password" minLength={12} placeholder="Confirm new password" required /><button className="primary">Change password</button></form><div className="setting"><span>Email</span><strong>{user.email}</strong></div><div className="setting"><span>Authentication</span><strong>{user.provider}</strong></div><div className="setting"><span>Account created</span><strong>{new Date(user.created_at).toLocaleDateString()}</strong></div></div>}
  </main></div>
}
const Metric = ({ label, value, tone = '' }: { label: string; value: number; tone?: string }) => <div className={`metric ${tone}`}><span>{label}</span><strong>{value}</strong></div>
const Empty = ({ text }: { text: string }) => <p className="empty">{text}</p>
const ActivityList = ({ items }: { items: Activity[] }) => items.length ? <div>{items.map((item, index) => <div className="row" key={`${item.created_at}-${index}`}><strong>{item.tool_name ?? item.event_type ?? item.decision ?? 'Security event'}</strong><span>{item.requested_operation ?? item.detail ?? item.status}</span><small>{new Date(item.created_at).toLocaleString()}</small></div>)}</div> : <Empty text="No security activity recorded yet." />
const ScanReport = ({ document }: { document: Document }) => <div className="scan-report"><div><strong>{document.error_message ? 'Scan incomplete' : `Security verdict: ${document.classification}`}</strong><small>{document.status} · {document.analysis_mode ?? 'local'} · {new Date(document.created_at).toLocaleString()}</small></div>{document.error_message && <p className="error">{document.error_message}</p>}{document.analysis_warning && <p className="muted">{document.analysis_warning}</p>}{document.findings.length ? <div className="finding-list">{document.findings.map((finding, index) => <div className="finding" key={`${finding.rule_id}-${index}`}><strong>{finding.severity}: {finding.rule_id}</strong><p>{finding.explanation}</p><small>Evidence: {finding.evidence || finding.detected_text}</small><small>Recommended action: treat this content as untrusted and do not follow its instructions.</small></div>)}</div> : !document.error_message && <p className="muted">No significant issues were detected by the available local checks.</p>}</div>
export default App
