'use client'

import { useEffect, useRef, useState } from 'react'
import { ArrowRight, Eye, FileCode2, FilePenLine, FolderOpen, Menu, ScanSearch, ShieldCheck, Trash2, Upload, X } from 'lucide-react'
import { authClient, useSession } from '@/lib/auth-client'
import { deleteAccount, deleteCodeFile, incrementSiteVisit, listFiles, saveCodeFile } from '@/app/actions/files'
import { getLeaderboard, getProfile, getProfileStats, updateProfile } from '@/app/actions/leaderboard'
import { getTokenBalance, obfuscateCode } from '@/app/actions/obfuscator'

type FileItem = { name: string; accesses: number; content: string }
const initialFiles: FileItem[] = [
  { name: 'middleware.ts', accesses: 1248, content: 'export function middleware(request) {\n  return NextResponse.next()\n}' },
  { name: 'route-handler.ts', accesses: 486, content: 'export async function GET() {\n  return Response.json({ ok: true })\n}' },
]

function Brand() {
  return <div className="brand-mark" aria-label="Secrovia"><ShieldCheck size={21} strokeWidth={2.2} /><span>SECROVIA</span></div>
}

function AmbientVideo() {
  const videoRef = useRef<HTMLVideoElement>(null)

  useEffect(() => {
    const keepPlaying = () => {
      const video = videoRef.current
      if (!video) return
      video.muted = false
      void video.play().catch(() => undefined)
    }
    const resumeIfPaused = () => {
      const video = videoRef.current
      if (video && !video.ended) void video.play().catch(() => undefined)
    }

    // A user gesture enables audio; keeping this in capture phase means clicks
    // on buttons, cards, and editors cannot accidentally interrupt the backdrop.
    document.addEventListener('pointerdown', keepPlaying, true)
    document.addEventListener('keydown', keepPlaying, true)
    document.addEventListener('visibilitychange', resumeIfPaused)
    const video = videoRef.current
    video?.addEventListener('pause', resumeIfPaused)
    return () => {
      document.removeEventListener('pointerdown', keepPlaying, true)
      document.removeEventListener('keydown', keepPlaying, true)
      document.removeEventListener('visibilitychange', resumeIfPaused)
      video?.removeEventListener('pause', resumeIfPaused)
    }
  }, [])

  return <>
    <video ref={videoRef} className="ambient-video" autoPlay muted loop playsInline preload="auto" aria-hidden="true">
      <source src="https://files.catbox.moe/87eeqs.mp4" type="video/mp4" />
    </video>
    <div className="ambient-video-overlay" aria-hidden="true" />
  </>
}

function AuthScreen({ onAuth }: { onAuth: () => void }) {
  const [mode, setMode] = useState<'login' | 'signup'>('login')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [message, setMessage] = useState('')
  const [rememberMe, setRememberMe] = useState(true)
  async function submit(event: React.FormEvent) {
    event.preventDefault()
    if (mode === 'signup' && password !== confirm) return setMessage('Mật khẩu nhập lại không khớp')
    const email = `${username.trim().toLowerCase()}@secrovia.local`
    const result = mode === 'login' ? await authClient.signIn.email({ email, password, rememberMe }) : await authClient.signUp.email({ email, password, name: username.trim() })
    if (result.error) return setMessage('Tên tài khoản hoặc mật khẩu không hợp lệ')
    setMessage('')
    onAuth()
  }
  return <main className="auth-page"><AmbientVideo /><div className="auth-panel"><Brand /><div className="auth-heading"><p className="eyebrow">Protected code storage</p><h1>{mode === 'login' ? 'Welcome back.' : 'Create your account.'}</h1><p>{mode === 'login' ? 'Sign in to continue to your workspace.' : 'Keep every code link under your control.'}</p></div><div className="auth-tabs"><button className={mode === 'login' ? 'active' : ''} onClick={() => setMode('login')}>Login</button><button className={mode === 'signup' ? 'active' : ''} onClick={() => setMode('signup')}>Sign Up</button></div><form onSubmit={submit} className="auth-form"><label>Username<input value={username} onChange={(event) => setUsername(event.target.value)} placeholder="Enter your username" required /></label><label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Enter your password" required /></label>{mode === 'login' && <label className="remember-option"><input type="checkbox" checked={rememberMe} onChange={(event) => setRememberMe(event.target.checked)} /> Remember me on this device</label>}{mode === 'signup' && <label>Confirm password<input type="password" value={confirm} onChange={(event) => setConfirm(event.target.value)} placeholder="Repeat your password" required /></label>}{message && <p className="form-error">{message}</p>}<button className="primary-button" type="submit">{mode === 'login' ? 'Login' : 'Sign Up'}</button></form><p className="secure-note"><ShieldCheck size={14} /> Your code stays protected.</p></div></main>
}

function AccountMenu({ profileName, menuOpen, setMenuOpen, onProfile, onLogout }: { profileName: string; menuOpen: boolean; setMenuOpen: (open: boolean) => void; onProfile: () => void; onLogout: () => void }) {
  return <div className="account-menu-wrap"><div className="topbar-right"><span>{profileName || 'Account'}</span><button className="menu-button" aria-label="Open account menu" aria-expanded={menuOpen} onClick={() => setMenuOpen(!menuOpen)}><Menu size={23} /></button></div>{menuOpen && <div className="menu-popover"><button onClick={onProfile}>Profile &amp; credit</button><button onClick={onLogout}>Log out</button></div>}</div>
}

function Workspace() {
  const [fileName, setFileName] = useState('')
  const [profileName, setProfileName] = useState('')
  const [profileImage, setProfileImage] = useState<string | null>(null)
  const [avatarZoom, setAvatarZoom] = useState(1)
  const [code, setCode] = useState('')
  const [files, setFiles] = useState(initialFiles)
  const [fileSearch, setFileSearch] = useState('')
  const [obfuscatorLevel, setObfuscatorLevel] = useState<'debug' | 'normal' | 'maximum'>('normal')
  const [obfuscating, setObfuscating] = useState(false)
  const [tokenBalance, setTokenBalance] = useState(0)
  const [obfuscatorMessage, setObfuscatorMessage] = useState('')
  const [menuOpen, setMenuOpen] = useState(false)
  const [view, setView] = useState<'dashboard' | 'workspace' | 'deobfuscator' | 'profile' | 'leaderboard'>('dashboard')
  const [deobfuscatorInput, setDeobfuscatorInput] = useState('')
  const [deobfuscatorOutput, setDeobfuscatorOutput] = useState('')
  const [deobfuscating, setDeobfuscating] = useState(false)
  const [deobfuscatorError, setDeobfuscatorError] = useState('')
  const [leaders, setLeaders] = useState<Array<{ name: string | null; image: string | null; accesses: number }>>([])
  const [profileStats, setProfileStats] = useState({ fileCount: 0, mostAccessedName: 'None yet' })
  const [newPassword, setNewPassword] = useState('')
  const [currentPassword, setCurrentPassword] = useState('')
  const [profileMessage, setProfileMessage] = useState('')
  const [modal, setModal] = useState<'delete' | null>(null)
  const [deleteName, setDeleteName] = useState('')
  const [deleteUsername, setDeleteUsername] = useState('')
  const [deletePassword, setDeletePassword] = useState('')
  const [deleteError, setDeleteError] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)
  useEffect(() => { void getProfile().then((profile) => { setProfileName(profile.name); setProfileImage(profile.image) }).catch(() => undefined); void getProfileStats().then(setProfileStats).catch(() => undefined); void getLeaderboard().then(setLeaders).catch(() => undefined); void getTokenBalance().then(setTokenBalance).catch(() => undefined); void incrementSiteVisit(); void listFiles().then((saved) => { if (saved.length) setFiles(saved.map((file) => ({ name: file.name, accesses: file.rawAccessCount, content: file.content }))) }).catch(() => undefined) }, [])
  function uploadFile(event: React.ChangeEvent<HTMLInputElement>) { const file = event.target.files?.[0]; if (!file) return; setFileName(file.name); const reader = new FileReader(); reader.onload = () => setCode(String(reader.result ?? '')); reader.readAsText(file) }
  async function logout() {
    await authClient.signOut()
    window.location.reload()
  }
  async function runDeobfuscator() {
    if (!deobfuscatorInput.trim() || deobfuscating) return
    setDeobfuscating(true)
    setDeobfuscatorError('')
    try {
      const response = await fetch('/api/deobfuscator.py', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: deobfuscatorInput }) })
      const result = await response.json() as { code?: string; error?: string }
      if (!response.ok || !result.code) throw new Error(result.error ?? 'Deobfuscation failed')
      setDeobfuscatorOutput(result.code)
    } catch (error) {
      setDeobfuscatorError(error instanceof Error ? error.message : 'Deobfuscation failed')
    } finally {
      setDeobfuscating(false)
    }
  }
  async function saveFile() { if (!fileName.trim() || !code.trim()) return; await saveCodeFile(fileName, code); setFiles((current) => { const name = fileName.trim(); const existing = current.some((file) => file.name === name); return existing ? current.map((file) => file.name === name ? { ...file, content: code } : file) : [{ name, content: code, accesses: 0 }, ...current] }) }
  async function runObfuscator() { if (!code.trim() || obfuscating) return; setObfuscating(true); setObfuscatorMessage(''); try { const output = await obfuscateCode(code, obfuscatorLevel); setCode(output); if (obfuscatorLevel === 'maximum') setTokenBalance(await getTokenBalance()); setObfuscatorMessage('Obfuscation complete') } catch (error) { setObfuscatorMessage(error instanceof Error ? error.message : 'Obfuscation failed') } finally { setObfuscating(false) } }
  function editFile(file: FileItem) { setFileName(file.name); setCode(file.content); window.scrollTo({ top: 0, behavior: 'smooth' }) }
  const visibleFiles = files.filter((file) => file.name.toLowerCase().includes(fileSearch.trim().toLowerCase()))
  async function prepareAvatar(source: string, zoom: number) {
    const image = new Image()
    image.src = source
    await new Promise<void>((resolve, reject) => { image.onload = () => resolve(); image.onerror = reject })
    const size = 256
    const canvas = document.createElement('canvas')
    canvas.width = size
    canvas.height = size
    const context = canvas.getContext('2d')
    if (!context) return source
    const scale = Math.max(size / image.width, size / image.height) * zoom
    const width = image.width * scale
    const height = image.height * scale
    context.drawImage(image, (size - width) / 2, (size - height) / 2, width, height)
    return canvas.toDataURL('image/jpeg', 0.82)
  }
  if (view === 'dashboard') return <main className="workspace-page dashboard-page"><AmbientVideo /><header className="topbar"><Brand /><AccountMenu profileName={profileName} menuOpen={menuOpen} setMenuOpen={setMenuOpen} onProfile={() => { setView('profile'); setMenuOpen(false) }} onLogout={logout} /></header><section className="dashboard-shell"><p className="eyebrow">Workspace</p><h1>Choose a workspace</h1><p className="dashboard-intro">Manage your code storage or inspect Lua scripts with Secrovia tools.</p><div className="dashboard-grid"><button className="dashboard-card" onClick={() => setView('workspace')}><span className="dashboard-icon"><FolderOpen size={22} /></span><strong>Storage code</strong><span>Save, edit and share your code files.</span><b>Open storage <ArrowRight size={16} /></b></button><button className="dashboard-card" onClick={() => setView('deobfuscator')}><span className="dashboard-icon"><ScanSearch size={22} /></span><strong>Deobfuscator Lua <em>Beta</em></strong><span>Paste or upload Lua code to inspect it.</span><b>Open tool <ArrowRight size={16} /></b></button></div></section></main>
  if (view === 'deobfuscator') return <main className="workspace-page settings-page"><AmbientVideo /><header className="topbar"><div className="topbar-left"><button className="back-button" onClick={() => setView('dashboard')} aria-label="Back">&lt;</button><Brand /></div><AccountMenu profileName={profileName} menuOpen={menuOpen} setMenuOpen={setMenuOpen} onProfile={() => { setView('profile'); setMenuOpen(false) }} onLogout={logout} /></header><section className="deobfuscator-shell"><p className="eyebrow">Developer tool · Beta</p><h1>Lua Deobfuscator</h1><div className="deobfuscator-grid"><div className="deobfuscator-pane"><div className="pane-heading"><strong>Input code</strong><label className="secondary-button upload-profile">Upload file<input type="file" accept=".lua,.txt" hidden onChange={(event) => { const file = event.target.files?.[0]; if (!file) return; const reader = new FileReader(); reader.onload = () => setDeobfuscatorInput(typeof reader.result === 'string' ? reader.result : ''); reader.readAsText(file) }} /></label></div><textarea className="code-editor deobfuscator-editor" value={deobfuscatorInput} onChange={(event) => setDeobfuscatorInput(event.target.value)} placeholder="Paste Lua code here..." /></div><button className="primary-button deobfuscate-button" onClick={runDeobfuscator} disabled={!deobfuscatorInput.trim() || deobfuscating}>{deobfuscating ? 'Deobfuscating...' : 'Deobfuscator'}</button><div className="deobfuscator-pane"><div className="pane-heading"><strong>Output code</strong></div><textarea className="code-editor deobfuscator-editor" value={deobfuscatorOutput} readOnly placeholder="Deobfuscated output will appear here..." /></div></div>{deobfuscatorError && <p className="form-error">{deobfuscatorError}</p>}</section></main>
  if (view === 'leaderboard') return <main className="workspace-page settings-page"><AmbientVideo /><header className="topbar"><Brand /><button className="back-button" onClick={() => setView('workspace')} aria-label="Back">&lt;</button></header><section className="settings-shell"><p className="eyebrow">Community</p><h1>Leaderboard</h1><div className="leaderboard-card">{leaders.slice(0, 10).map((leader, index) => <div className="leaderboard-row" key={`${leader.name ?? 'user'}-${index}`}><span className="leaderboard-rank">{index + 1}</span><div className="leaderboard-avatar">{leader.image ? <img src={leader.image} alt="" /> : (leader.name ?? '?').slice(0, 1).toUpperCase()}</div><strong>{leader.name ?? 'Unknown'}</strong><span className="leaderboard-accesses">{Number(leader.accesses).toLocaleString()} accesses</span></div>)}</div></section></main>
  if (view === 'profile') return <main className="workspace-page settings-page"><AmbientVideo /><header className="topbar"><Brand /><button className="back-button" onClick={() => setView('workspace')} aria-label="Back">&lt;</button></header><section className="settings-shell"><p className="eyebrow">Account</p><h1>Profile</h1><div className="profile-settings-card"><div className="profile-avatar-large">{profileImage ? <img src={profileImage} alt="Current avatar" style={{ transform: `scale(${avatarZoom})` }} /> : <span>{profileName.slice(0, 1).toUpperCase()}</span>}</div><label className="secondary-button upload-profile"><Upload size={16} /> Upload new avatar<input type="file" accept="image/*" hidden onChange={(event) => { const file = event.target.files?.[0]; if (!file || file.size > 8 * 1024 * 1024) return; const reader = new FileReader(); reader.onload = () => { setProfileImage(typeof reader.result === 'string' ? reader.result : ''); setAvatarZoom(1) }; reader.readAsDataURL(file) }} /></label>{profileImage && <label className="avatar-zoom">Image size<input type="range" min="1" max="2.5" step="0.05" value={avatarZoom} onChange={(event) => setAvatarZoom(Number(event.target.value))} /></label>}<label>Username<input value={profileName} onChange={(event) => setProfileName(event.target.value)} /></label><button className="primary-button" onClick={async () => { const savedImage = profileImage ? await prepareAvatar(profileImage, avatarZoom) : undefined; try { const saved = await updateProfile(profileName, savedImage); setProfileName(saved.name); setProfileImage(saved.image ?? null); setAvatarZoom(1); setProfileMessage('Profile saved') } catch { setProfileMessage('Không thể lưu profile, vui lòng thử lại') } }}>Save name</button><div className="password-change"><label>New password<input type="password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} /></label><label>Current password<input type="password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} /></label><button className="secondary-button" onClick={async () => { if (newPassword.length < 8) return setProfileMessage('Mật khẩu mới phải có ít nhất 8 ký tự'); if (!currentPassword) return setProfileMessage('Nhập mật khẩu hiện tại'); const result = await authClient.changePassword({ newPassword, currentPassword, revokeOtherSessions: false }); if (result.error) return setProfileMessage('Mật khẩu hiện tại không đúng hoặc đổi mật khẩu thất bại'); setNewPassword(''); setCurrentPassword(''); setProfileMessage('Password changed successfully') }}>Change password</button></div><div className="profile-stats"><div><span>Files created</span><strong>{profileStats.fileCount}</strong></div><div><span>Most accessed file</span><strong>{profileStats.mostAccessedName}</strong></div></div>{profileMessage && <p className="form-success">{profileMessage}</p>}</div></section></main>
  return <main className="workspace-page"><AmbientVideo /><header className="topbar"><div className="topbar-left"><button className="back-button storage-back" onClick={() => setView('dashboard')} aria-label="Back to dashboard">&lt;</button><Brand /></div><div className="topbar-right">{profileImage ? <img className="header-avatar" src={profileImage ?? undefined} alt="Account avatar" /> : <span className="online-dot" />}<span>{profileName || 'Account'}</span><button className="menu-button" aria-label="Open menu" onClick={() => setMenuOpen(!menuOpen)}><Menu size={23} /></button></div></header>{menuOpen && <div className="menu-popover"><button onClick={() => { setView('profile'); setMenuOpen(false) }}>Profile</button><button onClick={() => { setView('leaderboard'); setMenuOpen(false) }}>Leaderboard</button><div className="token-menu-item"><span>?/token</span><strong>{tokenBalance}</strong></div></div>}<section className="workspace-shell"><div className="workspace-heading"><div><p className="eyebrow">Private workspace</p><h1>Code vault</h1></div><span className="status-pill">Protected</span></div><div className="editor-card"><div className="editor-toolbar"><label className="file-name-input"><FileCode2 size={17} /><input value={fileName} onChange={(event) => setFileName(event.target.value)} placeholder="Code file name" /></label><input ref={inputRef} type="file" accept=".js,.jsx,.ts,.tsx,.json,.css,.html,.py,.txt" onChange={uploadFile} hidden /><button className="secondary-button" onClick={() => inputRef.current?.click()}><Upload size={16} /> Upload file code</button></div><p className="editor-hint">Paste code or upload a file. Save changes when you are ready.</p><textarea className="code-editor" value={code} onChange={(event) => setCode(event.target.value)} placeholder="Paste your code here..." spellCheck={false} /><div className="editor-actions"><button className="ghost-button" onClick={() => { setCode(''); setFileName('') }}>Clear</button><button className="primary-button compact" onClick={saveFile} disabled={!fileName.trim() || !code.trim()}>Save Code</button><select className="obfuscator-select" value={obfuscatorLevel} onChange={(event) => setObfuscatorLevel(event.target.value as typeof obfuscatorLevel)} aria-label="Obfuscator level"><option value="debug">Debug</option><option value="normal">Normal</option><option value="maximum">Maximum · {tokenBalance} token</option></select><button className="secondary-button compact" onClick={runObfuscator} disabled={!code.trim() || obfuscating}>{obfuscating ? 'Obfuscating...' : 'Obfuscator'}</button>{obfuscatorMessage && <span className="obfuscator-message">{obfuscatorMessage}</span>}</div></div><div className="files-heading"><div><h2>Your code files</h2><span>{visibleFiles.length} of {files.length} files</span></div><label className="file-search"><Eye size={15} /><input value={fileSearch} onChange={(event) => setFileSearch(event.target.value)} placeholder="Search files" aria-label="Search files" /></label></div><div className="file-list">{visibleFiles.map((file) => <article className="file-row" key={file.name}><div className="file-identity"><div className="file-icon"><FileCode2 size={18} /></div><div><strong>{file.name}</strong><small>Raw link protected · <button type="button" className="inline-copy" onClick={() => navigator.clipboard.writeText(`https://secrovia.vercel.app/raw/${encodeURIComponent(file.name)}`)}>Copy raw</button> <a href={`/raw/${encodeURIComponent(file.name)}`} target="_blank" rel="noreferrer">Open raw link</a></small></div></div><div className="file-actions"><button aria-label={`Edit ${file.name}`} onClick={() => editFile(file)}><FilePenLine size={17} /></button><button aria-label={`Delete ${file.name}`} onClick={() => { setDeleteName(file.name); setModal('delete') }}><Trash2 size={17} /></button><button className="copy-button" onClick={() => navigator.clipboard?.writeText(`/raw/${file.name}`)}>Copy full raw URL</button><span className="access-count"><Eye size={16} /> {file.accesses.toLocaleString()}</span></div></article>)}</div></section>{modal === 'delete' && <div className="modal-backdrop"><div className="modal-card"><button className="modal-close" onClick={() => setModal(null)} aria-label="Close"><X size={18} /></button><p className="eyebrow">Permanent action</p><h2>Delete Account</h2><p className="modal-copy">This permanently deletes your account and all saved code files.</p><form className="auth-form" onSubmit={async (event) => { event.preventDefault(); try { await deleteAccount(deleteUsername, deletePassword); await authClient.signOut(); window.location.reload() } catch { setDeleteError('Name or password is incorrect') } }}><label>Username<input value={deleteUsername} onChange={(event) => setDeleteUsername(event.target.value)} required /></label><label>Password<input type="password" value={deletePassword} onChange={(event) => setDeletePassword(event.target.value)} required /></label>{deleteError && <p className="form-error">{deleteError}</p>}<button className="danger-button" type="submit">Delete Account</button></form></div></div>}{modal && <div className="modal-backdrop"><div className="modal-card"><button className="modal-close" onClick={() => setModal(null)}><X size={18} /></button>{modal === 'delete' && <><p className="eyebrow">Delete file</p><h2>Are you sure?</h2><div className="modal-actions"><button className="ghost-button" onClick={() => setModal(null)}>No</button><button className="danger-button" onClick={async () => { const file = files.find((item) => item.name === deleteName); if (file) await deleteCodeFile(file.name); setFiles(files.filter((file) => file.name !== deleteName)); setModal(null) }}>Yes</button></div></>}{false && <><p className="eyebrow">Profile</p><h2>Account profile</h2><label>Username<input value={profileName} onChange={(event) => setProfileName(event.target.value)} /></label><label>Avatar<input type="file" accept="image/*" onChange={(event) => { const selected = event.target.files?.[0]; if (!selected) return; if (selected.size > 2 * 1024 * 1024) return; const reader = new FileReader(); reader.onload = () => setProfileImage(typeof reader.result === 'string' ? reader.result : ''); reader.readAsDataURL(selected) }} /></label>{profileImage && <img className="profile-preview" src={profileImage ?? undefined} alt="Selected avatar" />}<button className="primary-button" onClick={async () => { const saved = await updateProfile(profileName, profileImage ?? undefined); setProfileName(saved.name); if (saved.image !== undefined) setProfileImage(saved.image); setModal(null) }}>Save profile</button></>}{false && <><p className="eyebrow">Admin</p><h2>Secrovia overview</h2><div className="admin-stat"><span>Website visits</span><strong>12,840</strong></div><div className="admin-stat"><span>Total code files</span><strong>{files.length}</strong></div></>}</div></div>}</main>
}

export default function Home() {
  const session = useSession()
  const authenticated = Boolean(session.data?.user)
  if (session.isPending) return <main className="auth-page"><AmbientVideo /><div className="auth-panel"><Brand /><p className="eyebrow">Loading session</p><h1>Welcome back.</h1></div></main>
  return authenticated ? <Workspace /> : <AuthScreen onAuth={() => undefined} />
}
