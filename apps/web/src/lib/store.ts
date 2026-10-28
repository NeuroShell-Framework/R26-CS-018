import type { ChatMessage, ChatSession, FlowResponse } from './types'

const KEY = 'neuroshell.sessions.v1'
const ACTIVE = 'neuroshell.activeSession'

export function loadSessions(): ChatSession[] {
  try {
    const raw = localStorage.getItem(KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw) as ChatSession[]
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

function persist(sessions: ChatSession[]) {
  try {
    localStorage.setItem(KEY, JSON.stringify(sessions))
  } catch {
    /* quota exceeded / private mode — ignore */
  }
}

function uid(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID()
  }
  return `s-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`
}

export function newSession(): ChatSession {
  const now = Date.now()
  return {
    id: uid(),
    title: 'New chat',
    createdAt: now,
    updatedAt: now,
    messages: [],
  }
}

export function loadActiveSessionId(): string | null {
  return localStorage.getItem(ACTIVE)
}

export function saveActiveSessionId(id: string | null) {
  if (id) localStorage.setItem(ACTIVE, id)
  else localStorage.removeItem(ACTIVE)
}

export interface SessionStoreAPI {
  sessions: ChatSession[]
  activeId: string | null
  createAndSelect: () => { session: ChatSession; sessions: ChatSession[] }
  select: (id: string) => void
  delete: (id: string) => { sessions: ChatSession[] }
  rename: (id: string, title: string) => ChatSession[]
  appendUserMessage: (
    id: string,
    command: string,
  ) => { sessions: ChatSession[]; message: ChatMessage }
  appendAssistantMessage: (
    id: string,
  ) => { sessions: ChatSession[]; message: ChatMessage }
  resolveAssistantMessage: (
    id: string,
    messageId: string,
    flow?: FlowResponse,
    error?: string,
  ) => ChatSession[]
}

export function createStore(): SessionStoreAPI {
  function read() {
    return loadSessions()
  }
  function write(sessions: ChatSession[]) {
    persist(sessions)
  }

  return {
    get sessions() {
      return read()
    },
    get activeId() {
      return loadActiveSessionId()
    },
    createAndSelect() {
      const session = newSession()
      const sessions = [session, ...read()]
      write(sessions)
      saveActiveSessionId(session.id)
      return { session, sessions }
    },
    select(id: string) {
      saveActiveSessionId(id)
    },
    delete(id: string) {
      const sessions = read().filter((s) => s.id !== id)
      write(sessions)
      if (loadActiveSessionId() === id) {
        const next = sessions[0] ?? null
        saveActiveSessionId(next ? next.id : null)
      }
      return { sessions }
    },
    rename(id: string, title: string) {
      const sessions = read().map((s) =>
        s.id === id ? { ...s, title, updatedAt: Date.now() } : s,
      )
      write(sessions)
      return sessions
    },
    appendUserMessage(id: string, command: string) {
      const sessions = read()
      const message: ChatMessage = {
        id: uid(),
        role: 'user',
        content: command,
        ts: Date.now(),
      }
      const target = sessions.find((s) => s.id === id)
      if (target) {
        target.messages = [...target.messages, message]
        target.updatedAt = Date.now()
        if (
          target.title === 'New chat' ||
          target.messages.filter((m) => m.role === 'user').length === 1
        ) {
          target.title =
            command.length > 48 ? `${command.slice(0, 48)}…` : command
        }
        write(sessions)
      }
      return { sessions, message }
    },
    appendAssistantMessage(id: string) {
      const sessions = read()
      const message: ChatMessage = {
        id: uid(),
        role: 'assistant',
        content: '',
        ts: Date.now(),
      }
      const target = sessions.find((s) => s.id === id)
      if (target) {
        target.messages = [...target.messages, message]
        target.updatedAt = Date.now()
        write(sessions)
      }
      return { sessions, message }
    },
    resolveAssistantMessage(id: string, messageId: string, flow?, error?) {
      const newSessions = read().map((s) => {
        if (s.id !== id) return s
        return {
          ...s,
          messages: s.messages.map((m) =>
            m.id === messageId ? { ...m, flow, error } : m,
          ),
          updatedAt: Date.now(),
        }
      })
      write(newSessions)
      return newSessions
    },
  }
}