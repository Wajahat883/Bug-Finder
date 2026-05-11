import { useState, useCallback, useEffect } from "react";

export interface AppNotification {
  id: string;
  type: "finding" | "scan_complete" | "sla_breach" | "fp_marked" | "remediation" | "system";
  title: string;
  message: string;
  severity?: string;
  time: Date;
  read: boolean;
  href?: string;
  findingId?: string;
  scanId?: string;
}

// Global singleton state — shared between layout and notifications page
let _notifications: AppNotification[] = [];
let _listeners: Array<(n: AppNotification[]) => void> = [];

function notify(listeners: typeof _listeners, state: typeof _notifications) {
  for (const fn of listeners) fn([...state]);
}

export function pushNotification(n: Omit<AppNotification, "id" | "read" | "time">) {
  const entry: AppNotification = {
    ...n,
    id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
    read: false,
    time: new Date(),
  };
  _notifications = [entry, ..._notifications].slice(0, 100);
  notify(_listeners, _notifications);
  // Update browser tab title
  const unread = _notifications.filter(n => !n.read).length;
  if (unread > 0) {
    const base = document.title.replace(/^\(\d+\)\s*/, "");
    document.title = `(${unread}) ${base}`;
  }
  return entry;
}

export function useNotifications() {
  const [notifications, setNotifications] = useState<AppNotification[]>([..._notifications]);

  useEffect(() => {
    const listener = (n: AppNotification[]) => setNotifications(n);
    _listeners.push(listener);
    return () => { _listeners = _listeners.filter(l => l !== listener); };
  }, []);

  const markRead = useCallback((id: string) => {
    _notifications = _notifications.map(n => n.id === id ? { ...n, read: true } : n);
    notify(_listeners, _notifications);
    const unread = _notifications.filter(n => !n.read).length;
    const base = document.title.replace(/^\(\d+\)\s*/, "");
    document.title = unread > 0 ? `(${unread}) ${base}` : base;
  }, []);

  const markAllRead = useCallback(() => {
    _notifications = _notifications.map(n => ({ ...n, read: true }));
    notify(_listeners, _notifications);
    document.title = document.title.replace(/^\(\d+\)\s*/, "");
  }, []);

  const clearAll = useCallback(() => {
    _notifications = [];
    notify(_listeners, _notifications);
    document.title = document.title.replace(/^\(\d+\)\s*/, "");
  }, []);

  return { notifications, markRead, markAllRead, clearAll };
}
