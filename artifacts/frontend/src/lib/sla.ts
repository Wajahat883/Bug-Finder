const SLA_DAYS: Record<string, number> = {
  critical: 1,
  high: 7,
  medium: 30,
  low: 90,
  info: 180,
};

export type SlaStatus = {
  daysAllowed: number;
  daysElapsed: number;
  daysRemaining: number;
  overdue: boolean;
  percentUsed: number;
};

export function getSlaStatus(severity: string, createdAt: string | Date | null | undefined): SlaStatus {
  const daysAllowed = SLA_DAYS[String(severity).toLowerCase()] ?? 30;
  const created = createdAt ? new Date(createdAt as string) : new Date();
  const now = new Date();
  const daysElapsed = Math.floor((now.getTime() - created.getTime()) / (1000 * 60 * 60 * 24));
  const daysRemaining = daysAllowed - daysElapsed;
  return {
    daysAllowed,
    daysElapsed,
    daysRemaining,
    overdue: daysRemaining < 0,
    percentUsed: Math.min(100, Math.round((daysElapsed / daysAllowed) * 100)),
  };
}
