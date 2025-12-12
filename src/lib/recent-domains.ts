import { LIMITS, STORAGE_KEYS } from "@/constants"

export interface RecentDomain {
  accountId: string
  domainId: string
  domainName: string
  accountName: string
  provider: string
  timestamp: number
}

export function getRecentDomains(): RecentDomain[] {
  try {
    const stored = localStorage.getItem(STORAGE_KEYS.RECENT_DOMAINS)
    return stored ? JSON.parse(stored) : []
  } catch {
    return []
  }
}

export function addRecentDomain(domain: Omit<RecentDomain, "timestamp">) {
  const recent = getRecentDomains()
  const filtered = recent.filter((d) => d.domainId !== domain.domainId)
  const updated = [{ ...domain, timestamp: Date.now() }, ...filtered].slice(
    0,
    LIMITS.MAX_RECENT_DOMAINS
  )
  localStorage.setItem(STORAGE_KEYS.RECENT_DOMAINS, JSON.stringify(updated))
}

export function removeRecentDomainsByAccount(accountId: string) {
  const recent = getRecentDomains()
  const filtered = recent.filter((d) => d.accountId !== accountId)
  localStorage.setItem(STORAGE_KEYS.RECENT_DOMAINS, JSON.stringify(filtered))
}

export function cleanupInvalidRecentDomains(validAccountIds: string[]) {
  const recent = getRecentDomains()
  const filtered = recent.filter((d) => validAccountIds.includes(d.accountId))
  if (filtered.length !== recent.length) {
    localStorage.setItem(STORAGE_KEYS.RECENT_DOMAINS, JSON.stringify(filtered))
  }
}
