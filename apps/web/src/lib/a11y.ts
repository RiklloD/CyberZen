/**
 * §6.19 — Accessibility helpers for CyberZen.
 *
 * Shared focus management, focus-trap, and ARIA utilities used
 * by modals, drawers, and interactive widgets throughout the app.
 */

// ---------------------------------------------------------------------------
// Focus trap
// ---------------------------------------------------------------------------

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'area[href]',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  'button:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
  '[contenteditable]',
].join(', ')

/**
 * Return all focusable descendants of `container` in DOM order.
 */
export function getFocusableElements(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
    (el) => el.offsetParent !== null && !el.hasAttribute('aria-hidden'),
  )
}

/**
 * Trap keyboard focus within `container` (Tab / Shift+Tab cycle).
 * Returns a cleanup function that removes the listener.
 */
export function trapFocus(container: HTMLElement): () => void {
  function onKeyDown(e: KeyboardEvent) {
    if (e.key !== 'Tab') return

    const focusable = getFocusableElements(container)
    if (focusable.length === 0) {
      e.preventDefault()
      return
    }

    const first = focusable[0]
    const last = focusable[focusable.length - 1]

    if (e.shiftKey) {
      if (document.activeElement === first) {
        e.preventDefault()
        last.focus()
      }
    } else {
      if (document.activeElement === last) {
        e.preventDefault()
        first.focus()
      }
    }
  }

  container.addEventListener('keydown', onKeyDown)
  return () => container.removeEventListener('keydown', onKeyDown)
}

// ---------------------------------------------------------------------------
// Focus restore
// ---------------------------------------------------------------------------

/**
 * Save the currently focused element and return a function that restores it.
 * Useful when opening a modal/drawer — call the returned function on close.
 */
export function stashFocus(): () => void {
  const previouslyFocused = document.activeElement as HTMLElement | null
  return () => {
    previouslyFocused?.focus?.()
  }
}

// ---------------------------------------------------------------------------
// Auto-focus first element
// ---------------------------------------------------------------------------

/**
 * Move focus to the first focusable child of `container`.
 * Falls back to the container itself if nothing is focusable.
 */
export function autoFocusFirst(container: HTMLElement): void {
  const focusable = getFocusableElements(container)
  if (focusable.length > 0) {
    focusable[0].focus()
  } else {
    container.setAttribute('tabindex', '-1')
    container.focus()
  }
}

// ---------------------------------------------------------------------------
// ARIA live region helpers
// ---------------------------------------------------------------------------

let liveRegion: HTMLElement | null = null

/**
 * Announce a message to screen readers via an ARIA live region.
 * Creates the region lazily on first call.
 */
export function announceToScreenReader(message: string, politeness: 'polite' | 'assertive' = 'polite'): void {
  if (!liveRegion) {
    liveRegion = document.createElement('div')
    liveRegion.setAttribute('role', 'status')
    liveRegion.setAttribute('aria-live', politeness)
    liveRegion.setAttribute('aria-atomic', 'true')
    Object.assign(liveRegion.style, {
      position: 'absolute',
      width: '1px',
      height: '1px',
      padding: '0',
      margin: '-1px',
      overflow: 'hidden',
      clip: 'rect(0, 0, 0, 0)',
      whiteSpace: 'nowrap',
      border: '0',
    })
    document.body.appendChild(liveRegion)
  }

  liveRegion.setAttribute('aria-live', politeness)
  // Clear then set to ensure repeat announcements
  liveRegion.textContent = ''
  requestAnimationFrame(() => {
    liveRegion!.textContent = message
  })
}

// ---------------------------------------------------------------------------
// Escape key helper
// ---------------------------------------------------------------------------

/**
 * Call `onEscape` when the Escape key is pressed.
 * Returns a cleanup function.
 */
export function onEscapeKey(container: HTMLElement, onEscape: () => void): () => void {
  function handler(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.stopPropagation()
      onEscape()
    }
  }
  container.addEventListener('keydown', handler)
  return () => container.removeEventListener('keydown', handler)
}

// ---------------------------------------------------------------------------
// Roving tabindex for grid/list navigation
// ---------------------------------------------------------------------------

/**
 * Implements roving tabindex on a set of elements.
 * Arrow keys move the active descendant; Tab leaves the group.
 * Returns a cleanup function.
 */
export function rovingTabIndex(
  container: HTMLElement,
  itemSelector: string,
  options: { orientation?: 'horizontal' | 'vertical' | 'both' } = {},
): () => void {
  const { orientation = 'vertical' } = options

  function handler(e: KeyboardEvent) {
    const items = Array.from(container.querySelectorAll<HTMLElement>(itemSelector))
    if (items.length === 0) return

    const currentIndex = items.indexOf(document.activeElement as HTMLElement)
    if (currentIndex === -1) return

    let nextIndex = currentIndex

    if (
      (orientation === 'vertical' && e.key === 'ArrowDown') ||
      (orientation === 'horizontal' && e.key === 'ArrowRight') ||
      (orientation === 'both' && (e.key === 'ArrowDown' || e.key === 'ArrowRight'))
    ) {
      e.preventDefault()
      nextIndex = (currentIndex + 1) % items.length
    } else if (
      (orientation === 'vertical' && e.key === 'ArrowUp') ||
      (orientation === 'horizontal' && e.key === 'ArrowLeft') ||
      (orientation === 'both' && (e.key === 'ArrowUp' || e.key === 'ArrowLeft'))
    ) {
      e.preventDefault()
      nextIndex = (currentIndex - 1 + items.length) % items.length
    } else {
      return
    }

    items[currentIndex].setAttribute('tabindex', '-1')
    items[nextIndex].setAttribute('tabindex', '0')
    items[nextIndex].focus()
  }

  container.addEventListener('keydown', handler)
  return () => container.removeEventListener('keydown', handler)
}
