/**
 * GuidedTour — spotlight-style first-run walkthrough.
 *
 * Built in response to operator feedback: "the screen has a lot going on,
 * walk me through one piece at a time." A modal explainer (Onboarding.tsx)
 * fired once on first load but never *pointed at* the chrome it was
 * describing — operators read the copy then went hunting for the role
 * selector / classification banner / alert badge with no idea where any
 * of it lived.
 *
 * Expanded in v2 to walk through every page, not just the chrome:
 * each step optionally specifies a `route`, the tour navigates there
 * before measuring the target rect, and steps that the current role
 * can't reach (out-of-scope routes, role-only chrome) are silently
 * skipped. The tour now covers the operator's full workspace, not just
 * the global header.
 *
 * Polish pass v3: steps are grouped into named sections (Workspace,
 * BASTION, PULSE, SENTRY, ADMIN, Help) so the operator always sees
 * "PULSE · Risk Board · Section 3 of 6" instead of an opaque step
 * count. Card content cross-fades between steps so navigation between
 * pages doesn't feel jarring. Spotlight has a subtle breathing pulse
 * so the eye knows where to land. A "Loading next page…" hint shows
 * during route transitions so the gap between click and spotlight
 * feels intentional. Closes with a "Tour complete" celebration card
 * instead of just disappearing.
 *
 * Triggers (any of):
 *   - First-run, after Onboarding modal dismissed (auto, gated by
 *     localStorage `spire.tour.v1.seen`)
 *   - "Take the tour" button in HelpOverlay footer
 *   - "Show me around" CTA on Onboarding's last slide
 *   - window event `spire:start-tour` (programmatic)
 *
 * Persistence: localStorage `spire.tour.v1.seen`. Cleared by the "Replay
 * tour" button in HelpOverlay so operators can re-run it any time.
 */
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useLocation, useNavigate } from "react-router-dom";
import { useSpireStore, VIEW_SCOPE, type Role } from "../state/store";

const SEEN_KEY = "spire.tour.v1.seen";
export const TOUR_START_EVENT = "spire:start-tour";

// Pixel padding around the spotlight cutout so highlighted elements have
// a little breathing room from the dim overlay.
const SPOTLIGHT_PAD = 8;
// Extra room reserved for the tooltip card when computing placement.
const CARD_GAP = 16;
const CARD_WIDTH = 380;
const CARD_HEIGHT_ESTIMATE = 280;
// How long to poll for a target element after navigating to a route
// before giving up and either skipping the step or rendering the card
// without a spotlight.
const TARGET_POLL_MS = 100;
const TARGET_POLL_MAX_MS = 2500;
// Card cross-fade duration — long enough to feel intentional, short
// enough not to slow the user down.
const FADE_MS = 220;

type SectionKey = "workspace" | "bastion" | "pulse" | "sentry" | "admin" | "help";

interface TourStep {
  id: string;
  // Element selector (looked up via data-tour-id, or by id="main").
  target: string;
  title: string;
  body: string;
  // Section label — drives the "Section X of Y · LABEL" header in the
  // card and the grouping of progress pips.
  section: SectionKey;
  // If present, only show this step when the current role is in the list.
  // Steps absent from the DOM at runtime are skipped automatically too.
  roles?: Role[];
  // Optional route to navigate to *before* measuring the target. If the
  // current location already matches, no navigation happens. Steps with
  // a route whose top-level scope (/sentry, /pulse, /bastion, /admin)
  // is out-of-bounds for the current role are silently skipped.
  route?: string;
}

const SECTION_LABELS: Record<SectionKey, string> = {
  workspace: "Workspace",
  bastion: "BASTION",
  pulse: "PULSE",
  sentry: "SENTRY",
  admin: "ADMIN",
  help: "Help & feedback",
};

const STEPS: TourStep[] = [
  // ── Section 1 — global chrome (visible from any route) ────────────
  {
    id: "classification",
    section: "workspace",
    target: "classification",
    title: "Classification banner",
    body:
      "This green strip across the top tells you what level of information you're working with. It stays visible everywhere so you always know what you can — and can't — share. Today's session is unclassified demo data.",
  },
  {
    id: "brand",
    section: "workspace",
    target: "brand",
    title: "Welcome to SPIRE",
    body:
      "Think of SPIRE as one screen for the things that normally take a dozen tabs — readiness, parts, sensors, paperwork. Built by Marines, runs on a laptop, works without internet.",
  },
  {
    id: "nav-tabs",
    section: "workspace",
    target: "nav-tabs",
    title: "The three workspaces",
    body:
      "SENTRY handles the data side (classify, redact, release). PULSE is your readiness picture (what's broken, what's at risk). BASTION is the live map of base, units, and threats. Click a tab to switch — or press G then S, P, or B on the keyboard.",
  },
  {
    id: "role-selector",
    section: "workspace",
    target: "role-selector",
    title: "Switch your role",
    body:
      "Different jobs see different things. Pick your role here and SPIRE lands you on the screen built for that job. You can always switch back without losing anything.",
  },
  {
    id: "alert-badge",
    section: "workspace",
    target: "alert-badge",
    title: "What needs your attention",
    body:
      "The number tells you how many things SPIRE thinks you should look at — equipment going red, threats on the map, paperwork waiting. Green means clear, yellow means watch, red means act.",
  },
  {
    id: "airgap",
    section: "workspace",
    target: "airgap",
    title: "Air-gap mode (offline operations)",
    body:
      "Tap this to cut outbound writes when comms go down. SPIRE keeps working, queues your changes locally, and replays them when you reconnect. Confirmation required — this is a posture decision.",
    roles: ["security_manager", "mef_commander"],
  },

  // ── Section 2 — BASTION (live map) ────────────────────────────────
  {
    id: "bastion-overview",
    section: "bastion",
    target: "bastion-content",
    title: "BASTION · the live map",
    body:
      "Your situational picture: every unit, every alert, every sensor on one map. The left column streams alerts (gate cameras, perimeter, drone feeds). Click an alert to fly the map to it.",
    route: "/bastion",
  },

  // ── Section 3 — PULSE (readiness) ─────────────────────────────────
  {
    id: "pulse-overview",
    section: "pulse",
    target: "pulse-overview-content",
    title: "PULSE · Overview",
    body:
      "The big picture for readiness — KPIs across your unit, a 7-day trend, and the heatmap that lights up when an asset class is sliding. Start here when you want a one-glance answer to 'how are we doing?'",
    route: "/pulse/overview",
  },
  {
    id: "pulse-risk",
    section: "pulse",
    target: "pulse-risk-content",
    title: "PULSE · Risk Board",
    body:
      "Asset-by-asset risk, ranked by deadline urgency. Predicted Failures (top), Risk Assets (middle), and the action recommendations (bottom). Click any asset to drill into its history.",
    route: "/pulse/risk",
  },
  {
    id: "pulse-cannib",
    section: "pulse",
    target: "pulse-cannib-content",
    title: "PULSE · Cannibalization",
    body:
      "When a part's on backorder, SPIRE looks across your fleet for a donor — same NSN, lower priority, similar age. Pick the donor, draft the TMR, and the audit chain catches the swap automatically.",
    route: "/pulse/cannib",
  },
  {
    id: "pulse-forecast",
    section: "pulse",
    target: "pulse-forecast-content",
    title: "PULSE · Forecast",
    body:
      "Monte Carlo readiness projection 7-30 days out. The fan chart shows the range; the recommended actions panel below tells you which interventions buy you the most readiness per dollar per day.",
    route: "/pulse/forecast",
  },

  // ── Section 4 — SENTRY (data pipeline) ────────────────────────────
  {
    id: "sentry-upload",
    section: "sentry",
    target: "sentry-upload-content",
    title: "SENTRY · Upload",
    body:
      "The start of the classification pipeline. Drop a CSV / XLSX / JSON export from GCSS-MC or DRRS-MC and SPIRE seeds the canonical synthetic dataset for the demo.",
    route: "/sentry/upload",
  },
  {
    id: "sentry-review",
    section: "sentry",
    target: "sentry-review-content",
    title: "SENTRY · Review Queue",
    body:
      "Records the auto-classifier wasn't sure about land here. Approve (A) or reject (R) — keyboard nav with ↑↓. Every decision feeds the model retraining loop.",
    route: "/sentry/review",
  },
  {
    id: "sentry-coalition",
    section: "sentry",
    target: "sentry-coalition-content",
    title: "SENTRY · Coalition Preview",
    body:
      "See what JSDF, AUS, PHL, and FVEY partners would receive if you released this batch. Anything not releasable to a partner is blacked out in their preview.",
    route: "/sentry/coalition",
  },
  {
    id: "sentry-export",
    section: "sentry",
    target: "sentry-export-content",
    title: "SENTRY · Export / Release",
    body:
      "Generate the audit-chained release package — a real ZIP with the redacted manifest, partner-specific views, and a tamper-evident hash. This is the artifact you hand off.",
    route: "/sentry/export",
  },

  // ── Section 5 — ADMIN (security manager only) ─────────────────────
  {
    id: "admin",
    section: "admin",
    target: "admin-content",
    title: "ADMIN · Audit + Telemetry",
    body:
      "The security manager's surface: audit-chain integrity, node-status fingerprints, and the training-flywheel telemetry that watches operator decisions feed the classifier.",
    route: "/admin",
    roles: ["security_manager"],
  },

  // ── Section 6 — closing utilities ─────────────────────────────────
  {
    id: "help",
    section: "help",
    target: "help-button",
    title: "Quick help, anytime",
    body:
      "Press the ? key — or click this button — for keyboard shortcuts, what your role can do, and the FAQ. You can also restart this tour from there.",
  },
  {
    id: "feedback",
    section: "help",
    target: "feedback-button",
    title: "Tell us what's broken",
    body:
      "Press G then F, or click here, to file feedback — defect, idea, or question. SPIRE attaches diagnostics automatically and sends it as a ticket. We read every one.",
  },
];

interface Rect { top: number; left: number; width: number; height: number; }

function findTarget(id: string): HTMLElement | null {
  if (typeof document === "undefined") return null;
  // Special case: id "main" matches the <main id="main"> landmark.
  if (id === "main") return document.getElementById("main");
  return document.querySelector<HTMLElement>(`[data-tour-id="${id}"]`);
}

function rectOf(el: HTMLElement): Rect {
  const r = el.getBoundingClientRect();
  return { top: r.top, left: r.left, width: r.width, height: r.height };
}

// Top-level scope check: a step that targets /sentry, /pulse, /bastion,
// or /admin should only fire if the operator's role can reach it. Maps
// to the same VIEW_SCOPE the TopBar uses for tab gating.
function routeAllowedForRole(route: string | undefined, role: Role): boolean {
  if (!route) return true;
  const top = "/" + route.split("/")[1];
  const allowed = VIEW_SCOPE[top];
  if (!allowed) return true;
  return allowed.includes(role);
}

export function startTour() {
  window.dispatchEvent(new CustomEvent(TOUR_START_EVENT));
}

export function GuidedTour() {
  const role = useSpireStore((s) => s.role);
  const navigate = useNavigate();
  const location = useLocation();
  const [active, setActive] = useState(false);
  // Separate "visible" state drives the entrance/exit fade. We mount
  // immediately on activation but start at opacity 0, then bump to 1
  // on the next frame. On finish we drop to 0 and unmount once the
  // transition has played out.
  const [visible, setVisible] = useState(false);
  const [stepIdx, setStepIdx] = useState(0);
  // Separate "completed" state — when the user clicks past the last
  // step we show a celebration card before fully dismissing. Keeps the
  // tour from feeling like it just disappears.
  const [completed, setCompleted] = useState(false);
  const [rect, setRect] = useState<Rect | null>(null);
  // Cross-fade: when stepIdx changes we briefly hide the card content
  // (and the spotlight) so the new placement doesn't snap into view.
  const [transitioning, setTransitioning] = useState(false);
  // Tracks whether we're between navigating to a new route and the
  // target appearing. Drives the "Loading next page…" hint.
  const [waitingForTarget, setWaitingForTarget] = useState(false);

  // Steps applicable to the current role + route scope. Recomputed every
  // time `active` or `role` changes.
  const visibleSteps = useMemo(
    () =>
      STEPS.filter((s) => {
        if (s.roles && !s.roles.includes(role)) return false;
        if (!routeAllowedForRole(s.route, role)) return false;
        return true;
      }),
    [role],
  );

  // Per-section breakdown for the header label and grouped pips.
  const sectionBreakdown = useMemo(() => {
    const order: SectionKey[] = ["workspace", "bastion", "pulse", "sentry", "admin", "help"];
    const groups = order
      .map((key) => ({
        key,
        label: SECTION_LABELS[key],
        steps: visibleSteps.filter((s) => s.section === key),
      }))
      .filter((g) => g.steps.length > 0);
    return groups;
  }, [visibleSteps]);

  const totalSections = sectionBreakdown.length;

  // First-run autostart — see comment block below for the two triggers.
  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;

    function scheduleAutostart(delayMs: number) {
      try {
        if (localStorage.getItem(SEEN_KEY)) return;
      } catch { /* tolerant */ }
      window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        if (!cancelled) setActive(true);
      }, delayMs);
    }

    // Trigger 1: mount-time check.
    try {
      const onboardingSeen = localStorage.getItem("spire.onboarding.v1.seen");
      if (onboardingSeen) scheduleAutostart(600);
    } catch { /* tolerant */ }

    // Trigger 2: mid-session, after Onboarding fires its seen event.
    function onOnboardingSeen() {
      scheduleAutostart(900);
    }
    window.addEventListener("spire:onboarding-seen", onOnboardingSeen);

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
      window.removeEventListener("spire:onboarding-seen", onOnboardingSeen);
    };
  }, []);

  // External trigger (HelpOverlay button, Onboarding final-slide CTA).
  useEffect(() => {
    function onStart() {
      setStepIdx(0);
      setCompleted(false);
      setActive(true);
    }
    window.addEventListener(TOUR_START_EVENT, onStart);
    return () => window.removeEventListener(TOUR_START_EVENT, onStart);
  }, []);

  const currentStep = visibleSteps[stepIdx];

  // When the current step asks for a different route, navigate first.
  // The next effect (target poll) waits for the page to mount before
  // measuring. Done in a separate effect so navigate() doesn't fire
  // on every re-render of the same step.
  useEffect(() => {
    if (!active || completed || !currentStep) return;
    if (!currentStep.route) return;
    if (location.pathname !== currentStep.route) {
      navigate(currentStep.route);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, stepIdx, completed]);

  // Recompute spotlight rect on step change, viewport resize, and scroll.
  // Polls for the target up to TARGET_POLL_MAX_MS — needed because a
  // step that just navigated has to wait for the new view's lazy chunk
  // to load and render before its data-tour-id appears in the DOM.
  useLayoutEffect(() => {
    if (!active || completed || !currentStep) return;
    let cancelled = false;
    let attempts = 0;
    const maxAttempts = Math.ceil(TARGET_POLL_MAX_MS / TARGET_POLL_MS);
    let pollHandle: number | undefined;

    // Mark as waiting until target measured. Cleared in tryMeasure on
    // success or on max-attempts fallback.
    setWaitingForTarget(true);

    function tryMeasure() {
      if (cancelled) return;
      const el = findTarget(currentStep.target);
      if (el) {
        // Best-effort scroll-into-view if the target is off-screen.
        const r = el.getBoundingClientRect();
        const off =
          r.bottom < 0 || r.top > window.innerHeight ||
          r.right < 0 || r.left > window.innerWidth;
        if (off) {
          try { el.scrollIntoView({ block: "center", inline: "center", behavior: "auto" }); } catch { /* noop */ }
        }
        setRect(rectOf(el));
        setWaitingForTarget(false);
        return;
      }
      attempts += 1;
      if (attempts >= maxAttempts) {
        // Fallback: render the card without a spotlight (full-screen
        // dim). Better than blocking the tour entirely.
        setRect(null);
        setWaitingForTarget(false);
        return;
      }
      pollHandle = window.setTimeout(tryMeasure, TARGET_POLL_MS);
    }

    tryMeasure();

    function onResize() {
      const el = findTarget(currentStep.target);
      if (el) setRect(rectOf(el));
    }
    window.addEventListener("resize", onResize);
    window.addEventListener("scroll", onResize, true);

    return () => {
      cancelled = true;
      window.clearTimeout(pollHandle);
      window.removeEventListener("resize", onResize);
      window.removeEventListener("scroll", onResize, true);
    };
  }, [active, completed, currentStep, stepIdx, location.pathname]);

  const finish = useCallback(() => {
    // Fade out, then unmount. Persists immediately so a refresh
    // mid-fade still records "seen". 250ms matches FADE_MS-ish cadence
    // and the CSS transition below.
    try { localStorage.setItem(SEEN_KEY, "1"); } catch { /* tolerant */ }
    setVisible(false);
    window.setTimeout(() => {
      setActive(false);
      setStepIdx(0);
      setCompleted(false);
    }, 260);
  }, []);

  // Drive the entrance fade: when `active` flips on, mount with
  // opacity 0, then on the next frame set visible=true so the CSS
  // transition runs.
  useEffect(() => {
    if (!active) {
      setVisible(false);
      return;
    }
    // requestAnimationFrame ensures the initial render with
    // visible=false has actually committed before we transition to 1.
    const handle = window.requestAnimationFrame(() => setVisible(true));
    return () => window.cancelAnimationFrame(handle);
  }, [active]);

  const advance = useCallback(
    (delta: 1 | -1) => {
      // Cross-fade out, then update the index, then fade back in via
      // the rect/measurement flow. Spotlight is hidden during the fade
      // so the operator sees a clean transition rather than a snap.
      setTransitioning(true);
      window.setTimeout(() => {
        setStepIdx((i) => Math.max(0, Math.min(visibleSteps.length - 1, i + delta)));
        // Fade back in — handled by the next effect via setTransitioning(false)
        // after the new rect lands. We give it one frame here as a floor.
        window.setTimeout(() => setTransitioning(false), 30);
      }, FADE_MS);
    },
    [visibleSteps.length],
  );

  const next = useCallback(() => {
    if (stepIdx >= visibleSteps.length - 1) {
      // Final step → celebration card. Operator clicks "Got it" once
      // more (or any key) to actually dismiss.
      setTransitioning(true);
      window.setTimeout(() => {
        setCompleted(true);
        window.setTimeout(() => setTransitioning(false), 30);
      }, FADE_MS);
      return;
    }
    advance(1);
  }, [stepIdx, visibleSteps.length, advance]);

  const prev = useCallback(() => {
    if (completed) {
      // From celebration card, "Back" returns to the last step.
      setTransitioning(true);
      window.setTimeout(() => {
        setCompleted(false);
        window.setTimeout(() => setTransitioning(false), 30);
      }, FADE_MS);
      return;
    }
    if (stepIdx === 0) return;
    advance(-1);
  }, [stepIdx, advance, completed]);

  // ESC to dismiss, ←/→ to navigate.
  useEffect(() => {
    if (!active) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        e.preventDefault();
        finish();
      } else if (e.key === "ArrowRight" || e.key === "Enter") {
        e.preventDefault();
        next();
      } else if (e.key === "ArrowLeft") {
        e.preventDefault();
        prev();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [active, next, prev, finish]);

  if (!active) return null;

  // Compute card placement: prefer below, fall back to above, then to
  // centered. Falls back gracefully when rect is null (target not yet
  // measured) by centering the card.
  const vw = typeof window !== "undefined" ? window.innerWidth : 1280;
  const vh = typeof window !== "undefined" ? window.innerHeight : 720;
  const cardWidth = Math.min(CARD_WIDTH, vw - 32);

  let cardTop: number;
  let cardLeft: number;

  if (rect && !completed) {
    const spaceBelow = vh - (rect.top + rect.height) - CARD_GAP - 16;
    const spaceAbove = rect.top - CARD_GAP - 16;

    if (spaceBelow >= CARD_HEIGHT_ESTIMATE) {
      cardTop = rect.top + rect.height + CARD_GAP;
    } else if (spaceAbove >= CARD_HEIGHT_ESTIMATE) {
      cardTop = rect.top - CARD_HEIGHT_ESTIMATE - CARD_GAP;
    } else {
      cardTop = Math.max(16, vh / 2 - CARD_HEIGHT_ESTIMATE / 2);
    }
    cardLeft = rect.left + rect.width / 2 - cardWidth / 2;
    cardLeft = Math.max(16, Math.min(cardLeft, vw - cardWidth - 16));
  } else {
    cardTop = vh / 2 - CARD_HEIGHT_ESTIMATE / 2;
    cardLeft = vw / 2 - cardWidth / 2;
  }

  // Compute section header text and pip groupings.
  const sectionForCurrent = currentStep
    ? sectionBreakdown.find((g) => g.steps.some((s) => s.id === currentStep.id))
    : undefined;
  const sectionIdx = sectionForCurrent ? sectionBreakdown.indexOf(sectionForCurrent) : -1;

  // Spotlight: absolutely-positioned div over the target rect with a
  // giant box-shadow that blacks out everything outside it.
  return createPortal(
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="tour-card-title"
      className="fixed inset-0 z-[9500] pointer-events-none"
      style={{
        opacity: visible ? 1 : 0,
        transition: "opacity 250ms ease",
      }}
    >
      {/* Click-catcher absorbs clicks so the underlying app isn't
       * accidentally interacted with mid-tour. */}
      <div
        className="absolute inset-0 pointer-events-auto"
        onClick={(e) => e.stopPropagation()}
      />
      {/* Spotlight cutout. Hidden during transitions and on the
       * celebration card; falls back to full-screen dim when no rect. */}
      {rect && !completed && !transitioning ? (
        <div
          className="tour-spotlight absolute pointer-events-none"
          style={{
            top: rect.top - SPOTLIGHT_PAD,
            left: rect.left - SPOTLIGHT_PAD,
            width: rect.width + SPOTLIGHT_PAD * 2,
            height: rect.height + SPOTLIGHT_PAD * 2,
          }}
        />
      ) : (
        <div
          className="absolute inset-0 pointer-events-none transition-opacity duration-200"
          style={{ background: "rgba(4, 7, 12, 0.78)", opacity: 1 }}
        />
      )}
      {/* Tooltip card */}
      <div
        className="absolute pointer-events-auto rounded-md border border-[var(--color-primary)] bg-[var(--color-surface)] shadow-2xl"
        style={{
          top: cardTop,
          left: cardLeft,
          width: cardWidth,
          opacity: transitioning ? 0 : 1,
          transform: transitioning ? "translateY(4px)" : "translateY(0)",
          transition: `opacity ${FADE_MS}ms ease, transform ${FADE_MS}ms ease, top 200ms ease, left 200ms ease`,
        }}
      >
        {/* Card header — section + step counter + skip */}
        <div className="flex items-center justify-between border-b border-[var(--color-border)] px-5 pt-4 pb-3">
          <div className="min-w-0 flex-1">
            {completed ? (
              <div className="font-mono text-[10px] uppercase text-[var(--color-primary)] tracking-widest">
                Tour complete
              </div>
            ) : sectionForCurrent ? (
              <div className="font-mono text-[10px] uppercase tracking-widest">
                <span className="text-[var(--color-primary)]">{sectionForCurrent.label}</span>
                <span className="text-[var(--color-text-muted)]"> · Section {sectionIdx + 1} of {totalSections}</span>
              </div>
            ) : null}
            {!completed && currentStep ? (
              <div className="mt-0.5 font-mono text-[10px] uppercase text-[var(--color-text-muted)] tracking-widest">
                Step {stepIdx + 1} of {visibleSteps.length}
              </div>
            ) : null}
          </div>
          <button
            onClick={finish}
            className="font-mono text-[10px] uppercase text-[var(--color-text-muted)] hover:text-[var(--color-text)] tracking-widest"
            aria-label="Skip tour"
          >
            {completed ? "Close" : "Skip"}
          </button>
        </div>

        {/* Card body — title + body, or the closing celebration */}
        <div className="px-5 pt-4 pb-2">
          {completed ? (
            <>
              <h3 id="tour-card-title" className="font-sans text-lg font-semibold text-[var(--color-text)] tracking-tight">
                You're all set
              </h3>
              <p className="mt-2 text-sm leading-relaxed text-[var(--color-text-secondary)]">
                That's the whole tour. You can replay it any time from the help panel — press <kbd className="rounded-sm border border-[var(--color-border-active)] bg-[var(--color-bg)] px-1 py-0.5 font-mono text-[10px]">?</kbd> or click the <span className="font-mono text-xs text-[var(--color-primary)]">?</span> button bottom-right.
              </p>
              <p className="mt-3 text-sm leading-relaxed text-[var(--color-text-secondary)]">
                If anything feels off as you work, press <kbd className="rounded-sm border border-[var(--color-border-active)] bg-[var(--color-bg)] px-1 py-0.5 font-mono text-[10px]">G</kbd> then <kbd className="rounded-sm border border-[var(--color-border-active)] bg-[var(--color-bg)] px-1 py-0.5 font-mono text-[10px]">F</kbd> to send feedback. We read every one.
              </p>
            </>
          ) : currentStep ? (
            <>
              <h3 id="tour-card-title" className="font-sans text-lg font-semibold text-[var(--color-text)] tracking-tight">
                {currentStep.title}
              </h3>
              <p className="mt-2 text-sm leading-relaxed text-[var(--color-text-secondary)]">
                {currentStep.body}
              </p>
              {/* "Loading next page…" hint shows only when the target
               * hasn't appeared yet on a route-bearing step. Lets the
               * operator know nothing is broken — the page is just
               * loading. */}
              {waitingForTarget && currentStep.route ? (
                <div className="mt-3 flex items-center gap-2 font-mono text-[10px] uppercase text-[var(--color-text-muted)] tracking-widest">
                  <span className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-[var(--color-primary)]" />
                  Loading {currentStep.route}…
                </div>
              ) : null}
            </>
          ) : null}
        </div>

        {/* Grouped pips — small dots clustered by section with a gap
         * between groups. Past sections are filled in muted, current
         * step is the bright primary, future sections are outlined. */}
        {!completed ? (
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 px-5 pb-1 pt-1">
            {sectionBreakdown.map((group, gIdx) => (
              <div key={group.key} className="flex items-center gap-1" aria-hidden>
                {group.steps.map((s) => {
                  const idxOf = visibleSteps.findIndex((vs) => vs.id === s.id);
                  const isPast = idxOf < stepIdx;
                  const isCurrent = idxOf === stepIdx;
                  return (
                    <span
                      key={s.id}
                      className="h-1.5 rounded-full transition-all duration-200"
                      style={{
                        width: isCurrent ? 14 : 6,
                        background: isCurrent
                          ? "var(--color-primary)"
                          : isPast
                            ? "var(--color-border-active)"
                            : "var(--color-border)",
                      }}
                    />
                  );
                })}
                {gIdx < sectionBreakdown.length - 1 ? (
                  <span className="mx-0.5 h-px w-1 bg-[var(--color-border)]" aria-hidden />
                ) : null}
              </div>
            ))}
          </div>
        ) : null}

        {/* Footer — back / next buttons + keyboard hint */}
        <div className="flex items-center justify-between border-t border-[var(--color-border)] px-5 pt-3 pb-4">
          <button
            onClick={prev}
            disabled={!completed && stepIdx === 0}
            className="rounded-sm border border-[var(--color-border-active)] px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)] disabled:opacity-30"
          >
            Back
          </button>
          <div className="font-mono text-[10px] uppercase text-[var(--color-text-muted)] tracking-widest">
            ← / → · Esc
          </div>
          <button
            onClick={completed ? finish : next}
            className="rounded-sm border border-[var(--color-primary)] bg-[var(--color-primary)] px-4 py-1.5 font-mono text-xs font-semibold uppercase text-white tracking-widest hover:bg-[var(--color-primary-hover)]"
          >
            {completed
              ? "Finish"
              : stepIdx === visibleSteps.length - 1
                ? "Wrap up"
                : "Next"}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
}
