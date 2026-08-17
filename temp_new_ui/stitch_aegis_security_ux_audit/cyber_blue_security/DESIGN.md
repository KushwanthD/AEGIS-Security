---
name: Cyber Blue Security
colors:
  surface: '#131313'
  surface-dim: '#131313'
  surface-bright: '#393939'
  surface-container-lowest: '#0e0e0e'
  surface-container-low: '#1c1b1b'
  surface-container: '#201f1f'
  surface-container-high: '#2a2a2a'
  surface-container-highest: '#353534'
  on-surface: '#e5e2e1'
  on-surface-variant: '#bec7d4'
  inverse-surface: '#e5e2e1'
  inverse-on-surface: '#313030'
  outline: '#88919d'
  outline-variant: '#3f4852'
  surface-tint: '#98cbff'
  primary: '#98cbff'
  on-primary: '#003354'
  primary-container: '#00a3ff'
  on-primary-container: '#00375a'
  inverse-primary: '#00629d'
  secondary: '#f5fff3'
  on-secondary: '#00391d'
  secondary-container: '#27ff97'
  on-secondary-container: '#00723f'
  tertiary: '#ffba20'
  on-tertiary: '#412d00'
  tertiary-container: '#cc9200'
  on-tertiary-container: '#463000'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#cfe5ff'
  primary-fixed-dim: '#98cbff'
  on-primary-fixed: '#001d33'
  on-primary-fixed-variant: '#004a77'
  secondary-fixed: '#5bffa1'
  secondary-fixed-dim: '#00e383'
  on-secondary-fixed: '#00210e'
  on-secondary-fixed-variant: '#00522c'
  tertiary-fixed: '#ffdea8'
  tertiary-fixed-dim: '#ffba20'
  on-tertiary-fixed: '#271900'
  on-tertiary-fixed-variant: '#5e4200'
  background: '#131313'
  on-background: '#e5e2e1'
  surface-variant: '#353534'
  cyber-blue: '#00A3FF'
  security-green: '#00FF94'
  warning-amber: '#FFB800'
  critical-red: '#FF4B4B'
  deep-charcoal: '#1A1A1A'
  navy-surface: '#1E222D'
typography:
  headline-lg:
    fontFamily: Inter
    fontSize: 48px
    fontWeight: '700'
    lineHeight: 56px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.01em
  headline-sm:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  body-lg:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '400'
    lineHeight: 28px
  body-md:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-sm:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  code-md:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '500'
    lineHeight: 20px
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
  label-caps:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '700'
    lineHeight: 16px
    letterSpacing: 0.05em
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  base: 8px
  xs: 4px
  sm: 12px
  md: 24px
  lg: 40px
  xl: 64px
  gutter: 24px
  sidebar-width: 280px
---

## Brand & Style

The design system embodies a **Technological, Vigilant, and Premium** personality. It is designed for high-stakes environments where rapid incident response and data integrity are paramount. The aesthetic targets developers and security analysts who value sophisticated, high-tech tools that feel like a "lifestyle" upgrade rather than a utility chore.

The visual direction is **Modern SaaS with a Cyber-Technical edge**. It utilizes a dark, immersive canvas to reduce eye strain during long monitoring sessions, punctuated by vibrant, glowing accents that serve as functional status indicators. The layout is modular and card-based, prioritizing "Information Hierarchy over Data Density" to ensure that the most critical security telemetry is immediately digestible.

**Key Visual Principles:**
- **Vigilance through Glow:** Use subtle light emissions around status indicators to leverage peripheral vision for system monitoring.
- **Privacy-by-Design:** Intentional obfuscation of sensitive data (Masking) that requires deliberate user action to reveal.
- **Hybrid Interface:** A seamless blend of high-fidelity GUI components and terminal-inspired monospace data streams.

## Colors

The palette is anchored in a deep-space background to provide maximum contrast for functional color cues. 

- **Primary (Cyber Blue):** Used for interactive elements, focus states, and primary navigation highlights.
- **Secondary (Security Green):** Reserved for "Safe" states, successful validations, and healthy system scores.
- **Tertiary (Warning Amber):** Used for cautionary feedback and non-critical alerts that require attention.
- **Neutral (Deep Charcoal):** The foundation. `#121212` is the global background, while `#1A1A1A` and `#1E222D` are used for card surfaces and sidebars to create depth without relying on heavy borders.
- **Critical Red:** Strictly reserved for active threats, data breaches, and system failures.

**Glow Logic:** Functional accents should use a 15-25% opacity drop-shadow/outer-glow of the accent color (e.g., `Cyber Blue`) to signify "active" or "live" states.

## Typography

The typographic system balances professional SaaS clarity with technical precision. 

- **Inter** is the primary typeface for all UI controls and narrative content, providing high legibility in dark environments.
- **JetBrains Mono** is utilized for all "Data" roles, including the monitoring terminal, IP addresses, hashes, and credential vaults. This creates a clear mental model: Sans-serif = Interface; Monospace = Information.

**Scalability:**
- On mobile, `headline-lg` scales down to 32px to ensure titles do not break across multiple lines in small viewports. 
- Use `label-caps` for metadata headers above data tables or within small modular cards.

## Layout & Spacing

The system uses a **Fluid 12-Column Grid** for the main dashboard, allowing modular cards to resize based on data priority. 

- **Modular Rhythm:** Spacing follows an 8px base unit. Margins are generally large (24px - 40px) to prevent "industrial clutter" and provide breathing room for critical data visualization.
- **The Sidebar:** A fixed 280px sidebar on the left utilizes glassmorphism (background blur) to maintain a sense of depth.
- **Breakpoints:**
  - **Desktop (1440px+):** Full 12-column grid.
  - **Tablet (768px - 1439px):** 6-column grid; sidebar collapses into a rail or hamburger menu.
  - **Mobile (<767px):** Single-column stacked layout; 16px horizontal margins.

## Elevation & Depth

Hierarchy is established through **Tonal Layering** and **Glassmorphism**, rather than traditional shadows.

- **Background:** `#121212` (Base Layer)
- **Cards/Modules:** `#1A1A1A` with a subtle 1px border (`#FFFFFF` at 5% opacity).
- **Navigation/Modals:** Glassmorphic surfaces with a 12px backdrop blur and a slight blue-tinted overlay.
- **Functional Glows:** Instead of black shadows, "elevated" items like active alerts or primary buttons use a colored outer glow of their respective brand color (e.g., a 10px Blue glow for the active security shield). This communicates state and elevation simultaneously.

## Shapes

The design uses a **Rounded** language (8px / 0.5rem) to soften the "cold" technical nature of security software. 

- **Standard Cards/Buttons:** 8px (`rounded-md`).
- **Input Fields:** 8px.
- **Security Score Rings:** Perfect circles for continuous monitoring metrics.
- **Terminal Console:** Maintains a 4px radius (`rounded-sm`) to feel more rigid and technical compared to the softer dashboard elements.

## Components

- **Glassmorphism Sidebar:** Uses `navy-surface` at 70% opacity with a heavy backdrop blur. Active items use `Cyber Blue` text with a glowing left-border indicator.
- **Security Score Progress Rings:** Thick circular strokes using `Security Green` (Success) or `Critical Red` (Threat). Center the percentage in `headline-md`.
- **Credential Vault (Masked Fields):** Sensitive strings are replaced by `••••••••` using `JetBrains Mono`. On hover, the field gains a subtle `Cyber Blue` border, and the data is revealed with a fade-in transition.
- **Terminal Console:** A dedicated component with a `#000000` background. Text uses `code-sm` in `Security Green` or `Neutral White`. It should include a "live pulse" indicator in the top corner.
- **Buttons:**
  - **Primary:** Solid `Cyber Blue` with white text; 8px glow on hover.
  - **Ghost:** `Cyber Blue` outline (1px) with 5% fill on hover.
- **Status Chips:** Small badges with a low-opacity background of the status color (e.g., Green 10%) and a solid 1px border of the same color.