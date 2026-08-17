---
name: Amethyst Guardian
colors:
  surface: '#0b1326'
  surface-dim: '#0b1326'
  surface-bright: '#31394e'
  surface-container-lowest: '#060d20'
  surface-container-low: '#131b2e'
  surface-container: '#171f33'
  surface-container-high: '#222a3e'
  surface-container-highest: '#2d3449'
  on-surface: '#dbe2fd'
  on-surface-variant: '#ccc3d2'
  inverse-surface: '#dbe2fd'
  inverse-on-surface: '#283044'
  outline: '#958e9c'
  outline-variant: '#4a4551'
  surface-tint: '#d4bbff'
  primary: '#d4bbff'
  on-primary: '#3e1975'
  primary-container: '#b794f4'
  on-primary-container: '#492680'
  inverse-primary: '#6d4ca6'
  secondary: '#ffb867'
  on-secondary: '#482900'
  secondary-container: '#845000'
  on-secondary-container: '#ffcb94'
  tertiary: '#8ecdff'
  on-tertiary: '#00344f'
  tertiary-container: '#6cacdc'
  on-tertiary-container: '#003f5f'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#ebdcff'
  primary-fixed-dim: '#d4bbff'
  on-primary-fixed: '#270058'
  on-primary-fixed-variant: '#55338d'
  secondary-fixed: '#ffddbb'
  secondary-fixed-dim: '#ffb867'
  on-secondary-fixed: '#2b1700'
  on-secondary-fixed-variant: '#673d00'
  tertiary-fixed: '#cbe6ff'
  tertiary-fixed-dim: '#8ecdff'
  on-tertiary-fixed: '#001e30'
  on-tertiary-fixed-variant: '#004b71'
  background: '#0b1326'
  on-background: '#dbe2fd'
  surface-variant: '#2d3449'
  amethyst-glow: 'linear-gradient(135deg, #b794f4 0%, #63b3ed 100%)'
  admin-gold: '#ecc94b'
  surface-slate: '#1e293b'
  success-emerald: '#48bb78'
  critical-ruby: '#f56565'
typography:
  headline-lg:
    fontFamily: Sora
    fontSize: 48px
    fontWeight: '700'
    lineHeight: 52px
    letterSpacing: -0.02em
  headline-lg-mobile:
    fontFamily: Sora
    fontSize: 32px
    fontWeight: '700'
    lineHeight: 38px
  headline-md:
    fontFamily: Sora
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 38px
    letterSpacing: -0.01em
  headline-sm:
    fontFamily: Sora
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
    letterSpacing: 0.02em
  body-lg:
    fontFamily: Hanken Grotesk
    fontSize: 18px
    fontWeight: '400'
    lineHeight: 28px
  body-md:
    fontFamily: Hanken Grotesk
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  label-caps:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '700'
    lineHeight: 12px
    letterSpacing: 0.1em
  data-mono:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '500'
    lineHeight: 20px
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  base: 8px
  gutter: 24px
  margin-desktop: 32px
  margin-mobile: 16px
  sidebar-expanded: 260px
  sidebar-collapsed: 80px
---

## Brand & Style

The design system establishes a high-fidelity aesthetic for elite security operations, shifting the industry standard from "cyber blue" to a regal, authoritative **Amethyst** narrative. The brand personality is protective, sophisticated, and technically superior—evoking the feeling of a high-end digital vault rather than a standard utility tool.

The visual style is a hybrid of **Glassmorphism** and **Modern Corporate**. It uses deep slate-navy foundations as a canvas for translucent, shimmering overlays and precise technical accents. This multi-dimensional approach ensures that high-density security data feels breathable and premium.

**Key Visual Principles:**
- **Lustrous Depth:** Surfaces utilize gradients and light-refractive borders to simulate the facets of a gemstone.
- **Technical Elegance:** Geometric typography combined with precise, glowing monospaced data streams.
- **Atmospheric Protection:** Subtle background glows and "shimmer" effects denote active, high-fidelity system health.

## Colors

The palette is anchored in **Deep Slate (#0b1326)**, providing a sophisticated, low-strain canvas.

- **Primary (Amethyst Purple):** The core brand color, used for active security states and primary interaction points.
- **Secondary (Amber Warning):** Reserved for system warnings and attention-required telemetry.
- **Tertiary (Electric Blue):** Paired with Amethyst to create "Premium" gradients and secondary interactive highlights.
- **Admin Gold:** A specialized accent used for architectural markers and iconography within elevated privilege views.
- **Success & Critical:** Purpose-built semantic colors for status reporting that maintain high contrast against the slate background.

## Typography

The typography system balances wide, authoritative geometric sans-serifs with high-precision monospaced fonts.

- **Sora (Headlines):** Used for structural headings. It commands attention and feels futuristic yet grounded.
- **Hanken Grotesk (Body):** Ensures high readability for incident logs and narrative security reports.
- **JetBrains Mono (Data & Labels):** Dedicated to technical strings, metadata, and status labels.

**Formatting Note:** All `label-caps` should be rendered in uppercase to emphasize the "System Status" aesthetic. Use `data-mono` exclusively for system-generated content to distinguish it from UI instructions.

## Layout & Spacing

This design system utilizes a **Fixed Grid with Fluid Containers**. On desktop, the layout is constrained by a 12-column grid to maintain a "premium" sense of scale.

- **The Guard-Rail Sidebar:** A fixed navigation element that toggles between an expanded state (260px) and a collapsed rail (80px).
- **Spacing Rhythm:** Based on an 8px scale. Component internal padding should favor 16px (2 units) or 24px (3 units) to avoid visual clutter in data-heavy environments.
- **Breakpoints:**
  - **Desktop (1280px+):** 12-columns, 32px margins.
  - **Tablet (768px - 1279px):** 8-columns, 24px margins. Sidebar moves to a collapsible overlay.
  - **Mobile (<768px):** 4-columns, 16px margins. Cards and data widgets stack vertically.

## Elevation & Depth

Visual hierarchy is achieved through **Tonal Stacking** and **Chroma-Tinted Glows**.

- **Level 0 (Base):** Deep Slate surface.
- **Level 1 (Cards/Widgets):** Surface Slate containers with a 0.5px Amethyst-tinted outline at 20% opacity.
- **Level 2 (Modals/Overlays):** Glassmorphic surfaces with 16px backdrop blur and a 1px Admin Gold border for high-authorization content.
- **Shadows:** Use high-spread, low-opacity shadows tinted with the Amethyst Primary color (#b794f4) rather than black to create an "atmospheric glow."
- **Interactive Shimmer:** High-priority components utilize a moving background linear gradient to denote active system monitoring.

## Shapes

The shape language is **Rounded** to convey modern software sophistication, contrasting against the technical "hard" data.

- **Standard Elements:** 0.5rem (8px) for buttons, inputs, and standard cards.
- **Outer Containers:** 1rem (16px) to create a clear nested hierarchy for large dashboard modules.
- **Status Indicators:** Perfect circles are used for security pulses and shield icons.
- **Elite Admin State:** High-level admin cards may feature "faceted" corners (subtle 45-degree clips) in addition to the base radius to imply a cut-gemstone aesthetic.

## Components

- **Premium Buttons:** Applied with the `amethyst-glow` gradient. On hover, increase brightness and apply a 12px Amethyst outer glow.
- **Security Inputs:** Deep Slate background with a 1px Amethyst border. On focus, the border should "pulse" with a subtle glow.
- **Role-Aware Chips:** 
    - *Standard:* Amethyst text on 10% Amethyst background.
    - *Admin:* Gold text on 10% Gold background with a subtle shimmer animation.
- **Monitoring Lists:** Row-based with 1px Slate-gray separators. Hover states trigger a subtle Amethyst-to-Transparent gradient background.
- **Admin Cards:** Feature a 1px `Admin Gold` top border and use `label-caps` in Gold for section headers.
- **The "Guardian" Shield:** A central circular visual component using the Electric Blue-to-Amethyst gradient, heavy backdrop blur, and a rotating "scanning" light effect for system status.
- **Monospace Terminal:** Uses the deepest neutral shade (#060e20) for background with `data-mono` typography in Amethyst for high-priority logs.