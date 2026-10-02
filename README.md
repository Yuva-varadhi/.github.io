# Yuva Varadhi (యువ వారధి) — National Digital Governance & Citizen Services Portal

[![CI/CD Parity & Security Pipeline](https://github.com/leelavishnu2005-AV1423/yuva-vardahi-website/actions/workflows/deploy.yml/badge.svg)](https://github.com/leelavishnu2005-AV1423/yuva-vardahi-website/actions)
[![License: Institutional Universal](https://img.shields.io/badge/License-Institutional%20Universal-blue.svg)](LICENSE)
[![Zero Framework](https://img.shields.io/badge/Frontend-Pure%20HTML5%20%7C%20Vanilla%20CSS3%20%7C%20ES6%2B-2563eb.svg)](https://developer.mozilla.org)
[![Backend: Node.js Express](<https://img.shields.io/badge/Backend-Node.js%20Express%20(Clustered)-059669.svg>)](https://nodejs.org)
[![Database: Supabase PostgreSQL](<https://img.shields.io/badge/Database-Supabase%20PostgreSQL%20(Strict%20RLS)-3ecf8e.svg>)](https://supabase.com)
[![WCAG 2.1 Touch Target](<https://img.shields.io/badge/Accessibility-WCAG%202.1%20Compliant%20(44x44px)-4f46e5.svg>)](https://www.w3.org/WAI/WCAG21/quickref/)

**Yuva Varadhi (యువ వారధి)** is an enterprise-grade, national universal governance and citizen services web platform. Designed to deliver high-concurrency public administration, it connects students, farmers, youth, job aspirants, and citizens across the nation to academic syllabi, career intelligence, agronomy calculators, and confidential grievance redressal.

The architecture enforces strict **Zero-Framework Frontend Standards** (Pure HTML5, Modern Responsive CSS3, and ES6+ Vanilla JavaScript) coupled with a **Clustered Node.js/Express Backend** and **Supabase PostgreSQL Cloud Database** fortified by Zero-Leak Row-Level Security (RLS).

---

## 🏛️ Key Architectural Pillars

### 1. Selective Hard-Gated Wall & Public Grievance Desk

- **Publicly Accessible Desk (Pre-Login)**:
  - The **Citizen Grievance Redressal Desk** is 100% accessible to unauthenticated visitors. Any citizen can submit an urgent complaint and receive an anonymous cryptographically generated tracking token (`YV-GRV-XXXXXX`).
  - Structured complaints are automatically routed to the designated supreme administrative mailbox: `yuvavaradhi1@gmail.com`.
  - Complainant personal identifiable information (PII) is masked in public lookups (`S. V•••••`, `98480 •••••`) and unmasked exclusively for the Super Administrator.
- **Hard-Gated Core Modules (Post-Login Only)**:
  - Core functional modules—**Education & Syllabus**, **Agriculture & Agronomy**, **Sports Excellence**, and **Government Jobs Radar**—are 100% locked and unmounted from the DOM for unauthenticated visitors.
  - Attempted route or hash access (`#/education`, `#/agriculture`, `#/sports`, `#/govt_jobs`) triggers an immediate modal intercept (`#authModal`) and routes the user back to the safe dashboard view.

### 2. Multi-Device Cloud Sync Architecture (Zero Local Storage Dependency)

- **Zero Client-Side User Storage**:
  - User credentials, active session records, academic bookmarks, crop lots, and grievance dossiers do not depend on client-side `localStorage`.
  - Upon authentication, user state dynamically rehydrates live into memory (`yvRuntimeState`) directly from Supabase PostgreSQL tables (`public.profiles`, `public.academic_assets`, `public.crop_listings`, `public.grievances`).
- **Cross-Device Synchronization**:
  - Seamless cross-device login across Android, iOS, tablets, laptops, and desktop computers with live state restoration.
  - In offline scenarios, an encrypted client-side mirror cache ensures continuous operability until cloud sync reconnects.

### 3. 5-Tier RBAC & Root Super Administrator Provisioning Console

- **Supreme Master Identity**: `yuvavaradhi1@gmail.com`
  - Hardcoded root authority with an exclusive **Master Provisioning Console** (`#masterProvisioningModal`).
  - Features 5 management control panels: Super & Module Admins, Quota Enforcer, Verified Teachers Registry, Citizen & Student Roster, and Real-Time Telemetry / Unmasked Grievance Vault.
- **Statutory Sub-Admin Quota (Max 5 per Sector)**:
  - Enforced via database-level PostgreSQL triggers (`chk_subadmin_sector_quota`) and frontend validation. Rejects any attempt to recruit a 6th Sub-Admin in any functional sector (Education, Agriculture, Sports, Govt Jobs).
- **Cryptographic Verified Teacher IDs (`TCHR-XXXX`)**:
  - Provisions certified educators with unique hexadecimal identifiers (`TCHR-8821`, `TCHR-4A92`).
- **Anti-Self-Registration Protocol**:
  - Administrative, Sub-Admin, and Faculty accounts cannot self-register. Public registration is strictly restricted to Consumer roles (`Student` or `Citizen`).

### 4. Responsive Mobile-First Design & Institutional Palette

- **Fluid Viewports**: 100% responsive reflow from compact smartphones (320px, 375px), tablets (768px), up to 4K desktop displays (1024px, 1440px+).
- **WCAG 2.1 Touch Target Compliance**: All clickable elements, pills, inputs, and buttons maintain a minimum 44×44px interactive touch surface (`touch-action: manipulation`).
- **Collapsible Mobile Drawer**: Animated hamburger menu toggle (`#navHamburgerBtn`, `toggleMobileNav()`) with `aria-expanded` state tracking.
- **Pure Institutional Color System**:
  - Canvas: Pure White (`#FFFFFF`) with subtle slate elevation borders (`#E2E8F0`).
  - Hero Section: Light Sky-Blue gradient (`linear-gradient(135deg, #EBF4FF 0%, #E0F2FE 100%)`).
  - Primary Actions: Corporate Blue (`#2563EB`) with hover (`#1D4ED8`).
  - Badges & Accents: Emerald (`#059669`), Sky (`#0284c7`), Amber/Gold (`#D97706`), Rose (`#E11D48`).
- **Whole-Website Watermark Overlay**:
  - Non-intrusive institutional seal overlay (`#siteWatermark`) fixed centrally with `mix-blend-mode: multiply`, `opacity: 0.065`, and `pointer-events: none !important`.
- **Zero Dummy Data**:
  - Empty states feature standardized clean skeleton placeholders: `"No data published yet. Awaiting Administrator update"`.
- **Universal All-India Geo-Neutrality**:
  - Zero references to specific states ("AP", "Andhra Pradesh", "Telangana", "TS"). All agricultural centers, civil services, academic boards, and sports councils reflect an all-India national scope.

---

## 📁 Repository Structure

```
yuva-vardahi-website/
├── .github/
│   └── workflows/
│       └── deploy.yml              # GitHub Actions CI/CD (Parity check & Pages deployment)
├── assets/
│   ├── images/
│   │   ├── favicon.png             # Official web app icon
│   │   ├── logo.png                # National seal emblem
│   │   └── watermark.png           # Watermark emblem asset
│   └── docs/                       # Syllabi, circulars, and study blueprints
├── data/
│   └── security_store.json         # Encrypted fallback datastore & SHA-256 audit ledger
├── scratch/                        # Internal build engines & compilation utilities
│   ├── apply_gatekeeper_final.js   # Single-source portal compiler & parity engine
│   └── build_unified_portal.js     # Unified web portal build source
├── tests/                          # Automated Chrome/Edge DevTools Protocol (CDP) test suites
│   ├── test_enterprise_architecture.js    # 24-point end-to-end enterprise validation
│   ├── test_responsive_cross_device.js    # 320px, 375px, 768px, 1440px layout tests
│   ├── test_selective_hard_gate.js        # Hard-gated core modules vs public grievance test
│   ├── test_service_modules_order.js      # 1. Edu, 2. Agri, 3. Sports, 4. Jobs order test
│   ├── test_hidden_admin_box.js           # Production login modal credential security
│   ├── test_isolated_view_architecture.js # Zero-reload SPA isolated workspaces test
│   ├── test_agriculture_unified_module.js # 74-point agronomy, D2C, machinery test
│   └── test_security_server.js            # 32-point Helmet, PBKDF2, rate limit, audit test
├── index.html                      # Primary entry point (100% SHA-256 byte parity)
├── yuva_varadhi_unified.html        # Dual mirror distribution (100% SHA-256 byte parity)
├── register.html                   # Standalone citizen/student registration gateway
├── schema.sql                      # Complete PostgreSQL DDL schema with RLS & triggers
├── schema_rls_security.sql         # Production hardened RLS policies & triggers for Supabase
├── server.js                       # Clustered Node.js/Express backend server
├── package.json                    # Project metadata & npm scripts
└── README.md                       # Complete technical & deployment documentation
```

---

## 🚀 Quick Start & Local Development

### Prerequisites

- **Node.js**: v18.x or higher (v20+ / v22+ LTS recommended)
- **npm**: v9.x or higher
- **Microsoft Edge** or **Google Chrome** (for headless automated CDP testing)

### Installation

```bash
# Clone the repository
git clone https://github.com/leelavishnu2005-AV1423/yuva-vardahi-website.git
cd yuva-vardahi-website

# Install production and development dependencies
npm install
```

### Running the Clustered Backend

```bash
# Start the clustered server on http://127.0.0.1:3000
npm start

# Or start directly with node
node server.js
```

### Compiling & Verifying 100% SHA-256 Byte Parity

To compile changes into both `index.html` and `yuva_varadhi_unified.html` with dual byte parity:

```bash
node scratch/apply_gatekeeper_final.js
```

---

## 🧪 Comprehensive Verification & Test Suites

The portal is validated by 8 automated test suites interacting via Chrome/Edge DevTools Protocol (CDP):

| Test Suite                                 | Purpose                                                                                              | Target Coverage             |
| :----------------------------------------- | :--------------------------------------------------------------------------------------------------- | :-------------------------- |
| `tests/test_enterprise_architecture.js`    | Full lifecycle verification (RBAC, SQL schema, content filtering, grievance vault, 5-subadmin quota) | 24 / 24 Tests Passed (100%) |
| `tests/test_responsive_cross_device.js`    | Viewports (320px, 375px, 768px, 1440px), hamburger menu, 44px touch targets                          | 100% Passed                 |
| `tests/test_selective_hard_gate.js`        | Public grievance desk access vs hard-gated core modules & post-login DOM mounting                    | 100% Passed                 |
| `tests/test_service_modules_order.js`      | Enforces exact sequence: 1. Education, 2. Agriculture, 3. Sports, 4. Govt Jobs                       | 100% Passed                 |
| `tests/test_hidden_admin_box.js`           | Verifies default Super Admin credentials box is hidden on production login modals                    | 12 / 12 Tests Passed        |
| `tests/test_isolated_view_architecture.js` | Zero-reload isolated workspaces with zero DOM clutter or cross-module leakage                        | 28 / 28 Tests Passed        |
| `tests/test_agriculture_unified_module.js` | Dual gateways, machinery booking, pest diagnosis, D2C crop marketplace, APMC ticker                  | 74 / 74 Tests Passed        |
| `tests/test_security_server.js`            | Helmet headers, PBKDF2 salt hashing, rate limiting, audit chain integrity                            | 32 / 32 Tests Passed        |

Run tests individually:

```bash
node tests/test_enterprise_architecture.js
node tests/test_responsive_cross_device.js
node tests/test_selective_hard_gate.js
node tests/test_security_server.js
```

---

## 🌐 Cloud Deployment Guides

### Option A: Static Frontend Deployment (GitHub Pages)

1. Push changes to the `main` branch.
2. The included GitHub Actions workflow (`.github/workflows/deploy.yml`) automatically checks byte parity and publishes `index.html`, `assets/`, and related public assets to **GitHub Pages**.
3. In repository settings, navigate to **Pages** > **Build and deployment** > Source: **GitHub Actions**.

### Option B: Static Frontend Deployment (Vercel / Netlify)

- **Vercel**:
  - Link your GitHub repository.
  - Framework Preset: **Other**.
  - Root Directory: `./`
  - Build Command: `node scratch/apply_gatekeeper_final.js`
  - Output Directory: `./`
- **Netlify**:
  - Link your GitHub repository.
  - Publish directory: `./`
  - Build command: `node scratch/apply_gatekeeper_final.js`

### Option C: Backend Service Deployment (Render / Railway / VPS)

- **Render**:
  - Create a new **Web Service** connected to your repository.
  - Environment: **Node.js**.
  - Build Command: `npm install && node scratch/apply_gatekeeper_final.js`
  - Start Command: `node server.js`
  - Set Environment Variables:
    ```env
    PORT=10000
    NODE_ENV=production
    SESSION_SECRET=<random_256_bit_secret>
    SUPABASE_URL=https://<your-project>.supabase.co
    SUPABASE_ANON_KEY=<your_supabase_anon_key>
    ```

### Option D: Database Provisioning (Supabase PostgreSQL)

1. Create a new project in [Supabase](https://supabase.com).
2. Open the **SQL Editor** in your Supabase project dashboard.
3. Copy the entire contents of `schema.sql` (or `schema_rls_security.sql`) and click **Run**.
4. The script provisions:
   - Tables: `profiles`, `subjects`, `resources`, `academic_assets`, `crop_listings`, `farmer_crop_listings`, `grievances`, `admin_hierarchy`, `security_audit_ledger`.
   - Row-Level Security (RLS) policies isolating citizen grievances strictly to `yuvavaradhi1@gmail.com`.
   - Statutory Sub-Admin Quota triggers (`chk_subadmin_sector_quota`).
   - Foreign key constraints and automated `handle_new_user()` profile triggers.
5. Retrieve your **Project URL** and **Anon Public Key** from **Settings > API** and supply them to your frontend/backend configuration.

---

## 🛡️ Cybersecurity & Hardening Specifications

- **Content Security Policy (CSP)**: Hardened Helmet headers permitting only verified CDNs (`https://cdn.jsdelivr.net`, Google Fonts, and Supabase cloud endpoints).
- **Anti-Privilege Escalation**: Server strictly rejects registration requests for elevated roles (`super_admin`, `module_admin`, `sub_admin`, `faculty`). Contributor identities must be provisioned by `yuvavaradhi1@gmail.com`.
- **PBKDF2 Password Security**: Salted cryptographic password hashing with 10,000 iterations and constant-time verification (`crypto.timingSafeEqual`) to prevent timing attacks.
- **Rate Limiting & Lockout**: Express rate limiting mitigates brute-force attacks by locking out an IP for 15 minutes after 5 failed authentication attempts.
- **Zero-Leak Citizen Privacy**: Grievance petitioner contact numbers are masked in all public views.
- **SHA-256 Audit Trail**: Chained, tamper-evident hash ledger logs administrative and governance transactions.

---

## 👥 Core Technical Engineering Team

- **Mahendra**
- **Venkatesh**
- **Aswanth**
- **Adi Narayana Reddy**

---

## 📄 License & Institutional Rights

© 2026 **Yuva Varadhi (యువ వారధి) National Governance Initiative**. Developed for citizen empowerment, youth career acceleration, agricultural prosperity, and secure governance.
