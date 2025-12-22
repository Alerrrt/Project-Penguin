# Project Echo Frontend

A modern, high-performance React + TypeScript dashboard for Project Echo, featuring real-time scan controls, modular UI, API integration, and advanced vulnerability reporting.

## Project Structure

- `src/`
  - `App.tsx` — Main dashboard layout and logic
  - `components/` — Modular UI components (PulseButton, CircleProgress, VulnerabilityList, ModuleStatusGrid, etc.)
  - `context/ScanContext.tsx` — Global scan state management (React Context)
  - `api/scanApi.ts` — API service layer for backend communication
  - `index.css` — TailwindCSS and global styles
- `public/` — Static assets
- `vite.config.ts` — Vite configuration

## Setup & Development

1. **Install dependencies:**
   ```bash
   cd frontend
   npm install
   ```
2. **Run the development server:**
   ```bash
   npm run dev
   ```
   The dashboard will be available at [http://localhost:5173](http://localhost:5173).

3. **Build for production:**
   ```bash
   npm run build
   ```
   The output will be in the `dist/` directory.

## API Integration

- All scan controls, progress, vulnerabilities, and stats are API-driven via `src/api/scanApi.ts`.
- Real-time updates are handled via polling (every 2 seconds) when a scan is running.
- To connect to your backend, update the API endpoint URLs in `scanApi.ts` as needed.

## Features

- **Scan Controls:** Start/stop scans, with real-time progress and status updates.
- **Module/Plugin Status Grid:** Visual grid showing the status of each scan module (success, running, failed, with error messages).
- **Vulnerability Reporting:** List, filter, and view details for all discovered vulnerabilities.
- **Export:** Download vulnerabilities as CSV (PDF export is stubbed for future integration).
- **User Feedback:** Toast notifications for all actions and errors.
- **Responsive & Accessible:** Fully responsive layout, keyboard navigation, and accessible color contrast.

## Customization

- **Add/Remove Modules:** Update the module/plugin list in the backend or wire up real module status to the `ModuleStatusGrid`.
- **Styling:** TailwindCSS is used for rapid, modern UI development. Customize `index.css` or Tailwind config as needed.
- **Component Reuse:** All UI elements are modular and reusable for easy extension.

## Contributing

- Follow best practices for React, TypeScript, and TailwindCSS.
- Use the provided context and API layers for state and data management.
- Run `npm run lint` and `npm run format` before submitting changes.

---

For questions or support, please contact the Project Echo maintainers.
