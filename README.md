# Red Team Command Reference

A comprehensive, searchable command reference tool for penetration testing and red team operations.

## Features

- 🔍 **Real-time Search** - Search across command titles, descriptions, syntax, and tags
- 📋 **One-Click Copy** - Easily copy commands to clipboard
- 🪟 **Multi-OS Support** - Commands for both Windows and Linux
- 📁 **Categorized Commands** - Organized by awareness, enumeration, network, credentials, privesc, persistence, and lateral movement
- 🎨 **Dark Theme** - Optimized for terminal work
- 📱 **Responsive Design** - Works on desktop, tablet, and mobile

## Tech Stack

- **Framework**: React 18
- **Build Tool**: Vite
- **Styling**: Tailwind CSS 4
- **Language**: JavaScript (JSX)

## Getting Started

### Prerequisites

- Node.js 18+ 
- npm or pnpm

### Installation

1. Navigate to the project directory:
```bash
cd redteam-commands
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm run dev
```

4. Open your browser to `http://localhost:5173`

### Building for Production

```bash
npm run build
```

The built files will be in the `dist/` directory.

## Project Structure

```
src/
├── components/          # React components
│   ├── Header.jsx       # Top navigation with search
│   ├── SearchBar.jsx    # Search input component
│   ├── OSTabs.jsx       # Windows/Linux toggle
│   ├── Sidebar.jsx      # Category navigation
│   ├── MainContent.jsx  # Main content area
│   ├── SubcategoryTabs.jsx  # Subcategory filters
│   ├── CommandCard.jsx  # Individual command display
│   └── CommandGrid.jsx  # Grid of command cards
├── data/                # Command data
│   ├── categories.js    # Category definitions
│   ├── windows-commands.js  # Windows commands
│   ├── linux-commands.js    # Linux commands
│   └── index.js         # Data exports
├── utils/               # Utility functions
│   ├── clipboard.js     # Copy to clipboard
│   └── search.js        # Search helpers
├── App.jsx              # Main application component
├── main.jsx             # Entry point
└── index.css            # Global styles
```

## Keyboard Shortcuts

- `Ctrl/Cmd + K` - Focus search bar
- `Escape` - Clear search and close

## Categories

- **Situational Awareness** - System info, user context, OS details
- **Enumeration** - Users, groups, shares, services
- **Network Discovery** - Network config, connections, shares
- **Credential Hunting** - Password files, credentials, keys
- **Privilege Escalation** - SUID, sudo, weak permissions
- **Persistence** - Autoruns, services, cron jobs
- **Lateral Movement** - Pass-the-hash, sessions, shares

## Contributing

Feel free to add more commands by editing the data files in `src/data/`.

## License

MIT
