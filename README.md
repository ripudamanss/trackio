# Trackio — Smart Expense Tracker

Trackio is a modern, premium, full-stack personal finance and expense tracker built with Node.js, Express, and SQLite/libSQL. It helps users manage their income and expenses, visualize their spending splits with dynamic canvas-based charts, and keep track of daily averages.

## TEAM - NextByte
## 👥 Team Members

| Name |
|------|
| GORAV |
| RIPUDAMAN |
| KULWANT |
| SUNIL |

---

## 🚀 Key Features

* **Full-Stack Architecture**: Dynamic server-side API endpoints replace client-side localStorage.
* **Persistent Database**: Built using SQLite via `@libsql/client`, supporting both local file-based database and cloud-based persistent storage (Turso).
* **Secure Authentication**: User signup, login, and sessions using HttpOnly cookies. Passwords are encrypted using salted PBKDF2 hashing.
* **Transaction Management**: Add, view, edit, and delete transactions.
* **Smart UI Handlers**: 
  * Displays the expense emoji (`💸`) for all income entries in the list.
  * Description is completely optional; falls back to showing the Category Label (e.g. `Food`, `Study`) if omitted.
* **Account Settings**: A settings panel to securely change passwords and manage sessions.
* **WiFi Network Access**: Binds to all network interfaces (`0.0.0.0`) so you can access it on other devices (like your phone) over WiFi.
* **Vercel Serverless Ready**: Configured for seamless deployment to Vercel with path rewrites and read-only filesystem fallbacks.

## 🛠 Tech Stack

* **Frontend**: HTML5, Vanilla CSS3 (custom CSS design system with micro-animations), and Vanilla JavaScript.
* **Backend**: Node.js, Express.
* **Database**: SQLite / libSQL (`@libsql/client`).
* **Session & Security**: Native `node:crypto` hashing (PBKDF2) and HttpOnly session cookies.

---

## 💻 Local Development Setup

### Prerequisites

* [Node.js](https://nodejs.org/) (v22.5.0+ recommended for built-in fetch/sqlite support)
* [npm](https://www.npmjs.com/)

### Installation

1. **Clone the repository**:
   ```bash
   git clone <https://github.com/gorav18/trackio.git>
   cd trackio
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Start the local server**:
   ```bash
   npm run start
   # Or for auto-reload on file edits:
   npm run dev
   ```

4. **Access the application**:
   * WEBPAGE: [https://trackio-snowy.vercel.app](https://trackio-snowy.vercel.app)

---

## ☁️ Production Deployment (Vercel)

Trackio is pre-configured to run out of the box on Vercel.

## 📂 Project Structure

```text
├── api/
│   └── index.js          # Vercel serverless function entrypoint
├── database.db           # Local SQLite file database (git-ignored)
├── index.html            # Main frontend page
├── package.json          # Node project scripts & dependencies
├── problems.md           # Tracked issues & resolutions
├── server.js             # Express application & API router
└── vercel.json           # Vercel deployment & rewrite configuration
```
