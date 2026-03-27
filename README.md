#  Tetris in C (WebSocket Server)

A fully functional Tetris game implemented in **pure C**, served via a **custom WebSocket server** and rendered in the browser.

##  Features

* 🧠 Complete Tetris game logic in C
* 🌐 Custom WebSocket implementation (no external libraries)
* 🎮 Real-time gameplay in browser
* ⚡ Dynamic level progression and scoring
* 👻 Ghost piece visualization
* 🔁 Auto-reconnect WebSocket handling

## 🛠️ Tech Stack

* C (WinSock2 for networking)
* WebSockets (manual implementation)
* HTML5 Canvas (frontend rendering)

## ▶️ How to Run

### 1. Compile

```bash
gcc -o tetris_server tetris_server.c -lws2_32 -O2
```

### 2. Run

```bash
tetris_server.exe
```

### 3. Open in browser

```
http://localhost:3000
```

## 🎮 Controls

* ⬅️ ➡️ : Move
* ⬆️ : Rotate
* ⬇️ : Soft drop
* Space : Hard drop
* P : Pause

## 📸 Screenshots

<img width="1115" height="812" alt="image" src="https://github.com/user-attachments/assets/39530f54-0a18-45c6-902d-82bedc6b210d" />

## 💡 Learning Outcomes

* Low-level networking using sockets
* WebSocket protocol implementation
* Game logic design in C
* Client-server architecture

## 📌 Future Improvements

* Multiplayer support
* Leaderboard system
* Sound effects
* Linux compatibility

---

Made as a mini project for C programming course 💻
