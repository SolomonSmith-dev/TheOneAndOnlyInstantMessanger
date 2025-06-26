# TheOneAndOnlyInstantMessanger

AOL Instant Messenger clone with authentic 90s/2000s aesthetic for your friend group! 🎉

## Features

✨ **Authentic AIM Experience:**
- Classic blue gradient background
- Retro window decorations and styling
- Iconic AIM interface layout
- Sound effects for messages and login

💬 **Real-time Messaging:**
- Instant message delivery
- Multiple chat windows
- Message timestamps
- Online/offline status indicators

👥 **Buddy Management:**
- Add and remove buddies
- Real-time status updates
- Away messages
- Buddy list with status indicators

🔐 **User Authentication:**
- User registration and login
- Secure password hashing
- JWT token authentication
- Remember me functionality

🎨 **Classic UI Elements:**
- Draggable chat windows
- Minimize/maximize/close buttons
- Status dropdown (Available/Away/Busy)
- Retro form styling

## Quick Start

### Prerequisites
- Node.js (version 14 or higher)
- npm or yarn

### Installation

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd TheOneAndOnlyInstantMessanger
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the server:**
   ```bash
   npm start
   ```

4. **Open your browser:**
   Navigate to `http://localhost:3000`

### Development Mode

For development with auto-restart:
```bash
npm run dev
```

## How to Use

### First Time Setup

1. **Register a new account:**
   - Enter your desired screen name
   - Create a password
   - Provide your email address
   - Click "Register"

2. **Add buddies:**
   - Click the "+" button in the buddy list
   - Enter your friend's screen name
   - Click "Add Buddy"

### Messaging

1. **Start a conversation:**
   - Click on any online buddy in your buddy list
   - A chat window will open

2. **Send messages:**
   - Type your message in the input field
   - Press Enter or click "Send"

3. **Manage chat windows:**
   - Drag windows around the screen
   - Minimize, maximize, or close windows
   - Multiple conversations at once

### Status Management

- **Change your status:** Use the dropdown in the buddy list
- **Set away message:** Type your away message in the input field
- **Sign out:** Select "Sign Out" from the status dropdown

## Technical Details

### Backend
- **Express.js** server with Socket.IO for real-time communication
- **JWT** authentication for secure sessions
- **bcryptjs** for password hashing
- In-memory user storage (can be extended to use a database)

### Frontend
- **Vanilla JavaScript** for the client-side logic
- **Socket.IO client** for real-time messaging
- **CSS3** with retro styling and gradients
- **HTML5** with semantic markup

### Real-time Features
- WebSocket connections for instant messaging
- Live buddy status updates
- Real-time message delivery
- Online/offline detection

## Customization

### Adding Custom Sounds
Replace the base64 encoded audio in `public/index.html` with your own sound files:

```html
<audio id="messageSound" preload="auto">
    <source src="path/to/your/sound.wav" type="audio/wav">
</audio>
```

### Styling Modifications
Edit `public/styles.css` to customize:
- Colors and gradients
- Window decorations
- Font styles
- Layout dimensions

### Adding Features
The modular structure makes it easy to add:
- File sharing
- Emoticons
- Message history
- Group chats
- Custom themes

## Browser Compatibility

- Chrome/Chromium (recommended)
- Firefox
- Safari
- Edge

## Security Notes

- This is a demo application with in-memory storage
- For production use, implement:
  - Database storage
  - HTTPS
  - Rate limiting
  - Input validation
  - CSRF protection

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - feel free to use this for your own projects!

---

**Enjoy your nostalgic AIM experience!** 🚀

*"You've got mail!" - but now it's instant messages!* 💬
