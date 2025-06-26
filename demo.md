# AIM Clone Demo Guide

## Quick Demo Setup

### 1. Start the Server
```bash
npm start
```

### 2. Open Multiple Browser Windows
Open `http://localhost:3000` in multiple browser windows or tabs to simulate different users.

### 3. Create Test Accounts

**User 1:**
- Username: `alice`
- Password: `password123`
- Email: `alice@example.com`

**User 2:**
- Username: `bob`
- Password: `password123`
- Email: `bob@example.com`

**User 3:**
- Username: `charlie`
- Password: `password123`
- Email: `charlie@example.com`

### 4. Add Buddies
1. Log in as `alice`
2. Click the "+" button in the buddy list
3. Add `bob` and `charlie` as buddies
4. Repeat for other users

### 5. Start Chatting
1. Click on any online buddy to open a chat window
2. Send messages back and forth
3. Try different statuses (Available, Away, Busy)
4. Test away messages

## Features to Test

### ✅ Authentication
- [ ] Register new accounts
- [ ] Login with existing accounts
- [ ] Remember me functionality
- [ ] Sign out

### ✅ Buddy Management
- [ ] Add new buddies
- [ ] See buddy status (online/offline)
- [ ] View away messages
- [ ] Remove buddies

### ✅ Real-time Messaging
- [ ] Send instant messages
- [ ] Receive messages in real-time
- [ ] Multiple chat windows
- [ ] Message timestamps

### ✅ UI Features
- [ ] Draggable chat windows
- [ ] Minimize/maximize windows
- [ ] Status dropdown
- [ ] Away message input
- [ ] Sound effects

### ✅ Classic AIM Experience
- [ ] Blue gradient background
- [ ] Retro window styling
- [ ] Classic button designs
- [ ] Authentic layout

## Network Testing

To test with friends on your local network:

1. **Find your IP address:**
   ```bash
   # On macOS/Linux
   ifconfig | grep "inet " | grep -v 127.0.0.1
   
   # On Windows
   ipconfig | findstr "IPv4"
   ```

2. **Share the URL:**
   ```
   http://YOUR_IP_ADDRESS:3000
   ```

3. **Friends can connect:**
   - They'll see the same login screen
   - Can register their own accounts
   - Add each other as buddies
   - Start chatting!

## Troubleshooting

### Server won't start
- Check if port 3000 is already in use
- Try: `lsof -ti:3000 | xargs kill -9`
- Or change the port in `server.js`

### Can't connect from other devices
- Check your firewall settings
- Make sure you're on the same network
- Try using your computer's IP address instead of localhost

### Messages not sending
- Check browser console for errors
- Make sure both users are online
- Verify Socket.IO connection is established

## Fun Extras

### Custom Sounds
Replace the base64 audio in `public/index.html` with your own:
- Message notification sounds
- Login/logout sounds
- Error sounds

### Custom Themes
Modify `public/styles.css` to create:
- Different color schemes
- Custom gradients
- Alternative layouts

### Add Features
The modular code makes it easy to add:
- File sharing
- Emoticons
- Message history
- Group chats
- Custom avatars

---

**Enjoy your nostalgic AIM experience!** 🚀 