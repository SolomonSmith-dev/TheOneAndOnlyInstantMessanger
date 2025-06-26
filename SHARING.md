# 🚀 How to Share Your AIM Clone

## Quick Start

**Your server is already running!** Here are your sharing options:

### 🌐 **Option 1: Local Network (Same WiFi)**
**Share this URL with friends on your WiFi:**
```
http://192.168.1.44:3000
```

**Perfect for:**
- Friends in the same room/building
- No internet required
- Fastest connection
- Most secure

---

### 🌍 **Option 2: Internet Access (Anywhere)**
**Use the sharing script:**
```bash
./share.sh
```

This will create a public URL like: `https://abc123.ngrok.io`

**Perfect for:**
- Friends anywhere in the world
- Remote friends
- Anyone with internet access

---

## 📱 **How Your Friends Use It**

### Step 1: Open the URL
- Local: `http://192.168.1.44:3000`
- Public: `https://abc123.ngrok.io` (from share.sh)

### Step 2: Register Account
- Choose a screen name
- Create a password
- Enter email address
- Click "Register"

### Step 3: Add Buddies
- Click the "+" button in buddy list
- Enter your friend's screen name
- Click "Add Buddy"

### Step 4: Start Chatting!
- Click on any online buddy
- Type messages and press Enter
- Enjoy the nostalgic AIM experience!

---

## 🔧 **Sharing Methods**

### **Method 1: Easy Script (Recommended)**
```bash
./share.sh
```
- Automatically detects your IP
- Offers both local and public options
- Handles ngrok setup for you

### **Method 2: Manual Local Network**
```bash
# Find your IP
ifconfig | grep "inet " | grep -v 127.0.0.1

# Share the URL
http://YOUR_IP:3000
```

### **Method 3: Manual Public URL**
```bash
# Start ngrok
ngrok http 3000

# Share the URL from ngrok output
```

---

## 🎯 **Sharing Scenarios**

### **Scenario 1: Friends in Same Room**
- Use local network URL
- Everyone connects to WiFi
- Share: `http://192.168.1.44:3000`

### **Scenario 2: Remote Friends**
- Use public URL from `./share.sh`
- Share the ngrok URL
- Works from anywhere

### **Scenario 3: Multiple Locations**
- Start with local network
- Switch to public URL if needed
- Both work simultaneously

---

## 🛠 **Troubleshooting**

### **Can't Connect Locally**
- Check if friends are on same WiFi
- Verify firewall settings
- Try different browser

### **Can't Connect Publicly**
- Make sure ngrok is running
- Check if URL is still active
- Restart with `./share.sh`

### **Server Won't Start**
```bash
# Kill existing process
lsof -ti:3000 | xargs kill -9

# Restart server
npm start
```

---

## 📋 **Quick Reference**

| Method | URL Format | Best For | Speed |
|--------|------------|----------|-------|
| Local Network | `http://192.168.1.44:3000` | Same WiFi | Fast |
| Public URL | `https://abc123.ngrok.io` | Anywhere | Medium |

### **Commands**
```bash
# Start server
npm start

# Share options
./share.sh

# Test connection
curl http://localhost:3000

# Find your IP
ifconfig | grep "inet " | grep -v 127.0.0.1
```

---

## 🎉 **Pro Tips**

1. **Keep the server running** while friends are using it
2. **Use local network** when possible for best performance
3. **Public URLs expire** when you stop ngrok
4. **Multiple friends** can connect simultaneously
5. **No registration required** for ngrok (free tier)

---

**Ready to share? Run `./share.sh` and start chatting!** 🚀💬 