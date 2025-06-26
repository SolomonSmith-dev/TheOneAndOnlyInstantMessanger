#!/bin/bash

# Get the local IP address
LOCAL_IP=$(ifconfig | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -1)
PORT=3000

echo "🚀 AIM Clone Server Sharing Script"
echo "=================================="
echo ""
echo "📱 Mobile Access Instructions:"
echo "1. Make sure your phone is connected to the same WiFi network as this computer"
echo "2. Open your phone's web browser"
echo "3. Go to: http://$LOCAL_IP:$PORT"
echo ""
echo "💻 Local Access:"
echo "http://localhost:$PORT"
echo ""
echo "🌐 Network Access:"
echo "http://$LOCAL_IP:$PORT"
echo ""
echo "📋 Quick Share Links:"
echo "Mobile: http://$LOCAL_IP:$PORT"
echo "Local:  http://localhost:$PORT"
echo ""
echo "🔧 Troubleshooting:"
echo "- If mobile can't connect, check that both devices are on the same WiFi"
echo "- Try turning off mobile data temporarily"
echo "- Check if your router blocks local network communication"
echo ""
echo "📱 QR Code (if you have qrencode installed):"
if command -v qrencode &> /dev/null; then
    echo "Scan this QR code with your phone:"
    qrencode -t ansiutf8 "http://$LOCAL_IP:$PORT"
else
    echo "Install qrencode to generate QR codes: brew install qrencode"
fi

# Check if server is running
if ! curl -s http://localhost:3000 > /dev/null; then
    echo "❌ Server is not running!"
    echo "Start it with: npm start"
    exit 1
fi

echo "✅ Server is running on port 3000"
echo ""

echo "🌐 Option 1: Local Network (Same WiFi)"
echo "   Share this URL with friends on your WiFi:"
echo "   http://$LOCAL_IP:3000"
echo ""

echo "🌍 Option 2: Internet Access (Anywhere)"
echo "   This will create a public URL that anyone can access:"
echo ""

read -p "Do you want to create a public URL? (y/n): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Creating public URL with ngrok..."
    echo "This will give you a URL like: https://abc123.ngrok.io"
    echo ""
    
    # Start ngrok in background
    ngrok http 3000 > /dev/null 2>&1 &
    NGROK_PID=$!
    
    # Wait a moment for ngrok to start
    sleep 3
    
    # Get the public URL
    PUBLIC_URL=$(curl -s http://localhost:4040/api/tunnels | grep -o '"public_url":"[^"]*"' | cut -d'"' -f4 | head -1)
    
    if [ -n "$PUBLIC_URL" ]; then
        echo "✅ Public URL created!"
        echo "   Share this with anyone:"
        echo "   $PUBLIC_URL"
        echo ""
        echo "📱 Your friends can now access your AIM clone from anywhere!"
        echo ""
        echo "To stop sharing, press Ctrl+C"
        
        # Keep script running and show ngrok status
        while true; do
            echo "🔄 ngrok is running... (Press Ctrl+C to stop)"
            sleep 30
        done
    else
        echo "❌ Failed to create public URL"
        kill $NGROK_PID 2>/dev/null
    fi
else
    echo "📋 Summary of sharing options:"
    echo ""
    echo "🔗 Local Network: http://$LOCAL_IP:3000"
    echo "   - Friends on same WiFi only"
    echo "   - No internet required"
    echo "   - Fastest connection"
    echo ""
    echo "💡 To create public URL later, run: ./share.sh"
fi 