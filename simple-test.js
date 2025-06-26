// Simple test script to verify the AIM clone setup
console.log('🧪 Testing AIM Clone Setup...\n');

// Test 1: Check if server is running
async function testServerConnection() {
    console.log('1. Testing server connection...');
    try {
        const response = await fetch('http://localhost:3000');
        if (response.ok) {
            console.log('✅ Server is running and responding');
            return true;
        } else {
            console.log('❌ Server responded with error:', response.status);
            return false;
        }
    } catch (error) {
        console.log('❌ Cannot connect to server:', error.message);
        return false;
    }
}

// Test 2: Test user registration
async function testUserRegistration() {
    console.log('\n2. Testing user registration...');
    try {
        const response = await fetch('http://localhost:3000/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: 'testuser',
                password: 'testpass123',
                email: 'test@example.com'
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            console.log('✅ User registration successful');
            return data.token;
        } else {
            console.log('❌ Registration failed:', data.error);
            return null;
        }
    } catch (error) {
        console.log('❌ Registration error:', error.message);
        return null;
    }
}

// Test 3: Test user login
async function testUserLogin() {
    console.log('\n3. Testing user login...');
    try {
        const response = await fetch('http://localhost:3000/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: 'testuser',
                password: 'testpass123'
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            console.log('✅ User login successful');
            return data.token;
        } else {
            console.log('❌ Login failed:', data.error);
            return null;
        }
    } catch (error) {
        console.log('❌ Login error:', error.message);
        return null;
    }
}

// Test 4: Test buddy list endpoint
async function testBuddyList(token) {
    console.log('\n4. Testing buddy list endpoint...');
    try {
        const response = await fetch('http://localhost:3000/api/buddies', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            console.log('✅ Buddy list endpoint working');
            console.log(`   Found ${data.length} buddies`);
            return true;
        } else {
            console.log('❌ Buddy list failed:', response.status);
            return false;
        }
    } catch (error) {
        console.log('❌ Buddy list error:', error.message);
        return false;
    }
}

// Run all tests
async function runTests() {
    const serverOk = await testServerConnection();
    if (!serverOk) {
        console.log('\n❌ Server tests failed. Make sure the server is running with: npm start');
        process.exit(1);
    }
    
    const token = await testUserRegistration();
    if (!token) {
        console.log('\n❌ Registration test failed');
        process.exit(1);
    }
    
    const loginToken = await testUserLogin();
    if (!loginToken) {
        console.log('\n❌ Login test failed');
        process.exit(1);
    }
    
    const buddyListOk = await testBuddyList(loginToken);
    if (!buddyListOk) {
        console.log('\n❌ Buddy list test failed');
        process.exit(1);
    }
    
    console.log('\n🎉 All tests passed! Your AIM clone is ready to use!');
    console.log('\n📱 Open your browser and go to: http://localhost:3000');
    console.log('\n👥 To test with friends:');
    console.log('   1. Share your local IP address with them');
    console.log('   2. They can connect to: http://YOUR_IP:3000');
    console.log('   3. Register accounts and add each other as buddies');
    console.log('\n🚀 Have fun chatting!');
    console.log('\n💡 Features included:');
    console.log('   - Authentic 90s/2000s AIM interface');
    console.log('   - Real-time messaging with Socket.IO');
    console.log('   - User registration and authentication');
    console.log('   - Buddy list management');
    console.log('   - Away messages and status updates');
    console.log('   - Draggable chat windows');
    console.log('   - Classic sound effects');
}

runTests().catch(console.error); 