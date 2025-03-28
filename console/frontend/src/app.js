import React, { useState, useEffect } from 'react';

function App() {
  const [token, setToken] = useState(null);
  const [checking, setChecking] = useState(false);
  const [view, setView] = useState('home'); // home, signin, register
  const [accountname, setAccountname] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [adminEmail, setAdminEmail] = useState('');
  const [adminPhone, setAdminPhone] = useState('');
  const [accountExists, setAccountExists] = useState(null);

  useEffect(() => {
    checkAuthStatus(); // Initial check
    const interval = setInterval(checkAuthStatus, 2000); // Poll every 2s
    return () => clearInterval(interval);
  }, []);
  
  const checkAuthStatus = async () => {
    setChecking(true);
    try {
      const response = await fetch('http://localhost:11000/auth/status', { credentials: 'include' });
      if (!response.ok) {
        console.log(`Auth status failed: ${response.status}`);
        setToken(null); // Clear token on failure
        return;
      }
      const data = await response.json();
      if (data.token) {
        console.log('Token received:', data.token);
        setToken(data.token);
      }
    } catch (error) {
      console.error('Network error:', error);
      setToken(null);
    } finally {
      setChecking(false);
    }
  };

  const refreshToken = async () => {
    try {
      const response = await fetch('http://localhost:11000/refresh', { credentials: 'include' });
      if (!response.ok) {
        setToken(null);
        window.location.href = 'http://localhost:11000/logout';
        return false;
      }
      const data = await response.json();
      setToken(data.token);
      return true;
    } catch (error) {
      setToken(null);
      window.location.href = 'http://localhost:11000/logout';
      return false;
    }
  };

  const signIn = async () => {
    if (!username || !accountname) return alert('Username and account name required');
    const fullUsername = `${username}@${accountname}`;
    window.location.href = `http://localhost:4000/authorize?scope=openid&response_type=code&client_id=${accountname}-client&redirect_uri=http://localhost:11000/callback&state=xyz&realm=${accountname}&username=${fullUsername}`;
  };

  const checkAccountName = async () => {
    try {
      const response = await fetch(`http://localhost:12000/check-account?accountname=${accountname}`);
      const data = await response.json();
      setAccountExists(data.exists);
    } catch (error) {
      console.error('Error checking account:', error);
      setAccountExists(null);
    }
  };

  const register = async () => {
    if (!accountname || !adminEmail || !password) return alert('All fields required');
    try {
      const response = await fetch('http://localhost:12000/create-account', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ accountname, adminEmail, adminPhone, password }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Registration failed');
      alert('Account created successfully!');
      setView('signin');
    } catch (error) {
      console.error('Registration error:', error);
      alert('Failed to create account: ' + error.message);
    }
  };

  const createSchema = async () => { /* ... unchanged ... */ };
  const enroll = async () => { /* ... unchanged ... */ };

  useEffect(() => {
    checkAuthStatus();
    const interval = setInterval(checkAuthStatus, 2000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ textAlign: 'center', marginTop: '50px' }}>
      <h1>Console</h1>
      <p>Administrative Dashboard</p>
      {view === 'home' && (
        <div>
          <button onClick={() => setView('signin')}>Sign In</button>
          <button onClick={() => setView('register')} style={{ marginLeft: '10px' }}>Register</button>
        </div>
      )}
      {view === 'signin' && !token && (
        <div>
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <input
            type="text"
            placeholder="Account Name"
            value={accountname}
            onChange={(e) => setAccountname(e.target.value)}
          />
          <button onClick={signIn}>Sign In</button>
          <button onClick={() => setView('home')}>Back</button>
        </div>
      )}
      {view === 'register' && (
        <div>
          <input
            type="text"
            placeholder="Account Name"
            value={accountname}
            onChange={(e) => {
              setAccountname(e.target.value);
              setAccountExists(null);
            }}
            onBlur={checkAccountName}
          />
          {accountExists === true && <span style={{ color: 'red' }}>Account exists</span>}
          {accountExists === false && <span style={{ color: 'green' }}>✔</span>}
          <input
            type="email"
            placeholder="Admin Email"
            value={adminEmail}
            onChange={(e) => setAdminEmail(e.target.value)}
          />
          <input
            type="text"
            placeholder="Admin Phone (optional)"
            value={adminPhone}
            onChange={(e) => setAdminPhone(e.target.value)}
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button onClick={register}>Create Account</button>
          <button onClick={() => setView('home')}>Back</button>
        </div>
      )}
      {token && (
        <div>
          <p>Welcome, Administrator!</p>
          <button onClick={createSchema}>Create Schema</button>
          <button onClick={enroll} style={{ marginLeft: '10px' }}>Enroll</button>
          <button onClick={() => window.location.href = `http://localhost:8080/admin/${accountname}/console/`} style={{ marginLeft: '10px' }}>
            Manage Realm
          </button>
        </div>
      )}
    </div>
  );
}

export default App;