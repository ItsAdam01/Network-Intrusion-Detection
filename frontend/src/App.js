import React, { useEffect, useState } from 'react';
import io from 'socket.io-client';

const socket = io('http://localhost:5000');

function App() {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    socket.on('new_alert', (data) => {
      setAlerts((prevAlerts) => [data, ...prevAlerts]);
      console.log("New Alert Received:", data);
    });
    return () => socket.off('new_alert');
  }, []);

  return (
    <div className="dashboard">
      <h1>Live NIDS Dashboard</h1>
      {alerts.map((alert, index) => (
        <div key={index}>{JSON.stringify(alert)}</div>
      ))}
    </div>
  );
}

export default App;