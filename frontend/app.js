import React, { userEffect, useState } from 'react';
import io from 'socket.io-client';

const socket =  io('httpL//localhost:5000');

function App() {
    const [alerts, setAlerts] = useState([]);
    useEffect(() => {
        socket.on('new_alert', (data)=>{
            setAlerts((prevAlerts) => [data, ...prevAlerts]);
            console.log("New Alert Received: ", data);
        });

        return () => socket.off('new_alert');
    }, []);
}

return (
    <div className="dashboard">
        <h1>Live NIDS Dashboard</h1>
    </div>
)