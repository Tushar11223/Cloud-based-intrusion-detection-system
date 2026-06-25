import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

export default function TrafficChart({ data }) {
  // Transform data for chart
  const chartData = {};
  
  data.forEach(item => {
    const time = item._id.time;
    const label = item._id.label;
    
    if (!chartData[time]) {
      chartData[time] = { time, benign: 0, malware: 0 };
    }
    
    if (label === 'BENIGN') {
      chartData[time].benign = item.count;
    } else if (label === 'MALWARE') {
      chartData[time].malware = item.count;
    }
  });
  
  const transformedData = Object.values(chartData);
  
  if (transformedData.length === 0) {
    return <div style={{ padding: '20px', textAlign: 'center', color: '#999' }}>No data to display</div>;
  }
  
  return (
    <ResponsiveContainer width="100%" height={300}>
      <LineChart data={transformedData}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="time" tick={{ fontSize: 12 }} />
        <YAxis />
        <Tooltip />
        <Legend />
        <Line type="monotone" dataKey="benign" stroke="#4CAF50" name="Benign" />
        <Line type="monotone" dataKey="malware" stroke="#f44336" name="Malware" />
      </LineChart>
    </ResponsiveContainer>
  );
}
