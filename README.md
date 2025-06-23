# SOC Dashboard - Real-time Security Operations Center

A professional Security Operations Center (SOC) dashboard that displays real-world security data and threat intelligence.

## Features

### 🛡️ Real-time Security Monitoring
- **Critical Alerts**: Live tracking of high-priority security incidents
- **Active Threats**: Current threat landscape monitoring
- **Network Events**: Real-time network security events
- **Incident Resolution**: Daily resolved incident tracking

### 📊 Data Visualization
- **Threat Intelligence Charts**: 24-hour threat activity timeline
- **Attack Type Distribution**: Breakdown of different cyberattack categories
- **Interactive Filtering**: Filter events by severity level
- **Auto-refresh**: Updates every 30 seconds

### 🌐 Real Data Sources
The dashboard fetches data from multiple legitimate security sources:
- **NIST CVE Database**: Latest vulnerability information
- **GitHub Security Repositories**: Threat intelligence feeds
- **Malware Tracking**: Real malware campaign data
- **IP Blacklists**: Known malicious IP addresses

### 🔧 System Monitoring
- **Firewall Status**: Network perimeter security
- **IDS/IPS**: Intrusion detection and prevention
- **SIEM**: Security information and event management
- **Threat Intelligence**: Feed status and updates

## Installation & Usage

### Quick Start
1. Clone or download the dashboard files
2. Open `index.html` in a modern web browser
3. The dashboard will automatically start loading real security data

### File Structure
```
soc-dashboard/
├── index.html          # Main dashboard interface
├── styles.css          # Professional dark theme styling
├── script.js           # Real data fetching and processing
└── README.md           # This documentation
```

### Browser Requirements
- Modern web browser (Chrome, Firefox, Safari, Edge)
- JavaScript enabled
- Internet connection for real data feeds

## Technical Details

### Data Sources
The dashboard attempts to fetch real data from:
- **NIST NVD API**: `https://services.nvd.nist.gov/rest/json/cves/1.0/`
- **GitHub API**: `https://api.github.com/repos/stamparm/maltrail/commits`
- **Security Feeds**: Various open threat intelligence sources

### Fallback System
When external APIs are unavailable, the dashboard uses realistic simulated data to ensure continuous operation.

### Security Features
- **CORS-compliant**: Uses public APIs safely
- **No sensitive data**: All data sources are publicly available
- **Fallback mechanisms**: Graceful degradation when APIs are down
- **Real-time updates**: Automatic data refresh every 30 seconds

## Dashboard Components

### Header
- **System Status**: Online/offline indicator
- **Current Time**: Real-time clock
- **Refresh Button**: Manual data update

### Statistics Cards
- **Critical Alerts**: High-priority security events
- **Active Threats**: Current threat count
- **Network Events**: Network security activity
- **Resolved Incidents**: Daily resolution count

### Charts
- **Line Chart**: 24-hour threat activity timeline
- **Doughnut Chart**: Attack type distribution

### Events Table
- **Filterable**: View all, critical, or warning events
- **Real-time**: Live security event feed
- **Sortable**: Organized by timestamp

### Threat Map
- **Global Intelligence**: Worldwide threat data
- **Source Attribution**: Threat origin tracking
- **Real-time Updates**: Live threat feed

## Customization

### Refresh Interval
Modify the update interval in `script.js`:
```javascript
this.updateInterval = 30000; // 30 seconds (30000ms)
```

### Color Scheme
Customize colors in `styles.css`:
```css
:root {
    --primary-color: #3498db;
    --danger-color: #e74c3c;
    --warning-color: #f39c12;
    --success-color: #27ae60;
}
```

### Data Sources
Add new APIs in `script.js`:
```javascript
const urls = [
    'your-api-endpoint-here',
    // existing URLs...
];
```

## Performance

- **Lightweight**: Pure HTML/CSS/JS implementation
- **Responsive**: Mobile and desktop friendly
- **Optimized**: Efficient data processing
- **Reliable**: Fallback systems ensure uptime

## Security Considerations

- Uses only public, legitimate security data sources
- No authentication credentials required
- CORS-compliant API calls
- No sensitive information stored or transmitted

## Browser Console

Open developer tools to see:
- API call status
- Data loading progress
- Fallback mode notifications
- Real-time update logs

## Troubleshooting

### No Data Loading
1. Check internet connection
2. Verify browser allows cross-origin requests
3. Check browser console for errors
4. Dashboard will use fallback data if APIs are unavailable

### Performance Issues
1. Close other browser tabs
2. Refresh the page
3. Check system resources
4. Disable browser extensions temporarily

## Future Enhancements

- [ ] Historical data trends
- [ ] Custom alert thresholds
- [ ] Export functionality
- [ ] Additional data sources
- [ ] Advanced filtering options
- [ ] Mobile app integration

## License

This is a demonstration project for educational purposes. Use responsibly and in accordance with all applicable laws and API terms of service.

---

**Disclaimer**: This dashboard displays real security data for monitoring and educational purposes. It should not be used as the sole source for critical security decisions.
