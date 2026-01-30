# Cloud Security Labs Dashboard

An interactive, modern web dashboard for tracking progress through the Cloud Security & Compliance Labs learning paths.

## Features

### 🎯 **Progress Tracking**
- Real-time lab completion tracking
- Learning streak monitoring
- Skill level progression
- Time spent learning analytics

### 📊 **Visual Analytics**
- Interactive charts showing weekly progress
- Skill distribution visualization
- Learning path completion rates
- Performance trends over time

### 🏆 **Gamification**
- Achievement system
- Global leaderboard rankings
- Learning streaks and milestones
- Skill badges and certifications

### 🎨 **Modern UI/UX**
- Glassmorphism design
- Responsive layout for all devices
- Smooth animations and transitions
- Dark theme optimized for learning

## Quick Start

### Prerequisites
- Node.js 16+ installed
- npm or yarn package manager

### Installation

```bash
# Navigate to the dashboard directory
cd dashboard

# Install dependencies
npm install

# Start the development server
npm start
```

The dashboard will be available at `http://localhost:3000`

### Build for Production

```bash
# Build the optimized production bundle
npm run build

# The build files will be in the /build directory
```

## Dashboard Components

### 1. **Overview Stats**
- Overall completion percentage
- Total learning hours
- Achievements unlocked
- Global ranking position

### 2. **Learning Paths**
- Azure Security
- Compliance Frameworks
- DevSecOps Practices
- Incident Response
- Security Architecture

Each path shows:
- Progress bars
- Difficulty level
- Estimated completion time
- Labs completed vs total

### 3. **Analytics Charts**
- Weekly progress line chart
- Skill distribution pie chart
- Performance trends
- Time investment analysis

### 4. **Achievements System**
- Recent achievements display
- Milestone tracking
- Badge collection
- Progress rewards

### 5. **Recommendations**
- Personalized next lab suggestions
- Difficulty-based recommendations
- Path optimization suggestions
- Learning schedule optimization

## Technology Stack

- **React 18** - Modern UI framework
- **Tailwind CSS** - Utility-first CSS framework
- **Lucide React** - Beautiful icon library
- **Recharts** - Interactive chart library
- **Glassmorphism Design** - Modern UI aesthetic

## Customization

### Adding New Learning Paths

1. Update the `learningPaths` array in `src/App.js`
2. Add new path data with:
   - `id`: Unique identifier
   - `name`: Display name
   - `icon`: Lucide React icon
   - `color`: Tailwind color class
   - `labs`: Total number of labs
   - `completed`: Completed labs count
   - `difficulty`: Difficulty level
   - `estimatedHours`: Time estimate

### Modifying Colors

Update the Tailwind configuration in `tailwind.config.js` to customize the color scheme.

### Adding New Charts

Import additional chart components from Recharts and add them to the dashboard layout.

## Deployment

### Netlify Deployment

```bash
# Build the project
npm run build

# Deploy the /build folder to Netlify
```

### Vercel Deployment

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel --prod
```

### GitHub Pages

```bash
# Install gh-pages
npm install --save-dev gh-pages

# Add to package.json scripts
"homepage": "https://[username].github.io/[repository-name]",
"predeploy": "npm run build",
"deploy": "gh-pages -d build"

# Deploy
npm run deploy
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Future Enhancements

- [ ] User authentication and profiles
- [ ] Real-time collaboration features
- [ ] Mobile app version
- [ ] Integration with lab completion APIs
- [ ] Advanced analytics and reporting
- [ ] Community features and forums
- [ ] Certificate generation
- [ ] Integration with learning management systems

## Support

For issues and questions:
- Open an issue on GitHub
- Check the documentation
- Review the troubleshooting guide

---

**Built with passion for the cloud security community** 🛡️
