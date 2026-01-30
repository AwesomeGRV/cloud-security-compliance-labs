import React, { useState, useEffect } from 'react';
import { Shield, Cloud, Lock, AlertTriangle, CheckCircle, Clock, TrendingUp, Users, BookOpen, Award, Target, Zap } from 'lucide-react';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const CloudSecurityDashboard = () => {
  const [selectedPath, setSelectedPath] = useState('all');
  const [userProgress, setUserProgress] = useState({
    completedLabs: 12,
    totalLabs: 50,
    currentStreak: 7,
    totalHours: 24,
    skillLevel: 'Intermediate'
  });

  const learningPaths = [
    {
      id: 'azure',
      name: 'Azure Security',
      icon: Cloud,
      color: 'bg-blue-500',
      labs: 15,
      completed: 8,
      difficulty: 'Intermediate',
      estimatedHours: 20
    },
    {
      id: 'compliance',
      name: 'Compliance Frameworks',
      icon: Shield,
      color: 'bg-green-500',
      labs: 12,
      completed: 3,
      difficulty: 'Advanced',
      estimatedHours: 25
    },
    {
      id: 'devsecops',
      name: 'DevSecOps',
      icon: Lock,
      color: 'bg-purple-500',
      labs: 10,
      completed: 1,
      difficulty: 'Advanced',
      estimatedHours: 30
    },
    {
      id: 'incident-response',
      name: 'Incident Response',
      icon: AlertTriangle,
      color: 'bg-red-500',
      labs: 8,
      completed: 0,
      difficulty: 'Intermediate',
      estimatedHours: 15
    },
    {
      id: 'architecture',
      name: 'Security Architecture',
      icon: Target,
      color: 'bg-indigo-500',
      labs: 5,
      completed: 0,
      difficulty: 'Expert',
      estimatedHours: 35
    }
  ];

  const progressData = [
    { week: 'Week 1', completed: 2, hours: 4 },
    { week: 'Week 2', completed: 3, hours: 6 },
    { week: 'Week 3', completed: 4, hours: 8 },
    { week: 'Week 4', completed: 3, hours: 6 }
  ];

  const skillDistribution = [
    { name: 'Beginner', value: 15, color: '#10B981' },
    { name: 'Intermediate', value: 25, color: '#3B82F6' },
    { name: 'Advanced', value: 8, color: '#8B5CF6' },
    { name: 'Expert', value: 2, color: '#EF4444' }
  ];

  const recentAchievements = [
    { id: 1, title: 'Azure Network Security Expert', date: '2 days ago', icon: Award },
    { id: 2, title: '7-Day Streak Master', date: '1 week ago', icon: Zap },
    { id: 3, title: 'SOC 2 Compliance Basics', date: '2 weeks ago', icon: Shield }
  ];

  const upcomingLabs = [
    { id: 1, title: 'Implement Zero Trust Architecture', path: 'architecture', difficulty: 'Expert', duration: '4 hours' },
    { id: 2, title: 'Azure Sentinel Integration', path: 'azure', difficulty: 'Advanced', duration: '3 hours' },
    { id: 3, title: 'GDPR Compliance Automation', path: 'compliance', difficulty: 'Advanced', duration: '2 hours' }
  ];

  const completionRate = Math.round((userProgress.completedLabs / userProgress.totalLabs) * 100);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <header className="mb-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="w-10 h-10 text-blue-400" />
              <div>
                <h1 className="text-4xl font-bold text-white">Cloud Security Labs</h1>
                <p className="text-blue-200">Interactive Learning Dashboard</p>
              </div>
            </div>
            <div className="flex items-center space-x-6">
              <div className="text-right">
                <p className="text-blue-200 text-sm">Current Level</p>
                <p className="text-white text-xl font-semibold">{userProgress.skillLevel}</p>
              </div>
              <div className="text-right">
                <p className="text-blue-200 text-sm">Learning Streak</p>
                <p className="text-white text-xl font-semibold">{userProgress.currentStreak} days 🔥</p>
              </div>
            </div>
          </div>
        </header>

        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-blue-200 text-sm">Progress</p>
                <p className="text-3xl font-bold text-white">{completionRate}%</p>
                <p className="text-blue-200 text-xs mt-1">{userProgress.completedLabs}/{userProgress.totalLabs} labs</p>
              </div>
              <TrendingUp className="w-8 h-8 text-green-400" />
            </div>
          </div>
          
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-blue-200 text-sm">Total Hours</p>
                <p className="text-3xl font-bold text-white">{userProgress.totalHours}</p>
                <p className="text-blue-200 text-xs mt-1">Learning time</p>
              </div>
              <Clock className="w-8 h-8 text-blue-400" />
            </div>
          </div>

          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-blue-200 text-sm">Achievements</p>
                <p className="text-3xl font-bold text-white">12</p>
                <p className="text-blue-200 text-xs mt-1">Unlocked</p>
              </div>
              <Award className="w-8 h-8 text-yellow-400" />
            </div>
          </div>

          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-blue-200 text-sm">Rank</p>
                <p className="text-3xl font-bold text-white">#42</p>
                <p className="text-blue-200 text-xs mt-1">Global leaderboard</p>
              </div>
              <Users className="w-8 h-8 text-purple-400" />
            </div>
          </div>
        </div>

        {/* Learning Paths */}
        <div className="mb-8">
          <h2 className="text-2xl font-bold text-white mb-6">Learning Paths</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {learningPaths.map((path) => {
              const Icon = path.icon;
              const pathProgress = Math.round((path.completed / path.labs) * 100);
              
              return (
                <div key={path.id} className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20 hover:bg-white/15 transition-all cursor-pointer">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center space-x-3">
                      <div className={`p-2 rounded-lg ${path.color}`}>
                        <Icon className="w-6 h-6 text-white" />
                      </div>
                      <div>
                        <h3 className="text-white font-semibold">{path.name}</h3>
                        <p className="text-blue-200 text-sm">{path.difficulty}</p>
                      </div>
                    </div>
                  </div>
                  
                  <div className="space-y-3">
                    <div className="flex justify-between text-sm">
                      <span className="text-blue-200">Progress</span>
                      <span className="text-white">{path.completed}/{path.labs} labs</span>
                    </div>
                    <div className="w-full bg-white/20 rounded-full h-2">
                      <div 
                        className={`${path.color} h-2 rounded-full transition-all duration-300`}
                        style={{ width: `${pathProgress}%` }}
                      />
                    </div>
                    <div className="flex justify-between text-xs text-blue-200">
                      <span>📚 {path.estimatedHours}h total</span>
                      <span>📊 {pathProgress}% complete</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Charts Section */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <h3 className="text-xl font-semibold text-white mb-4">Weekly Progress</h3>
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={progressData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                <XAxis dataKey="week" stroke="#93C5FD" />
                <YAxis stroke="#93C5FD" />
                <Tooltip 
                  contentStyle={{ backgroundColor: 'rgba(0,0,0,0.8)', border: 'none', borderRadius: '8px' }}
                  labelStyle={{ color: '#93C5FD' }}
                />
                <Legend />
                <Line type="monotone" dataKey="completed" stroke="#10B981" strokeWidth={2} name="Labs Completed" />
                <Line type="monotone" dataKey="hours" stroke="#3B82F6" strokeWidth={2} name="Hours Spent" />
              </LineChart>
            </ResponsiveContainer>
          </div>

          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <h3 className="text-xl font-semibold text-white mb-4">Skill Distribution</h3>
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={skillDistribution}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, value }) => `${name}: ${value}`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {skillDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Recent Achievements & Upcoming Labs */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <h3 className="text-xl font-semibold text-white mb-4">Recent Achievements</h3>
            <div className="space-y-3">
              {recentAchievements.map((achievement) => {
                const Icon = achievement.icon;
                return (
                  <div key={achievement.id} className="flex items-center space-x-3 p-3 bg-white/5 rounded-lg">
                    <Icon className="w-8 h-8 text-yellow-400" />
                    <div className="flex-1">
                      <p className="text-white font-medium">{achievement.title}</p>
                      <p className="text-blue-200 text-sm">{achievement.date}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <h3 className="text-xl font-semibold text-white mb-4">Recommended Next Labs</h3>
            <div className="space-y-3">
              {upcomingLabs.map((lab) => (
                <div key={lab.id} className="p-3 bg-white/5 rounded-lg hover:bg-white/10 transition-all cursor-pointer">
                  <div className="flex justify-between items-start">
                    <div>
                      <p className="text-white font-medium">{lab.title}</p>
                      <div className="flex items-center space-x-3 mt-1">
                        <span className="text-xs bg-blue-500/20 text-blue-300 px-2 py-1 rounded">{lab.path}</span>
                        <span className="text-xs text-blue-200">{lab.duration}</span>
                      </div>
                    </div>
                    <span className={`text-xs px-2 py-1 rounded ${
                      lab.difficulty === 'Expert' ? 'bg-red-500/20 text-red-300' :
                      lab.difficulty === 'Advanced' ? 'bg-purple-500/20 text-purple-300' :
                      'bg-green-500/20 text-green-300'
                    }`}>
                      {lab.difficulty}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CloudSecurityDashboard;
